#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
//#include <attr/attributes.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSLIB

#include "etcd.h"
#include "network.h"
#include "allocator.h"
#include "mds_rpc.h"
#include "sysutil.h"
#include "net_table.h"
#include "diskid.h"
#include "cds_rpc.h"
#include "ylib.h"
#include "dbg.h"

#if 1
#define STATIC
#else
#define STATIC static
#endif

typedef struct {
        int count;
        int cursor;
        diskid_t array[0];
} allocator_node_t;

typedef struct {
        struct list_head hook;
        uint64_t poolid;
        int etcd_idx;
        sy_rwlock_t lock;
        int count;
        int cursor;
        allocator_node_t **array;
} allocator_t;

typedef struct {
        sy_rwlock_t rwlock;
        struct list_head list;
} allocator_list_t;

static allocator_list_t *__allocator_list__ = NULL; 

STATIC int __allocator_disk(const diskid_t *diskid)
{
        int ret;
        nid_t nid;

        ret = d2n_nid(diskid, &nid);
        if(ret)
                GOTO(err_ret, ret);

        ret = network_connect(&nid, NULL, 1, 0);
        if(ret)
                GOTO(err_ret, ret);

        DINFO("disk %s/%d online\n", network_rname(&nid), diskid->id);
        
        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_node(const char *nodeinfo, allocator_node_t **_allocator_node)
{
        int ret, disk_count = 512;
        char *list[512];
        allocator_node_t *allocator_node;
        diskid_t diskid;

        const char *pos = strchr(nodeinfo, ' ');
        if (pos == NULL) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }
        
        DINFO("scan %s, disk %s\n", nodeinfo, pos + 1);

        disk_count = 1024;
        char tmp[MAX_BUF_LEN];
        strcpy(tmp, pos + 1);
        _str_split(tmp, ',', list, &disk_count);

        YASSERT(disk_count);

        ret = ymalloc((void **)&allocator_node, sizeof(*allocator_node)
                      + sizeof(diskid_t) * disk_count);
        if (ret)
                GOTO(err_ret, ret);

        allocator_node->count = 0;
        allocator_node->cursor = _random();
        for (int i = 0; i < disk_count; i++) {
                str2nid(&diskid, list[i]);

                ret = __allocator_disk(&diskid);
                if (ret)
                        continue;
                
                allocator_node->array[allocator_node->count] = diskid;
                allocator_node->count++;
        }

        if (allocator_node->count == 0) {
                yfree((void **)&allocator_node);
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }

        *_allocator_node = allocator_node;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_scan(char *value, int *_count, allocator_node_t ***_array)
{
        int ret, node_count, count;
        char *list[1024];
        allocator_node_t **node_array, *allocator_node;

        node_count = 1024;
        _str_split(value, '\n', list, &node_count);

        if (node_count == 0) {
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }

        ret = ymalloc((void **)&node_array, sizeof(allocator_node_t *) * node_count);
        if (ret)
                GOTO(err_ret, ret);

        count = 0;
        for (int i = 0; i < node_count; i++) {
                ret = __allocator_node(list[i], &allocator_node);
                if (ret)
                        continue;

                node_array[count] = allocator_node;
                count++;
        }

        if (count == 0) {
                yfree((void **)&node_array);
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }
        
        *_array = node_array;
        *_count = count;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_replace(allocator_t *allocator, int count,
                               allocator_node_t **array)
{
        int ret, old;
        allocator_node_t **old_array;
        
        ret = sy_rwlock_wrlock(&allocator->lock);
        if (ret)
                GOTO(err_ret, ret);

        old = allocator->count;
        old_array = allocator->array;
        allocator->count = count;
        allocator->array = array;
                
        sy_rwlock_unlock(&allocator->lock);

        for (int i = 0; i < old; i++) {
                yfree((void **)&old_array[i]);
        }

        return 0;
err_ret:
        return ret;
}

STATIC allocator_t *__allocator_find(allocator_list_t *allocator_list, uint64_t poolid)
{
        struct list_head *pos;
        allocator_t *allocator;

        list_for_each(pos, &allocator_list->list) {
                allocator = (void *)pos;
                if (allocator->poolid == poolid) {
                        return allocator;
                }
        }
        
        return NULL;
}

STATIC int __allocator_update(uint64_t poolid, int count,
                              allocator_node_t **node_array)
{
        int ret;
        allocator_list_t *allocator_list = __allocator_list__;
        allocator_t *allocator;

        ret = sy_rwlock_rdlock(&allocator_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        allocator = __allocator_find(allocator_list, poolid);
        if (allocator) {
                ret = __allocator_replace(allocator, count, node_array);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = ENOENT;
                goto err_lock;
        }
        
        sy_rwlock_unlock(&allocator_list->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&allocator_list->rwlock);
err_ret:
        return ret;
}

STATIC int __allocator_insert(uint64_t poolid, int count,
                              allocator_node_t **node_array)
{
        int ret;
        allocator_list_t *allocator_list = __allocator_list__;
        allocator_t *allocator;

        ret = sy_rwlock_wrlock(&allocator_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        allocator = __allocator_find(allocator_list, poolid);
        if (allocator) {
                ret = __allocator_replace(allocator, count, node_array);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = ymalloc((void **)&allocator, sizeof(*allocator));
                if (ret)
                        GOTO(err_lock, ret);

                memset(allocator, 0x0, sizeof(*allocator));
                ret = sy_rwlock_init(&allocator->lock, "allocator");
                if (ret)
                        GOTO(err_lock, ret);

                allocator->poolid = poolid;
                allocator->etcd_idx = -1;
                list_add_tail(&allocator->hook, &allocator_list->list);

                ret = __allocator_replace(allocator, count, node_array);
                if (ret)
                        GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&allocator_list->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&allocator_list->rwlock);
err_ret:
        return ret;
}

STATIC int __allocator_needupdate(uint64_t poolid, int idx)
{
        int ret, _idx;
        allocator_list_t *allocator_list = __allocator_list__;
        allocator_t *allocator;

        YASSERT(idx != -1);
        
        ret = sy_rwlock_rdlock(&allocator_list->rwlock);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        allocator = __allocator_find(allocator_list, poolid);
        if (allocator == NULL) {
                _idx = -1;
        } else {
                _idx = allocator->etcd_idx;
        }
        
        sy_rwlock_unlock(&allocator_list->rwlock);

        return _idx != idx;
}


STATIC int __allocator_pool(uint64_t poolid, char *value)
{
        int ret, idx, count;
        char key[MAX_PATH_LEN];
        allocator_node_t **node_array;

        snprintf(key, MAX_NAME_LEN, "id/%ju/diskmap", poolid);

        ret = etcd_get_text(ETCD_POOL, key, value, &idx);
        if (ret)
                GOTO(err_ret, ret);

        if (__allocator_needupdate(poolid, idx) == 0) {
                DINFO("need not update\n");
                goto out;
        }
        
        ret = __allocator_scan(value, &count, &node_array);
        if (ret) {
                DWARN("scan fail\n");
                goto out;
        }

        ret = __allocator_update(poolid, count, node_array);
        if (ret) {
                if (ret == ENOENT) {
                        ret = __allocator_insert(poolid, count, node_array);
                        if (ret)
                                GOTO(err_ret, ret);
                }
        }

out:
        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_worker__(char *buf)
{
        int ret;
        etcd_node_t *array = NULL;
        uint64_t poolid;

        ret = etcd_list1(ETCD_POOL, "id", &array);
        if (ret)
                GOTO(err_ret, ret);

        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                poolid = atoll(node->key);

                ret = __allocator_pool(poolid, buf);
                if (ret)
                        continue;
        }        
        
        free_etcd_node(array);
        
        return 0;
err_ret:
        return ret;
}

STATIC void *__allocator_worker(void *arg)
{
        int ret;
        char *buf;

        (void) arg;

        ret = ymalloc((void **)&buf, 1024 * 1024);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        while (1) {
                __allocator_worker__(buf);
                sleep(5);
        }
        
        yfree((void **)&buf);
        pthread_exit(NULL);
}

int allocator_init()
{
        int ret;
        allocator_list_t *allocator_list;

        ret = ymalloc((void **)&allocator_list, sizeof(*allocator_list));
        if (ret)
                GOTO(err_ret, ret);

        ret = sy_rwlock_init(&allocator_list->rwlock, "allocator_list");
        if (ret)
                GOTO(err_ret, ret);

        INIT_LIST_HEAD(&allocator_list->list);

        __allocator_list__ = allocator_list;
        
        ret = sy_thread_create2(__allocator_worker, NULL, "allocator");
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

STATIC void __allocator_new_disk(allocator_node_t *node, diskid_t *diskid)
{
        *diskid = node->array[node->cursor % node->count];
        node->cursor++;
}

STATIC int __allocator_new__(allocator_t *allocator, int repnum, diskid_t *disks)
{
        int ret;

        if (allocator->count < repnum) {
                ret = ENOSPC;
                DWARN("need %u got %u\n", repnum, allocator->count);
                GOTO(err_ret, ret);
        }

        int cur = allocator->cursor;
        for (int i = 0; i < repnum; i++ ) {
                __allocator_new_disk(allocator->array[(i + cur) % allocator->count],
                                     &disks[i]);
        }

        allocator->cursor++;

        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_solo(allocator_t *allocator, int repnum, diskid_t *disks)
{
        int ret;
        allocator_node_t *node = allocator->array[0];

        YASSERT(allocator->count == 1);

        if (node->count < repnum) {
                ret = ENOSPC;
                DWARN("need %u got %u\n", repnum, node->count);
                GOTO(err_ret, ret);
        }

        int cur = node->cursor;
        for (int i = 0; i < repnum; i++ ) {
                disks[i] = node->array[(i + cur) % node->count];
        }

        node->cursor++;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_new(uint64_t poolid, int repnum, diskid_t *disks)
{
        int ret;
        allocator_list_t *allocator_list = __allocator_list__;
        allocator_t *allocator;

        YASSERT(allocator_list);
        
        ret = sy_rwlock_rdlock(&allocator_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        allocator = __allocator_find(allocator_list, poolid);
        if (allocator == NULL) {
                ret = ENOSPC;
                GOTO(err_lock, ret);
        }

        if (gloconf.solomode && allocator->count == 1) {
                ret = __allocator_solo(allocator, repnum, disks);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = __allocator_new__(allocator, repnum, disks);
                if (ret)
                        GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&allocator_list->rwlock);

        return 0;
err_lock:
        sy_rwlock_unlock(&allocator_list->rwlock);
err_ret:
        return ret;
}

int allocator_new(uint64_t poolid, int repnum, nid_t *disks)
{
#if ENABLE_ALLOCATE_BALANCE
        int ret;
        nid_t array[16];

        YASSERT(repnum + 1 < 16);

        ret = __allocator_new(poolid, repnum + 1, array);
        if (ret) {
                if (ret == ENOSPC) {
                        return __allocator_new(poolid, repnum, disks);
                } else {
                        GOTO(err_ret, ret);
                }
        }

        netable_sort(array, repnum + 1);
        memcpy(disks, array, sizeof(nid_t) * repnum);
        
        return 0;
err_ret:
        return ret;
#else
        return  __allocator_new(repnum, hardend, tier, disks);
#endif
}

int allocator_disk_register(uint64_t poolid, const nid_t *nid, diskid_t *diskid,
                            const char *faultdomain)
{
        int ret;
        char key[MAX_PATH_LEN], buf[MAX_BUF_LEN];

        snprintf(key, MAX_NAME_LEN, "id/%ju/node/%d/disk/%d", poolid, nid->id,
                 diskid->id);

        ret = etcd_get_text(ETCD_POOL, key, buf, NULL);
        if (ret) {
                if (ret == ENOKEY) {
                        DINFO("register %s\n", key);
                        ret = etcd_set_text(ETCD_POOL, key, faultdomain, O_CREAT, -1);
                        if (ret)
                                GOTO(err_ret, ret);
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int allocator_disk_unregister(uint64_t poolid, const nid_t *nid, const diskid_t *diskid)
{
        int ret;
        char key[MAX_PATH_LEN];

        snprintf(key, MAX_NAME_LEN, "id/%ju/node/%d/disk/%d", poolid, nid->id,
                 diskid->id);
        ret = etcd_del(ETCD_POOL, key);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __allocator_disk_dump(const char *pool, const nid_t *nid, char *buf)
{
        int ret;
        char key[MAX_PATH_LEN];
        etcd_node_t *array = NULL;
        diskid_t diskid;
        uint64_t poolid;
        disk_info_t stat;

        snprintf(key, MAX_NAME_LEN, "id/%s/node/%d/disk", pool, nid->id);
        ret = etcd_list1(ETCD_POOL, key, &array);
        if (ret)
                GOTO(err_ret, ret);

        if (array->num_node == 0) {
                goto out;
        }
        
        snprintf(buf + strlen(buf), MAX_NAME_LEN, "%d ", nid->id);
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s, nodeid %d diskid %s, faultdomain %s\n",
                      pool, nid->id, node->key, node->value);

                str2diskid(&diskid, node->key);

                ret = cds_rpc_stat(&diskid, &stat);
                if (ret || stat.capacity - stat.used < mdsconf.disk_keep) {
                        poolid = atoll(pool);
                        allocator_disk_unregister(poolid, nid, &diskid);
                        continue;
                }
                
                snprintf(buf + strlen(buf), MAX_NAME_LEN, "%s,", node->key);
        }

        buf[strlen(buf) - 1] = '\n';
        
out:
        free_etcd_node(array);

        return 0;
//err_free:
        //free_etcd_node(array);
err_ret:
        return ret;
}

STATIC int __allocator_node_dump(const char *pool)
{
        int ret;
        char key[MAX_PATH_LEN], buf[MAX_BUF_LEN];
        etcd_node_t *array = NULL;
        nid_t nid;

        snprintf(key, MAX_NAME_LEN, "id/%s/node", pool);
        ret = etcd_list1(ETCD_POOL, key, &array);
        if (ret)
                GOTO(err_ret, ret);

        buf[0] = '\0';
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s, nodeid %s, faultdomain %s\n",
                      pool, node->key, node->value);

                str2nid(&nid, node->key);
                ret = network_connect(&nid, NULL, 1, 0);
                if (ret) {
                        DWARN("node %s offline\n", network_rname(&nid));
                        continue;
                }

                ret = __allocator_disk_dump(pool, &nid, buf);
                if (ret)
                        GOTO(err_free, ret);
        }
        
        free_etcd_node(array);

        int len = strlen(buf);
        if (len && buf[len -1] == '\n') {
                buf[len - 1] = '\0';
        }

        snprintf(key, MAX_NAME_LEN, "id/%s/diskmap", pool);
        ret = etcd_set_text(ETCD_POOL, key, buf, O_CREAT, -1);
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_free:
        free_etcd_node(array);
err_ret:
        return ret;
}


int allocator_dump()
{
        int ret;
        etcd_node_t *array = NULL;

        ret = etcd_list1(ETCD_POOL, "id", &array);
        if (ret)
                GOTO(err_ret, ret);

        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s\n", node->key);

                ret = __allocator_node_dump(node->key);
                if (ret)
                        GOTO(err_free, ret);
        }
        
        free_etcd_node(array);
        
        return 0;
err_free:
        free_etcd_node(array);
err_ret:
        return ret;
}
