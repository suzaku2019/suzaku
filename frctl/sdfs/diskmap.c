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
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSLIB

#include "etcd.h"
#include "network.h"
#include "diskmap.h"
#include "mds_rpc.h"
#include "sysutil.h"
#include "net_table.h"
#include "diskid.h"
#include "cds_rpc.h"
#include "ylib.h"
#include "nodeid.h"
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
} diskmap_node_t;

typedef struct {
        struct list_head hook;
        uint64_t poolid;
        int etcd_idx;
        sy_rwlock_t lock;
        int count;
        int cursor;
        diskmap_node_t **array;
} diskmap_t;

typedef struct {
        sy_rwlock_t rwlock;
        struct list_head list;
} diskmap_list_t;

static diskmap_list_t *__diskmap_list__ = NULL;

STATIC int __diskmap_disk(const diskid_t *diskid)
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

STATIC int __diskmap_node(const char *nodeinfo, diskmap_node_t **_diskmap_node)
{
        int ret, disk_count = 512;
        char *list[512];
        diskmap_node_t *diskmap_node;
        diskid_t diskid;

        const char *pos = strchr(nodeinfo, ' ');
        if (pos == NULL) {
                ret = EINVAL;
                DWARN("nodeinfo %s\n", nodeinfo);
                GOTO(err_ret, ret);
        }
        
        DINFO("scan %s, disk %s\n", nodeinfo, pos + 1);

        disk_count = 1024;
        char tmp[MAX_BUF_LEN];
        strcpy(tmp, pos + 1);
        _str_split(tmp, ',', list, &disk_count);

        YASSERT(disk_count);

        ret = ymalloc((void **)&diskmap_node, sizeof(*diskmap_node)
                      + sizeof(diskid_t) * disk_count);
        if (ret)
                GOTO(err_ret, ret);

        diskmap_node->count = 0;
        diskmap_node->cursor = _random();
        for (int i = 0; i < disk_count; i++) {
                char *tmp[2];
                int tmp_count = 2;
                _str_split(list[i], '/', tmp, &tmp_count);
                str2nid(&diskid, tmp[0]);

                if (atoi(tmp[1]) == 0)
                        continue;
                
                diskmap_node->array[diskmap_node->count] = diskid;
                diskmap_node->count++;
        }

        if (diskmap_node->count == 0) {
                yfree((void **)&diskmap_node);
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }

        *_diskmap_node = diskmap_node;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __diskmap_scan(char *value, int *_count, diskmap_node_t ***_array)
{
        int ret, node_count, count;
        char *list[1024];
        diskmap_node_t **node_array, *diskmap_node;

        node_count = 1024;
        _str_split(value, '\n', list, &node_count);

        if (node_count == 0) {
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }

        ret = ymalloc((void **)&node_array, sizeof(diskmap_node_t *) * node_count);
        if (ret)
                GOTO(err_ret, ret);

        count = 0;
        for (int i = 0; i < node_count; i++) {
                ret = __diskmap_node(list[i], &diskmap_node);
                if (ret)
                        continue;

                node_array[count] = diskmap_node;
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

STATIC int __diskmap_replace(diskmap_t *diskmap, int count,
                             diskmap_node_t **array, int idx)
{
        int ret, old;
        diskmap_node_t **old_array;

        ret = sy_rwlock_wrlock(&diskmap->lock);
        if (ret)
                GOTO(err_ret, ret);

        DBUG("pool %ju idx %u -> %u\n", diskmap->poolid, diskmap->etcd_idx, idx);
        
        old = diskmap->count;
        old_array = diskmap->array;
        diskmap->count = count;
        diskmap->array = array;
        diskmap->etcd_idx = idx;

        sy_rwlock_unlock(&diskmap->lock);

        for (int i = 0; i < old; i++) {
                yfree((void **)&old_array[i]);
        }

        return 0;
err_ret:
        return ret;
}

STATIC diskmap_t *__diskmap_find(diskmap_list_t *diskmap_list, uint64_t poolid)
{
        struct list_head *pos;
        diskmap_t *diskmap;

        list_for_each(pos, &diskmap_list->list) {
                diskmap = (void *)pos;
                if (diskmap->poolid == poolid) {
                        return diskmap;
                }
        }
        
        return NULL;
}

STATIC int __diskmap_update(uint64_t poolid, int count,
                            diskmap_node_t **node_array, int idx)
{
        int ret;
        diskmap_list_t *diskmap_list = __diskmap_list__;
        diskmap_t *diskmap;

        ret = sy_rwlock_rdlock(&diskmap_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        diskmap = __diskmap_find(diskmap_list, poolid);
        if (diskmap) {
                ret = __diskmap_replace(diskmap, count, node_array, idx);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = ENOENT;
                goto err_lock;
        }
        
        sy_rwlock_unlock(&diskmap_list->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&diskmap_list->rwlock);
err_ret:
        return ret;
}

STATIC int __diskmap_insert(uint64_t poolid, int count,
                            diskmap_node_t **node_array, int idx)
{
        int ret;
        diskmap_list_t *diskmap_list = __diskmap_list__;
        diskmap_t *diskmap;

        ret = sy_rwlock_wrlock(&diskmap_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        diskmap = __diskmap_find(diskmap_list, poolid);
        if (diskmap) {
                ret = __diskmap_replace(diskmap, count, node_array, idx);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = ymalloc((void **)&diskmap, sizeof(*diskmap));
                if (ret)
                        GOTO(err_lock, ret);

                memset(diskmap, 0x0, sizeof(*diskmap));
                ret = sy_rwlock_init(&diskmap->lock, "diskmap");
                if (ret)
                        GOTO(err_lock, ret);

                diskmap->poolid = poolid;
                diskmap->etcd_idx = -1;
                list_add_tail(&diskmap->hook, &diskmap_list->list);

                ret = __diskmap_replace(diskmap, count, node_array, idx);
                if (ret)
                        GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&diskmap_list->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&diskmap_list->rwlock);
err_ret:
        return ret;
}

STATIC int __diskmap_needupdate(uint64_t poolid, int idx)
{
        int ret, _idx;
        diskmap_list_t *diskmap_list = __diskmap_list__;
        diskmap_t *diskmap;

        YASSERT(idx != -1);
        
        ret = sy_rwlock_rdlock(&diskmap_list->rwlock);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        diskmap = __diskmap_find(diskmap_list, poolid);
        if (diskmap == NULL) {
                _idx = -1;
        } else {
                _idx = diskmap->etcd_idx;
        }
        
        sy_rwlock_unlock(&diskmap_list->rwlock);

        DBUG("pool %d idx %u %u\n", poolid, idx, _idx);
        
        return _idx != idx;
}


STATIC int __diskmap_pool(uint64_t poolid, char *value, int *update)
{
        int ret, idx, count;
        char key[MAX_PATH_LEN];
        diskmap_node_t **node_array;

        snprintf(key, MAX_NAME_LEN, "id/%ju/diskmap", poolid);

        ret = etcd_get_text(ETCD_POOL, key, value, &idx);
        if (ret)
                GOTO(err_ret, ret);

        if (__diskmap_needupdate(poolid, idx) == 0) {
                DBUG("need not update\n");
                *update = 0;
                goto out;
        }

        ret = __diskmap_scan(value, &count, &node_array);
        if (ret) {
                DWARN("scan fail\n");
                goto out;
        }

        ret = __diskmap_update(poolid, count, node_array, idx);
        if (ret) {
                if (ret == ENOENT) {
                        ret = __diskmap_insert(poolid, count, node_array, idx);
                        if (ret)
                                GOTO(err_ret, ret);
                }
        }

        *update = 1;
out:
        return 0;
err_ret:
        return ret;
}

static int __diskmap_worker_scan(char *buf, int *_update)
{
        int ret, update;
        etcd_node_t *array = NULL;
        uint64_t poolid;

        ret = etcd_list1(ETCD_POOL, "id", &array);
        if (ret)
                GOTO(err_ret, ret);

        *_update = 0;
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                poolid = atoll(node->key);

                ret = __diskmap_pool(poolid, buf, &update);
                if (ret)
                        continue;

                *_update += update;
        }
        
        free_etcd_node(array);

        return 0;
err_ret:
        return ret;
}

STATIC int __diskmap_worker__(char *buf)
{
        int ret, update;

        ret = __diskmap_worker_scan(buf, &update);
        if (ret)
                GOTO(err_ret, ret);
        
        if (update) {
                ret = disktab_rebuild(buf);
                YASSERT(ret == 0);
        }
        
        return 0;
err_ret:
        return ret;
}

STATIC void *__diskmap_worker(void *arg)
{
        int ret;
        char *buf;

        (void) arg;

        ret = ymalloc((void **)&buf, 1024 * 1024);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        while (1) {
                __diskmap_worker__(buf);
                sleep(5);
        }
        
        yfree((void **)&buf);
        pthread_exit(NULL);
}

int diskmap_init()
{
        int ret;
        diskmap_list_t *diskmap_list;

        ret = ymalloc((void **)&diskmap_list, sizeof(*diskmap_list));
        if (ret)
                GOTO(err_ret, ret);

        ret = sy_rwlock_init(&diskmap_list->rwlock, "diskmap_list");
        if (ret)
                GOTO(err_ret, ret);

        INIT_LIST_HEAD(&diskmap_list->list);

        __diskmap_list__ = diskmap_list;

        ret = disktab_init();
        if (ret)
                UNIMPLEMENTED(__DUMP__);
        
        ret = sy_thread_create2(__diskmap_worker, NULL, "diskmap");
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

STATIC void __diskmap_new_disk(diskmap_node_t *node, diskid_t *diskid)
{
        *diskid = node->array[node->cursor % node->count];
        node->cursor++;
}

STATIC int __diskmap_new__(diskmap_t *diskmap, int repnum, diskid_t *disks)
{
        int ret;

        if (diskmap->count < repnum) {
                ret = ENOSPC;
                DWARN("need %u got %u\n", repnum, diskmap->count);
                GOTO(err_ret, ret);
        }

        int cur = diskmap->cursor;
        for (int i = 0; i < repnum; i++ ) {
                __diskmap_new_disk(diskmap->array[(i + cur) % diskmap->count],
                                     &disks[i]);
        }

        diskmap->cursor++;

        return 0;
err_ret:
        return ret;
}

STATIC int __diskmap_solo(diskmap_t *diskmap, int repnum, diskid_t *disks)
{
        int ret;
        diskmap_node_t *node = diskmap->array[0];

        YASSERT(diskmap->count == 1);

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

STATIC int __diskmap_new(uint64_t poolid, int repnum, diskid_t *disks)
{
        int ret;
        diskmap_list_t *diskmap_list = __diskmap_list__;
        diskmap_t *diskmap;

        YASSERT(diskmap_list);
        
        ret = sy_rwlock_rdlock(&diskmap_list->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        diskmap = __diskmap_find(diskmap_list, poolid);
        if (diskmap == NULL) {
                ret = ENOSPC;
                GOTO(err_lock, ret);
        }

        if (gloconf.solomode && diskmap->count == 1) {
                ret = __diskmap_solo(diskmap, repnum, disks);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = __diskmap_new__(diskmap, repnum, disks);
                if (ret)
                        GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&diskmap_list->rwlock);

        return 0;
err_lock:
        sy_rwlock_unlock(&diskmap_list->rwlock);
err_ret:
        return ret;
}

int diskmap_new(uint64_t poolid, int repnum, nid_t *disks)
{
#if ENABLE_ALLOCATE_BALANCE
        int ret;
        nid_t array[16];

        YASSERT(repnum + 1 < 16);

        ret = __diskmap_new(poolid, repnum + 1, array);
        if (ret) {
                if (ret == ENOSPC) {
                        return __diskmap_new(poolid, repnum, disks);
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
        return  __diskmap_new(repnum, hardend, tier, disks);
#endif
}

int diskmap_disk_register(uint64_t poolid, const nid_t *nid, diskid_t *diskid,
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

int diskmap_disk_unregister(uint64_t poolid, const nid_t *nid, const diskid_t *diskid)
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

static int __nid_cmp(const void *arg1, const void *arg2)
{
        const nid_t *n1 = arg1, *n2 = arg2;
        //DINFO("%ld %ld %ld\n", *n1, *n2, *n1 - *n2);

        if (n1->id == n2->id)
                return 0;
        else if (n1->id < n2->id)
                return -1;
        else
                return 1;
}

static int __diskid_cmp(const void *arg1, const void *arg2)
{
        const diskid_t *n1 = arg1, *n2 = arg2;
        //DINFO("%ld %ld %ld\n", *n1, *n2, *n1 - *n2);

        if (n1->id == n2->id)
                return 0;
        else if (n1->id < n2->id)
                return -1;
        else
                return 1;
}


STATIC int __diskmap_disk_dump(const char *pool, const nid_t *nid, char *buf)
{
        int ret, count;
        char key[MAX_PATH_LEN];
        etcd_node_t *array = NULL;
        diskid_t diskid;
        disk_info_t stat;
        diskid_t diskids[512];
        char tmp[MAX_BUF_LEN];

        snprintf(key, MAX_NAME_LEN, "id/%s/node/%d/disk", pool, nid->id);
        ret = etcd_list1(ETCD_POOL, key, &array);
        if (ret)
                GOTO(err_ret, ret);

        if (array->num_node == 0) {
                goto out;
        }
        
        count = 0;
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s, nodeid %d diskid %s, faultdomain %s\n",
                      pool, nid->id, node->key, node->value);

                str2diskid(&diskid, node->key);
                diskids[count] = diskid;
                count++;
        }

        qsort(diskids, count, sizeof(diskid_t), __diskid_cmp);

        tmp[0] = '\0';
        for (int i = 0; i < count; i++) {
                ret = cds_rpc_diskstat(&diskids[i], &stat);
                if (ret) {
                        uint64_t poolid = atoll(pool);
                        diskmap_disk_unregister(poolid, nid, &diskid);
                        continue;
                }

                if (stat.capacity - stat.used < mdsconf.disk_keep) {
                        snprintf(tmp + strlen(tmp), MAX_NAME_LEN, "%d/0,", diskids[i].id);
                } else {
                        snprintf(tmp + strlen(tmp), MAX_NAME_LEN, "%d/1,", diskids[i].id);
                }
        }

        if (strlen(tmp)) {
                tmp[strlen(tmp) - 1] = '\0';
                snprintf(buf + strlen(buf), MAX_NAME_LEN, "%d %s\n", nid->id, tmp);
        } else {
                DWARN("all disk offline %s\n", network_rname(nid));
        }

out:
        free_etcd_node(array);

        return 0;
err_ret:
        return ret;
}

STATIC int __diskmap_node_dump(const char *pool)
{
        int ret, count;
        char key[MAX_PATH_LEN], buf[MAX_BUF_LEN];
        etcd_node_t *array = NULL;
        nid_t nids[512], nid;

        snprintf(key, MAX_NAME_LEN, "id/%s/node", pool);
        ret = etcd_list1(ETCD_POOL, key, &array);
        if (ret)
                GOTO(err_ret, ret);

        YASSERT(array->num_node < 512);

        count = 0;
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s, nodeid %s, faultdomain %s\n",
                      pool, node->key, node->value);

                str2nid(&nid, node->key);

                ret = network_connect(&nid, NULL, 1, 0);
                if (ret) {
                        DWARN("node %s offline\n", network_rname(&nids[i]));
                        continue;
                }

                nids[count] = nid;
                count++;
        }

        free_etcd_node(array);

        qsort(nids, count, sizeof(nid_t), __nid_cmp);
        
        buf[0] = '\0';
        for (int i = 0; i < count; i++) {
                ret = __diskmap_disk_dump(pool, &nids[i], buf);
                if (ret)
                        GOTO(err_ret, ret);
        }
        
        
        int len = strlen(buf);
        if (len && buf[len -1] == '\n') {
                buf[len - 1] = '\0';
        }

        snprintf(key, MAX_NAME_LEN, "id/%s/diskmap", pool);

        char tmp[MAX_BUF_LEN];
        ret = etcd_get_text(ETCD_POOL, key, tmp, NULL);
        if (ret) {
                DINFO("errno  %d\n", ret);
                //pass
        } else {
                if (strcmp(tmp, buf) == 0) {
                        DINFO("skip update %s\n", key);
                        goto out;
                } else {
                        DINFO("update %s, (%s) (%s)\n", key, tmp, buf);
                }
        }

        ret = etcd_set_text(ETCD_POOL, key, buf, O_CREAT, -1);
        if (ret)
                GOTO(err_ret, ret);

out:
        return 0;
err_ret:
        return ret;
}

int diskmap_dump()
{
        int ret;
        etcd_node_t *array = NULL;

        ret = etcd_list1(ETCD_POOL, "id", &array);
        if (ret)
                GOTO(err_ret, ret);

        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                DINFO("pool %s\n", node->key);

                ret = __diskmap_node_dump(node->key);
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
