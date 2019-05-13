/*Persistence Array*/

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#define DBG_SUBSYS S_YFSMDS

#include "ylib.h"
#include "net_table.h"
#include "configure.h"
#include "net_global.h"
#include "mem_cache.h"
#include "partition.h"
#include "yfs_md.h"
#include "variable.h"
#include "core.h"
#include "range.h"
#include "network.h"
#include "ylog.h"
#include "dbg.h"

#define MAX_PART 1024

typedef struct {
        sy_spinlock_t lock;
        int count;
        char name[MAX_NAME_LEN];
        int32_t *array;
} part_t;

static part_t *__part_mds__;
static part_t *__part_frctl__;

static int __part_cmp(const void *arg1, const void *arg2)
{
        const int32_t *n1 = arg1, *n2 = arg2;
        //DINFO("%ld %ld %ld\n", *n1, *n2, *n1 - *n2);

        if (*n1 == *n2)
                return 0;
        else if (*n1 < *n2)
                return -1;
        else
                return 1;
}

static void __part_update(part_t *part, const char *_part)
{
        int ret, count;
        char *list[MAX_PART], tmp[MAX_BUF_LEN];
        int32_t *array;

        DINFO("new partition list %s\n", _part);
        
        strcpy(tmp, _part);
        count = MAX_PART;
        _str_split(tmp, ',', list, &count);

        ret = ymalloc((void **)&array, sizeof(*array) * (count + 1));
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        array[0] = 0;
        for(int i = 0; i < count; i++) {
                array[i + 1] = atoll(list[i]);
        }

        qsort(array, count + 1, sizeof(int32_t), __part_cmp);

#if 1
        for(int i = 0; i < count + 1; i++) {
                DINFO("part %s[%u] : %ju\n", part->name, i, array[i]);
        }
#endif
        
        ret = sy_spin_lock(&part->lock);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        part->count = count;
        if (part->array) {
                yfree((void **)&part->array);
        }

        part->array = array;

        sy_spin_unlock(&part->lock);
}


static void *__part_worker(void *arg)
{
        int ret, idx = 0;
        etcd_node_t  *node = NULL;
        etcd_session  sess;
        char key[MAX_PATH_LEN], *host;
        part_t *part = arg;
        char *buf;

        ret = ymalloc((void **)&buf, 1024 * 1024);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        while (1) {
                ret = etcd_get_text(ETCD_PARTITION, part->name, buf, NULL);
                if (ret) {
                        DWARN("partition %s not found\n", part->name);
                        sleep(1);
                        continue;
                }

                __part_update(part, buf);

                break;
        }

        yfree((void **)&buf);
        
        host = strdup("localhost:2379");
        sess = etcd_open_str(host);
        if (!sess) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }

        snprintf(key, MAX_NAME_LEN, "%s/%s/%s", ETCD_ROOT, ETCD_PARTITION, part->name);
        DINFO("watch %s idx %u\n", key, idx);
        while (1) {
                ret = etcd_watch(sess, key, &idx, &node, 0);
                if(ret != ETCD_OK){
                        if (ret == ETCD_ENOENT) {
                                DWARN("%s not exist\n");
                                sleep(1);
                                continue;
                        } else
                                GOTO(err_close, ret);
                }

                DINFO("conn watch node:%s nums:%d\n", node->key, node->num_node);
                idx = node->modifiedIndex + 1;
                __part_update(part, node->value);

                free_etcd_node(node);
        }

        etcd_close_str(sess);
        free(host);
        pthread_exit(NULL);
err_close:
        etcd_close_str(sess);
err_ret:
        free(host);
        UNIMPLEMENTED(__DUMP__);
        pthread_exit(NULL);
}

static int __part_init(const char *name, part_t **_part)
{
        int ret;
        part_t *part;

        ret = ymalloc((void **)&part, sizeof(*part));
        if (ret)
                GOTO(err_ret, ret);

        ret = sy_spin_init(&part->lock);
        if (ret)
                GOTO(err_ret, ret);
        
        part->count = 0;
        part->array = NULL;
        strcpy(part->name, name);
        *_part = part;

        ret = sy_thread_create2(__part_worker, part, "partition");
        if(ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __part_init_private(va_list ap)
{
        int ret;
        part_t *part;
        int *type = va_arg(ap, int *);

        va_end(ap);
        
        if (*type & PART_MDS) {
                ret = __part_init(ROLE_MDCTL, &part);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);

                variable_set(VARIABLE_PART_MDS, part);
        }

        if (*type & PART_FRCTL) {
                ret = __part_init(ROLE_FRCTL, &part);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);

                variable_set(VARIABLE_PART_FRCTL, part);
        }

        return 0;
}

int part_init(int type)
{
        int ret;

        if (type & PART_MDS) {
                ret = __part_init(ROLE_MDCTL, &__part_mds__);
                if (ret)
                        GOTO(err_ret, ret);
        }

        if (type & PART_FRCTL) {
                ret = __part_init(ROLE_FRCTL, &__part_frctl__);
                if (ret)
                        GOTO(err_ret, ret);
        }

        if (ng.daemon) {
                ret = core_init_modules("part_init_private", __part_init_private, &type);
                if(ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __part_hash(const part_t *part, uint64_t id, uint32_t *coreid)
{
        int ret, i;
        int32_t hash;

        if (unlikely(part->array == NULL)) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        hash = id % part->array[part->count];
        hash = hash ? hash : part->array[part->count];
        for(i = 0; i < part->count; i++) {
                if (hash > part->array[i] && hash <= part->array[i + 1]) {
                        *coreid = part->array[i + 1];
                        break;
                }
        }

        YASSERT(i < part->count);

        coreid_t _coreid;
        int2coreid(*coreid, &_coreid);
        DINFO("hash %u --> %u --> %s/%u\n", id, hash,
              network_rname(&_coreid.nid), _coreid.idx);
        
        return 0;
err_ret:
        return ret;
}

void coreid2int(const coreid_t *coreid, uint32_t *coreid32)
{
        static_assert(sizeof(*coreid32) == sizeof(*coreid), "coreid");
        memcpy(coreid32, coreid, sizeof(*coreid32));
}

void int2coreid(const uint32_t coreid32, coreid_t *coreid)
{
        static_assert(sizeof(coreid32) == sizeof(*coreid), "coreid");
        memcpy(coreid, &coreid32, sizeof(coreid32));
}

int part_hash(uint64_t id, int type, coreid_t *coreid)
{
        int ret, var = (type == PART_MDS) ? VARIABLE_PART_MDS : VARIABLE_PART_FRCTL;
        part_t *part = variable_get(var);
        uint32_t _coreid;

        if (unlikely(part == NULL)) {
                part = (type == PART_MDS) ? __part_mds__ : __part_frctl__;
        }

        ret = sy_spin_lock(&part->lock);
        if(unlikely(ret))
                GOTO(err_ret, ret);

        ret = __part_hash(part, id, &_coreid);
        if(unlikely(ret))
                GOTO(err_lock, ret);

        int2coreid(_coreid, coreid);
        
        sy_spin_unlock(&part->lock);

        return 0;
err_lock:
        sy_spin_unlock(&part->lock);
err_ret:
        return ret;
}

static int __part_register(const char *name)
{
        int ret;
        char key[MAX_PATH_LEN], hostname[MAX_NAME_LEN];
        uint32_t _coreid;
        coreid_t coreid;
        
        ret = core_getid(&coreid);
        if(unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = gethostname(hostname, MAX_NAME_LEN);
        if(unlikely(ret))
                GOTO(err_ret, ret);

        coreid2int(&coreid, &_coreid);
        snprintf(key, MAX_NAME_LEN, "%s/coreid/%u", name, _coreid);
        ret = etcd_set_text(ETCD_INSTANCE, key, hostname, O_CREAT, -1);
        if(unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __part_register__(va_list ap)
{
        int ret;
        int *type = va_arg(ap, int *);

        va_end(ap);
        
        if (*type & PART_FRCTL) {
                ret = __part_register(ROLE_FRCTL);
                if(unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }
 
        if (*type & PART_MDS) {
                ret = __part_register(ROLE_MDCTL);
                if(unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }

        return 0;
}

int part_register(int type)
{
        int ret;

        ret = core_init_modules("part_register", __part_register__, &type);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __part_dump_update(const char *name, const char *_buf)
{
        int ret;
        char buf[MAX_BUF_LEN];
        
        ret = etcd_get_text(ETCD_PARTITION, name, buf, NULL);
        if(unlikely(ret)) {
                if (ret == ENOKEY) {
                        ret = etcd_set_text(ETCD_PARTITION, name, _buf, O_CREAT, -1);
                        if(unlikely(ret))
                                GOTO(err_ret, ret);

                        goto out;
                } else
                        GOTO(err_ret, ret);
        } else {
                if (strcmp(_buf, buf)) {
                        DINFO("update partition %s\n", _buf);
                        ret = etcd_set_text(ETCD_PARTITION, name, _buf, 0, -1);
                        if(unlikely(ret))
                                GOTO(err_ret, ret);
                }
        }

out:
        return 0;
err_ret:
        return ret;
}

static int __part_dump(const char *name)
{
        int ret, count;
        char path[MAX_PATH_LEN], buf[MAX_BUF_LEN];
        etcd_node_t *node = NULL, *list;
        uint32_t array[MAX_PART];

        snprintf(path, MAX_NAME_LEN, "%s/%s/coreid", ETCD_INSTANCE, name);
        ret = etcd_list(path, &list);
        if(unlikely(ret)) {
                DWARN("path %s not found\n", path);
                GOTO(err_ret, ret);
        }

        if (list->num_node == 0) {
                free_etcd_node(list);
                goto out;
        }
        
        count = list->num_node;
        for(int i = 0; i < list->num_node; i++) {
                node = list->nodes[i];
                array[i] = atol(node->key);
        }

        free_etcd_node(list);
        
        qsort(array, count, sizeof(int32_t), __part_cmp);

        buf[0] = '\0';
        coreid_t coreid;
        for(int i = 0; i < count; i++) {
                int2coreid(array[i], &coreid);

                ret = network_connect(&coreid.nid, NULL, 1, 1);
                if(unlikely(ret)) {
                        DWARN("connect to %u fail\n", coreid.nid.id);
                        continue;
                }
                
                snprintf(buf + strlen(buf), MAX_NAME_LEN, "%u,", array[i]);
        }

        if (strlen(buf) == 0) {
                DWARN("skip update\n");
                goto out;
        }

        buf[strlen(buf) - 1] = '\0';
        
        __part_dump_update(name, buf);

out:
        return 0;
err_ret:
        return ret;
}

int part_dump(int type)
{
        if (type & PART_MDS) {
                __part_dump(ROLE_MDCTL);
        }

        if (type & PART_FRCTL) {
                __part_dump(ROLE_FRCTL);
        }
        
        return 0;
}


static int __part_range(const part_t *part, const coreid_t *coreid, range_t *range)
{
        int ret, i;
        uint32_t _coreid;

        if (unlikely(part->array == NULL)) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        coreid2int(coreid, &_coreid);

        UNIMPLEMENTED(__WARN__);
        for(i = 0; i < part->count; i++) {
                if ((int32_t)_coreid == part->array[i + 1]) {
                        DBUG("%ju %ju %ju\n", _coreid, part->array[i],
                              part->array[i + 1]);
                        range->begin = part->array[i];
                        range->end = part->array[i + 1];
                        break;
                }
        }
        
        if (i == part->count) {
                ret = EAGAIN;
                DWARN("nid %d not found, count %u\n", _coreid, i);
                GOTO(err_ret, ret);
        }

        DBUG("%s/%d range (%ju, %ju), count %u\n", network_rname(&coreid->nid), coreid->idx,
              range->begin, range->end, part->count);

        return 0;
err_ret:
        return ret;
}

int part_range(int type, const coreid_t *coreid, range_t *range)
{
        int ret, var = (type == PART_MDS) ? VARIABLE_PART_MDS : VARIABLE_PART_FRCTL;
        part_t *part = variable_get(var);

        if (unlikely(part == NULL)) {
                part = (type == PART_MDS) ? __part_mds__ : __part_frctl__;
        }

        ret = sy_spin_lock(&part->lock);
        if(unlikely(ret))
                GOTO(err_ret, ret);

        ret = __part_range(part, coreid, range);
        if(unlikely(ret))
                GOTO(err_lock, ret);
        
        sy_spin_unlock(&part->lock);

        return 0;
err_lock:
        sy_spin_unlock(&part->lock);
err_ret:
        return ret;
}

int part_location(const chkid_t *chkid, int type, coreid_t *coreid)
{
        int ret;
        rid_t rid;

        if (type == PART_FRCTL) {
                cid2rid(chkid, &rid);

                ret = part_hash(rid.id + rid.idx, type, coreid);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        } else {
                ret = part_hash(chkid->id, type, coreid);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

