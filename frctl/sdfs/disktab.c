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

typedef struct {
        sy_rwlock_t rwlock;
        bmap_t bmap;
} disktab_t;

static disktab_t *__disktab__ = NULL;

#if 0
STATIC int __disktab_scan(char *value, int *_count, diskmap_node_t ***_array)
{
        
        return 0;
err_ret:
        return ret;
}
#endif

STATIC int __disktab_node(const char *nodeinfo, char *online)
{
        int ret, disk_count = 512;
        char *list[512];
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

        for (int i = 0; i < disk_count; i++) {
                char *tmp[2];
                int tmp_count = 2;
                _str_split(list[i], '/', tmp, &tmp_count);
                str2nid(&diskid, tmp[0]);

                online[diskid.id] = 1;
        }

        return 0;
err_ret:
        return ret;
}


static int __disktab_pool(uint64_t poolid, char *value, char *online)
{
        int ret, node_count;
        char key[MAX_PATH_LEN];
        char *list[1024];

        snprintf(key, MAX_NAME_LEN, "id/%ju/diskmap", poolid);

        ret = etcd_get_text(ETCD_POOL, key, value, NULL);
        if (ret)
                GOTO(err_ret, ret);

        node_count = 1024;
        _str_split(value, '\n', list, &node_count);

        if (node_count == 0) {
                ret = ENOSPC;
                GOTO(err_ret, ret);
        }

        for (int i = 0; i < node_count; i++) {
                ret = __disktab_node(list[i], online);
                if (ret)
                        continue;
        }

        return 0;
err_ret:
        return ret;
}

int disktab_rebuild(char *buf)
{
        int ret;
        etcd_node_t *array = NULL;
        uint64_t poolid;
        char online[NODEID_MAX];

        memset(online, 0x0, sizeof(online));
        
        ret = etcd_list1(ETCD_POOL, "id", &array);
        if (ret)
                GOTO(err_ret, ret);

        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                poolid = atoll(node->key);

                ret = __disktab_pool(poolid, buf, online);
                if (ret)
                        continue;
        }
        
        free_etcd_node(array);

        for (int i = 0; i < NODEID_MAX; i++) {
                if (online[i]) {
                        bmap_set(&__disktab__->bmap, i);
                } else {
                        bmap_del(&__disktab__->bmap, i);
                }
        }

        return 0;
err_ret:
        return ret;
}

int disktab_online(const diskid_t *diskid)
{
        return bmap_get(&__disktab__->bmap, diskid->id);
}

int disktab_init()
{
        int ret;
        disktab_t *disktab;

        ret = ymalloc((void **)&disktab, sizeof(*disktab));
        if (ret)
                GOTO(err_ret, ret);

        ret = sy_rwlock_init(&disktab->rwlock, "disktab");
        if (ret)
                GOTO(err_ret, ret);

        ret = bmap_create(&disktab->bmap, NODEID_MAX);
        if (ret)
                GOTO(err_ret, ret);
        
        __disktab__ = disktab;
        
        return 0;
err_ret:
        return ret;
}
