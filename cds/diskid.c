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

#define DBG_SUBSYS S_YFSCDS

#include "yfs_conf.h"
#include "yfscds_conf.h"
#include "chk_meta.h"
#include "cds.h"
#include "disk.h"
#include "md_proto.h"
#include "ylib.h"
#include "ynet_rpc.h"
#include "sdfs_lib.h"
#include "aio.h"
#include "md_lib.h"
#include "bh.h"
#include "cds_hb.h"
#include "net_global.h"
#include "nodeid.h"
#include "mds_rpc.h"
#include "dbg.h"
#include "adt.h"

static nid_t *__diskid2nid__ = NULL;
static int32_t *__diskid2idx__ = NULL;

int d2n_register(const diskid_t *diskid)
{
        int ret;
        char key[MAX_PATH_LEN], buf[MAX_BUF_LEN];

        snprintf(key, MAX_NAME_LEN, "bactl/diskid/%u", diskid->id);
        nid2str(buf, net_getnid());

        ret = etcd_set_text(ETCD_INSTANCE, key, buf, 0, -1);
        if (ret) {
                if (ret == ENOENT) {
                        ret = etcd_set_text(ETCD_INSTANCE, key, buf, O_CREAT, -1);
                        if (ret)
                                GOTO(err_ret, ret);
                } else 
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __d2n_load(const diskid_t *diskid, nid_t *nid)
{
        int ret;
        char key[MAX_PATH_LEN], buf[MAX_BUF_LEN];

        snprintf(key, MAX_NAME_LEN, "bactl/diskid/%u", diskid->id);

        DINFO("load %s\n", key);
        
        ret = etcd_get_text(ETCD_INSTANCE, key, buf, NULL);
        if (ret) {
                if (ret == ENOKEY) {
                        ret = ENODEV;
                }

                GOTO(err_ret, ret);
        }

        str2nid(nid, buf);
        
        return 0;
err_ret:
        return ret;
}


int d2n_nid(const diskid_t *diskid, nid_t *nid)
{
        int ret;

        if (unlikely(__diskid2nid__[diskid->id].id == 0)) {
                ret = __d2n_load(diskid, nid);
                if (ret)
                        GOTO(err_ret, ret);

                __diskid2nid__[diskid->id] = *nid;
        }

        nid->id = __diskid2nid__[diskid->id].id;
        
        return 0;
err_ret:
        return ret;
}

int d2n_init()
{
        int ret;
        nid_t *nid;

        ret = huge_malloc((void **)&nid, sizeof(*nid) * NODEID_MAX);
        if (ret)
                GOTO(err_ret, ret);

        memset(nid, 0x0, sizeof(*nid) * NODEID_MAX);
        __diskid2nid__ = nid;

        return 0;
err_ret:
        return ret;
}

int disk2idx_init()
{
        int ret;
        int32_t *idx;
        
        ret = huge_malloc((void **)&idx, sizeof(*idx) * NODEID_MAX);
        if (ret)
                GOTO(err_ret, ret);

        memset(idx, -1, sizeof(*idx) * NODEID_MAX);
        __diskid2idx__ = idx;

        return 0;
err_ret:
        return ret;
}

int disk2idx(const diskid_t *diskid, int *idx)
{
        int ret;
        
        if (unlikely(__diskid2idx__[diskid->id] == -1)) {
                ret = ENODEV;
                DWARN("disk %d not online\n", diskid->id);
                GOTO(err_ret, ret);
        }

        *idx = __diskid2idx__[diskid->id];

        return 0;
err_ret:
        return ret;
}

void disk2idx_online(const diskid_t *diskid, uint32_t idx)
{
        __diskid2idx__[diskid->id] = idx;
}

void disk2idx_offline(const diskid_t *diskid)
{
        __diskid2idx__[diskid->id] = -1;
}

int chkid2coreid(const chkid_t *chkid, const nid_t *nid, coreid_t *coreid)
{
        int ret;
        uint32_t cores;

        ret = netable_cores(nid, &cores);
        if (ret)
                GOTO(err_ret, ret);

        coreid->idx = (chkid->id + chkid->idx) % cores;
        coreid->nid = *nid;
        
        return 0;
err_ret:
        return ret;
}
