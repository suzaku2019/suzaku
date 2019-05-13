#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#define DBG_SUBSYS S_YFSMDC

#include "net_global.h"
#include "job_dock.h"
#include "ynet_rpc.h"
#include "ylib.h"
#include "md_proto.h"
#include "md_lib.h"
#include "redis.h"
#include "dir.h"
#include "md.h"
#include "md_db.h"
#include "quota.h"
#include "schedule.h"
#include "redis_conn.h"
#include "sdfs_quota.h"
#include "dbg.h"

typedef struct {
        char name[MAX_NAME_LEN];
        int port;
} redis_addr_t;

static dirop_t *dirop = &__dirop__;
static inodeop_t *inodeop = &__inodeop__;

static int __md_mkpool(const char *name, const fileid_t *fileid);

typedef struct {
        struct list_head hook;
        char name[MAX_NAME_LEN];
        int count;
        int disk[0];
} redis_list_t;


int md_mkpool(const char *name, const setattr_t *setattr, fileid_t *_fileid)
{
        int ret;
        fileid_t fileid;
        uint64_t _volid;

        ret = md_newid(idtype_fileid, &_volid);
        if (ret)
                GOTO(err_ret, ret);

        fileid.poolid = _volid;
        fileid.idx = 0;
        fileid.id = _volid;
        fileid.__pad__ = 0;
        fileid.type = ftype_pool;

        ret = __md_mkpool(name, &fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = inodeop->mkvol(NULL, &fileid, setattr);
        if (ret)
                GOTO(err_ret, ret);

        if (_fileid) {
                *_fileid = fileid;
        }
        
        return 0;
err_ret:
        return ret;
}

int md_getpool(const char *name, fileid_t *fileid)
{
        int ret, size = sizeof(*fileid);
        char key[MAX_PATH_LEN];

        snprintf(key, MAX_NAME_LEN, "name/%s/id", name);
        
        ret = etcd_get_bin(ETCD_POOL, key, fileid, &size, NULL);
        if (ret)
                GOTO(err_ret, ret);

        YASSERT(size == sizeof(*fileid));

        return 0;
err_ret:
        ret = (ret == ENOKEY) ? ENOENT : ret;
        return ret;
}

int md_dirlist(const volid_t *volid, const dirid_t *dirid, uint32_t count,
               uint64_t offset, dirlist_t **dirlist)
{
        return dirop->dirlist(volid, dirid, count, offset, dirlist);
}

int md_rmvol(const char *name)
{
        (void) name;
        UNIMPLEMENTED(__DUMP__);

        return 0;
}

static int __md_mkpool(const char *name, const fileid_t *fileid)
{
        int ret;
        fileid_t tmp;
        char key[MAX_PATH_LEN], value[MAX_BUF_LEN];

        snprintf(key, MAX_NAME_LEN, "name/%s/id", name);
        ret = etcd_get_text(ETCD_POOL, key, (void *)&tmp, NULL);
        if (ret == 0) {
                ret = EEXIST;
                GOTO(err_ret, ret);
        }

        snprintf(key, MAX_NAME_LEN, "name/%s/poolid", name);
        snprintf(value, MAX_NAME_LEN, "%ju", fileid->poolid);
        ret = etcd_create_text(ETCD_POOL, key, value, -1);
        if (ret) {
                if (ret == EEXIST) {
                        ret = etcd_get_text(ETCD_POOL, key, value, NULL);
                        if (ret)
                                GOTO(err_ret, ret);

                        uint64_t volid = atol(value);
                        if (fileid->poolid != volid) {
                                ret = EINVAL;
                                GOTO(err_ret, ret);
                        }
                } else
                        GOTO(err_ret, ret);
        }

         
        snprintf(key, MAX_NAME_LEN, "name/%s/id", name);
        ret = etcd_create(ETCD_POOL, key, fileid, sizeof(*fileid), -1);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(key, MAX_NAME_LEN, "id/%ju/name", fileid->poolid);
        ret = etcd_create_text(ETCD_POOL, key, name, -1);
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}
