#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "net_global.h"
#include "sdfs_macro.h"
#include "md.h"
#include "md_db.h"
#include "mds_rpc.h"
#include "dbg.h"

static int __chunk_create__(const chkinfo_t *chkinfo)
{
        int ret;
        const chkid_t *chkid = &chkinfo->chkid;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("create /%s/%s\n", ETCD_TREE, path);
        ret = etcd_create(ETCD_TREE, path, chkinfo, CHKINFO_SIZE(chkinfo->repnum), -1);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __chunk_load__(const chkid_t *chkid,
                          chkinfo_t *chkinfo, uint64_t *version)
{
        int ret, len, idx;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        len = CHKINFO_SIZE(YFS_CHK_REP_MAX);
        
        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("load /%s/%s\n", ETCD_TREE, path);
        ret = etcd_get_bin(ETCD_TREE, path, chkinfo, &len, &idx);
        if (unlikely(ret)) {
                ret = (ret == ENOKEY) ? ENOENT : ret;
                GOTO(err_ret, ret);
        }

        if (version)
                *version = idx;
        
        return 0;
err_ret:
        return ret;
}

static int __chunk_update__(const chkinfo_t *chkinfo, int *idx)
{
        int ret;
        const chkid_t *chkid = &chkinfo->chkid;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("update /%s/%s\n", ETCD_TREE, path);
        ret = etcd_update(ETCD_TREE, path, chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                          idx, -1);
        if (unlikely(ret)) {
                ret = (ret == ENOKEY) ? ENOENT : ret;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __chunk_create(const chkinfo_t *chkinfo)
{
        if (chkinfo->chkid.type == ftype_file) {
                return __chunk_create__(chkinfo);
        } else {
                return mds_rpc_paset(&chkinfo->chkid, chkinfo, NULL);
        }
}

static int __chunk_load(const chkid_t *chkid,
                        chkinfo_t *chkinfo, uint64_t *version)
{
        if (chkid->type == ftype_file) {
                return __chunk_load__(chkid, chkinfo, version);
        } else {
                return mds_rpc_paget(chkid, chkinfo, version);
        }
}

static int __chunk_update(const chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;
        
        if (chkinfo->chkid.type == ftype_file) {
                if (version) {
                        int idx = *version;
                        ret = __chunk_update__(chkinfo, &idx);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);

                        *version = idx;
                } else {
                        ret = __chunk_update__(chkinfo, NULL);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);
                }
        } else {
                ret = mds_rpc_paset(&chkinfo->chkid, chkinfo, version);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

chunkop_t __chunkop__ = {
        .create = __chunk_create,
        .load = __chunk_load,
        .update = __chunk_update,
};
