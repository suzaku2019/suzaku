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

static int __chunk_create__(const volid_t *volid, const chkinfo_t *chkinfo)
{
        int ret;
        const chkid_t *chkid = &chkinfo->chkid;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        
        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("create /%s/%s\n", ETCD_TREE, path);
        ret = etcd_set_bin(ETCD_TREE, path, chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                           O_CREAT, -1);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __chunk_load__(const volid_t *volid, const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret, len;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        len = CHKINFO_SIZE(YFS_CHK_REP_MAX);
        
        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("load /%s/%s\n", ETCD_TREE, path);
        ret = etcd_get_bin(ETCD_TREE, path, chkinfo, &len, NULL);
        if (unlikely(ret)) {
                ret = (ret == ENOKEY) ? ENOENT : ret;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __chunk_update__(const volid_t *volid, const chkinfo_t *chkinfo)
{
        int ret;
        const chkid_t *chkid = &chkinfo->chkid;
        fileid_t fileid;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        
        cid2fid(&fileid, chkid);
        fid2str(&fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/chkinfo", fileid.poolid, key);
        DINFO("update /%s/%s\n", ETCD_TREE, path);
        ret = etcd_set_bin(ETCD_TREE, path, chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                           0, -1);
        if (unlikely(ret)) {
                ret = (ret == ENOKEY) ? ENOENT : ret;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __chunk_create(const volid_t *volid, const chkinfo_t *chkinfo)
{
        if (chkinfo->chkid.type == ftype_file) {
                return __chunk_create__(volid, chkinfo);
        } else {
                return mds_rpc_paset(net_getnid(), chkinfo, -1);
        }
}

static int __chunk_load(const volid_t *volid, const chkid_t *chkid, chkinfo_t *chkinfo)
{
        if (chkid->type == ftype_file) {
                return __chunk_load__(volid, chkid, chkinfo);
        } else {
                return mds_rpc_paget(net_getnid(), chkid, chkinfo);
        }
}

static int __chunk_update(const volid_t *volid, const chkinfo_t *chkinfo)
{
        if (chkinfo->chkid.type == ftype_file) {
                return __chunk_update__(volid, chkinfo);
        } else {
                return mds_rpc_paset(net_getnid(), chkinfo, -1);
        }
}

chunkop_t __chunkop__ = {
        .create = __chunk_create,
        .load = __chunk_load,
        .update = __chunk_update,
};
