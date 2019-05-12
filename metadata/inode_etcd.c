#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "dir.h"
#include "schedule.h"
#include "net_global.h"
#include "md_lib.h"
#include "sdfs_macro.h"
#include "quota.h"
#include "attr_queue.h"
#include "md.h"
#include "md_db.h"
#include "dbg.h"

static inodeop_t *inodeop = &__inodeop__;

static int __inode_childcount(const volid_t *volid, const fileid_t *fid, uint64_t *_count);
static int __inode_remove(const volid_t *volid, const fileid_t *fileid, md_proto_t *_md);

static int __md_set(const volid_t *volid, const md_proto_t *md, int flag)
{
        int ret;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];
        const fileid_t *fileid = &md->fileid;

        (void) volid;

        fid2str(fileid, key);
        if (1) {
                snprintf(path, MAX_NAME_LEN, "%ju/%s/%s", fileid->poolid, key, MD_CHILDREN);
                DINFO("path %s\n", path);
                ret = etcd_mkdir(ETCD_TREE, path, -1);
                if (unlikely(ret)) {
                        if (ret == EEXIST) {
                        } else {
                                GOTO(err_ret, ret);
                        }
                }
        }
        

        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s", fileid->poolid, key, MD_INFO);
        ret = etcd_set_bin(ETCD_TREE, path, md, md->md_size, flag, 0);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DINFO(CHKID_FORMAT" nlink %d, size %ju, path %s\n", CHKID_ARG(&md->fileid),
              md->at_nlink, md->at_size, path);
        
        return 0;
err_ret:
        return ret;
}

static int __inode_create(const volid_t *volid, const fileid_t *parent,
                          const setattr_t *setattr,
                          int type, fileid_t *_fileid)
{
        int ret;
        char buf[MAX_BUF_LEN], buf1[MAX_BUF_LEN];
        fileid_t fileid;
        md_proto_t *md_parent, *md;

        ANALYSIS_BEGIN(0);
        
        md_parent = (md_proto_t *)buf;
        ret = inodeop->getattr(volid, parent, md_parent);
        if (ret)
                GOTO(err_ret, ret);

        ret = md_attr_getid(&fileid, parent, type, volid);
        if (ret)
                GOTO(err_ret, ret);

        md = (void *)buf1;
        ret = md_attr_init((void *)md, setattr, type, md_parent, &fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = __md_set(volid, md, O_EXCL);
        if (ret)
                GOTO(err_ret, ret);

        if (_fileid) {
                *_fileid = fileid;
        }

        ANALYSIS_QUEUE(0, IO_WARN, NULL);
        
        return 0;
err_ret:
        return ret;
}

static int __md_get(const volid_t *volid, const fileid_t *fileid, md_proto_t *md)
{
        int ret, len;
        char buf[MAX_BUF_LEN] = {0};
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];
        uint64_t count;

        DBUG("getattr "CHKID_FORMAT"\n", CHKID_ARG(fileid));

        len = MAX_BUF_LEN;
        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s", fileid->poolid, key, MD_INFO);
        ret = etcd_get_bin(ETCD_TREE, path, buf, &len, NULL);
        if (ret) {
                if (ret == ENOENT) {
                        memset(md, 0x0, sizeof(*md));
                        md->fileid = *fileid;
                        goto out;
                } else
                        GOTO(err_ret, ret);
        }

        memcpy(md, buf, len);
        YASSERT(md->md_size == (size_t )len);

        DINFO(CHKID_FORMAT" nlink %d, size %ju, path %s\n", CHKID_ARG(&md->fileid),
              md->at_nlink, md->at_size, path);
        
        if (S_ISDIR(stype(fileid->type))) {
                ret = __inode_childcount(volid, fileid, &count);
                if (ret)
                        GOTO(err_ret, ret);

                md->at_nlink = count + 2;
        }

out:
        return 0;
err_ret:
        return ret;
}

static int __inode_getattr(const volid_t *volid, const fileid_t *fileid, md_proto_t *md)
{
        int ret;

        ret = __md_get(volid, fileid, md);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG(CHKID_FORMAT" nlink %d, size %ju\n", CHKID_ARG(fileid),
             md->at_nlink, md->at_size);

        return 0;
err_ret:
        return ret;
}

static int __inode_setattr(const volid_t *volid, const fileid_t *fileid,
                           const setattr_t *setattr, int force)
{
        int ret;
        char buf[MAX_BUF_LEN] = {0};
        md_proto_t *md;

        DBUG("setattr "CHKID_FORMAT", force %u\n", CHKID_ARG(fileid), force);

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, md);
        if (ret)
                GOTO(err_lock, ret);
        
        md_attr_update(md, setattr);
        DBUG(CHKID_FORMAT" nlink %d, size %ju\n", CHKID_ARG(fileid),
              md->at_nlink, md->at_size);
        YASSERT(md->at_mode);
        
        ret = __md_set(volid, md, 0);
        if (ret)
                GOTO(err_lock, ret);

        return 0;
err_lock:
        return ret;
}

static int __inode_extend(const volid_t *volid, const fileid_t *fileid, size_t size)
{
        int ret, retry = 0;
        char buf[MAX_BUF_LEN] = {0};
        md_proto_t *md;

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, md);
        if (ret)
                GOTO(err_ret, ret);

        if (md->at_size >= size) {
                return 0;
        }

        (void) retry;
        
        ret = __inode_getattr(volid, fileid, md);
        if (ret)
                GOTO(err_lock, ret);

        if (md->at_size < size) {
                md->at_size = size;
                md->chknum = _get_chknum(md->at_size, md->split);
                md->md_version++;
                ret = __md_set(volid, md, 0);
                if (ret)
                        GOTO(err_lock, ret);
        }

        
        return 0;
err_lock:
err_ret:
        return ret;
}

static int __inode_del(const volid_t *volid, const fileid_t *fileid)
{
        int ret;
        char path[MAX_PATH_LEN];

        (void) volid;
        
        DBUG("del "CHKID_FORMAT" \n", CHKID_ARG(fileid));

        snprintf(path, MAX_NAME_LEN, CHKID_FORMAT, CHKID_ARG(fileid));
        ret = etcd_del_dir(ETCD_POOL, path, 1);
        if (ret) {
                if (ret == ENOENT) {
                        //pass
                } else {
                        GOTO(err_ret, ret);
                }
        }
        
        return 0;
err_ret:
        return ret;
}

static int __inode_setxattr(const volid_t *volid, const fileid_t *fileid, const char *_key,
                            const char *value, size_t size, int flag)
{
        int ret; 
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        DBUG("set %s\n", _key);

        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s", fileid->poolid, key, MD_XATTR, _key);
        ret = etcd_set_bin(ETCD_TREE, path, value, size, flag, 0);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;     
}

static int __inode_getxattr(const volid_t *volid, const fileid_t *fileid, const char *_key,
                            char *value, size_t *value_len)
{
        int ret, size;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        size = *value_len;
        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s", fileid->poolid, key, MD_XATTR, _key);
        ret = etcd_get_bin(ETCD_TREE, path, value, &size, NULL);
        if (unlikely(ret)) {
                ret = ENOENT ? ENOKEY : ret;
                GOTO(err_ret, ret);
        }

        *value_len = size;
        
        return 0;
err_ret:
        return ret;
}

static int __inode_removexattr(const volid_t *volid, const fileid_t *fileid, const char *_key)
{
        int ret;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s", fileid->poolid, key, MD_XATTR, _key);
        ret = etcd_del(ETCD_TREE, path);
        if (unlikely(ret)) {
                ret = ENOENT ? ENOKEY : ret;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __inode_listxattr(const volid_t *volid, const fileid_t *fileid,
                             char *list, size_t *size)
{
        int ret, len, left;
        etcd_node_t *array = NULL;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s", fileid->poolid, key, MD_XATTR);
        ret = etcd_list1(ETCD_TREE, path, &array);
        if(ret){
                GOTO(err_ret, ret);
        }

        list[0] = '\0';
        left = *size;
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];

                len = strlen(node->key);
                if (left < len + 1) {
                        UNIMPLEMENTED(__DUMP__);
                }
                
                snprintf(list + len, left, "%s\n", node->key);

                left -= (len + 1);
        }

        *size = strlen(list);
        
        free_etcd_node(array);

        return 0;
err_ret:
        return ret;
}

static int __inode_childcount(const volid_t *volid, const fileid_t *fileid, uint64_t *_count)
{
        int ret;
        etcd_node_t *array = NULL;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        
        if (!S_ISDIR(stype(fileid->type))) {
                ret = ENOTDIR;
                GOTO(err_ret, ret);
        }

        fid2str(fileid, key);
        snprintf(path, MAX_NAME_LEN, "%ju/%s", fileid->poolid, key);
        ret = etcd_list1(ETCD_TREE, path, &array);
        if(ret){
                GOTO(err_ret, ret);
        }

        *_count = array->num_node;
        free_etcd_node(array);

        return 0;
err_ret:
        return ret;
}

static int __inode_link(const volid_t *volid, const fileid_t *fileid)
{
        int ret;
        md_proto_t *md;
        char buf[MAX_BUF_LEN];

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, md);
        if (ret)
                GOTO(err_lock, ret);

        md->at_nlink++;
        md->md_version++;

        ret = __md_set(volid, md, 0);
        if (ret)
                GOTO(err_lock, ret);

        return 0;
err_lock:
        return ret;
}

static int __inode_unlink(const volid_t *volid, const fileid_t *fileid, md_proto_t *_md)
{
        int ret;
        md_proto_t *md;
        char buf[MAX_BUF_LEN];

        if (S_ISDIR(stype(fileid->type))) {
                return __inode_remove(volid, fileid, _md);
        }

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, md);
        if (ret)
                GOTO(err_lock, ret);

        md->at_nlink--;
        md->md_version++;

        DBUG(CHKID_FORMAT" nlink %d\n", CHKID_ARG(fileid), md->at_nlink);

        if (_md) {
                memcpy(_md, md, md->md_size);
        }

#if 1
        ret = __md_set(volid, md, 0);
        if (ret)
                GOTO(err_lock, ret);
#else
        if (md->at_nlink == 0) {
                ret = __inode_del(fileid);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = __md_set(volid, md, 0);
                if (ret)
                        GOTO(err_lock, ret);
        }
#endif

        return 0;
err_lock:
        return ret;
}

static int __inode_symlink(const volid_t *volid, const fileid_t *fileid, const char *link_target)
{
        int ret;
        symlink_md_t *md;
        char buf[MAX_BUF_LEN];

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, (void *)md);
        if (ret)
                GOTO(err_ret, ret);

        strcpy(md->name, link_target);
        md->md_size += (strlen(link_target) + 1);
        md->md_version++;

        DBUG(CHKID_FORMAT" link %s\n", CHKID_ARG(fileid), md->name);
        
        ret = __md_set(volid, (void *)md, 0);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __inode_readlink(const volid_t *volid, const fileid_t *fileid, char *link_target)
{
        int ret;
        symlink_md_t *md;
        char buf[MAX_BUF_LEN];

        md = (void *)buf;
        ret = __inode_getattr(volid, fileid, (void *)md);
        if (ret)
                GOTO(err_ret, ret);

        DBUG(CHKID_FORMAT" link %s\n", CHKID_ARG(fileid), md->name);
        
        strcpy(link_target, md->name);

        return 0;
err_ret:
        return ret;
}

static int __inode_mkvol(const volid_t *volid, const fileid_t *fileid,
                         const setattr_t *setattr)
{
        int ret;
        char buf1[MAX_BUF_LEN];
        md_proto_t *md;

        md = (void *)buf1;
        ret = md_attr_init((void *)md, setattr, ftype_pool, NULL, fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = __md_set(volid, md, O_EXCL);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __inode_remove(const volid_t *volid, const fileid_t *fileid, md_proto_t *md)
{
        int ret;

        if (md) {
                ret = __inode_getattr(volid, fileid, md);
                if (ret)
                        GOTO(err_ret, ret);
        }

        ret = __inode_del(volid, fileid);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

inodeop_t __inodeop__ = {
        .create = __inode_create,
        .getattr = __inode_getattr,
        .setattr = __inode_setattr,
        .extend = __inode_extend,
        .getxattr = __inode_getxattr,
        .setxattr = __inode_setxattr,
        .listxattr = __inode_listxattr,
        .removexattr = __inode_removexattr,
        .childcount = __inode_childcount,
        //.init = __inode_init,
        .link = __inode_link,
        .unlink = __inode_unlink,
        .symlink = __inode_symlink,
        .readlink = __inode_readlink,
        .mkvol = __inode_mkvol,
        .remove = __inode_remove,
#if 0
        .setlock = __inode_setlock,
        .getlock = __inode_getlock,
#else
        .setlock = NULL,
        .getlock = NULL,
#endif
};
