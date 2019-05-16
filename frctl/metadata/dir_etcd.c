#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "sdfs_conf.h"
#include "net_global.h"
#include "sdfs_macro.h"
#include "md.h"
#include "md_db.h"
#include "dbg.h"

static int dir_lookup(const volid_t *volid, const fileid_t *parent,
                      const char *name, fileid_t *fileid, uint32_t *type)
{
        int ret, len;
        char buf[MAX_BUF_LEN];
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        
        fid2str(parent, key);
        if (parent->type == ftype_file) {
                snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s/%s/id",
                         parent->poolid, key, MD_SNAPSHOT, MD_CHILDREN, name);
        } else {
                snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s/id",
                         parent->poolid, key, MD_CHILDREN, name);
        }

        len = MAX_BUF_LEN;
        ret = etcd_get_bin(ETCD_TREE, path, buf, &len, 0);
        if (unlikely(ret)) {
                ret = (ret == ENOKEY) ? ENOENT : ret;
                GOTO(err_ret, ret);
        } 

        YASSERT(len == sizeof(*fileid));
        memcpy(fileid, buf, len);
        if (type)
                *type = 0;

        return 0;
err_ret:
        return ret;
}

static int dir_newrec(const volid_t *volid, const fileid_t *parent, const char *name,
                      const fileid_t *fileid, uint32_t type, int flag)
{
        int ret;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        (void) flag;
        (void) type;
        
        DINFO("mkdir %s @ "CHKID_FORMAT" newid "CHKID_FORMAT"\n",
              name, CHKID_ARG(parent), CHKID_ARG(fileid));

        fid2str(parent, key);
        
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s/id", parent->poolid, key, MD_CHILDREN, name);
        DINFO("path %s\n", path);

        ret = etcd_create(ETCD_TREE, path, fileid, sizeof(*fileid), 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int dir_unlink(const volid_t *volid, const fileid_t *parent, const char *name)
{
        int ret;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;
        
        fid2str(parent, key);
        
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s/%s/id", parent->poolid, key, MD_CHILDREN, name);
        ret = etcd_del(ETCD_TREE, path);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

static int __etcd_listvol__(const fileid_t *parent, const etcd_node_t *array,
                            char *buf, int *_buflen, int plus)
{
        int ret, i, buflen, reclen, len;
        struct dirent *de;
        const char *key;
        md_proto_t *md;
        etcd_node_t *node;

        de = (void *)buf;
        buflen = *_buflen;
        for (i = 0; i < array->num_node; i++) {
                node = array->nodes[i];
                key = node->key;
                reclen = sizeof(*de) - sizeof(de->d_name) + strlen(key) + 1;
                if (plus)
                        len = reclen + sizeof(md_proto_t);
                else
                        len = reclen;

                if ((void *)de - (void *)buf + len  > buflen) {
                        ret = ENOSPC;
                        GOTO(err_ret, ret);
                }

                strcpy(de->d_name, key);
                de->d_reclen = len;
                de->d_off = 0;
                de->d_type = 0;

                if (plus) {
                        md = (void *)de + reclen;
                        ret = dir_lookup(NULL, parent, key, &md->fileid, NULL);
                        if (unlikely(ret)) {
                                DWARN("%s not found\n", key);
                                continue;
                        }
                }

                //DBUG("%s : (%s) fileid "CHKID_FORMAT" reclen %u\n", _key,
                //de->d_name, CHKID_ARG(&md->fileid), de->d_reclen);

                de = (void *)de + len;
        }

        *_buflen = (void *)de - (void *)buf;

        return 0;
err_ret:
        return ret;
}

static int __readdir(const volid_t *volid, const fileid_t *dirid, void *buf, int *_buflen,
                     uint64_t _offset, const filter_t *filter, int is_plus)
{
        int ret, buflen;
        etcd_node_t *node = NULL;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) filter;
        (void) volid;
        (void) _offset;
        
        buflen = *_buflen;

        fid2str(dirid, key);
        
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s",
                 dirid->poolid, key, MD_CHILDREN);
        ret = etcd_list1(ETCD_TREE, path, &node);
        if(ret){
                GOTO(err_ret, ret);
        }
        
        ret = __etcd_listvol__(dirid, node, buf, &buflen, is_plus);
        if(ret) {
                GOTO(err_ret, ret);
        }

        free_etcd_node(node);
        *_buflen = buflen;

        return 0;
err_ret:
        return ret;
}

static int __dir_list(const volid_t *volid, const dirid_t *dirid,
                      uint32_t count, uint64_t offset, dirlist_t **_dirlist)
{
        int ret, idx;
        dirlist_t *dirlist;
        etcd_node_t *array = NULL;
        char path[MAX_PATH_LEN], key[MAX_NAME_LEN];

        (void) volid;

        fid2str(dirid, key);
        
        snprintf(path, MAX_NAME_LEN, "%ju/%s/%s",
                 dirid->poolid, key, MD_CHILDREN);

        DINFO("path %s\n", path);
        ret = etcd_list1(ETCD_TREE, path, &array);
        if(ret){
                GOTO(err_ret, ret);
        }
        
        DBUG("req:(offset %ju count %jd), rep:(count %ju)\n",
              offset, count, array->num_node);

        ret = ymalloc((void **)&dirlist, DIRLIST_SIZE(array->num_node));
        if (ret)
                GOTO(err_free, ret);

        idx = 0;
        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                char *key = node->key;
                __dirlist_t *p = &dirlist->array[idx];
                p->d_type = 0;
                strcpy(p->name, key);

                DINFO("%s : %s\n", node->key, node->value);
                ret = dir_lookup(NULL, dirid, key, &p->fileid, NULL);
                if (ret) {
                        DWARN("%s not found\n", key);
                        continue;
                }
                
                DBUG("name %s "CHKID_FORMAT"\n", p->name, CHKID_ARG(&p->fileid));
                idx++;
        }
        

        dirlist->count = idx;
        dirlist->cursor = 0;
        dirlist->offset = 0;
        *_dirlist = dirlist;

        free_etcd_node(array);

        return 0;
err_free:
        free_etcd_node(array);
err_ret:
        return ret;
}

static int dir_readdir(const volid_t *volid, const fileid_t *fileid, void *buf, int *buflen,
                       uint64_t offset)
{
        return __readdir(volid, fileid, buf, buflen, offset, NULL, 0);
}

static int dir_readdirplus(const volid_t *volid, const fileid_t *fid, void *buf, int *buflen,
                           uint64_t offset)
{
        return __readdir(volid, fid, buf, buflen, offset, NULL, 1);
}

static int __readdirplus_filter(const volid_t *volid, const fileid_t *fid,
                                void *buf, int *buflen,
                                uint64_t offset, const filter_t *filter)
{
        return __readdir(volid, fid, buf, buflen, offset, filter, 1);
}


dirop_t __dirop__ = {
        .lookup = dir_lookup,
        .readdir = dir_readdir,
        .readdirplus = dir_readdirplus,
        .readdirplus_filter = __readdirplus_filter,
        .newrec = dir_newrec,
        .unlink = dir_unlink,
        .dirlist = __dir_list,
};
