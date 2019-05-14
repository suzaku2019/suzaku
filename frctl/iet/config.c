/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi_config.h"
#include "iscsi.h"
#include "configure.h"
#include "adt.h"
#include "network.h"
#include "sdfs_id.h"
#include "sdfs_lib.h"
#include "etcd.h"
#include "auth.h"
#include "schedule.h"
#include "dbg.h"

#define SCAN_INTERVAL   10
#define AUTH_SUCCESS    0
#define AUTH_FAIL       1

static char *__iqn;

static int __sdfs_account_query_discovery(int dir, char *name, char *pass)
{
        (void) dir;

        (void) pass;
        (void) name;

        return 0;
}

typedef struct {
        char ip[MAX_MSG_SIZE];
        char initiator[MAX_MSG_SIZE];
} lun_auth_t;

struct chap_acct_key {
        char *key_user;
        char *key_pass;
} __chap_keys[2] = {
        { "iscsi.in_user", "iscsi.in_pass" },
        { "iscsi.out_user", "iscsi.out_pass" },
};

#if 0
static int __sdfs_account_query_target(u32 tid, int dir, char *_name, char *_pass)
{
        int ret = 0;
        char name[MAX_BUF_LEN], pass[MAX_BUF_LEN];
        fileid_t fileid;
        struct iscsi_target *target;

        /*
         * The `raw_removexattr' is not impliment now, use a special value
         * to express this, see `ytgtadm'
         */

        DBUG("chap querying ...\n");

        if (dir != AUTH_DIR_INCOMING && dir != AUTH_DIR_OUTGOING) {
                ret = EINVAL;
                GOTO(out, ret);
        }

        target = target_get_by_id(tid);
        if (!target) {
                ret = ENOENT;
                goto out;
        }

        fileid = target->fileid;
        target_put(target);

        memset(name, 0x00, sizeof(name));
        memset(pass, 0x00, sizeof(pass));

        ret = object_getxattr(&fileid, __chap_keys[dir].key_user, name);
        if (unlikely(ret))
                goto out;

        ret = object_getxattr(&fileid, __chap_keys[dir].key_pass, pass);
        if (unlikely(ret))
                goto out;

        if (!strcmp(name, yiscsi_none_value) || !strcmp(pass, yiscsi_none_value)) {
                ret = ENOENT;
                goto out;
        }

        if (!strlen(_name)) {
                snprintf(_name, MAX_BUF_LEN, "%s", name);
                snprintf(_pass, MAX_BUF_LEN, "%s", pass);
        } else {
                if (strcmp(_name, name)) {
                        ret = ENOENT;
                        goto out;
                }
                snprintf(_pass, MAX_BUF_LEN, "%s", pass);
        }

        DBUG("chap query: tid %d, dir %d, user %s, pass %s\n",
             tid, dir, name, pass);

        return 0;
out:
        return ret;
}
#else

/**
 * login 用户名和密码验证过程
 */
static int __sdfs_account_query_target(struct iscsi_conn *conn, int dir, char *_name, char *_pass)
{
        int ret;

        DBUG("chap querying ...\n");

        switch (dir) {
        case AUTH_DIR_INCOMING:
                break;
        case AUTH_DIR_OUTGOING:
                ret = ENOENT;
                goto out;
        default:
                ret = EINVAL;
                GOTO(out, ret);
        }

#if ENABLE_ISCSI_CHAP
        ret = auth_get(conn->initiator, _name, _pass);
        if (unlikely(ret))
                GOTO(out, ret);
#endif

        DINFO("chap query: tid %d, dir %d, user %s(%p), pass %s(%p)\n",
             conn->target->tid, dir, _name, _name, _pass, _pass);

        return 0;
out:
        return ret;
}

#endif

/*
 * sdfs_account_query -
 *
 * @tid: tid of target to search. if the tid is RESERVE_TID, search the
 *       discovery session chap user and password.
 * @dir:
 *      1> AUTH_DIR_INCOMING  : use for target identify initiator.
 *      2> AUTH_DIR_OUTCOMINT : use for initiator identify target.
 * @name:
 *      1> if `strlen(name) == 0', return name and pass of this target.
 *      2> if `strlen(name) != 0', return pass of this name.
 * @pass: see @name
 *
 * The CHAP Account is:
 *      1> iscsi.in_user
 *      2> iscsi.in_pass
 *      3> iscsi.out_user
 *      4> iscsi.out_pass
 *
 * @return 0 if success, otherwise the error is returned.
 *
 */
static int sdfs_account_query(struct iscsi_conn *conn, int dir, char *name, char *pass)
{
        int ret;

        if (!conn->target)
                ret = __sdfs_account_query_discovery(dir, name, pass);
        else
                ret = __sdfs_account_query_target(conn, dir, name, pass);

        return ret;
}

/*
 * SDFS LogicUnit
 */

void sdfs_lun_free(struct sdfs_lun_entry *lun)
{
        list_del_init(&lun->entry);
        yfree((void **)&lun);
}

static struct sdfs_lun_entry *sdfs_lun_create()
{
        int ret;
        struct sdfs_lun_entry *lun;

        ret = ymalloc((void **)&lun, sizeof(struct sdfs_lun_entry));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(lun, 0x00, sizeof(struct sdfs_lun_entry));

        INIT_LIST_HEAD(&lun->entry);

        return lun;
err_ret:
        return NULL;

}

static void sdfs_lun_release(struct list_head *head)
{
        struct sdfs_lun_entry *lun, *tmp;

        list_for_each_entry_safe(lun, tmp, head, entry) {
                sdfs_lun_free(lun);
        }
}

static int __sdfs_lun_getattr(const char *pool, const fileid_t *oid, struct stat *stbuf)
{
        int ret;

        (void) pool;

        ret = sdfs_getattr(NULL, oid, stbuf);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DINFO("file "CHKID_FORMAT" size %llu\n", CHKID_ARG(oid), (LLU)stbuf->st_size);

        return 0;
err_ret:
        return ret;
}

/*************************************************************
 *
 *ipvalue likes "192.168.1.1~100;192.168.120.[10~20,120,125,128];192.168.2.88"
 *
 * ***********************************************************/
#if 0
static int __sdfs_lun_checkip(const char *ipvalue, const char * ip)
{
        char buf[MAX_MSG_SIZE] = {};
        char network_id[16] = {};
        char host_id_list[256] = {};
        char *s, *p, *tmp_id, *netp, *hostp;
        int ret, from = 0, to = 0, host_id = 0;

        strcpy(buf, ipvalue);
        s = strtok(buf, "&");
        while (s) {
                memset(network_id, 0, sizeof(network_id));
                memset(host_id_list, 0, sizeof(host_id_list));

                netp = strrchr(s, '.');
                strncpy(network_id, s, netp-s);
                if (strncmp(network_id, ip, strlen(network_id))) {
                        s = strtok(NULL, "&");
                        continue;
                }

                hostp = strrchr(ip, '.');
                host_id = atoi(hostp+1);

                if ( (p = strchr(netp, '[')) && strchr(netp, ']')) { //192.168.120.[10~20,102,105,108]
                        strcpy(host_id_list, ++p);
                        host_id_list[strlen(host_id_list) - 1] = '\0'; //host_id_list:10~20,102,105,108
                        tmp_id = host_id_list;
                        while (1) {
                                p = strchr(tmp_id, ',');
                                if (p)
                                        *p = '\0';

                                if (strchr(tmp_id, '~')) {
                                        ret = sscanf(tmp_id, "%d~%d", &from, &to);
                                        if (ret != 2) {
                                                ret = EINVAL;
                                                GOTO(err_ret, ret);
                                        }

                                        if (host_id >= from && host_id <= to)
                                                return 1;
                                } else {
                                        if (host_id == atoi(tmp_id))
                                                return 1;
                                }

                                if (p == NULL)
                                        break;
                                else
                                        tmp_id = ++p;
                        }
                } else if (strchr(netp, '~')) { //192.168.1.1~100
                        ret = sscanf(netp+1, "%d~%d", &from, &to);
                        if (ret != 2) {
                                ret = EINVAL;
                                GOTO(err_ret, ret);
                        }

                        if (host_id >= from && host_id <= to)
                                return 1;

                } else {
                        if (!strcmp(s, ip))
                                return 1;
                }

                s = strtok(NULL, "&");
        }

        return 0;
err_ret:
        return ret;
}
#endif

#if 0
/**
 * 在volume 属性上设置lich_system_connect_permission = limited,
 * 则卷默认不能被访问
 * 在etcd里建立volume和initiator映射后,
 * 才允许建立映射的initiator访问volume.
 */
static int sdfs_lun_check_initiator(nid_t *nid, chkid_t *fileid, lun_auth_t *lun_auth, int *auth_result)
{
        int ret, retry = 0, is_mapping;
        char buf[MAX_NAME_LEN];
        int buflen = MAX_NAME_LEN;

retry1:
        ret = md_xattr_get(nid, fileid, SDFS_SYSTEM_ATTR_CONNECT_PERMISSION, buf, &buflen);
        if (unlikely(ret)) {
                if (ret == ENOKEY || ret == ENOENT) {
                        DWARN(""CHKID_FORMAT" attr[%s] not exist or empty, ret[%d] !!!\n",
                                        CHKID_ARG(fileid), SDFS_SYSTEM_ATTR_CONNECT_PERMISSION, ret);
                        *auth_result = AUTH_SUCCESS;
                        goto out;
                } else if (ret == EAGAIN) {
                        DWARN("get "CHKID_FORMAT" %s attr fail, errno EAGAIN, retry %d\n",
                                        CHKID_ARG(fileid), SDFS_SYSTEM_ATTR_CONNECT_PERMISSION, retry++);
                        USLEEP_RETRY(err_ret, ret, retry1, retry, gloconf.lease_timeout + gloconf.lease_timeout / 2, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        ret = auth_is_mapping(lun_auth->initiator, fileid, &is_mapping);
        if (unlikely(ret)) {
                if (strcmp(buf, "limited") == 0) {
                        *auth_result = AUTH_FAIL;
                        goto out;
                } else
                        GOTO(err_ret, ret);
        }

        *auth_result = is_mapping ? AUTH_SUCCESS : AUTH_FAIL;

out:
        return 0;
err_ret:
        return ret;
}
#endif

#if 0
static int sdfs_lun_check_ip(nid_t *nid, chkid_t *fileid, lun_auth_t *lun_auth, int *auth_result)
{
        int ret, retry = 0, ip_nokey, valuelen;
        int connect_allowed = AUTH_FAIL;
        char ipvalue[MAX_MSG_SIZE];

retry1:
        ip_nokey = 0;
        valuelen = MAX_MSG_SIZE;
        ret = md_xattr_get(nid, fileid, SDFS_SYSTEM_ATTR_IP, ipvalue, &valuelen);
        if (unlikely(ret)) {
                if (ret == ENOKEY) {
                        //nothing to do
                        ip_nokey = 1;
                } else if (ret == EAGAIN){
                        DWARN("get "CHKID_FORMAT" ip attr fail, errno EAGAIN, retry %d\n", CHKID_ARG(fileid), retry++);
                        USLEEP_RETRY(err_ret, ret, retry1, retry, 30, (1000 * 1000));
                } else {
                        DERROR("get "CHKID_FORMAT" ip attr fail, ret:%d\n", CHKID_ARG(fileid), ret);
                        GOTO(err_ret, ret);
                }
        } else {
                /*check ip is allowed or not*/
                if (__sdfs_lun_checkip(ipvalue, lun_auth->ip)) {
                        connect_allowed = AUTH_SUCCESS;
                }
        }

        if ((ip_nokey == 1) || (connect_allowed == AUTH_SUCCESS)) {
                *auth_result = AUTH_SUCCESS;
        } else {
                *auth_result = AUTH_FAIL;
        }

        return 0;
err_ret:
        return ret;
}
#endif

static int is_connect_allowed(chkid_t *oid, lun_auth_t *lun_auth, int *auth_result)
{
#if 0
        int ret;
        nid_t nid;

        YASSERT(lun_auth);

        ret = md_map_getsrv(oid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = sdfs_lun_check_initiator(&nid, oid, lun_auth, auth_result);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
#else
        (void) oid;
        (void) lun_auth;
        *auth_result = AUTH_SUCCESS;
        return 0;
#endif
}

#if 0
static int name_to_lun(char *name, uint32_t *_lun)
{
        size_t i;
        uint32_t lun;

        for (i = 0; i < strlen(name); ++i) {
                if (!isdigit(name[i])) {
                        goto err_ret;
                }
        }

        lun = atoll(name);

        if (lun > ISCSI_LUN_MAX) {
                goto err_ret;
        }

        *_lun = lun;

        return 0;
err_ret:
        return EINVAL;
}


static int sdfs_lun_build_pool(const char *pool, const char *path, const fileid_t *tgtid,
                              struct list_head *head, lun_auth_t * lun_auth)
{
        int ret, delay, retry = 0, auth_result;
        uint64_t offset = 0, offset2 = 0;
        int delen;
        struct dirent *de;
        struct sdfs_lun_entry *lu;
        uint32_t lun;
        uint32_t blk_shift = 0;
        uint64_t blk_size = 0;
        char  *de0;
        struct stat stbuf;
        chkid_t oid;
        char uuid[MAX_NAME_LEN] = {};

        delen = BIG_BUF_LEN;
        ret = ymalloc((void **)&de0, delen);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        get_uuid(uuid);

        ret = block_listpool_open(tgtid, uuid);
        if (unlikely(ret))
                GOTO(err_free, ret);

        while (1) {
                memset(de0, 0, BIG_BUF_LEN);
                delen = BIG_BUF_LEN;
                ret = block_listpool(tgtid, uuid, offset, de0, &delen);
                if (unlikely(ret)) {
                        if (ret == EAGAIN) {
                                sleep(1);
                                continue;
                        } else if (ret == ENOENT) {     /* This target is removed */
                                goto out;
                        } else
                                GOTO(err_close, ret);
                } else if (delen == 0)
                        break;

                offset2 = 0;
                dir_for_each(de0, delen, de, offset2) {
                        /*DINFO("dir_for_each "OID_FORMAT"%s \n", CHKID_ARG(tgtid), de->d_name);*/
                        if (strlen(de->d_name) == 0)
                                goto out;
                        else if (delen - offset2 < sizeof(*de) + MAX_NAME_LEN)
                                break;

                        offset += de->d_reclen;

                        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") ||
                                        /* Skip Lun if the name start with '.' */
                                        de->d_name[0] == '.') {
                                continue;
                        }

                        ret = name_to_lun(de->d_name, &lun);
                        if (unlikely(ret))
                                continue;

retry:
                        ret = sdfs_lookup(NULL, tgtid, de->d_name, &oid);
                        if (unlikely(ret)) {
                                if (ret == EAGAIN) {
                                        DINFO("retry "CHKID_FORMAT" %s \n",
                                              CHKID_ARG(tgtid), de->d_name);
                                        USLEEP_RETRY(err_ret, ret, retry, retry,
                                                     gloconf.lease_timeout +
                                                     gloconf.lease_timeout / 2, (1000 * 1000));
                                } else
                                        GOTO(err_close, ret);
                        }

                        delay = 0;
                        retry = 0;
retry1:
                        ret = __sdfs_lun_getattr(pool, &oid, &stbuf);
                        if (unlikely(ret)) {
                                DWARN(""CHKID_FORMAT" get attribute return %u\n",
                                                CHKID_ARG(&oid), ret);

                                if (ret == EAGAIN) {
                                        DINFO("retry ...\n");
                                        USLEEP_RETRY(err_close, ret, retry1, retry, gloconf.lease_timeout + gloconf.lease_timeout / 2, (1000 * 1000));
                                } else
                                        continue;
                        }

                        blk_size = stbuf.st_size;
                        blk_shift = sanconf.lun_blk_shift;

                        /*judge if lun is authorised*/
                        auth_result = AUTH_FAIL;
                        if (lun_auth) {
                                ret = is_connect_allowed(&oid, lun_auth, &auth_result);
                                if (unlikely(ret)) {
                                        GOTO(err_close, ret);
                                }
                                if (auth_result == AUTH_FAIL) {
                                        DWARN("%s don't allowed to connect lun:"CHKID_FORMAT"\n", 
                                                        (lun_auth->ip[0] == '\0' ? lun_auth->initiator : lun_auth->ip), CHKID_ARG(&oid));
                                        continue;
                                }
                        }

                        lu = sdfs_lun_create();
                        if (unlikely(!lu)) {
                                ret = ENOMEM;
                                GOTO(err_close, ret);
                        }

                        strcpy(lu->path, path);
                        lu->lun = lun;
                        lu->fileid = oid;
                        lu->delay_check = delay;
                        lu->blk_size = blk_size;
                        lu->blk_shift = blk_shift;
                        list_add(&lu->entry, head);
                }
        }

out:
        block_listpool_close(tgtid, uuid);
        yfree((void **)&de0);
        return 0;
err_close:
        block_listpool_close(tgtid, uuid);
err_free:
        yfree((void **)&de0);
err_ret:
        sdfs_lun_release(head);
        return ret;
}
#endif

static int sdfs_lun_build_volume(const char *pool, const char *path,
                                const fileid_t *tgtid, struct list_head *head)
{
        int ret, delay, retry = 0;
        struct sdfs_lun_entry *lu;
        uint32_t blk_shift = 0;
        uint64_t blk_size = 0;
        struct stat stbuf;

        delay = 0;
retry:
        ret = __sdfs_lun_getattr(pool, tgtid, &stbuf);
        if (unlikely(ret)) {
                DWARN(""CHKID_FORMAT" get attribute return %u\n",
                      CHKID_ARG(tgtid), ret);

                if (ret == EAGAIN) {
                        DINFO("retry ...\n");
                        USLEEP_RETRY(err_ret, ret, retry, retry,
                                     gloconf.lease_timeout
                                     + gloconf.lease_timeout / 2, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        blk_size = stbuf.st_size;
        blk_shift = sanconf.lun_blk_shift;

        lu = sdfs_lun_create();
        if (!lu) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }

        strcpy(lu->path, path);
        strcpy(lu->pool, pool);
        lu->lun = 0;
        lu->fileid = *tgtid;
        lu->delay_check = delay;
        lu->blk_size = blk_size;
        lu->blk_shift = blk_shift;
        list_add(&lu->entry, head);

        return 0;
err_ret:
        sdfs_lun_release(head);
        return ret;
}

static int sdfs_lun_build(const char *pool, const char *path, const fileid_t *tgtid,
                         struct list_head *head, lun_auth_t * lun_auth)
{
#if 0
        if (tgtid->type == ftype_dir) {
                return sdfs_lun_build_pool(pool, path, tgtid, head, lun_auth);
        } else {
                return sdfs_lun_build_volume(pool, path, tgtid, head);
        }
#else
        (void) lun_auth;
        return sdfs_lun_build_volume(pool, path, tgtid, head);
#endif
}

struct sdfs_lun_entry *sdfs_lun_find(struct list_head *head, uint32_t lun, fileid_t *fileid)
{
        struct sdfs_lun_entry *lu;

        list_for_each_entry(lu, head, entry) {
                if (lu->lun == lun && !fileid_cmp(&lu->fileid, fileid))
                        return lu;
        }
        return NULL;
}

/*
 * SDFS Target
 */

void sdfs_tgt_free(struct sdfs_tgt_entry *tgt)
{
        list_del_init(&tgt->entry);
        yfree((void **)&tgt);
}

static struct sdfs_tgt_entry *sdfs_tgt_create()
{
        int ret;
        struct sdfs_tgt_entry *tgt;

        ret = ymalloc((void **)&tgt, sizeof(struct sdfs_tgt_entry));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(tgt, 0x00, sizeof(struct sdfs_tgt_entry));

        return tgt;
err_ret:
        return NULL;
}

static void sdfs_tgt_release(struct list_head *head)
{
        struct sdfs_tgt_entry *tgt, *tmp;

        list_for_each_entry_safe(tgt, tmp, head, entry) {
                sdfs_tgt_free(tgt);
        }
}

static int __sdfs_iscsi_enabled(const dirid_t *dirid, const char *name, int *enabled)
{
        int ret;
        fileid_t fileid;
        char value[MAX_NAME_LEN];
        size_t valuelen;

        ret = sdfs_lookup(NULL, dirid, name, &fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        valuelen = MAX_NAME_LEN;
        ret = sdfs_getxattr(NULL, &fileid, SDFS_SYSTEM_ATTR_ISCSI, value, &valuelen);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DINFO("%s %s\n", name, value);
        
        if (strcmp(value, SDFS_SYSTEM_ATTR_ENABLE) == 0) {
                *enabled = 1;
        } else {
                *enabled = 0;
        }

        return 0;
err_ret:
        return ret;       
}

static int __sdfs_tgt_build_list(fileid_t *nsid, struct list_head *head)
{
        int ret, enable;
        struct dirent *de;
        struct load_tgt_entry *load_tgt;
        dirhandler_t *dirhandler;
        struct list_head *pos, *n;

        ret = sdfs_opendir(NULL, nsid, &dirhandler);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        while (1) {
                ret = sdfs_readdir(NULL, dirhandler, &de, NULL);
                if (unlikely(ret)) {
                        if (ret == EAGAIN) {
                                sleep(1);
                                continue;
                        } else
                                GOTO(err_close, ret);
                }

                if (de == NULL)
                        break;

                DINFO("name %s\n", de->d_name);
                
                ret = __sdfs_iscsi_enabled(nsid, de->d_name, &enable);
                if (unlikely(ret))
                        continue;

                if (!enable) {
                        continue;
                }
                
                DINFO("load %s\n", de->d_name);

                ret = ymalloc((void **)&load_tgt, sizeof(*load_tgt));
                if (unlikely(ret))
                        GOTO(err_close, ret);

                strcpy(load_tgt->name, de->d_name);
                list_add(&load_tgt->entry, head);
        }

        sdfs_closedir(NULL, dirhandler);

        return 0;
err_close:
        sdfs_closedir(NULL, dirhandler);
err_ret:
        list_for_each_safe(pos, n, head) {
                list_del(pos);
                yfree((void **)&pos);
        }
        return ret;
}

static int __sdfs_tgt_build_try_load(const char *pool, fileid_t *nsid,
                                    struct list_head *head,
                                    struct list_head *newlist, lun_auth_t *lun_auth)
{
        int ret, auth_result;
        struct load_tgt_entry *load_tgt;
        struct list_head *pos, *n;
        fileid_t oid;

        (void) pool;

        list_for_each_safe(pos, n, head) {
                load_tgt = (void *)pos;

                ret = sdfs_lookup(NULL, nsid, load_tgt->name, &oid);
                if (unlikely(ret)) {
                        ret = _errno(ret);
                        if (ret == EAGAIN) {
                                continue;
                        } else if (ret == ENOENT) {
                                DWARN("%s deleted\n", load_tgt->name);
                                list_del(pos);
                                yfree((void **)&pos);
                                continue;
                        } else
                                GOTO(err_ret, ret);
                }

                list_del(pos);
                load_tgt->oid = oid;

                if (oid.type == ftype_file && lun_auth) {
                        auth_result = AUTH_FAIL;
                        ret = is_connect_allowed(&oid, lun_auth, &auth_result);
                        if (unlikely(ret)) {
                                ret = _errno(ret);
                                if (ret == EAGAIN) {
                                        continue;
                                } else
                                        GOTO(err_ret, ret);
                        }
                        if (auth_result == AUTH_FAIL) {
                                DWARN("%s don't allowed to connect lun:"CHKID_FORMAT"\n", 
                                      (lun_auth->ip[0] == '\0'
                                       ? lun_auth->initiator : lun_auth->ip), CHKID_ARG(&oid));
                                continue;
                        }
                }

                list_add(&load_tgt->entry, newlist);
        }

        return 0;
err_ret:
        return ret;
}

static int __sdfs_tgt_build_load(const char *ns, struct list_head *newlist,
                                struct list_head *head)
{
        int ret, len;
        struct sdfs_tgt_entry *tgt;
        chkid_t oid;
        char name[MAX_NAME_LEN];
        struct load_tgt_entry *load_tgt;
        struct list_head *pos, *n;

        list_for_each_safe(pos, n, newlist) {
                list_del(pos);
                load_tgt = (void *)pos;
                strcpy(name, load_tgt->name);
                oid = load_tgt->oid;
                yfree((void **)&pos);

                len = strlen(__iqn) + strlen(":") + strlen(ns) + strlen(".") + strlen(name);
                if ( len > ISCSI_IQN_NAME_MAX) {
                        DERROR("target %s:%s.%s length has %d more than iscsi max name length %d\n",
                               __iqn, ns, name, len, ISCSI_IQN_NAME_MAX);
                        continue;
                }
                tgt = sdfs_tgt_create();
                if (!tgt) {
                        ret = ENOMEM;
                        GOTO(err_ret, ret);
                }

                snprintf(tgt->iqn, sizeof(tgt->iqn), "%s:%s.%s", __iqn, ns, name);
                tgt->fileid = oid;
                tgt->delay_check = 0;
                list_add(&tgt->entry, head);

                DINFO("target %s "CHKID_FORMAT"\n", tgt->iqn, CHKID_ARG(&oid));
        }

        return 0;
err_ret:
        return ret;
}

/**
 * session_type:
 *      SESSION_DISCOVERY: 会进入该函数,且target还没建立
 *              conn->session->target is nil
 *      SESSION_NORMAL: 不会进入该函数
 */
static int sdfs_tgt_build(fileid_t *nsid, const char *ns, struct list_head *head,
                         struct iscsi_conn *conn)
{
        int ret;
        struct list_head list1, list2;
        struct list_head *pos, *n;
        lun_auth_t lun_auth;

        INIT_LIST_HEAD(&list1);
        INIT_LIST_HEAD(&list2);

        memcpy(lun_auth.ip, _inet_ntop((struct sockaddr *)&conn->peer),
               strlen(_inet_ntop((struct sockaddr *)&conn->peer)) + 1);
        memcpy(lun_auth.initiator, conn->initiator, strlen(conn->initiator) + 1);

        ret = __sdfs_tgt_build_list(nsid, &list1);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        while (!list_empty(&list1)) {
                ret = __sdfs_tgt_build_try_load(NULL, nsid, &list1, &list2, &lun_auth);
                if (unlikely(ret))
                        GOTO(err_list, ret);
        }

        ret = __sdfs_tgt_build_load(ns, &list2, head);
        if (unlikely(ret))
                GOTO(err_list, ret);

        return 0;
err_list:
        list_for_each_safe(pos, n, &list1) {
                list_del(pos);
                yfree((void **)&pos);
        }
        list_for_each_safe(pos, n, &list2) {
                list_del(pos);
                yfree((void **)&pos);
        }
err_ret:
        return ret;
}

struct sdfs_tgt_entry *sdfs_tgt_find(struct list_head *head, const char *iqn, fileid_t *fileid)
{
        struct sdfs_tgt_entry *tgt;

        list_for_each_entry(tgt, head, entry) {
                if (!strcmp(tgt->iqn, iqn) && !fileid_cmp(&tgt->fileid, fileid))
                        return tgt;
        }
        return NULL;
}

/*
 * SDFS NameSpace
 */

static void sdfs_ns_free(struct sdfs_ns_entry *ns)
{
        list_del_init(&ns->entry);
        yfree((void **)&ns);
}

static struct sdfs_ns_entry *sdfs_ns_create()
{
        int ret;
        struct sdfs_ns_entry *ns;

        ret = ymalloc((void **)&ns, sizeof(struct sdfs_ns_entry));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(ns, 0x00, sizeof(struct sdfs_ns_entry));

        INIT_LIST_HEAD(&ns->entry);

        return ns;
err_ret:
        return NULL;
}

static void sdfs_ns_release(struct list_head *head)
{
        struct sdfs_ns_entry *ns, *tmp;

        list_for_each_entry_safe(ns, tmp, head, entry) {
                sdfs_ns_free(ns);
        }
}

typedef struct {
        struct list_head *head;
        struct iscsi_conn *conn;
} arg_t;

STATIC int __sdfs_pool_scan(const char *pool, struct list_head *head)
{
        int ret;
        fileid_t id;
        struct sdfs_ns_entry *ns;
        char path[MAX_NAME_LEN];

        snprintf(path, MAX_BUF_LEN, "/%s", pool);
        
        ret = sdfs_lookup_recurive(path, &id);
        if (unlikely(ret)) {
                DERROR("iscsi descover root error, pool:%s ret:%d\n", pool, ret);
                return 0;
        }

        ns = sdfs_ns_create();
        if (!ns) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }

        DINFO("pool %s "CHKID_FORMAT"\n", (char *)pool, CHKID_ARG(&id));

        ns->ns.fileid = id;
        strcpy(ns->ns.vname, pool);
        list_add(&ns->entry, head);

        return 0;
err_ret:
        return ret;
}

static int sdfs_pool_scan(struct list_head *head, struct iscsi_conn *conn)
{
        int ret;
        dirid_t dirid;
        dirhandler_t *dirhandler;
        struct dirent *de;

        (void) conn;
        
        ret = sdfs_lookup_recurive("/", &dirid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = sdfs_opendir(NULL, &dirid, &dirhandler);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        while (1) {
                ret = sdfs_readdir(NULL, dirhandler, &de, NULL);
                if (ret) {
                        GOTO(err_close, ret);
                }

                if (de == NULL) {
                        break;
                }

                ret = __sdfs_pool_scan(de->d_name, head);
                if (unlikely(ret))
                        GOTO(err_close, ret);
        }

        sdfs_closedir(NULL, dirhandler);

        return 0;
err_close:
        sdfs_closedir(NULL, dirhandler);
err_ret:
        sdfs_ns_release(head);
        return ret;
}

static int __sdfs_scan_target(struct list_head *tgt_head, struct iscsi_conn *conn)
{
        int ret;
        struct list_head ns_head;
        struct sdfs_ns_entry *ns;

        DINFO("build target, scaning ...\n");

        INIT_LIST_HEAD(&ns_head);

        ret = sdfs_pool_scan(&ns_head, conn);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        list_for_each_entry(ns, &ns_head, entry) {
                if (ns->ns.fileid.type != ftype_dir
                    && ns->ns.fileid.type != ftype_pool) {
                        DINFO("skip "CHKID_FORMAT", type %u\n",
                              CHKID_ARG(&ns->ns.fileid), ns->ns.fileid.type);
                        continue;
                }

                DINFO("scan "CHKID_FORMAT"\n", CHKID_ARG(&ns->ns.fileid));
                
                ret = sdfs_tgt_build(&ns->ns.fileid, ns->ns.vname, tgt_head, conn);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        sdfs_ns_release(&ns_head);

        return 0;
err_ret:
        sdfs_ns_release(&ns_head);
        return ret;
}

static int sdfs_scan_target(struct list_head *tgt_head, struct iscsi_conn *conn)
{
        int ret, retry = 0;

retry:
        INIT_LIST_HEAD(tgt_head);

        ret = __sdfs_scan_target(tgt_head, conn);
        if (unlikely(ret)) {
                if (ret == EAGAIN || ret == ENOSPC) {
                        sdfs_tgt_release(tgt_head);
                        USLEEP_RETRY(err_ret, ret, retry, retry, 60, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        sdfs_tgt_release(tgt_head);
        return ret;
}

static int sdfs_free_target(struct list_head *tgt_head)
{
        sdfs_tgt_release(tgt_head);
        return 0;
}

static int sdfs_build_target(const char *name, struct sdfs_tgt_entry *utgt)
{
        int ret, retry = 0;
        char namespace[MAX_NAME_LEN], *target, path[MAX_PATH_LEN];
        fileid_t rootid;
        fileid_t id;

        DINFO("sdfs build target %s\n", name);

        if (strlen(name) > ISCSI_IQN_NAME_MAX) {
                ret = ENOENT;
                GOTO(err_ret, ret);
        }

        sprintf(namespace, "%s:", __iqn);
        if (strncmp(name, namespace, strlen(namespace))) {
                ret = ENOENT;
                GOTO(err_ret, ret);
        }
        strcpy(namespace, name + strlen(namespace));
        target = strchr(namespace, '.');
        if (target) {
                *target = '\0';
                target++;
        }

        snprintf(path, MAX_BUF_LEN, "/%s", namespace);
retry2:
        ret = sdfs_lookup_recurive(path, &rootid);
        if (unlikely(ret)) {
                if (ret == EAGAIN || ret == ENOSPC) {
                        USLEEP_RETRY(err_ret, ret, retry2, retry, 60, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

retry1:
        ret = sdfs_lookup(NULL, &rootid, target, &id);
        if (unlikely(ret)) {
                if (ret == EAGAIN || ret == ENOSPC) {
                        USLEEP_RETRY(err_ret, ret, retry1, retry, 60, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        utgt->fileid = id;
        strcpy(utgt->iqn, name);
        strcpy(utgt->pool, namespace);
        snprintf(utgt->path, MAX_PATH_LEN, "/iscsi/%s", target);

        DINFO("maping %s --> %s\n", name, utgt->path);

        return 0;
err_ret:
        return ret;
}

static int __sdfs_scan_lun(struct iscsi_conn *conn)
{
        int ret, retry = 0;
        struct list_head lun_head;
        lun_auth_t lun_auth;

        DINFO("build luns  %s "CHKID_FORMAT", scaning ...\n",
              conn->session->target->path,
              CHKID_ARG(&conn->session->target->fileid));

        memcpy(lun_auth.ip, _inet_ntop((struct sockaddr *)&conn->peer),
               strlen(_inet_ntop((struct sockaddr *)&conn->peer)) + 1);
        memcpy(lun_auth.initiator, conn->initiator, strlen(conn->initiator) + 1);

retry:
        INIT_LIST_HEAD(&lun_head);

        YASSERT(conn->session->target);
        ret = sdfs_lun_build(conn->session->target->pool,
                            conn->session->target->path,
                            &conn->session->target->fileid,
                            &lun_head, &lun_auth);
        if (unlikely(ret)) {
                if (ret == EAGAIN || ret == ENOSPC) {
                        sdfs_lun_release(&lun_head);
                        USLEEP_RETRY(err_ret, ret, retry, retry, 60, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        if (conn->session->target) {
                volume_apply_change(conn->session->target, &lun_head);
        }

        sdfs_lun_release(&lun_head);

        return 0;
err_ret:
        sdfs_lun_release(&lun_head);
        return ret;
}

static int sdfs_scan_lun(struct iscsi_conn *conn)
{
        return __sdfs_scan_lun(conn);
}

static int sdfs_rescan_lun(struct iscsi_conn *conn)
{
        time_t now;

        now = gettime();

        if (now - conn->session->target->last_scan > SCAN_INTERVAL) {
                conn->session->target->last_scan = now;
                return __sdfs_scan_lun(conn);
        }

        return 0;
}

static int sdfs_iscsi_init()
{
        int ret;

        __iqn = sanconf.iqn;

        if (!strlen(__iqn)) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        DINFO("iqn: %s\n", __iqn);

        return 0;
err_ret:
        return ret;
}

struct config_operations plain_ops = {
        .init           = sdfs_iscsi_init,
        .scan_target    = sdfs_scan_target,
        .free_target    = sdfs_free_target,
        .build_target   = sdfs_build_target,
        .scan_lun       = sdfs_scan_lun,
        .rescan_lun     = sdfs_rescan_lun,
        .account_query  = sdfs_account_query,
};

struct config_operations *cops = &plain_ops;
