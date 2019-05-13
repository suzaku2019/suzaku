/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <pthread.h>
#include <netdb.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "iscsi_config.h"
#include "dbg.h"
#include "core.h"

#define MAX_NR_TARGETS  (1UL << 30)

/* Target list and lock */
static LIST_HEAD(target_list);

typedef struct {
        struct list_head hook;
        int count;
        fileid_t fileid[0];
} args_t;

typedef struct {
        struct list_head list;
        sy_spinlock_t lock;
        worker_handler_t sem;
        //sem_t sem;
} preload_list_t;

static struct iscsi_sess_param default_sess_param = {
	.initial_r2t           = 1,
	.immediate_data        = 1,
	.max_connections       = 1,
	.max_recv_data_length  = 262144,
	.max_xmit_data_length  = 262144,
	.max_burst_length      = 16776192,
	.first_burst_length    = 262144,
	.default_wait_time     = 2,
	.default_retain_time   = 0,
	.max_outstanding_r2t   = 1,
	.data_pdu_inorder      = 1,
	.data_sequence_inorder = 1,
	.error_recovery_level  = 0,
	.header_digest         = DIGEST_NONE,
	.data_digest           = DIGEST_NONE,
	.ofmarker              = 0,
	.ifmarker              = 0,
	.ofmarkint             = 2048,
	.ifmarkint             = 2048,

    .rdma_extensions                    = 1,
    .target_recv_data_length            = 262144,
    .initiator_recv_data_length         = 262144,
    .max_outstanding_unexpected_pdus    = 0,
};

static struct iscsi_trgt_param default_trgt_param = {
	.target_type = ISCSI_TARGET_TYPE_DISK,
	.queued_cmds = DEFAULT_NR_QUEUED_CMDS,
};

static int __iscsi_target_create(u32 tid, const char *name, const char *path,
                                 const fileid_t *fileid, struct iscsi_target **_tgt)
{
        int ret;
        char pool[ISCSI_IQN_NAME_MAX], *vol;
        struct iscsi_target *target;

        if (!name) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        ret = ymalloc((void **)&target, sizeof(struct iscsi_target));
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        target->tid = tid;

        memcpy(&target->sess_param, &default_sess_param, sizeof(default_sess_param));
        memcpy(&target->trgt_param, &default_trgt_param, sizeof(default_trgt_param));

        snprintf(target->name, sizeof(target->name), "%s", name);
        snprintf(target->path, sizeof(target->path), "%s", path);
        
        if (strncmp(name, sanconf.iqn, strlen(sanconf.iqn))) {
                ret = EINVAL;
                GOTO(err_free, ret);
        }

        strcpy(pool, name + strlen(sanconf.iqn) + strlen(":"));
        vol = strchr(pool, '.');
        if (vol) {
                *vol = '\0';
                vol++;
        } else {
                ret = EINVAL;
                GOTO(err_free, ret);
        }

        snprintf(target->pool, sizeof(target->pool), "%s", pool);

        target->fileid = *fileid;

        atomic_set(&target->nr_volumes, 0);
        target->stat = ITGT_RUNNING;
        target->loaded = 0;
        target->last_scan = 0;

        INIT_LIST_HEAD(&target->volume_list);

        if (_tgt)
                *_tgt = target;

#if ENABLE_ISCSI_CACHE_REUSE
        memset(target->volume_entrys, 0x0, sizeof(mcache_entry_t *) * TARGET_MAX_LUNS);
#endif

        DINFO("target: "CHKID_FORMAT" pool:%s target:%s\n", CHKID_ARG(fileid), pool, vol);

        {
                char vaai[8] = {0};
                size_t vallen = 8;

                target->vaai_enabled = 0;
                ret = sdfs_getxattr(NULL, fileid, SDFS_SYSTEM_ATTR_VAAI, vaai, &vallen);
                if (!ret){
                        if (atoi(vaai)) {
                                target->vaai_enabled = 1;
                        }
                }
                DINFO("vaai supported: %d\n", target->vaai_enabled);

                char thin[32] = {0};
                vallen = 32;

                target->thin_provisioning = 1;
                ret = sdfs_getxattr(NULL, fileid, SDFS_SYSTEM_ATTR_THIN, thin, &vallen);
                if (!ret){
                        if (strcmp(thin, SDFS_SYSTEM_ATTR_ENABLE) != 0) {
                                target->thin_provisioning = 0;
                        }
                }

                DINFO("thin provisioning supported: %d\n", target->thin_provisioning);

                char scsi_id[128] = {0};
                vallen = 128;
                ret = sdfs_getxattr(NULL, fileid, SDFS_SYSTEM_ATTR_SCSI_ID, scsi_id, &vallen);
                if (ret) {      //no exists.
                        uint8_t data[128];
                        int len = 16;

                        *((uint32_t *)data) = cpu_to_be32(ISCSI_IEEE_VEN_ID);
                        memcpy(data + 4, &gloconf.cluster_id, 4);
                        memcpy(data + 8, &target->fileid.id, 8);

                        strcpy(scsi_id, "wwn-0x");
                        for(int i=0;i<len;i++)
                                sprintf(scsi_id + 6 + i * 2, "%02x", data[i]);

                        ret = sdfs_setxattr(NULL, fileid, SDFS_SYSTEM_ATTR_SCSI_ID,
                                            scsi_id, len * 2 + 6, O_CREAT);   
                        if(ret)
                                DERROR("set scsi_id error.\r\n");
                }
                
        }

        return 0;
err_free:
        yfree((void **)&target);
err_ret:
        return ret;
}

int target_alloc_by_name(const char *name, struct iscsi_target **_tgt)
{
        int ret;
        struct sdfs_tgt_entry utgt;

        if (!name) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        ret = cops->build_target(name, &utgt);
        if(ret)
                GOTO(err_ret, ret);

        ret = __iscsi_target_create(utgt.fileid.id, utgt.iqn, utgt.path, &utgt.fileid, _tgt);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int target_free(struct iscsi_target *target)
{
        return yfree((void **)&target);
}

/* @LOCK: caller must hold the @target_list_mutex */
static int __target_del(struct iscsi_target *target)
{
        struct iscsi_volume *volume, *tmp;

        list_for_each_entry_safe(volume, tmp, &target->volume_list, entry) {
                list_del_init(&volume->entry);
                volume_del(volume);
        }

        DINFO("vol "CHKID_FORMAT" target %s\n",
              CHKID_ARG(&target->fileid), target->name);

#if ENABLE_ISCSI_CACHE_REUSE
        int i;
        for (i = 0; i < TARGET_MAX_LUNS; i++) {
                if (target->volume_entrys[i] == NULL)
                        continue;

                volume_ctl_release(target->volume_entrys[i]);
                target->volume_entrys[i] = NULL;
        }
#endif

        yfree((void **)&target);

        return 0;
}

void target_del(struct iscsi_target *target)
{
        __target_del(target);
}

void target_add_lun_nolock(struct iscsi_target *target, struct iscsi_volume *lun)
{
        list_add(&lun->entry, &target->volume_list);
        atomic_inc(&target->nr_volumes);
}

void target_del_lun_nolock(struct iscsi_target *target, struct iscsi_volume *lun)
{
        list_del_init(&lun->entry);
        atomic_dec(&target->nr_volumes);
}

void target_list_entry_build(struct iscsi_cmd *rsp, char *name)
{
        struct sdfs_tgt_entry *tgt;
        struct sockaddr_storage ss1;
        socklen_t slen = sizeof(struct sockaddr_storage);
        char addr1[NI_MAXHOST];
        int ret, family;
        struct iscsi_conn *conn = rsp->conn;
        struct list_head tgt_head;

        ret = getsockname(conn->conn_fd, (struct sockaddr *)&ss1, &slen);
        if (unlikely(ret)) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = getnameinfo((struct sockaddr *)&ss1, slen, addr1,
                          sizeof(addr1), NULL, 0, NI_NUMERICHOST);
        if (unlikely(ret)) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        family = ss1.ss_family;

        cops->scan_target(&tgt_head, conn);

        list_for_each_entry(tgt, &tgt_head, entry) {
                if (name && strcmp(tgt->iqn, name))
                        continue;
                else {
                        char taddr[NI_MAXHOST + NI_MAXSERV + 5];
                        char *addr, *ptr;

                        tio_add_param(rsp, "TargetName", tgt->iqn);

                        /* strip ipv6 zone id */
                        ptr = addr1;
                        addr = strsep(&ptr, "%");

                        snprintf(taddr, sizeof(taddr),
                                 (family == AF_INET) ? "%s:%d,1" : "[%s]:%d,1",
                                 addr, sanconf.iscsi_port);
                        tio_add_param(rsp, "TargetAddress", taddr);
                }
        }

        cops->free_target(&tgt_head);

        if (rsp->tio) {
                ret = mbuffer_compress(&rsp->tio->buffer);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        return;
err_ret:
        (void) ret;
}

int target_redirect(int conn_fd, struct iscsi_target *target)
{
#if ENABLE_ISCSI_VIP
        int ret, len;
        diskid_t diskid;
        char rack[MAX_NAME_LEN], ip[MAX_NAME_LEN];
        struct sockaddr_in ip_addr;
        socklen_t slen = sizeof(struct sockaddr_storage);

        ret =  stor_get_location(target->pool, &target->fileid, rack, &diskid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = getsockname(conn_fd, (struct sockaddr *)&ip_addr, &slen);
        if (unlikely(ret)) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = netvip_getip_byid(&diskid, ip_addr.sin_addr.s_addr, ip, &len);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (strlen(ip) == 0) {
                ret = ENXIO;
                GOTO(err_ret, ret);
        }

        strcpy(target->redirect.addr, ip);
        sprintf(target->redirect.port, "%d", sanconf.iscsi_port);
        target->redirect.type = ISCSI_STATUS_TGT_MOVED_TEMP;

        return 0;
err_ret:
        return ret;
#else
        (void) conn_fd;
        (void) target;
        UNIMPLEMENTED(__DUMP__);
        return 0;
#endif
}

int target_redirected(struct iscsi_conn *conn, struct iscsi_target *target)
{
        if (!core_self()) {
                strcpy(target->redirect.addr, inet_ntoa(conn->self.sin_addr));
                sprintf(target->redirect.port, "%d", ISER_LISTEN_PORT + core_hash(&target->fileid));
                target->redirect.type = ISCSI_STATUS_TGT_MOVED_TEMP;
                return 1;
        }

        return 0;
}

int iser_target_redirect(struct iscsi_conn *conn, struct iscsi_target *target)
{
#if ENABLE_ISCSI_VIP
        int ret, len;
        diskid_t diskid;
        char rack[MAX_NAME_LEN], ip[MAX_NAME_LEN];

	ret =  stor_get_location(target->pool, &target->fileid, rack, &diskid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = netvip_getip_byid(&diskid, conn->self.sin_addr.s_addr, ip, &len);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (strlen(ip) == 0) {
                ret = ENXIO;
                GOTO(err_ret, ret);
        }

        strcpy(target->redirect.addr, ip);
        sprintf(target->redirect.port, "%d", ISER_LISTEN_PORT + core_hash(&target->fileid));
        target->redirect.type = ISCSI_STATUS_TGT_MOVED_TEMP;

        return 0;
err_ret:
        return ret;
#else
        (void) conn;
        (void) target;
        UNIMPLEMENTED(__DUMP__);
        return 0;
#endif
}

#if ENABLE_ISCSI_VIP
int target_islocal(struct iscsi_target *target)
{
        int ret, retry = 0;
        char rack[MAX_NAME_LEN];
        diskid_t diskid;
        fileid_t fileid = target->fileid;

retry:
        ret = stor_get_location(target->pool, &fileid, rack, &diskid);
        if (unlikely(ret)) {
                if (ret == EAGAIN) {
                        USLEEP_RETRY(no, ret, retry, retry, 3, (500 * 1000));
                } else
                        GOTO(no, ret);
        }

        if (sanconf.iscsi_gateway) {
                if (nid_cmp(&diskid, &g_local_nid))
                        goto no;
        } else {
                if (!net_islocal(&diskid)) {
                        goto no;
                }
        }

        return 1;
no:
        return 0;
}

int target_localize_confirm(struct iscsi_target *target)
{
        int ret;
        time_t now;

        now = gettime();
        target->confirm = now;

        if (!target_islocal(target)) {
                DINFO("target %s "CHKID_FORMAT" not local\n", target->name,
                      CHKID_ARG(&target->fileid));
                ret = EREMCHG;
                goto err_ret;
        }

        return 0;
err_ret:
        return ret;
}
#endif

#if 1
int target_connect(struct iscsi_target *target, const char *addr, int port)
{
        int ret, retry = 0, i;
        fileid_t fileid[TARGET_MAX_LUNS];
        struct list_head *pos;
        struct iscsi_volume *lun;

        if (!target) {
                DWARN("target has been released!!!\r\n");
                return -1;
        }

        memset(fileid, 0x0, sizeof(fileid));

        list_for_each(pos, &target->volume_list) {
                lun = (void *)pos;
                fileid[lun->lun] = lun->fileid;
                DBUG("fileid %ju idx %u addr %s:%d\n", lun->fileid.id, lun->lun, addr, port);
        }

        for (i = 0; i < TARGET_MAX_LUNS; i++) {
                if (fileid[i].id == 0)
                        continue;

                DINFO("vol "CHKID_FORMAT" target %s/%d addr %s:%d\n",
                      CHKID_ARG(&fileid[i]), target->name, i, addr, port);

retry:
                ret = sdfs_localize(&fileid[i]);
                if (unlikely(ret)) {
                        if (ret == EAGAIN) {
                                DWARN("%s connect to %s:%d, need retry\n", addr, port, target->name);
                                USLEEP_RETRY(err_ret, ret, retry, retry, 50, (100 * 1000));
                        } else
                                GOTO(err_ret, ret);
                }

#if ENABLE_ISCSI_CACHE_REUSE
                retry = 0;
                mcache_entry_t *entry;
retry1:
                entry = target->volume_entrys[i];
                if (!entry) {
                        ret = core_request(core_hash(&fileid[i]), -1,
                                           "volume_ctl_get", __iscsi_volume_ctl_get_,
                                           &fileid[i], &entry);
                        //ret = volume_ctl_get(&fileid[i], &entry);
                        if (unlikely(ret)) {
                                if (ret == EREMCHG) {
                                        DWARN("%s/%d ("CHKID_FORMAT") not localized\n",
                                                        target->name, i, CHKID_ARG(&fileid[i]));
                                } else {
                                        if (ret == EAGAIN) {
                                                USLEEP_RETRY(err_ret, ret, retry1, retry, 50, (100 * 1000));
                                        } else
                                                GOTO(err_ret, ret);
                                }
                        } else {
                                if (target->volume_entrys[i]) {
                                        volume_ctl_release(entry);
                                } else {
                                        target->volume_entrys[i] = entry;
                                }
                                DINFO(CHKID_FORMAT" localized\n", CHKID_ARG(&target->fileid));
                        }
                }
#endif

#if ENABLE_ISCSI_CONN_LIST
        retry2:
                ret = block_connect(target->pool, &fileid[i], addr, port, "target");
                if (unlikely(ret)) {
                        if (ret == EAGAIN) {
                                DWARN("%s:%d connect to %s/%d "CHKID_FORMAT"\n",
                                      addr, port, target->name, i, CHKID_ARG(&fileid[i]));
                                USLEEP_RETRY(err_ret, ret, retry2, retry, 50, (100 * 1000));
                        } else
                                GOTO(err_ret, ret);
                }
#endif
        }

        return 0;
err_ret:
        return ret;
}
#endif

int target_disconnect(struct iscsi_target *target, const char *addr, int port)
{
        DINFO("vol "CHKID_FORMAT" target %s addr %s:%d\n",
              CHKID_ARG(&target->fileid), target->name, addr, port);

#if ENABLE_ISCSI_CONN_LIST
        int ret;

        ret = block_disconnect(target->pool, &target->fileid, addr, port, "target");
        if (unlikely(ret)) {
                DWARN("target %s/"CHKID_FORMAT" iscsi connection release fail:%d",
                      target->pool, CHKID_ARG(&target->fileid), ret);
        }
#endif

        return 0;
}

#if 0
int target_lichbd_connect(struct iscsi_target *target)
{
        int ret, retry = 0;
        char path[MAX_NAME_LEN], *tmp;

        tmp = strchr(target->name, ':');
        if (!tmp) {
                ret = EIO;
                GOTO(err_ret, ret);
        } else {
                sprintf(path, "/iscsi/%s", tmp + 1);
                tmp = strchr(path, '.');
                if (!tmp) {
                        ret = EIO;
                        GOTO(err_ret, ret);
                }

                *tmp = '/';
        }

retry1:
        ret = lichbd_connect(target->pool, path, &target->ioctx, 0);
        if (ret) {
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry1, retry, 50, (500 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}
#endif
