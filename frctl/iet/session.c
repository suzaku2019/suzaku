/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "schedule.h"
#include "dbg.h"

static pthread_spinlock_t session_lock;
static struct list_head session_list;

struct iscsi_session *__session_find_by_name(char *iname, union iscsi_sid sid, chkid_t *chkid)
{
        struct iscsi_session *sess;

        /*
         * chkid for windows or vmware client.
         * windows & vmware client connect multi target just create one session.
         */
        list_for_each_entry(sess, &session_list, entry) {
                if (!memcmp(sid.id.isid, sess->sid.id.isid, 6)
                    && !strcmp(iname, sess->initiator)
                    && !chkid_cmp(chkid, &sess->target->fileid)) {
                        return sess;
                }
        }

        return NULL;
}

struct iscsi_session *__session_find_by_id(u64 sid)
{
        struct iscsi_session *sess;

        list_for_each_entry(sess, &session_list, entry) {
                if (sess->sid.id64 == sid)
                        return sess;
        }

        return NULL;
}

struct iscsi_session *session_find_by_name(char *iname, union iscsi_sid sid, chkid_t *chkid)
{
        struct iscsi_session *sess = NULL;

        pthread_spin_lock(&session_lock);
        sess = __session_find_by_name(iname, sid, chkid);
        pthread_spin_unlock(&session_lock);

        return sess;
}


struct iscsi_session *session_find_by_id(u64 sid)
{
        struct iscsi_session *sess = NULL;

        pthread_spin_lock(&session_lock);
        sess = __session_find_by_id(sid);
        pthread_spin_unlock(&session_lock);

        return sess;
}

static int session_exist(u64 sid)
{
        return (session_find_by_id(sid) != NULL);
}

int session_remove(struct iscsi_session *sess)
{
        int ret;
        struct iscsi_conn *conn, *tmp;

again:
        pthread_spin_lock(&sess->conn_lock);
        list_for_each_entry_safe(conn, tmp, &sess->conn_list, entry) {
#ifdef USE_CORENET
                if (conn->state == STATE_CLOSE) {
                        ret = EAGAIN;
                        GOTO(err_lock, ret);
                }

                DINFO("connection %s:%d closed\n",
                                _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));
                conn->state = STATE_CLOSE;

                list_del_init(&conn->entry);
                pthread_spin_unlock(&sess->conn_lock);  /*to prevent: core request will dead lock.*/

                goto again;

                iscsid_close(conn);    
#else
                if (!conn->vm) {
                        ret = EAGAIN;
                        GOTO(err_lock, ret);
                }

                DWARN("session remove sid:%lX, cid:%d, vm:%d\n", sess->sid.id64, conn->cid, conn->vm->idx);
                vm_stop(conn->vm);
#endif
        }
        pthread_spin_unlock(&sess->conn_lock);

        return 0;
err_lock:
        pthread_spin_unlock(&sess->conn_lock);
        return ret;
}

void session_free(struct iscsi_session *sess)
{
        u32 i;
        struct ua_entry *ua, *tmp;
        struct list_head *list;

        DINFO("session(%p) removing... type(%u), sid(%lX)\n",
             sess, sess->type, sess->sid.id64);

        /* Delete from target */
        if (sess->type == SESSION_NORMAL && sess->target) {
                pthread_spin_lock(&session_lock);
                list_del_init(&sess->entry);
                pthread_spin_unlock(&session_lock);

                target_del(sess->target);
        }

        YASSERT(conn_empty(sess));

        for (i = 0; i < ARRAY_SIZE(sess->cmd_hash); ++i) {
                if (!list_empty(&sess->cmd_hash[i]))
                        UNIMPLEMENTED(__DUMP__);
        }

        for (i = 0; i < ARRAY_SIZE(sess->ua_hash); ++i) {
                list = &sess->ua_hash[i];

                list_for_each_entry_safe(ua, tmp, list, entry) {
                        list_del_init(&ua->entry);
                        ua_free(ua);
                }
        }

        free(sess->initiator);
        yfree((void **)&sess);
}

static void session_set_param(struct iscsi_session *sess, struct iscsi_conn *conn)
{
#define SESS_PARAM_SET(sess, conn, parameter) \
        (sess)->param.parameter = (conn)->session_param[key_##parameter].val;

        SESS_PARAM_SET(sess, conn, initial_r2t);
        SESS_PARAM_SET(sess, conn, immediate_data);
        SESS_PARAM_SET(sess, conn, max_connections);
        SESS_PARAM_SET(sess, conn, max_recv_data_length);
        SESS_PARAM_SET(sess, conn, max_xmit_data_length);
        SESS_PARAM_SET(sess, conn, max_burst_length);
        SESS_PARAM_SET(sess, conn, first_burst_length);
        SESS_PARAM_SET(sess, conn, default_wait_time);
        SESS_PARAM_SET(sess, conn, default_retain_time);
        SESS_PARAM_SET(sess, conn, max_outstanding_r2t);
        SESS_PARAM_SET(sess, conn, data_pdu_inorder);
        SESS_PARAM_SET(sess, conn, data_sequence_inorder);
        SESS_PARAM_SET(sess, conn, error_recovery_level);
        SESS_PARAM_SET(sess, conn, header_digest);
        SESS_PARAM_SET(sess, conn, data_digest);
        SESS_PARAM_SET(sess, conn, ofmarker);
        SESS_PARAM_SET(sess, conn, ifmarker);
        SESS_PARAM_SET(sess, conn, ofmarkint);
        SESS_PARAM_SET(sess, conn, ifmarkint);

        SESS_PARAM_SET(sess, conn, rdma_extensions);
        SESS_PARAM_SET(sess, conn, target_recv_data_length);
        SESS_PARAM_SET(sess, conn, initiator_recv_data_length);
        SESS_PARAM_SET(sess, conn, max_outstanding_unexpected_pdus);
}

static struct iscsi_session *session_alloc(u8 type)
{
        int ret;
        u32 i;
        struct iscsi_session *sess;

        ret = ymalloc((void **)&sess, sizeof(struct iscsi_session));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = pthread_spin_init(&sess->conn_lock, PTHREAD_PROCESS_PRIVATE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        INIT_LIST_HEAD(&sess->conn_list);
        INIT_LIST_HEAD(&sess->pending_list);
        INIT_LIST_HEAD(&sess->cmd_list);
        INIT_LIST_HEAD(&sess->pending_cmd_list);

        for (i = 0; i < sizeof(sess->cmd_hash) / sizeof(sess->cmd_hash[0]); ++i)
                INIT_LIST_HEAD(&sess->cmd_hash[i]);

        for (i = 0; i < sizeof(sess->ua_hash) / sizeof(sess->ua_hash[0]); ++i)
                INIT_LIST_HEAD(&sess->ua_hash[i]);

        sess->type = type;
        sess->next_ttt = 1;

        return sess;
err_ret:
        return NULL;
}

/*
 * session_create - Create and initialize a session
 *
 * @conn: the first connection pointer.
 * @return: 0 on success, otherwise errno is returned
 */
int session_create(struct iscsi_conn *conn)
{
        int ret, retry = 0;
        struct iscsi_session *sess;
        static u16 tsih = 1;
        struct iscsi_target *target;

        if (conn->session_type != SESSION_NORMAL &&
            conn->session_type != SESSION_DISCOVERY) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        sess = session_alloc(conn->session_type);
        if (!sess) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }

        if (conn->session_type == SESSION_NORMAL) {
                target = conn->target;
                if (!target) {
                        ret = ENOENT;
                        GOTO(err_free, ret);
                }

                /* Generate a TSIH for normal session */
                sess->sid = conn->sid;
                sess->sid.id.tsih = tsih;

                while (session_exist(sess->sid.id64))
                        sess->sid.id.tsih++;
                tsih = sess->sid.id.tsih + 1;
                tsih = tsih == 0 ? 1 : tsih;

                memcpy(&sess->param, &target->sess_param, sizeof(sess->param));
                sess->max_queued_cmds = target->trgt_param.queued_cmds;
                sess->target = target;
        } else {
                /* Set a phony TSIH for discovery session */
                sess->sid = conn->sid;
                sess->sid.id.tsih = 1;
                sess->max_queued_cmds = 1;
        }

        sess->initiator = strdup(conn->initiator);
        if (!sess->initiator) {
                ret = ENOMEM;
                GOTO(err_free, ret);
        }

retry:
        ret = conn_add(sess, conn);
        if (unlikely(ret)) {
                USLEEP_RETRY(err_free, ret, retry, retry, 50, (100 * 1000));
        }

        conn->session = sess;
        conn->sid = sess->sid;

        DBUG("session %p add connection %p\n", sess, conn);

        sess->exp_cmd_sn = conn->exp_cmd_sn;
        sess->max_cmd_sn = sess->exp_cmd_sn + sess->max_queued_cmds;
        session_set_param(sess, conn);

        DINFO("session %p initiator %s create: type(%u), sid(%lX), exp_cmd_sn(%u), max_cmd_sn(%u)\n",
              sess, sess->initiator, sess->type, sess->sid.id64, sess->exp_cmd_sn, sess->max_cmd_sn);

        if (conn->session_type == SESSION_NORMAL) {
                DINFO("add session to list sid:%lX, cid:%d, tid:"CHKID_FORMAT"\n",
                                sess->sid.id64, conn->cid, CHKID_ARG(&conn->target->fileid));
                pthread_spin_lock(&session_lock);
                list_add(&sess->entry, &session_list);
                pthread_spin_unlock(&session_lock);
        }
#if 0
        iscsi_dump_session_param(&sess->param);
#endif

        return 0;
err_free:
        session_free(sess);
err_ret:
        return ret;
}

int session_init()
{
        int ret;

        INIT_LIST_HEAD(&session_list);

        ret = pthread_spin_init(&session_lock, PTHREAD_PROCESS_PRIVATE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
