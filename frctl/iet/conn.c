/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

#if ENABLE_ISCSI_MEM
static int mem_mcache_init(struct iscsi_conn *conn)
{
        int ret, i;
        struct iscsi_mem_cache **mem_cache = conn->mem_cache;
        static struct mem_mcache_param {
                char *name;
                u32 unit_size;
                u32 base_nr;
                u8 align;
        } mem_mcache_params[ISCSI_MEM_CACHE_NR] = {
                /*    name       |          size          | base_nr | align */
                /*
                { "target_cache", sizeof(struct iscsi_target),     8,  0, },
                { "volume_cache", sizeof(struct iscsi_volume),     8,  0, },
                { "conn_cache",   sizeof(struct iscsi_conn),       8,  0, },
                { "sess_cache",   sizeof(struct iscsi_session),    8,  0, },
                */
                { "cmd_cache",    sizeof(struct iscsi_cmd),        64, 0, },
                { "tio_cache",    sizeof(struct iscsi_tio),        64, 0, },
        };

        for (i = 0; i < ISCSI_MEM_CACHE_NR; ++i) {
                mem_cache[i] =
                        iscsi_mem_mcache_create(mem_mcache_params[i].name,
                                                mem_mcache_params[i].unit_size,
                                                mem_mcache_params[i].base_nr,
                                                mem_mcache_params[i].align);
                if (!mem_cache[i]) {
                        ret = ENOMEM;
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        for (--i; i >= 0; --i)
                iscsi_mem_mcache_destroy(mem_cache[i]);
        return ret;
}

static int mem_mcache_destory(struct iscsi_conn *conn)
{
        int i;
        struct iscsi_mem_cache **mem_cache = conn->mem_cache;

        for (i = 0; i < ISCSI_MEM_CACHE_NR; ++i) {
                iscsi_mem_mcache_destroy(mem_cache[i]);
        }

        return 0;
}
#endif

struct iscsi_conn *__conn_find(struct iscsi_session *sess, u16 cid)
{
        struct iscsi_conn *conn;

        list_for_each_entry(conn, &sess->conn_list, entry) {
                if (conn->cid == cid)
                        return conn;
        }

        return NULL;
}

struct iscsi_conn *conn_find(struct iscsi_session *sess, u16 cid)
{
        struct iscsi_conn *conn;

        pthread_spin_lock(&sess->conn_lock);
        conn = __conn_find(sess, cid);
        pthread_spin_unlock(&sess->conn_lock);

        return conn;
}

int conn_add(struct iscsi_session *sess, struct iscsi_conn *conn)
{
        int ret;
        struct iscsi_conn *old_conn;

        pthread_spin_lock(&sess->conn_lock);
        old_conn = __conn_find(sess, conn->cid);
        if (old_conn) {
#ifdef USE_CORENET
                UNIMPLEMENTED(__WARN__);
                if (1) {
                        ret = EAGAIN;
                        GOTO(err_lock, ret);
                }
#else
                if (!old_conn->vm) {
                        ret = EAGAIN;
                        GOTO(err_lock, ret);
                }

                DWARN("conn found, sid:%lX, cid:%d vm:%d\n", sess->sid.id64, conn->cid, old_conn->vm->idx);
                vm_stop(old_conn->vm);
#endif
        }

        list_add_tail(&conn->entry, &sess->conn_list);

        if (sess->target) {
                DINFO("vol "CHKID_FORMAT" sess %ju conn %s:%d count %d\n",
                      CHKID_ARG(&sess->target->fileid),
                      sess->sid.id64,
                      _inet_ntop((struct sockaddr *)&conn->peer),
                      ntohs(conn->peer.sin_port),
                      list_size(&sess->conn_list));
        }

        pthread_spin_unlock(&sess->conn_lock);

        return 0;
err_lock:
        pthread_spin_unlock(&sess->conn_lock);
        return ret;
}

int conn_empty(struct iscsi_session *sess)
{
        int ret;

        pthread_spin_lock(&sess->conn_lock);
        ret = list_empty(&sess->conn_list);
        pthread_spin_unlock(&sess->conn_lock);

        return ret;
}

int conn_alloc(struct iscsi_conn **pptr)
{
        int ret;
        struct iscsi_conn *conn;

        /*
        conn = iscsi_mem_mcache_calloc(g_mem_cache[ISCSI_MEM_CACHE_CONN], 0);
        if (!conn) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }
        */
        ret = ymalloc((void **)&conn, sizeof(struct iscsi_conn));
        if(ret)
                GOTO(err_ret, ret);

        conn->state = STATE_FREE;

        atomic_set(&conn->nr_cmds, 0);
        //atomic_set(&conn->nr_busy_cmds, 0);

        conn->hdigest_type |= DIGEST_NONE;
        conn->ddigest_type |= DIGEST_NONE;

        conn->in_check = 0;
        conn->waiting_free = 0;
        conn->close_time = 0;
        conn->ltime = gettime();

#if ENABLE_ISCSI_MEM
        mem_mcache_init(conn);
#endif

        param_set_defaults(conn->session_param, session_keys);

        INIT_LIST_HEAD(&conn->entry);
        INIT_LIST_HEAD(&conn->cmd_list);
        INIT_LIST_HEAD(&conn->param_list);
        INIT_LIST_HEAD(&conn->write_list);

        DINFO("connection alloced: %p\n", conn);

        *pptr = conn;

        return 0;
err_ret:
        return ret;
}

static void conn_free(struct iscsi_conn *conn)
{
        time_t used;
        struct iscsi_session *sess;
        struct iscsi_cmd *cmd, *tmp;

        DINFO("free connection %p from %s:%d\n",
              conn, _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));

        used = gettime() - conn->close_time;
        if (used > 5) {
                DERROR("conn_free used %u\n", (uint32_t)used);
        }

        list_for_each_entry_safe(cmd, tmp, &conn->cmd_list, conn_entry) {
                list_del_init(&cmd->entry);
                iscsi_cmd_release(cmd, 1);
        }

        if (atomic_read(&conn->nr_cmds)) {
                DERROR("BUG: still have cmds !!!\n");
                UNIMPLEMENTED(__DUMP__);
        }

        /* Unlink from session */
        list_del_init(&conn->entry);    /*may be done twice.*/

        sess = conn->session;

        if (sess && sess->target) {
                DINFO("vol "CHKID_FORMAT" sess %ju conn %s:%d count %d\n",
                      CHKID_ARG(&sess->target->fileid),
                      sess->sid.id64,
                      _inet_ntop((struct sockaddr *)&conn->peer),
                      ntohs(conn->peer.sin_port),
                      list_size(&sess->conn_list));
        }

        if (sess && conn_empty(sess))
                session_free(sess);

        YASSERT(conn->state == STATE_CLOSE);
        YASSERT(list_empty(&conn->param_list));
        YASSERT(list_empty(&conn->entry));

        free(conn->auth.chap.challenge);
        free(conn->initiator);
        //iscsi_mem_mcache_free(g_mem_cache[ISCSI_MEM_CACHE_CONN], conn);
#if ENABLE_ISCSI_MEM
        mem_mcache_destory(conn);
#endif

        yfree((void **)&conn);
}

void conn_busy_get(struct iscsi_conn *conn)
{
        //atomic_inc(&conn->nr_busy_cmds);
        atomic_inc(&conn->nr_cmds);
}

int conn_busy_put(struct iscsi_conn *conn)
{
        //if (atomic_dec_and_test(&conn->nr_busy_cmds) && conn->waiting_free && conn->in_check == 0) {
        if (atomic_dec_and_test(&conn->nr_cmds) && conn->waiting_free && conn->in_check == 0) {
                conn_free(conn);
                return 1;
        }

        return 0;
}

void conn_busy_tryfree(struct iscsi_conn *conn)
{
        //if (atomic_read(&conn->nr_busy_cmds) == 0 && conn->waiting_free) {
        if (atomic_read(&conn->nr_cmds) == 0 && conn->waiting_free) {
                conn_free(conn);
                return;
        }
}

void conn_close(struct iscsi_conn *conn)
{
        struct iscsi_cmd *cmd;

        /*
         * Set all commands to abort state
         */
        list_for_each_entry(cmd, &conn->cmd_list, conn_entry) {
                cmd->flags |= CMD_FLG_TMF_ABORT;
        }

        DINFO("close connection from %s:%d " "conn close: cmds(%u), busy_cmds(%u)\n",
                        _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port),
              (u32)atomic_read(&conn->nr_cmds),
              (u32)atomic_read(&conn->nr_cmds));

        /*
         * Check and free the connection
         */
        //close(conn->conn_fd);

        conn->waiting_free = 1;
        conn->close_time = gettime();

        //if (atomic_read(&conn->nr_busy_cmds)) {
        if (atomic_read(&conn->nr_cmds)) {
                /*
                 * Must wait for all the jobs handled by thread finish, can't free the
                 * connection before this.
                 */
                DWARN("wanting thread's job done: nr(%u)\n",
                     //atomic_read(&conn->nr_busy_cmds));
                     atomic_read(&conn->nr_cmds));
        } else if (conn->in_check) {
                /*
                 * Must wait for iscsi_check finish, can't free the
                 * connection before this.
                 */
                DWARN("wanting iscsi_check done\n");
        } else {
                DBUG("there is no busy cmd to wait, free now\n");
                conn_free(conn);
                return;
        }
}

void conn_update_stat_sn(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        u32 exp_stat_sn;

        exp_stat_sn = be32_to_cpu(cmd->pdu.bhs.exp_sn);

        if ((int)(exp_stat_sn - conn->exp_stat_sn) > 0 &&
            (int)(exp_stat_sn - conn->stat_sn) <= 0) {
                conn->exp_stat_sn = exp_stat_sn;
        }
}
