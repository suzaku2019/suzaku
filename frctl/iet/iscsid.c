/*
 * iscsid.c - ietd iSCSI protocol processing
 *
 * Copyright (C) 2002-2003 Ardis Technolgies <roman at ardistech dot com>
 * Copyright (C) 2004-2010 VMware, Inc. All Rights Reserved.
 * Copyright (C) 2007-2010 Ross Walker <rswwalker at gmail dot com>
 *
 * This file is part of iSCSI Enterprise Target software.
 *
 * Released under the terms of the GNU GPL v2.0.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi_config.h"
#include "iscsi.h"
#include "vm.h"
#include "core.h"
#include "corenet.h"
#include "get_version.h"
#include "job_dock.h"
#include "../ynet/sock/sock_tcp.h"
#include "net_table.h"
#include "analysis.h"
#include "dbg.h"
#include "iscsid.h"

#define ISCSI_CHECK 1

enum {
        RET_DONE,
        RET_CLOSE,
        RET_AGAIN,
        RET_FREE,
};

static int __listen_sd__;
static int __listen_sd6__;
struct iscsi_mem_cache *g_mem_cache[ISCSI_MEM_CACHE_NR];

#if 0
static int mem_mcache_init()
{
        int ret, i;
        static struct mem_mcache_param {
                char *name;
                u32 unit_size;
                u32 base_nr;
                u8 align;
        } mem_mcache_params[ISCSI_MEM_CACHE_NR] = {
                /*    name       |          size          | base_nr | align */
                { "target_cache", sizeof(struct iscsi_target),     8,  0, },
                { "volume_cache", sizeof(struct iscsi_volume),     8,  0, },
                { "conn_cache",   sizeof(struct iscsi_conn),       8,  0, },
                { "sess_cache",   sizeof(struct iscsi_session),    8,  0, },
                { "cmd_cache",    sizeof(struct iscsi_cmd),        64, 0, },
                { "tio_cache",    sizeof(struct iscsi_tio),        64, 0, },
        };

        for (i = 0; i < ISCSI_MEM_CACHE_NR; ++i) {
                g_mem_cache[i] =
                        iscsi_mem_mcache_create(mem_mcache_params[i].name,
                                                mem_mcache_params[i].unit_size,
                                                mem_mcache_params[i].base_nr,
                                                mem_mcache_params[i].align);
                if (!g_mem_cache[i]) {
                        ret = ENOMEM;
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        for (--i; i >= 0; --i)
                iscsi_mem_mcache_destroy(g_mem_cache[i]);
        return ret;
}
#endif

static void forward_iov(struct msghdr *msg, u32 len)
{
        while (msg->msg_iov->iov_len <= len) {
                len -= msg->msg_iov->iov_len;
                ++msg->msg_iov;
                --msg->msg_iovlen;
        }

        msg->msg_iov->iov_base = (char *)msg->msg_iov->iov_base + len;
        msg->msg_iov->iov_len -= len;
}

/** ,====================
 * /  iscsi_recv
 * `==============================
 */

enum rx_state {
        RX_INIT_BHS,    /* Must be zero */
        RX_BHS,

        RX_INIT_AHS,
        RX_AHS,

        RX_INIT_HDIGEST,
        RX_HDIGEST,
        RX_CHECK_HDIGEST,

        RX_INIT_DATA,
        RX_DATA,

        RX_INIT_DDIGEST,
        RX_DDIGEST,
        RX_CHECK_DDIGEST,

        RX_END,
};

static void iscsi_conn_init_read(struct iscsi_conn *conn, void *data, size_t len)
{
        len = iscsi_cmd_size_align(len);
        conn->read_iov[0].iov_base = data;
        conn->read_iov[0].iov_len = len;
        conn->read_msg.msg_iov = conn->read_iov;
        conn->read_msg.msg_iovlen = 1;
        conn->read_size = len;
}

static int iscsi_conn_read_ahs(struct iscsi_conn *conn, struct iscsi_cmd *cmd)
{
        int ret;

        cmd->pdu.ahs = malloc(cmd->pdu.ahssize);
        if (!cmd->pdu.ahs) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }

        iscsi_conn_init_read(conn, cmd->pdu.ahs, cmd->pdu.ahssize);

        return 0;
err_ret:
        return ret;
}

static int do_recv(struct iscsi_conn *conn)
{
        int ret, i;
        size_t len, size = 0;

        if (conn->login_state == STATE_FREE) {
                while (1) {
                        ret = recvmsg(conn->conn_fd, &conn->read_msg, 0);
                        if (ret == 0) {
                                /* Peer is closed */
                                DINFO("closed by peer %s:%d\n",
                                      _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));
                                ret = RET_CLOSE;
                                break;
                        } else if (ret < 0) {
                                if (errno == EINTR)
                                        continue;
                                else if (errno == EAGAIN) {
                                        ret = RET_AGAIN;
                                        break;
                                } else {
                                        DWARN("ret: %d, %s\n", errno, strerror(errno));
                                        ret = RET_CLOSE;
                                        break;
                                }
                        }

                        conn->read_size -= ret;

                        if (conn->read_size)
                                /* Update the index and offset */
                                forward_iov(&conn->read_msg, ret);
                        else {
                                /* Read finish */
                                ret = RET_DONE;
                                break;
                        }
                }
        } else {
                for (i = 0; i < (int)conn->read_msg.msg_iovlen; i++) {
                        len = conn->read_msg.msg_iov[i].iov_len;
                        size += len;
                }

                if (conn->buf->len < size) {
                        ret = RET_AGAIN;
                        goto out;
                }

                for (i = 0; i < (int)conn->read_msg.msg_iovlen; i++) {
                        len = conn->read_msg.msg_iov[i].iov_len;

                        mbuffer_get(conn->buf, conn->read_msg.msg_iov[i].iov_base, len);
                        mbuffer_pop(conn->buf, NULL, len);
                }

                conn->read_size -= size;
                ret = RET_DONE;
        }

out:
        return ret;
}

static int iscsi_recv(void *arg)
{
        struct iscsi_conn *conn = arg;
        int ret, hdigest, ddigest;
        struct iscsi_cmd *cmd = conn->read_cmd;

        hdigest = conn->hdigest_type & DIGEST_NONE ? 0 : 1;
        ddigest = conn->ddigest_type & DIGEST_NONE ? 0 : 1;

next_state:
        switch (conn->read_state) {
        case RX_INIT_BHS:
                cmd = conn->read_cmd = iscsi_cmd_alloc(conn, 1);
                iscsi_conn_init_read(cmd->conn, &cmd->pdu.bhs, sizeof(cmd->pdu.bhs));
                conn->read_state = RX_BHS;
                break;

        case RX_BHS:
                ret = do_recv(conn);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        goto out_again;
                case RET_DONE:
                        conn->read_state = RX_INIT_AHS;
                        break;
                }
                break;

        case RX_INIT_AHS:
                iscsi_cmd_get_length(&cmd->pdu);
                if (cmd->pdu.ahssize) {
                        ret = iscsi_conn_read_ahs(conn, cmd);
                        if (unlikely(ret))
                                GOTO(out_close, ret);
                        conn->read_state = RX_AHS;
                } else {
                        conn->read_state = hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA;
                        break;
                }
                break;

        case RX_AHS:
                ret = do_recv(conn);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        goto out_again;
                case RET_DONE:
                        conn->read_state = hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA;
                        break;
                }
                break;

        case RX_INIT_HDIGEST:
                iscsi_conn_init_read(conn, &cmd->hdigest, sizeof(u32));
                conn->read_state = RX_HDIGEST;
                break;

        case RX_HDIGEST:
                ret = do_recv(conn);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        goto out_again;
                case RET_DONE:
                        conn->read_state = RX_CHECK_HDIGEST;
                        break;
                }
                break;

        case RX_CHECK_HDIGEST:
                ret = digest_rx_header(cmd);
                if (unlikely(ret))
                        GOTO(out_close, ret);
                conn->read_state = RX_INIT_DATA;
                break;

        case RX_INIT_DATA:
                ret = cmd_rx_start(cmd);
                if (unlikely(ret))
                        GOTO(out_close, ret);
                conn->read_state = cmd->pdu.datasize ? RX_DATA : RX_END;
                break;

        case RX_DATA:
                ret = do_recv(conn);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        goto out_again;
                case RET_DONE:
                        conn->read_state = ddigest ? RX_INIT_DDIGEST : RX_END;
                        break;
                }
                break;

        case RX_INIT_DDIGEST:
                iscsi_conn_init_read(conn, &cmd->ddigest, sizeof(u32));
                conn->read_state = RX_DDIGEST;
                break;

        case RX_DDIGEST:
                ret = do_recv(conn);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        goto out_again;
                case RET_DONE:
                        conn->read_state = RX_CHECK_DDIGEST;
                        break;
                }
                break;

        case RX_CHECK_DDIGEST:
                ret = digest_rx_data(cmd);
                if (unlikely(ret))
                        GOTO(out_close, ret);
                conn->read_state = RX_END;
                break;

        default:
                DERROR("Should not come here: %d\n", conn->read_state);
                UNIMPLEMENTED(__DUMP__);
        }

        if (conn->read_state != RX_END)
                goto next_state;

        if (ISCSI_CMD_RECORD) {
                struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(cmd);
                DINFO("iscsi recv %s:%d cmd record opcode:%x cmd:%x\n",
                                _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port),
                                cmd_opcode(cmd), req_hdr->scb[0]);
        }

        ret = cmd_rx_end(cmd);
        if (unlikely(ret))
                GOTO(out_close, ret);

        conn->read_cmd = NULL;
        conn->read_state = RX_INIT_BHS;

        return 0;
out_again:
        /* Waiting for next read */
        return ret;
out_close:
        /* Just close the connection */
        DBUG("close point 3\n");
        conn->state = STATE_CLOSE;
        iscsi_cmd_release(cmd, 1);
        return ret;
}

/** ,====================
 * /  iscsi_send
 * `==============================
 */

enum tx_state {
        TX_INIT,        /* Must be zero */
        TX_DATA,
        TX_INIT_SEND,
        TX_SEND,
        TX_END,
};

static int do_send(struct iscsi_conn *conn)
{
        int ret, i;
        buffer_t buf;
        size_t len, size = 0;

        if (conn->login_state == STATE_FREE) {
                while (1) {
                        ANALYSIS_BEGIN(0);

                        ret = sendmsg(conn->conn_fd, &conn->write_msg, 0);
                        if (ret < 0) {
                                if (errno == EINTR)
                                        continue;
                                else if (errno == EAGAIN) {
                                        ret = RET_AGAIN;
                                        break;
                                } else {
                                        DWARN("ret: %d, %s\n", errno, strerror(errno));
                                        ret = RET_CLOSE;
                                        break;
                                }
                        }

                        ANALYSIS_END(0, 2000, "send");

                        conn->write_size -= ret;

                        if (conn->write_size)
                                /* Update the index and offset */
                                forward_iov(&conn->write_msg, ret);
                        else {
                                /* Read finish */
                                ret = RET_DONE;
                                break;
                        }
                }
        } else {
                ret = mbuffer_init(&buf, 0);
                if (unlikely(ret)) {
                        DWARN("iscsi send error %d, %s\n", ret, strerror(ret));
                        ret = RET_CLOSE;
                        goto out;
                }

                for (i = 0; i < (int)conn->write_msg.msg_iovlen; i++) {
                        len = conn->write_msg.msg_iov[i].iov_len;
                        ret = mbuffer_appendmem(&buf, conn->write_msg.msg_iov[i].iov_base, len);
                        if (unlikely(ret)) {
                                DWARN("iscsi send error %d, %s\n", ret, strerror(ret));
                                ret = RET_CLOSE;
                                goto out;
                        }

                        size += len;
                }

                corenet_send(NULL, &conn->sockid, &buf, 0);
                conn->write_size -= size;
                ret = RET_DONE;
        }

out:
        return ret;
}

static inline void init_tx_header(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iovec *iop;

        iop = conn->write_iov;

        iop->iov_base = &cmd->pdu.bhs;
        iop->iov_len = sizeof(cmd->pdu.bhs);
        ++iop;
        iop->iov_len = 0;

        conn->write_size = sizeof(cmd->pdu.bhs);
}

static inline void init_tx_hdigest(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iovec *iop;

        if (conn->hdigest_type & DIGEST_NONE)
                goto out;

        digest_tx_header(cmd);

        for (iop = conn->write_iov; iop->iov_len; ++iop)
                ;

        iop->iov_base = &(cmd->hdigest);
        iop->iov_len = sizeof(u32);
        iop++;
        iop->iov_len = 0;

        conn->write_size += sizeof(u32);
out:
        return;
}

static inline void init_tx_align(struct iscsi_cmd *cmd, int align)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iovec *iop;

        for (iop = conn->write_iov; iop->iov_len; ++iop)
                ;

        iop->iov_base = conn->__align;
        iop->iov_len = align;
        iop++;
        iop->iov_len = 0;

        conn->write_size += align;
}

static void init_tx_tio(struct iscsi_cmd *cmd)
{
        int align, count;
        struct iovec *iop;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_tio *tio = conn->write_tio;

        for (iop = conn->write_iov; iop->iov_len; ++iop)
                ;

        mbuffer_trans2(iop, &count, conn->write_tio_off, conn->write_tio_size, &tio->buffer);

        iop += count;
        iop->iov_len = 0;

        conn->write_size += conn->write_tio_size;

        align = iscsi_cmd_size_align(conn->write_size) - conn->write_size;
        if (align)
                init_tx_align(cmd, align);
}

static void init_tx_ddigest(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iovec *iop;

        if (conn->ddigest_type & DIGEST_NONE)
                goto out;

        if (!cmd->pdu.datasize)
                goto out;

        digest_tx_data(cmd);

        for (iop = conn->write_iov; iop->iov_len; ++iop)
                ;

        iop->iov_base = &(cmd->ddigest);
        iop->iov_len = sizeof(u32);
        iop++;
        iop->iov_len = 0;

        conn->write_size += sizeof(u32);
out:
        return;
}

static void init_tx_msghdr(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iovec *iop;

        conn->write_msg.msg_iov = conn->write_iov;
        conn->write_msg.msg_iovlen = 0;

        for (iop = conn->write_iov; iop->iov_len; ++iop)
                conn->write_msg.msg_iovlen++;

}

static int iscsi_send_one(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;
        conn->write_cmd = cmd;

        ANALYSIS_BEGIN(0);
        ANALYSIS_BEGIN(1);
        ANALYSIS_BEGIN(2);
        ANALYSIS_BEGIN(3);
        ANALYSIS_BEGIN(4);

        YASSERT(cmd->time == conn->ltime);

        if (conn->state == STATE_CLOSE) {
                goto out_close;
        }

next_state:
        switch (conn->write_state) {
        case TX_INIT:
                ret = cmd_tx_start(cmd);
                if (unlikely(ret))
                        GOTO(out_close, ret);

                init_tx_header(cmd);
                init_tx_hdigest(cmd);

                conn->write_state = cmd->pdu.datasize ? TX_DATA : TX_INIT_SEND;
                break;

        case TX_DATA:
                init_tx_tio(cmd);
                init_tx_ddigest(cmd);
                conn->write_state = TX_INIT_SEND;
                break;

        case TX_INIT_SEND:
                init_tx_msghdr(cmd);
                conn->write_state = TX_SEND;
                break;

        case TX_SEND:
                ret = do_send(conn);
                switch (ret) {
                case RET_CLOSE:
                        ANALYSIS_END(0, 100 * 1000, NULL);
                        goto out_close;
                case RET_AGAIN:
                        ANALYSIS_END(1, 100 * 1000, NULL);
                        goto out_again;
                case RET_DONE:
                        ANALYSIS_END(2, 100 * 1000, NULL);
                        conn->write_state = TX_END;
                        break;
                }
                break;

        default:
                DERROR("Should not came here: %d\n", conn->write_state);
                UNIMPLEMENTED(__DUMP__);
        }

        if (conn->write_state != TX_END) {
                ANALYSIS_END(3, 100 * 1000, NULL);
                goto next_state;
        }

        if (ISCSI_CMD_RECORD) {
                struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(cmd);
                /*opcode: ((cmd)->pdu.bhs.opcode & 0x3f) */
                /*cmd: ((struct iscsi_scsi_cmd_hdr *)(&((cmd)->pdu.bhs)))->scb[0] */
                DINFO("iscsi send %s:%d cmd record opcode:%x cmd:%x\n",
                                _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port),
                                cmd_opcode(cmd), req_hdr->scb[0]);
        }

        ret = cmd_tx_end(cmd);
        if (unlikely(ret))
                GOTO(out_close, ret);

        conn->write_cmd = NULL;
        conn->write_tio = NULL;
        conn->write_state = TX_INIT;
        ret = iscsi_cmd_release(cmd, 0);
        if (ret) {
                goto out_free;
        }

        ANALYSIS_END(4, 100 * 1000, NULL);

        return RET_DONE;
out_again:
        return RET_AGAIN;
out_close:
        return RET_CLOSE;
out_free:
        return RET_FREE;
}

static int iscsi_send(void *arg)
{
        int ret;
        struct iscsi_cmd *cmd;
        struct iscsi_conn *conn = arg;

        /**
         * 使用valgrind工具检测到list_empty(&conn->write_list)访问无效地址。
         * 原因如下：iscsid_send会调用协程，产生多个task来处理cmd，而在每个
         * task里面处理iscsi_send_one的时候，如果是最后一个cmd会释放conn，
         * 这就导致其他task执行的时候，发现conn已经被释放了，访问无效地址。
         **/
        if (conn == NULL)
                return 0;

out_again:
        while (1) {
                if (list_empty(&conn->write_list)) {
                        break;
                }
                /* Send one command */
                cmd = list_entry(conn->write_list.next, struct iscsi_cmd, entry);
                list_del_init(&cmd->entry);

                /*
                 * Send one command, if need next write, link it back
                 */

                ANALYSIS_BEGIN(0);
                ret = iscsi_send_one(cmd);
                ANALYSIS_END(0, 100 * 1000, NULL);
                switch (ret) {
                case RET_CLOSE:
                        goto out_close;
                case RET_AGAIN:
                        list_add(&cmd->entry, &conn->write_list);
                        goto out_again;
                case RET_DONE:
                        //break;
                        continue;
                case RET_FREE:
                        //break;
                        goto out;
                }
        }

out:
        return 0;
out_close:
        /* Just close the connection */
        DBUG("close point 4\n");
        conn->state = STATE_CLOSE;
        iscsi_cmd_release(cmd, 0);
        return ret;
}

int iscsi_connection_check(struct iscsi_conn *conn)
{
        int i, peer_port;
        fileid_t fileid[TARGET_MAX_LUNS];
        struct list_head *pos;
        struct iscsi_volume *lun;
        struct iscsi_target *target = conn->session->target;
        char addr[TARGET_MAX_LUNS];

        if (target) {
                memset(fileid, 0x0, sizeof(fileid));
                memset(addr, 0x0, sizeof(addr));

                list_for_each(pos, &target->volume_list) {
                        lun = (void *)pos;
                        fileid[lun->lun] = lun->fileid;
                        DBUG("fileid %llu idx %u\n", (LLU)lun->fileid.id, lun->lun);
                }

                peer_port = ntohs(conn->peer.sin_port);

                for (i = 0; i < TARGET_MAX_LUNS; i++) {
                        if (fileid[i].id == 0)
                                continue;

                        strcpy(addr, _inet_ntop((struct sockaddr *)&conn->peer));
                        DINFO("conn %p (%d) %s:%d connect to %s/%d "CHKID_FORMAT"\n",
                              conn, conn->state,
                              addr, peer_port, target->name, i, CHKID_ARG(&fileid[i]));

#if ENABLE_ISCSI_CONN_LIST
                        // TODO bug 11350
                        int ret;
                        if (conn->state == STATE_FULL) {
                                
                                ret = block_connect(target->pool, &fileid[i], addr, peer_port, "check");
                                if (unlikely(ret)) {
                                        GOTO(err_ret, ret);
                                }
                        }
#endif
                }
        }

        return 0;
#if ENABLE_ISCSI_CONN_LIST
err_ret:
        return ret;
#endif
}

#if ENABLE_ISCSI_VIP
int iscsi_check_vip(struct iscsi_conn *conn)
{
        int ret;

        if (conn->state == STATE_FULL) {
                ret = target_localize_confirm(conn->target);
                if (unlikely(ret)) {
                        GOTO(err_close, ret);
                }
        }

        return 0;
err_close:
        DINFO("connection %s:%d will be closed\n",
              _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));

        conn->state = STATE_CLOSE;
        YASSERT(ret == EREMCHG);

        corenet_tcp_close(&conn->sockid);

        return ret;
}
#endif

#if ENABLE_ISCSI_CACHE_REUSE
int  iscsi_session_check(struct iscsi_conn *conn)
{
        int ret, i, count;
        struct iscsi_target *target = conn->target;
        mcache_entry_t *entry;

        DBUG("session check\n");

        count = atomic_read(&target->nr_volumes);
        for (i = 0; i < count; i++) {
                if (target->volume_entrys[i] == NULL) {
                        DINFO(CHKID_FORMAT" not localized, need check\n", CHKID_ARG(&target->fileid));

                        ret = volume_ctl_get(&target->fileid, &entry);
                        if (unlikely(ret)) {
                                if (ret == EREMCHG) {
                                        DWARN(""CHKID_FORMAT" not localized\n", CHKID_ARG(&target->fileid));
                                } else {
                                        DWARN(""CHKID_FORMAT" check fail %u %s\n", CHKID_ARG(&target->fileid),
                                              ret, strerror(ret));
                                }
                        } else {
                                if (target->volume_entrys[i]) {
                                        volume_ctl_release(entry);
                                } else {
                                        target->volume_entrys[i] = entry;
                                }
                                DINFO(CHKID_FORMAT" localized\n", CHKID_ARG(&target->fileid));
                        }
                } else {
                        DINFO(CHKID_FORMAT" localize check\n", CHKID_ARG(&target->fileid));

                        ret = volume_ctl_get(&target->fileid, &entry);
                        if (unlikely(ret)) {
                                if (ret == EREMCHG) {
                                        DWARN("release "CHKID_FORMAT" localize\n", CHKID_ARG(&target->fileid));
                                        if (target->volume_entrys[i]) {
                                                volume_ctl_release(target->volume_entrys[i]);//release previous reference
                                                target->volume_entrys[i] = NULL;
                                        }
                                } else {
                                        DWARN(""CHKID_FORMAT" check fail %u %s\n", CHKID_ARG(&target->fileid),
                                              ret, strerror(ret));
                                }
                        } else {
                                YASSERT(target->volume_entrys[i] == entry);
                                volume_ctl_release(entry);
                                DINFO(CHKID_FORMAT" localized\n", CHKID_ARG(&target->fileid));
                        }
                }
        }

        return 0;
//err_ret:
//        return ret;
}
#endif

static void __iscsi_check__(void *arg)
{
        struct iscsi_conn *conn = arg;

#if ENABLE_ISCSI_CACHE_REUSE
        iscsi_session_check(conn);
#endif

        /* connection recored in volume_proto, if the volume_proto reload,then connections will not be correct */
        iscsi_connection_check(conn);

#if ENABLE_ISCSI_VIP
        if (ISCSI_CHECK && sanconf.iscsi_vip.vip_count && netvip_in_vipnet(conn->conn_fd)) {
                iscsi_check_vip(conn);
        }
#endif

        conn->in_check = 0;
        conn_busy_tryfree(conn);
}

static int __iscsi_newtask_core(void *ctx, void *buf, int *_count)
{
        int ret;
        struct iscsi_conn *conn = ctx;

        conn->buf = (buffer_t *)buf;
        while (conn->buf->len) {
                if (conn->state == STATE_CLOSE)
                        break;

                ret = iscsi_recv(conn);
                if (unlikely(ret))
                        break;
        }

        //XXX: fake data
        *_count = 1;

        return 0;
}

static void __iscsi_close__(void *arg)
{
        struct iscsi_conn *conn = arg;

        DINFO("connection release - initiator: %s, pool: %s, vol:"CHKID_FORMAT" logout.\n",
              _inet_ntop((struct sockaddr *)&conn->peer), conn->target->pool,
              CHKID_ARG(&conn->target->fileid));

#if ENABLE_ISCSI_CONN_LIST
        int ret = 0;
        /* why are we need this, connection already release in target_disconnect */
        ret = block_disconnect(conn->target->pool, &conn->target->fileid,
                               _inet_ntop((struct sockaddr *)&conn->peer),
                               ntohs(conn->peer.sin_port),
                               "close");
        if (unlikely(ret))
                DWARN("connection release failed[%d] !!!\n", ret);
#endif

        conn_close(conn);
}

static void __iscsi_close_core(void *arg)
{
        struct iscsi_conn *conn = arg;

        DINFO("connection %s:%d closed\n",
              _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));

        conn->state = STATE_CLOSE;
        schedule_task_new("iscsi_close", __iscsi_close__, conn, -1);
}

static void __iscsi_check_core(void *arg)
{
        struct iscsi_conn *conn;
        time_t now;

        conn = arg;
        now = gettime();

        DBUG("iscsi target check last %ld, now %ld\n", conn->target->confirm, now);
        if ((now - conn->target->confirm) % CONFIRM_INTERVAL && conn->in_check == 0) {
                conn->in_check = 1;
                schedule_task_new("iscsi_check", __iscsi_check__, conn, -1);
        }
}

void iscsid_recv_core(struct iscsi_conn *conn)
{
        int ret, hash;

        conn->sockid.sd = conn->conn_fd;
        conn->sockid.seq = _random();
        conn->sockid.type = SOCKID_CORENET;
        conn->sockid.addr = conn->peer.sin_addr.s_addr;

        hash = core_hash(&conn->target->fileid);

        /**
         * @brief 把iscsi连接纳入core的事件循环之中, 每条iscsi命令都由派生的task执行.
         *
         * __iscsi_newtask_core在scheduler里执行,不属于task,此时schedule.running_task == -1
         *
         * @see iscsid_exec
         */
        ret = core_attach(hash, &conn->sockid, "iscsi", conn,
                          __iscsi_newtask_core, __iscsi_close_core, __iscsi_check_core);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return;
err_ret:
        DINFO("connection %s:%d closed\n",
              _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));
        conn->state = STATE_CLOSE;
        return;
}

void iscsid_recv(struct iscsi_conn *conn)
{
        return iscsid_recv_core(conn);
}

static void iscsi_exec_task(void *arg)
{
        struct iscsi_cmd *cmd = arg;
        disk_execute_cmd(cmd);
}

int worker_thread_queue(struct iscsi_cmd *cmd)
{
        //conn_busy_get(cmd->conn);
        if (cmd->flags & CMD_FLG_TMF_ABORT) {
                //struct iscsi_conn *conn = cmd->conn;
                iscsi_cmd_release(cmd, 1);
                //conn_busy_put(conn);
        } else {
                iscsid_exec(cmd);
        }

        return 0;
}

void iscsid_exec(struct iscsi_cmd *cmd)
{
        schedule_task_new("iscsi_exec", iscsi_exec_task, cmd, -1);
}

static void iscsi_send_task(void *arg)
{
        struct iscsi_conn *conn = arg;
        (void) iscsi_send(conn);
}

void iscsid_send(struct iscsi_conn *conn)
{
        if (conn->login_state == STATE_FREE) {
                 (void) iscsi_send(conn);
        } else {
                 schedule_task_new("iscsi_send", iscsi_send_task, conn, -1);
        }
}

static int iscsi_close(va_list ap)
{
        struct iscsi_conn *conn = va_arg(ap, struct iscsi_conn *);
        va_end(ap);

        corenet_tcp_close(&conn->sockid);

        return 0;
}

void iscsid_close(struct iscsi_conn *conn)
{
        int ret;

        ret = core_request(core_hash(&conn->target->fileid), -1, "iscsid_close", iscsi_close, conn);
        if (unlikely(ret)) {
                UNIMPLEMENTED(__DUMP__);
        }
}

static void *__iscsi_accept_worker(void *_arg)
{
        struct iscsi_conn *conn = _arg;

        while (conn->login_state == STATE_FREE) {
                (void) iscsi_recv(conn);

                if (conn->state == STATE_CLOSE) {
                        close(conn->conn_fd);
                        conn_close(conn);
                        break;
                }

                if (conn->login_state == STATE_LOGIN) {
                        iscsid_recv(conn);
                        break;
                }
        }

        return NULL;
}

static int __iscsi_accept__(int fd)
{
        int ret, sd;
        struct sockaddr_in sin;
        socklen_t alen;
        struct iscsi_conn *conn;
        pthread_t th;
        pthread_attr_t ta;

        _memset(&sin, 0, sizeof(sin));
        alen = sizeof(struct sockaddr_in);

        sd = accept(fd, &sin, &alen);
        if (sd < 0 ) {
                ret = errno;
		        GOTO(err_ret, ret);
        }

        ret = tcp_sock_tuning(sd, 1, YNET_RPC_NONBLOCK);
        if (unlikely(ret))
                GOTO(err_close, ret);

        ret = conn_alloc(&conn);
        if (unlikely(ret))
                GOTO(err_close, ret);

        conn->conn_fd = sd;
        conn->login_state = STATE_FREE;
        memcpy(&conn->peer, &sin, sizeof(struct sockaddr_in));

        DINFO("connection %s:%d connected\n",
                        _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port));

        (void) pthread_attr_init(&ta);
        (void) pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);

        ret = pthread_create(&th, &ta, __iscsi_accept_worker, conn);
        if (unlikely(ret))
                GOTO(err_close, ret);

        return 0;
err_close:
        close(sd);
err_ret:
        return ret;
}

static void *__iscsi_accept(void *_arg)
{
        int ret;

        int fd =  *(int *)_arg;
        DINFO("start accept fd:%d...\n", fd);

        while (1) {
                ret = sock_poll_sd(fd, 1000 * 1000, POLLIN);
                if (unlikely(ret)) {
                        if (ret == ETIMEDOUT || ret == ETIME)
                                continue;
                        else
                                GOTO(err_ret, ret);
                 }

                ret = __iscsi_accept__(fd);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        return NULL;
err_ret:
        return NULL;
}

static void *__iscsi_service(void *_arg)
{
        int ret, retry = 0, *fd = &__listen_sd__, *fd6 = &__listen_sd6__;
        char port[MAXSIZE];

        (void) _arg;
        DINFO("start...\n");

        if(gloconf.rdma && !sanconf.tcp_discovery)
                goto skip_tcp;

        sprintf(port, "%d", sanconf.iscsi_port);
retry:
        ret = tcp_sock_hostlisten(fd, NULL, port,
                                  YNET_QLEN, YNET_RPC_BLOCK, 1);
        if (unlikely(ret)) {
                if (ret == EADDRINUSE) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 30, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        DINFO("iscsi service starting, port:%d fd:%d...\n", sanconf.iscsi_port, *fd);

#if ENABLE_ISCSI_IPV6
        sprintf(port, "%d", sanconf.iscsi_port);
retry6:
        ret = tcp_sock_hostlisten6(fd6, NULL, port,
                                  YNET_QLEN, YNET_RPC_BLOCK, 1);
        if (unlikely(ret)) {
                if (ret == EADDRINUSE) {
                        USLEEP_RETRY(err_ret, ret, retry6, retry, 30, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        DINFO("iscsi service starting, port:%d fd6:%d...\n", sanconf.iscsi_port, *fd);
#else
        (void) fd6;
#endif
        /*
        ret = target_preload_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        */

skip_tcp:

        ret = session_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = iscsi_cmd_hook_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        /*
        ret = mem_mcache_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        */

        retry = 0;
retry1:
        ret = cops->init();
        if (unlikely(ret)) {
                DERROR("init fail ret %d %s\n", ret, strerror(ret));
                USLEEP_RETRY(err_ret, ret, retry1, retry, 50, (100 * 1000));
        }

        if (!gloconf.rdma || sanconf.tcp_discovery) {
                ret = sy_thread_create(__iscsi_accept, fd);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                DINFO("iscsi service started, fd:%d...\n", *fd);

#if ENABLE_ISCSI_IPV6
                ret = sy_pthread_create(__iscsi_accept, fd6);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                DINFO("iscsi service started, fd6:%d...\n", *fd);
#endif
        }

        return NULL;
err_ret:
        exit(ret);
        //YASSERT(0);
        return NULL;
}

#if ENABLE_ISER
static void *__iser_service(void *_arg)
{
        int ret, fd;

        (void) _arg;

        if (!sanconf.iser)
                return NULL;

        ret = iser_init(sanconf.iscsi_port, &fd, NULL);
        if (ret)
                GOTO(err_ret, ret);
        DWARN("iser listen fd %d\n", fd);

        return NULL;
err_ret:
        EXIT(ret);
        return NULL;
}
#endif

int iscsid_srv(int driver)
{
        int ret;
        pthread_t th;
        pthread_attr_t ta;

        (void) pthread_attr_init(&ta);
        (void) pthread_attr_setdetachstate(&ta,PTHREAD_CREATE_DETACHED);

        YASSERT(driver & (ISCSID_DRIVER_TCP | ISCSID_DRIVER_ISER));

        if(driver & ISCSID_DRIVER_TCP)
                ret = pthread_create(&th, &ta, __iscsi_service, NULL);

#if ENABLE_ISER
        if(driver & ISCSID_DRIVER_ISER)
                ret = pthread_create(&th, &ta, __iser_service, NULL);
#endif

        if (unlikely(ret))
                GOTO(err_ret, ret);

#ifndef ENABLE_ISCSI_CACHE_REUSE
        DERROR("iscsi cache reuse disabled\n");
#endif

        return 0;
err_ret:
        return ret;
}
