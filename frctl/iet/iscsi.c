#include <stdlib.h>
#include <netinet/tcp.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

/*
 * LUN
 */

u32 translate_lun(u16 *data)
{
        u8 *p = (u8 *)data;
        u32 lun = ~0U;

        switch (*p >> 6) {
        case 0:
                lun = p[1];
                break;
        case 1:
                lun = (0x3f & p[0]) << 8 | p[1];
                break;
        case 2:
        case 3:
        default:
                DERROR("%u %u %u %u\n", data[0], data[1], data[2], data[3]);
                break;
        }

        return lun;
}

/*
 * Command
 */

/*
 * iscsi_cmd_alloc - Create a command
 *
 * @conn: connection pointer
 * @req: no zero if this is a request command, elsewise zero.
 *
 * @return the command pointer on success, otherwise NULL.
 */
struct iscsi_cmd *iscsi_cmd_alloc(struct iscsi_conn *conn, int req)
{
        struct iscsi_cmd *cmd;

#if ENABLE_ISCSI_MEM
        cmd = iscsi_mem_mcache_calloc(conn->mem_cache[ISCSI_MEM_CACHE_CMD],
                                     MC_FLAG_NOFAIL);
#else
        cmd = mem_cache_calloc1(MEM_CACHE_4K, 1);
        memset(cmd, 0x0, sizeof(*cmd));
        static_assert(sizeof(*cmd) < 4096, "cmd");
#endif

        INIT_LIST_HEAD(&cmd->entry);
        INIT_LIST_HEAD(&cmd->conn_entry);
        INIT_LIST_HEAD(&cmd->rsp_list);
        INIT_LIST_HEAD(&cmd->hash_entry);

        cmd->time = conn->ltime;
        cmd->conn = conn;
        //atomic_inc(&conn->nr_cmds);
        conn_busy_get(conn);
        if (req) {
                /* Only request command is linked to @cmd_list of connection.
                 */
                list_add_tail(&cmd->conn_entry, &conn->cmd_list);
        }

        return cmd;
}

static void iscsi_device_queue_cmd(struct iscsi_cmd *cmd)
{
        cmd->flags |= CMD_FLG_WAITIO;
        worker_thread_queue(cmd);
}

static void iscsi_cmd_scsi_dequeue(struct iscsi_cmd *cmd)
{
        struct iscsi_queue *queue;

        if (!cmd->lun)
                goto out;

        queue = &cmd->lun->queue;

        switch (cmd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
        case ISCSI_CMD_UNTAGGED:
        case ISCSI_CMD_SIMPLE:
                --queue->active_cnt;
                break;
        case ISCSI_CMD_ORDERED:
        case ISCSI_CMD_HEAD_OF_QUEUE:
        case ISCSI_CMD_ACA:
                UNIMPLEMENTED(__DUMP__);
        default:
                /* Should the iscsi_scsi_queuecmd func reject this ? */
                break;
        }

        while (!list_empty(&queue->wait_list)) {
                cmd = list_entry(queue->wait_list.next, struct iscsi_cmd, entry);
                switch (cmd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
                case ISCSI_CMD_UNTAGGED:
                case ISCSI_CMD_SIMPLE:
                        list_del_init(&cmd->entry);
                        queue->active_cnt++;
                        iscsi_device_queue_cmd(cmd);
                        break;
                case ISCSI_CMD_ORDERED:
                case ISCSI_CMD_HEAD_OF_QUEUE:
                case ISCSI_CMD_ACA:
                        UNIMPLEMENTED(__DUMP__);
                }
        }

out:
        return;
}

int iscsi_cmd_release(struct iscsi_cmd *cmd, int force)
{
        int ret;
        struct iscsi_cmd *req, *rsp;
        int is_last = 0;

        ANALYSIS_BEGIN(0);

        if (!cmd)
                goto out;

        req = cmd->req;

        /*
         * If the `final' flag is set, this is the last response message, in this
         * case we should release the request message too.
         */
        is_last = (cmd->flags & CMD_FLG_FINAL);

        if (force) {
                while (!list_empty(&cmd->rsp_list)) {
                        rsp = list_entry(cmd->rsp_list.next, struct iscsi_cmd, rsp_list);
                        list_del_init(&rsp->entry);
                        list_del_init(&rsp->rsp_list);
                        ret = iscsi_cmd_remove(rsp);
                        if (ret)
                                GOTO(err_ret, ret);
                }
                list_del_init(&cmd->entry);
        } else
                if (cmd->flags & CMD_FLG_QUEUED)
                        iscsi_cmd_scsi_dequeue(cmd);

        if (cmd->flags & CMD_FLG_HASHED)
                iscsi_cmd_remove_hash(cmd);

        if (cmd->flags & CMD_FLG_LUNIT) {
                YASSERT(cmd->lun);
                volume_put(cmd->lun);
        }

        list_del_init(&cmd->rsp_list);
        ret = iscsi_cmd_remove(cmd);
        if (ret)
                GOTO(err_ret, ret);

        if (is_last) {
                YASSERT(!force);
                YASSERT(req);
                ret = iscsi_cmd_release(req, 0);
                if (ret)
                        GOTO(err_ret, ret);
        }

        ANALYSIS_END(0, IO_WARN, NULL);
out:
        return 0;
err_ret:
        return ret;
}

int iscsi_cmd_remove(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn;

        if (!cmd)
                goto out;

        ANALYSIS_BEGIN(0);

        conn = cmd->conn;

        if (cmd->pdu.ahs) {
                free(cmd->pdu.ahs);
                cmd->pdu.ahs = NULL;
        }

        if (!list_empty(&cmd->entry)) {
                DERROR("cmd %p still on some list?\n", cmd);
                UNIMPLEMENTED(__DUMP__);
        }

        list_del_init(&cmd->entry);
        //atomic_dec(&conn->nr_cmds);
        list_del_init(&cmd->conn_entry);

        if (cmd->tio)
                tio_put(cmd->conn, cmd);

        ANALYSIS_END(0, IO_WARN, NULL);

#if ENABLE_ISCSI_MEM
        iscsi_mem_mcache_free(conn->mem_cache[ISCSI_MEM_CACHE_CMD], cmd);
#else
        mem_cache_free(MEM_CACHE_4K, cmd);
#endif
        return conn_busy_put(conn);
out:
        return 0;
}

int iscsi_cmd_check_sn(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_session *sess = conn->session;
        u32 cmd_sn, exp_cmd_sn, max_cmd_sn;

        exp_cmd_sn = sess ? sess->exp_cmd_sn : conn->exp_cmd_sn;
        max_cmd_sn = sess ? sess->max_cmd_sn : conn->max_cmd_sn;

        cmd->pdu.bhs.sn = cmd_sn = be32_to_cpu(cmd->pdu.bhs.sn);

        if (between(cmd_sn, exp_cmd_sn, max_cmd_sn))
                ret = 0;
        else if (cmd->pdu.bhs.flags & ISCSI_OP_IMMEDIATE)
                ret = 0;
        else {
                DWARN("sequence error: cmd_sn(%u), exp_cmd_sn(%u), max_cmd_sn(%u)\n",
                      cmd_sn, exp_cmd_sn, max_cmd_sn);

                cmd->flags |= CMD_FLG_TMF_ABORT;

#if 1
                cmd->conn->state = STATE_CLOSE;
#endif

                ret = ISCSI_REASON_PROTOCOL_ERROR;
        }

        return ret;
}

void iscsi_cmd_set_sn(struct iscsi_cmd *cmd, int set_stat_sn)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_session *sess = conn->session;

        if (set_stat_sn)
                cmd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn++);

        if (sess) {
                sess->max_cmd_sn = sess->exp_cmd_sn + sess->max_queued_cmds;
                cmd->pdu.bhs.exp_sn = cpu_to_be32(sess->exp_cmd_sn);
                cmd->pdu.bhs.max_sn = cpu_to_be32(sess->max_cmd_sn);
        }
}

static struct iscsi_cmd *__iscsi_cmd_find_hash(struct iscsi_session *sess, u32 itt, u32 ttt)
{
        struct list_head *head;
        struct iscsi_cmd *cmd;

        head = &sess->cmd_hash[cmd_hashfn(itt)];

        list_for_each_entry(cmd, head, hash_entry) {
                if (cmd->pdu.bhs.itt == itt) {
                        if ((ttt != ISCSI_RESERVED_TAG) && (ttt != cmd->target_task_tag))
                                continue;
                        goto found;
                }
        }
        return NULL;
found:
        return cmd;
}

struct iscsi_cmd *iscsi_cmd_find_hash(struct iscsi_session *sess, u32 itt, u32 ttt)
{
        struct iscsi_cmd *cmd;

        cmd = __iscsi_cmd_find_hash(sess, itt, ttt);

        return cmd;
}

static int iscsi_cmd_insert_hash_ttt(struct iscsi_cmd *cmd, u32 ttt)
{
        int ret = 0;
        struct iscsi_session *sess = cmd->conn->session;
        struct iscsi_cmd *tmp;
        struct list_head *head;
        u32 itt = cmd->pdu.bhs.itt;

        head = &sess->cmd_hash[cmd_hashfn(itt)];

        tmp = __iscsi_cmd_find_hash(sess, itt, ttt);
        if (!tmp) {
                list_add_tail(&cmd->hash_entry, head);
                cmd->flags |= CMD_FLG_HASHED;
        } else
                ret = ISCSI_REASON_TASK_IN_PROGRESS;

        return ret;
}

int iscsi_cmd_insert_hash(struct iscsi_cmd *cmd)
{
        int ret;

        if (cmd->pdu.bhs.itt == ISCSI_RESERVED_TAG) {
                ret = ISCSI_REASON_PROTOCOL_ERROR;
                goto out;
        }

        ret = iscsi_cmd_insert_hash_ttt(cmd, ISCSI_RESERVED_TAG);
        if (!ret) {
                ret = iscsi_cmd_check_sn(cmd);
                if (!ret)
                        conn_update_stat_sn(cmd);
        } else if (!(cmd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE))
                cmd->flags |= CMD_FLG_TMF_ABORT;

out:
        return ret;
}

static void __iscsi_cmd_remove_hash(struct iscsi_cmd *cmd)
{
        list_del_init(&cmd->hash_entry);
}

void iscsi_cmd_remove_hash(struct iscsi_cmd *cmd)
{
        struct iscsi_session *session = cmd->conn->session;
        struct iscsi_cmd *tmp;

        tmp = __iscsi_cmd_find_hash(session, cmd->pdu.bhs.itt,
                              cmd->target_task_tag);
        if (tmp && tmp == cmd)
                __iscsi_cmd_remove_hash(tmp);
        else
                DERROR("%p: not found\n", cmd);
}

/*
 * iscsi_cmd_list_init_write - send command
 *
 * @send: list of response commands to send
 *
 * Remove each response command in the @send list, and link them to the
 * connection's @write_list, then set the IO Event.
 */
void iscsi_cmd_list_init_write(struct list_head *send)
{
        int ret;
        struct iscsi_cmd *cmd = list_entry(send->next, struct iscsi_cmd, entry);
        struct iscsi_conn *conn = cmd->conn;
        struct list_head *pos, *next;
        struct epoll_event ev;

        list_for_each_safe(pos, next, send) {
                cmd = list_entry(pos, struct iscsi_cmd, entry);
                list_del_init(&cmd->entry);
                list_add_tail(&cmd->entry, &conn->write_list);
        }

        if (conn->waiting_free) {
                /*
                 * If the @conn_close has been called to this connection, the
                 * @epoll_ctl must not be called here, also the connection
                 * is deleted from epoll in @conn_close. otherwise, @epoll_ctl
                 * here may not return an error, and then @epoll_wait may still
                 * repo some epoll event of this connection.
                 */

                /* for connet close in iscsi_check_vip */
                iscsid_send(conn);
        } else {
                (void) ev;
                (void) ret;
                iscsid_send(conn);
                /*
                conn->ev |= EPOLLOUT;
                ev.events = conn->ev;
                ev.data.ptr = conn;

                ret = epoll_ctl(conn->efd, EPOLL_CTL_MOD, conn->conn_fd, &ev);
                if (unlikely(ret)) {
                        ret = errno;
                        DERROR("epoll_ctl error %d:%s\n", ret, strerror(ret));
                }
                */
        }
}

void iscsi_cmd_init_write(struct iscsi_cmd *cmd)
{
        LIST_HEAD(send_list);

        list_add(&cmd->entry, &send_list);
        iscsi_cmd_list_init_write(&send_list);
}

/*
 * See Table-41/42 in chapter 4.5.6 of the SPC-3 (SCSI Primary Commands - 3)
 * for detail.
 */
void iscsi_cmd_set_sense(struct iscsi_cmd *cmd, u8 sense_key, u8 asc, u8 ascq)
{	
        cmd->status = SAM_STAT_CHECK_CONDITION;

        cmd->sense_buf[0] = 0xf0;
        cmd->sense_buf[2] = sense_key;
        cmd->sense_buf[7] = 6;  /* Additional sense length */
        cmd->sense_buf[12] = asc;
        cmd->sense_buf[13] = ascq;

        cmd->sense_len = ISCSI_SENSE_BUF_SIZE;
}

void iscsi_cmd_skip_pdu(struct iscsi_cmd *cmd)
{
        int i, count;
        struct iscsi_conn *conn = cmd->conn;
        char *addr, buf[MAX_BUF_LEN];
        struct iovec *iov;
        u32 size;

        if (!(size = cmd->pdu.datasize))
                goto out;

        if (!cmd->tio) {
                cmd->tio = tio_alloc(conn, PAGE_SIZE);
        }

        iov = (void *)buf;
        mbuffer_trans2(iov, &count, 0, cmd->tio->buffer.len, &cmd->tio->buffer);
        YASSERT(count);

        /*
         * Pointe all iovec to the same tio buffer
         */
        addr = iov[0].iov_base;
        size = iscsi_cmd_size_align(size);
        conn->read_size = size;

        for (i = 0; size > iov[0].iov_len; ++i, size -= iov[0].iov_len) {
                YASSERT(i < ISCSI_CONN_IOV_MAX);
                conn->read_iov[i].iov_base = addr;
                conn->read_iov[i].iov_len = iov[0].iov_len;
        }
        conn->read_iov[i].iov_base = addr;
        conn->read_iov[i].iov_len = size;
        conn->read_msg.msg_iov = conn->read_iov;
        conn->read_msg.msg_iovlen = ++i;
out:
        return;
}

/*
 * NOTE: Should only be called in the command's @rx_start function
 */
void iscsi_cmd_reject(struct iscsi_cmd *req, int reason)
{
        struct iscsi_cmd *rsp;
        struct iscsi_reject_hdr *rsp_hdr;

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);

        rsp_hdr = (struct iscsi_reject_hdr *)&rsp->pdu.bhs;
        rsp_hdr->opcode = ISCSI_OP_REJECT;
        rsp_hdr->ffffffff = ISCSI_RESERVED_TAG;
        rsp_hdr->reason = reason;

        /* Used the request command header as data */
        rsp->tio = tio_alloc(req->conn, 0);
        mbuffer_appendmem(&rsp->tio->buffer, &req->pdu.bhs, sizeof(req->pdu.bhs));
        rsp->pdu.datasize = sizeof(req->pdu.bhs);

        iscsi_cmd_skip_pdu(req);

        /* Set the request's opcode to a dummy vendor opcode to fit the message
         * process flow.
         */
        req->pdu.bhs.opcode = ISCSI_OP_PDU_REJECT;
}

void iscsi_cmd_set_length(struct iscsi_pdu *pdu)
{
        pdu->bhs.ahssize = pdu->ahssize / 4;
        hton24(pdu->bhs.datasize, pdu->datasize);
}

void iscsi_cmd_get_length(struct iscsi_pdu *pdu)
{
        pdu->ahssize = pdu->bhs.ahssize * 4;
        pdu->datasize = ntoh24(pdu->bhs.datasize);
}

u32 iscsi_cmd_write_size(struct iscsi_cmd *cmd)
{
        u32 ret = 0;
        struct iscsi_scsi_cmd_hdr *hdr = cmd_scsi_hdr(cmd);

        if (hdr->flags & ISCSI_CMD_WRITE)
                ret = be32_to_cpu(hdr->data_length);
        return ret;
}

void iscsi_cmd_alloc_data_tio(struct iscsi_cmd *cmd)
{
        int count;
        u32 size;
        struct iscsi_conn *conn = cmd->conn;

        if ((size = cmd->pdu.datasize)) {
                size = iscsi_cmd_size_align(size);
                conn->read_msg.msg_iov = conn->read_iov;
                cmd->tio = tio_alloc(conn, size);
                mbuffer_trans2(conn->read_iov, &count, 0, cmd->tio->buffer.len, &cmd->tio->buffer);
                conn->read_overflow = 0;
                conn->read_size = size;
                conn->read_msg.msg_iovlen = count;
        }
}

u32 iscsi_cmd_read_size(struct iscsi_cmd *cmd)
{
        u32 size = 0;
        struct iscsi_scsi_cmd_hdr *hdr = cmd_scsi_hdr(cmd);

        if (hdr->flags & ISCSI_CMD_READ) {
                struct iscsi_rlength_ahdr *ahdr =
                        (struct iscsi_rlength_ahdr *)cmd->pdu.ahs;

                if (!(hdr->flags & ISCSI_CMD_WRITE)) {
                        size = be32_to_cpu(hdr->data_length);
                        goto out;
                }
                if (ahdr && ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH) {
                        size = be32_to_cpu(ahdr->read_length);
                        goto out;
                }
        }

out:
        return size;
}

struct iscsi_cmd *iscsi_cmd_create_rsp_cmd(struct iscsi_cmd *cmd, int final)
{
        struct iscsi_cmd *rsp;

        rsp = iscsi_cmd_alloc(cmd->conn, 0);

        if (final)
                rsp->flags |= CMD_FLG_FINAL;

        list_add_tail(&rsp->rsp_list, &cmd->rsp_list);
        rsp->req = cmd;

        return rsp;
}

inline struct iscsi_cmd *iscsi_cmd_get_rsp_cmd(struct iscsi_cmd *req)
{
        return list_entry(req->rsp_list.prev, struct iscsi_cmd, rsp_list);
}

int iscsi_cmd_recv_pdu(struct iscsi_conn *conn, struct iscsi_tio *tio, u32 offset, u32 size)
{
        int ret, count;

        if (!size)
                goto out;

        if ((offset >= tio->buffer.len) || (offset + size > tio->buffer.len)) {
                DERROR("%u %u %u", offset, size, tio->buffer.len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        conn->read_msg.msg_iov = conn->read_iov;
        conn->read_size = size = iscsi_cmd_size_align(size);
        conn->read_overflow = 0;

        mbuffer_trans2(conn->read_iov, &count, offset, size, &tio->buffer);
        conn->read_msg.msg_iovlen = count;

out:
        return 0;
err_ret:
        return ret;
}

void iscsi_cmd_send_pdu_tio(struct iscsi_conn *conn, struct iscsi_tio *tio, u32 offset, u32 size)
{
        YASSERT(offset <= tio->buffer.len);
        YASSERT(offset + size <= tio->buffer.len);

        conn->write_tio = tio;
        conn->write_tio_off = offset;
        conn->write_tio_size = size;
}

void iscsi_cmd_send_pdu(struct iscsi_conn *conn, struct iscsi_cmd *cmd)
{
        u32 size;
        struct iscsi_tio *tio = cmd->tio;

        if (!cmd->pdu.datasize)
                goto out;

        size = iscsi_cmd_size_align(cmd->pdu.datasize);
        if (size != tio->buffer.len) {
                YASSERT(tio->buffer.len < size);
                mbuffer_appendzero(&tio->buffer, size - tio->buffer.len);
        }

        iscsi_cmd_send_pdu_tio(conn, tio, 0, size);
out:
        return;
}

static void send_r2t(struct iscsi_cmd *req)
{
        struct iscsi_sess_param *param = &req->conn->session->param;
        struct iscsi_cmd *rsp;
        struct iscsi_r2t_hdr *rsp_hdr;
        u32 offset, burst;
        LIST_HEAD(send);

        if (req->outstanding_r2t >= param->max_outstanding_r2t)
                goto out;

        burst = param->max_burst_length;
        offset = iscsi_cmd_write_size(req) - req->r2t_length;

        while (req->r2t_length) {
                rsp = iscsi_cmd_create_rsp_cmd(req, 0);
                rsp->pdu.bhs.ttt = req->target_task_tag;

                rsp_hdr = (struct iscsi_r2t_hdr *)&rsp->pdu.bhs;
                rsp_hdr->opcode = ISCSI_OP_R2T;
                rsp_hdr->flags = ISCSI_FLG_FINAL;
                memcpy(rsp_hdr->lun, cmd_scsi_hdr(req)->lun, 8);
                rsp_hdr->itt = cmd_scsi_hdr(req)->itt;
                rsp_hdr->r2t_sn = cpu_to_be32(req->r2t_sn++);
                rsp_hdr->buffer_offset = cpu_to_be32(offset);

                if (req->r2t_length > burst) {
                        rsp_hdr->data_length = cpu_to_be32(burst);
                        req->r2t_length -= burst;
                        offset += burst;
                } else {
                        rsp_hdr->data_length = cpu_to_be32(req->r2t_length);
                        req->r2t_length = 0;
                }

                list_add_tail(&rsp->entry, &send);

                if (++req->outstanding_r2t > param->max_outstanding_r2t)
                        break;
        }

        if (!list_empty(&send))
                iscsi_cmd_list_init_write(&send);
out:
        return;
}

/**
 * iscsi_session_push_cmd -
 *
 * Push the command for execution.
 * This functions reorders the commands.
 *
 * @cmd: ptr to command
 */
void iscsi_session_push_cmd(struct iscsi_cmd *cmd)
{
        struct iscsi_session *sess = cmd->conn->session;
        struct list_head *entry;
        u32 cmd_sn;

        if (cmd->r2t_length) {
                /*
                 * SCSI Command are wait for Data-Out PDU. Send R2T PDU if need.
                 */
                if (!cmd->is_unsolicited_data)
                        send_r2t(cmd);
                goto out;
        }

        if (cmd->outstanding_r2t) {
                /*
                 * Slice of Solicited Data-Out PDU is received, wait for others.
                 */
                goto out;
        }

        /*
         * For Immediate PDU, execute it directly and don't advance the session's
         * ExpCmdSN
         */
        if (cmd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
                iscsi_cmd_hook_get(cmd_opcode(cmd))->cmd_exec(cmd);
                goto out;
        }

        cmd_sn = cmd->pdu.bhs.sn;

        /*
         * The target Must silently ignore any non-immediate command outside of
         * range of exp_cmd_sn and max_cmd_sn or non-immediate duplicates within
         * the range - RFC3720
         */
        if (cmd_sn == sess->exp_cmd_sn) {
                while (1) {
                        sess->exp_cmd_sn = ++cmd_sn;
                        iscsi_cmd_hook_get(cmd_opcode(cmd))->cmd_exec(cmd);

                        if (list_empty(&sess->pending_list))
                                break;

                        cmd = list_entry(sess->pending_list.next, struct iscsi_cmd, entry);
                        if (cmd->pdu.bhs.sn != cmd_sn)
                                break;

                        list_del_init(&cmd->entry);
                        cmd->flags &= ~CMD_FLG_PENDING;
                }
        } else {
                cmd->flags |= CMD_FLG_PENDING;

                /* Insert command to list, from small to big */
                list_for_each(entry, &sess->pending_list) {
                        struct iscsi_cmd *tmp = list_entry(entry, struct iscsi_cmd, entry);
                        if (before(cmd_sn, tmp->pdu.bhs.sn))
                                break;
                }

                YASSERT(list_empty(&cmd->entry));

                list_add_tail(&cmd->entry, entry);
        }
out:
        return;
}

/*
 * RX/TX
 */

static void set_cork(int fd, int on)
{
        /*
         * Set TCP_CORK option, this let tcp dont' send out partial frames, all
         * queued partial frames are send when the option is cleared again.
         */
        int opt = on;
        (void) setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static int check_segment_length(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_session *sess = conn->session;
        u32 max_sz = sess ? sess->param.max_recv_data_length : PAGE_SIZE;

        if (cmd->pdu.datasize > max_sz) {
                DERROR("data too long: %u, %u\n",
                       cmd->pdu.datasize, max_sz);
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

inline int cmd_rx_start(struct iscsi_cmd *cmd)
{
        int ret;

        cmd->flags |= CMD_FLG_RX_START;

        ret = check_segment_length(cmd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = iscsi_cmd_hook_get(cmd_opcode(cmd))->rx_start(cmd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

inline int cmd_rx_end(struct iscsi_cmd *cmd)
{
        int ret = iscsi_cmd_hook_get(cmd_opcode(cmd))->rx_end(cmd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int cmd_tx_start(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;

        iscsi_cmd_set_length(&cmd->pdu);

        set_cork(conn->conn_fd, 1);

        ret = iscsi_cmd_hook_get(cmd_opcode(cmd))->tx_start(cmd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int cmd_tx_end(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_session *sess = conn->session;

        ret = iscsi_cmd_hook_get(cmd_opcode(cmd))->tx_end(cmd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (cmd->flags & CMD_FLG_CLOSE) {
                DBUG("close point 5\n");
                conn->state = STATE_CLOSE;
        } else if (cmd->flags & CMD_FLG_CLOSE_SESSION) {
                if (sess) {
                        pthread_spin_lock(&sess->conn_lock);
                        list_for_each_entry(conn, &sess->conn_list, entry) {
                                DBUG("close point 6\n");
                                conn->state = STATE_CLOSE;
                        }
                        pthread_spin_unlock(&sess->conn_lock);
                }
        }

        list_del_init(&cmd->entry);
        set_cork(cmd->conn->conn_fd, 0);

        return 0;
err_ret:
        return ret;
}
