#include <ctype.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

#define BUFFER_SIZE     16

/*
 * size required for a hex dump of BUFFER_SIZE bytes (' ' + 2 chars = 3 chars
 * per byte) with a ' |' separator each 4th byte:
 */
#define LINE_SIZE (BUFFER_SIZE * 3 + BUFFER_SIZE / 4 * 2 + 1)

static void __dump_line(unsigned char *buf, int *cp)
{
        char line[LINE_SIZE], *lp = line;
        int i, cnt;

        cnt = *cp;
        if (!cnt)
                goto out;

        for (i = 0; i < BUFFER_SIZE; ++i) {
                if (i < cnt)
                        lp += sprintf(lp, " %02x", buf[i]);
                else
                        lp += sprintf(lp, "   ");
                if ((i % 4) == 3)
                        lp += sprintf(lp, " |");
                if (i >= cnt || !isprint(buf[i]))
                        buf[i] = ' ';
        }

        /* `buf' is not zero-terminated! */
        DBUG("%s %.*s |\n", line, BUFFER_SIZE, buf);
        *cp = 0;
out:
        return;
}

static void __dump_char(unsigned char *buf, int *cp, int ch)
{
        int cnt = (*cp)++;

        buf[cnt] = ch;

        if (cnt == BUFFER_SIZE - 1)
                __dump_line(buf, cp);
}

#define dump_line() __dump_line(char_buf, &char_cnt)
#define dump_char(ch) __dump_char(char_buf, &char_cnt, ch)

void iscsi_dump_pdu(struct iscsi_pdu *pdu)
{
        unsigned char char_buf[BUFFER_SIZE];
        int char_cnt = 0;
        unsigned char *buf;
        u32 i;

        DBUG("---------- dump pdu ----------\n");

        buf = (void *)&pdu->bhs;
        DBUG("BHS: (%p, %u)\n", buf, (u32)sizeof(pdu->bhs));
        for (i = 0; i < sizeof(pdu->bhs); ++i)
                dump_char(*buf++);
        dump_line();

        buf = (void *)pdu->ahs;
        DBUG("AHS: (%p, %u)\n", buf, (u32)pdu->ahssize);
        for (i = 0; i < pdu->ahssize; ++i)
                dump_char(*buf++);
        dump_line();

        DBUG("DATA: (%d)\n", pdu->datasize);
}

void iscsi_dump_pdu_list(struct iscsi_cmd *req)
{
        struct iscsi_cmd *cmd;

        DBUG("---------- dump pdu list ----------\n");
        DBUG("req: %p\n", req);
        list_for_each_entry(cmd, &req->rsp_list, rsp_list) {
                DBUG("rsp: %p, opcode: %x\n", cmd, cmd_opcode(cmd));
        }
}

void iscsi_dump_tio(struct iscsi_tio *tio)
{
        int i, j, iovcnt;
        struct iovec *iov;
        char buf[MAX_BUF_LEN];
        unsigned char char_buf[BUFFER_SIZE];
        int char_cnt = 0;

        DBUG("---------- dump tio ----------\n");
        DBUG("tio: %p\n", tio);
        if (!tio)
                goto out;

        DBUG("buffer.len: %u\n", (u32)tio->buffer.len);
        DBUG("io_off: %u\n", (u32)tio->io_off);
        DBUG("io_len: %u\n", (u32)tio->io_len);
        DBUG("count: %u\n", tio->count);

        iov = (void *)buf;
        mbuffer_trans2(iov, &iovcnt, 0, tio->buffer.len, &tio->buffer);

        for (i = 0; i < iovcnt; ++i) {
                for (j = 0; j < (int)iov[i].iov_len; ++j) {
                        dump_char(((char *)(iov[i].iov_base))[j]);
                }
                dump_line();
        }
out:
        return;
}

void iscsi_dump_ua(struct ua_entry *ua, struct iscsi_session *sess, u32 lun)
{
        if (!ua || !sess)
                goto out;

        DBUG("---------- dump ua ------------\n");
        DBUG("sess: %lX, lun: %u, ua: %p\n", sess->sid.id64, lun, ua);
        DBUG("asc:  %u, ascq: %u\n", ua ? ua->asc : 0, ua ? ua->ascq : 0);
out:
        return;
}

void iscsi_dump_session_param(struct iscsi_sess_param *param)
{
#define PARAM_DUMP(mem) DBUG("%30s : %u\n", #mem, mem);

        DBUG("---------- dump session param ----------\n");
	PARAM_DUMP(param->initial_r2t);
	PARAM_DUMP(param->immediate_data);
	PARAM_DUMP(param->max_connections);
	PARAM_DUMP(param->max_recv_data_length);
	PARAM_DUMP(param->max_xmit_data_length);
	PARAM_DUMP(param->max_burst_length);
	PARAM_DUMP(param->first_burst_length);
	PARAM_DUMP(param->default_wait_time);
	PARAM_DUMP(param->default_retain_time);
	PARAM_DUMP(param->max_outstanding_r2t);
	PARAM_DUMP(param->data_pdu_inorder);
	PARAM_DUMP(param->data_sequence_inorder);
	PARAM_DUMP(param->error_recovery_level);
	PARAM_DUMP(param->header_digest);
	PARAM_DUMP(param->data_digest);
	PARAM_DUMP(param->ofmarker);
	PARAM_DUMP(param->ifmarker);
	PARAM_DUMP(param->ofmarkint);
	PARAM_DUMP(param->ifmarkint);
#undef PARAM_DUMP
}
