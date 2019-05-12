/*
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 *
 * heavily based on code from kernel/iscsi.c:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 */

#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "job_dock.h"
#include "iscsi.h"
#include "dbg.h"
#include "schedule.h"

#define TRACKER_SCSI_SUBNAME    0

#if TRACKER_SCSI_SUBNAME
# define TRACKER_SET_NAME(cmd, name) \
        do { \
                if ((cmd)->tracker.job) { \
                        job_setname((cmd)->tracker.job, (name));      \
                        job_timermark((cmd)->tracker.job, "execute"); \
                        (cmd)->tracker.name_inited = 1; \
                } \
        } while (0)
#else
# define TRACKER_SET_NAME(cmd, name)
#endif

static int insert_disconnect_pg(u8 *ptr)
{
        u8 disconnect_pg[] = {
                0x02, 0x0e, 0x80, 0x80, 0x00, 0x0a, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        memcpy(ptr, disconnect_pg, sizeof(disconnect_pg));
        return sizeof(disconnect_pg);
}

static int insert_caching_pg(u8 *ptr, int wcache, int rcache)
{
        u8 caching_pg[] = {
                0x08, 0x12, 0x10, 0x00, 0xff, 0xff, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
        };

        memcpy(ptr, caching_pg, sizeof(caching_pg));

        if (wcache)
                ptr[2] |= 0x04; /* Set WCE bit if we're caching writes */
        if (!rcache)
                ptr[2] |= 0x01; /* Read Cache Disable */

        return sizeof(caching_pg);
}

static int insert_ctrl_m_pg(u8 *ptr)
{
        u8 ctrl_m_pg[] = {
                0x0a, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x4b,
        };

        memcpy(ptr, ctrl_m_pg, sizeof(ctrl_m_pg));
        return sizeof(ctrl_m_pg);
}

static int insert_iec_m_pg(u8 *ptr)
{
        u8 iec_m_pg[] = {
                0x1c, 0x0a, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
        };

        memcpy(ptr, iec_m_pg, sizeof(iec_m_pg));
        return sizeof(iec_m_pg);
}

static int insert_format_m_pg(u8 *ptr, u32 sector_size)
{
        u8 format_m_pg[] = {
                0x03, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
        };

        memcpy(ptr, format_m_pg, sizeof(format_m_pg));
        ptr[12] = (sector_size >> 8) & 0xff;
        ptr[13] = (sector_size) & 0xff;
        return sizeof(format_m_pg);
}

static int insert_geo_m_pg(u8 *ptr, u64 sec)
{
        u8 geo_m_pg[] = {
                0x04, 0x16, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x3a, 0x98, 0x00, 0x00,
        };
        u32 ncyl;
        u32 n;

        /* Assume 0xff heads, 15krpm */
        memcpy(ptr, geo_m_pg, sizeof(geo_m_pg));
        ncyl = sec >> 14; /* 256 * 64 */
        memcpy(&n, ptr + 1, sizeof(u32));
        n = n | cpu_to_be32(ncyl);
        memcpy(ptr + 1, &n, sizeof(u32));
        return sizeof(geo_m_pg);
}

struct iscsi_cmd *create_scsi_rsp(struct iscsi_cmd *req)
{
        struct iscsi_cmd *rsp;
        struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(req);
        struct iscsi_scsi_rsp_hdr *rsp_hdr;

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);

        rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
        rsp_hdr->opcode = ISCSI_OP_SCSI_RSP;
        rsp_hdr->flags = ISCSI_FLG_FINAL;
        rsp_hdr->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
        rsp_hdr->cmd_status = req->status;
        rsp_hdr->itt = req_hdr->itt;

        /* Sense key is set ! */
        if (req->status == SAM_STAT_CHECK_CONDITION) {
                char buf[MAX_BUF_LEN];
                struct iscsi_sense_data *sense;

                rsp->tio = tio_alloc(req->conn, 0);

                memset(buf, 0x0, sizeof(buf));
                sense = (void *)buf;
                sense->length = cpu_to_be16(ISCSI_SENSE_BUF_SIZE);
                memcpy(sense->data, req->sense_buf, ISCSI_SENSE_BUF_SIZE);

                rsp->pdu.datasize = sizeof(struct iscsi_sense_data) + ISCSI_SENSE_BUF_SIZE;
                mbuffer_appendmem(&rsp->tio->buffer, buf, iscsi_cmd_size_align(rsp->pdu.datasize));
        }

        return rsp;
}

static void send_scsi_rsp(struct iscsi_cmd *req, void (*func)(struct iscsi_cmd *))
{
        struct iscsi_cmd *rsp;
        struct iscsi_scsi_rsp_hdr *rsp_hdr;
        u32 size;

        func(req);
        rsp = create_scsi_rsp(req);

        switch (req->status) {
        case SAM_STAT_GOOD:
        case SAM_STAT_RESERVATION_CONFLICT:
                rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
                if ((size = iscsi_cmd_read_size(req)) != 0) {
                        rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
                        rsp_hdr->residual_count = cpu_to_be32(size);
                }
                break;
        default:
                break;
        }

        iscsi_cmd_init_write(rsp);
}

static void do_send_data_rsp(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_cmd *data_cmd;
        struct iscsi_tio *tio = cmd->tio;
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        struct iscsi_data_in_hdr *rsp;
        u32 pdusize, expsize, scsisize, size, offset, sn;
        LIST_HEAD(send);

        pdusize = conn->session->param.max_xmit_data_length;
        expsize = iscsi_cmd_read_size(cmd);
        size = min(expsize, (u32)tio->buffer.len);
        offset = 0;
        sn = 0;

        while (1) {
                data_cmd = iscsi_cmd_create_rsp_cmd(cmd, size <= pdusize);
                tio_get(tio);
                data_cmd->tio = tio;

                rsp = (struct iscsi_data_in_hdr *)&data_cmd->pdu.bhs;
                rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
                rsp->itt = req->itt;
                rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
                rsp->buffer_offset = offset;
                rsp->data_sn = cpu_to_be32(sn);

                if (size <= pdusize) {
                        data_cmd->pdu.datasize = size;
                        rsp->flags = ISCSI_FLG_FINAL | ISCSI_FLG_STATUS;

                        scsisize = tio->buffer.len;
                        if (scsisize < expsize) {
                                rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
                                size = expsize - scsisize;
                        } else if (scsisize > expsize) {
                                rsp->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
                                size = scsisize - expsize;
                        } else
                                size = 0;

                        rsp->residual_count = cpu_to_be32(size);
                        list_add_tail(&data_cmd->entry, &send);

                        break;
                }

                data_cmd->pdu.datasize = pdusize;

                size -= pdusize;
                offset += pdusize;
                sn++;

                list_add_tail(&data_cmd->entry, &send);
        }

        iscsi_cmd_list_init_write(&send);
}

static void send_data_rsp(struct iscsi_cmd *req, void (*func)(struct iscsi_cmd *))
{
        struct iscsi_cmd *rsp;

        func(req);

        if (req->status == SAM_STAT_GOOD) {
                do_send_data_rsp(req);
        } else {
                rsp = create_scsi_rsp(req);
                iscsi_cmd_init_write(rsp);
        }
}

static void build_generic_response(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return;
}

static void build_reservation_conflict_response(struct iscsi_cmd *cmd)
{
        cmd->status = SAM_STAT_RESERVATION_CONFLICT;
}

static int disk_check_ua(struct iscsi_cmd *cmd)
{
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        struct ua_entry *ua;

        if (cmd->lun && ua_pending(cmd->conn->session, cmd->lun->lun)) {
                switch (req->scb[0]) {
                case INQUIRY:
                case REQUEST_SENSE:
                        break;
                case REPORT_LUNS:
                        ua = ua_get_match(cmd->conn->session,
                                          cmd->lun->lun,
                                          /* Reported luns data has changed */
                                          0x3f, 0x0e);
                        ua_free(ua);
                        break;
                default:
                        ua = ua_get_first(cmd->conn->session, cmd->lun->lun);
                        /*
                         * Potential race: another worker thread could've reported
                         * it in the meantime.
                         */
                        if (ua) {
                                DWARN("iscsi check ua failed \n");
                                iscsi_cmd_set_sense(cmd, UNIT_ATTENTION,
                                                    ua->asc, ua->ascq);
                                ua_free(ua);
                                send_scsi_rsp(cmd, build_generic_response);
                                goto yes;
                        }
                }
        }

        return 0;
yes:
        return 1;
}

static int disk_check_reservation(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);

        ret = volume_is_reserved(cmd->lun, cmd->conn->session->sid.id64);
        if (ret == EBUSY) {
                switch (req->scb[0]) {
                case INQUIRY:
                case RELEASE:
                case REPORT_LUNS:
                case REQUEST_SENSE:
                case READ_CAPACITY:
                        /* Allowed commands when reserved */
                        break;
                case SERVICE_ACTION_IN:
                        if ((cmd_scsi_hdr(cmd)->scb[1] & 0x1f) == 0x10)
                                break;
                        /* Fall through */
                default:
                        /* Return reservation conflict for all others */
                        send_scsi_rsp(cmd, build_reservation_conflict_response);
                        return 1;
                }
        }
        return 0;
}

static void build_report_luns_response(struct iscsi_cmd *cmd)
{
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        u32 *data, size, len;
        struct iscsi_volume *lun;
        struct iscsi_target *target;
        char buf[MAX_BUF_LEN];

        size = (u32)req->scb[6] << 24 | (u32)req->scb[7] << 16 |
                (u32)req->scb[8] << 8 | (u32)req->scb[9];
        if (size < 16) {
                /* Invalid field in CDB */
                DWARN("build report luns error\n");
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
                goto out;
        }

        target = cmd->conn->session->target;

        len = atomic_read(&cmd->conn->session->target->nr_volumes) * 8;
        size = min(size & ~(8 - 1), len + 8);


        /* BYTE:
         *    0: LUN LIST LENGTH
         *    3:
         *    4: Reserved
         *    7:
         *    8: LUN [first]
         *   15:
         *  ...:
         *  n-7: LUN [last]
         *    n:
         */
        data = (u32 *)buf;
        *data++ = cpu_to_be32(len);
        *data++ = 0;

        list_for_each_entry(lun, &target->volume_list, entry) {
                if (lun->stat != IDEV_RUNNING)
                        continue;

                DINFO("build lun %u len %d\n", lun->lun, len / 8);

                *data++ = cpu_to_be32((0x3ff & lun->lun) << 16) |
                        ((lun->lun > 0xff) ? (0x01 << 30) : 0);
                *data++ = 0;
        }

        cmd->tio = tio_alloc(cmd->conn, 0);
        mbuffer_appendmem(&cmd->tio->buffer, buf, size);
out:
        return;
}

static void build_inquiry_response(struct iscsi_cmd *cmd)
{
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        u8 *data;
        u8 *scb = req->scb;
        int tio_len = 0;
        char buf[MAX_BUF_LEN];

	DBUG("the scsi disk send cmd INQUIRY and the lun id is %u \n", translate_lun(req->lun));
        /*
         * - CmdDt and EVPD both set or EVPD and Page Code set: illegal
         * - CmdDt set: not supported
         */
        //if ((scb[1] & 0x03) > 0x01 || (!(scb[1] & 0x03) && scb[2])) {
        if (!(scb[1] & 0x01) && scb[2]) {
                DWARN("invalid scsi inquiry cmd\n");
               // goto set_sense;
        }

        YASSERT(!cmd->tio);

        memset(buf, 0x0, sizeof(buf));
        data = (u8 *)buf;
        if (!(scb[1] & 0x03)) {
retry:
                /* Standard INQUIRY data */
                data[2] = 4;            /* Version */
                data[3] = 0x52;         /* | Obsolete | Obsolete | NORMACA | HISUP | RESPONSE DATA FORMAT | */
                data[4] = 59;           /* ADDTIONAL LENGTH (n-4) */
                data[7] = 0x02;         /* | Obsolete | Obsolete | WBUS | SYNC | Obsolete | Obsolete | CMDQUE | VS | */
                memset(data + 8, 0x20, 28);
                memcpy(data + 8, VENDOR_ID, min_t(size_t, strlen(VENDOR_ID), 8));       /* T10 VENDOR IDENTIFICATION */
                memcpy(data + 16, PRODUCT_ID, min_t(size_t, strlen(PRODUCT_ID), 16));   /* PRODUCT IDENTIFICATION */
                memcpy(data + 32, PRODUCT_REV, min_t(size_t, strlen(PRODUCT_REV), 16)); /* PRODUCT REVISION LEVEL */
                data[58] = 0x03;        /* VERSION DESCRIPTOR 1 */
                data[59] = 0x20;
                data[60] = 0x09;        /* VERSION DESCRIPTOR 2 */
                data[61] = 0x60;
                data[62] = 0x03;        /* VERSION DESCRIPTOR 3 */
                data[63] = 0x00;

                #if ENABLE_VAAI

                if(cmd->conn->target->vaai_enabled)
                {
                        data[2] = 6;
                        data[5] = 0xb8; //3PR copy.
                        data[7] = 0x10;

                        data[58] = 0x00;
                        data[59] = 0x8b;
                        data[60] = 0x09;
                        data[61] = 0x60;
                        data[62] = 0x04;        /* VERSION DESCRIPTOR 2 */
                        data[63] = 0x63;
                }

                #endif

                tio_len = 64;
        } else if (scb[1] & 0x01) {
                /* EVPD bit set */
                if (scb[2] == 0x00) {
                        data[1] = 0x00;
                        data[3] = 8;
                        data[4] = 0x00;
                        data[5] = 0x80;
                        data[6] = 0x83;
                //#if ENABLE_VAAI
                if(cmd->conn->target->vaai_enabled)
                {
                        data[7] = 0x86;
                        data[8] = 0x8f;
                        data[9] = 0xb0;
                        data[10] = 0xb1;
                        data[11] = 0xb2;

                        tio_len = 12;
                }
                else
                        tio_len = 7;
                
                } else if (scb[2] == 0x80) {
                        u32 len = 4;

                        if (cmd->lun) {
                                if (strlen((char *)cmd->lun->scsi_sn) <= 16)
                                        len = 16;
                                else
                                        len = SCSI_SN_LEN;
                        }

                        data[1] = 0x80;
                        data[3] = len;
                        memset(data + 4, 0x20, len);

                        if (cmd->lun) {
                                size_t offset = len - strlen((char *)cmd->lun->scsi_sn);
                                memcpy(data + 4 + offset, cmd->lun->scsi_sn,
                                       strlen((char *)cmd->lun->scsi_sn));
                        }
                        tio_len = len + 4;

                        /*if(cmd->conn->target->vaai_enabled)
                        {
                                uint8_t cdata[16] = {0x60,0x01,0x40,0x5e,0x3b,0x09,0xc5,0xcd,0x03,0x14,0xa5,0x68,0xe1,0xec,0x25,0xcd};
                                memcpy(data + 4, cdata, sizeof(cdata));
                                len = 16;
                                tio_len = len + 4;
                        }*/

                } else if (scb[2] == 0x83) {
                        if(cmd->conn->target->vaai_enabled)
                        {
                                u32 len = 4;

                                data[1] = 0x83;
                                
                                //page 1, ieee extend.
                                {
                                        //uint8_t cdata[16] = {0x60,0x01,0x40,0x5e,0x3b,0x09,0xc5,0xcd,0x03,0x14,0xa5,0x68,0xe1,0xec,0x25,0xcd};

                                        data[len] = 0x01;
                                        data[len + 1] = 0x03;
                                        data[len + 2] = 0;
                                        data[len + 3] = 16;
                                        
                                        len += 4;
                                        if (cmd->lun) {
                                                uint32_t cluster_id = 0;

                                                //same as scsi_id generation.
                                                /*for(int i=0;i<sizeof(gloconf.uuid);i++){
                                                        cluster_id = (cluster_id << 1) + gloconf.uuid[i];
                                                }*/

#if 1
                                                UNIMPLEMENTED(__WARN__);
                                                cluster_id = 0;
#else
                                                cluster_id = gloconf.cluster_id;
#endif

                                                *((uint32_t *)(data+len)) = cpu_to_be32(ISCSI_IEEE_VEN_ID);
                                                memcpy(data + len + 4, &cluster_id, 4);
                                                memcpy(data + len + 8, &cmd->conn->target->fileid.id, 8);
                                        }

                                        len += 16;
                                }

                                //page2, T10 vendor ID based
                                {
                                        char *vol;
                                        
                                        data[len] = 0x02;
                                        data[len + 1] = 0x01;
                                        data[len + 2] = 0;
                                        data[len + 3] = 48;
                                        
                                        len += 4;

                                        //make it as:
                                        //mds......volname.scsi_sn, vendor is 8 bytes.

                                        vol = cmd->conn->target->name;
                                        if(strlen(vol) > strlen(sanconf.iqn))
                                                vol = cmd->conn->target->name + strlen(sanconf.iqn) + strlen(":");

                                         
                                        /*vol = strchr(pool, '.');
                                        if (vol) {
                                                *vol = '\0';
                                                vol++;
                                        } else {
                                                ret = EINVAL;
                                                GOTO(err_free, ret);
                                        }*/

                                        if (cmd->lun) {

                                                data[len - 1] = (u8)(8 + strlen(vol) + 1 + strlen((char *)cmd->lun->scsi_sn) + 1);

                                                memset(data + len, 0, 8);
                                                strncpy((char *)data + len, VENDOR_ID, 8);
                                                strncpy((char *)data + len + 8, vol, MAX_BUF_LEN - 128);
                                                strcat((char *)data + len + 8, ".");
                                                strcat((char *)data + len + 8, (char *)cmd->lun->scsi_sn);

                                                len += data[len - 1];
                                                //memcpy(data + len, cdata,48);
                                        }
                                        else
                                                len += 48;      //fatal, wrong.
                                }

                                //page3, Relative target port identifier, fixed 1
                                {
                                        data[len] = 0x51;
                                        data[len + 1] = 0x94;
                                        data[len + 2] = 0;
                                        data[len + 3] = 4;

                                        data[len + 7] = 1;

                                        len += 4;
                                        
                                        len += 4;       //+4 for int32 1
                                }

                                //page4, Target port group, fixed 0
                                {
                                        data[len] = 0x51;
                                        data[len + 1] = 0x95;
                                        data[len + 2] = 0;
                                        data[len + 3] = 4;

                                        len += 4;
                                        if (cmd->lun) {
                                                memset(data + len, 0,4);
                                        }
                                        len += 4;
                                }

                                //page5, Logical unit group, fixed 0
                                {
                                        data[len] = 0x01;
                                        data[len + 1] = 0x06;
                                        data[len + 2] = 0;
                                        data[len + 3] = 4;

                                        len += 4;
                                        if (cmd->lun) {
                                                memset(data + len, 0,4);
                                        }
                                        len += 4;
                                }

                                //page6, SCSI name string
                                {
                                        //uint8_t cdata[32] = {0x69,0x71,0x6e,0x2e,0x32,0x30,0x31,0x37,0x2d,0x30,0x35,0x2e,0x63,0x6f,0x6d,0x2e,0x6d,0x64,0x73,0x3a,0x76,0x31,0x2c,0x74,0x2c,0x30,0x78,0x30,0x30,0x30,0x31,0x00};
                                        char *iqn = cmd->conn->target->name;
                                        int iqnlen = strlen(iqn);

                                        data[len] = 0x53;
                                        data[len + 1] = 0x98;
                                        data[len + 2] = 0;
                                        data[len + 3] = iqnlen + 1;

                                        len += 4;
                                        if (cmd->lun) {
                                                memcpy(data + len, iqn, iqnlen);
                                                data[len + iqnlen] = 0;
                                        }

                                        len += iqnlen + 1;
                                }

                                //page6, SCSI name string in utf8
                                {
                                        //uint8_t cdata[24] = {0x69,0x71,0x6e,0x2e,0x32,0x30,0x31,0x37,0x2d,0x30,0x35,0x2e,0x63,0x6f,0x6d,0x2e,0x6d,0x64,0x73,0x3a,0x76,0x31,0x00,0x00};
                                        char *utf8_iqn = cmd->conn->target->name;
                                        int iqnlen = strlen(utf8_iqn);

                                        data[len] = 0x53;
                                        data[len + 1] = 0xa8;
                                        data[len + 2] = 0;
                                        data[len + 3] = iqnlen + 2;

                                        len += 4;
                                        if (cmd->lun) {
                                                memcpy(data + len, utf8_iqn, iqnlen);
                                                data[len + iqnlen] = 0;
                                                data[len + iqnlen + 1] = 0;     
                                        }
                                        len += iqnlen + 2;
                                }
                                
                                data[3] = len - 4;
                                tio_len = len;
                        }
                        else{
                                u32 len = SCSI_ID_LEN + 8;

                                data[1] = 0x83;
                                data[3] = len + 4;
                                data[4] = 0x01;
                                data[5] = 0x01;
                                data[7] = len;

                                if (cmd->lun) {
                                        memset(data + 8, 0x00, 8);
                                        memcpy(data + 8, VENDOR_ID,
                                        min_t(size_t, strlen(VENDOR_ID), 8));
                                        memcpy(data + 16, cmd->lun->scsi_id, SCSI_ID_LEN);
                                }
                                tio_len = len + 8;
                        }
                } 

                //#if ENABLE_VAAI
                else if (scb[2] == 0x86 && cmd->conn->target->vaai_enabled) {
                        
                        data[1] = 0x86;
                        data[3] = 64 - 4;
                        data[8] = 0x12;
                        data[10] = 0x80;

                        tio_len = 64;
                } else if (scb[2] == 0x8f && cmd->conn->target->vaai_enabled) {
                        data[1] = 0x8f;
                        data[3] = 4 * 20 + 32 + 36 - 4;

			unsigned char *pPage0001 = data + 4;
			pPage0001[0] = 0x00;
			pPage0001[1] = 0x01;	//Supported Commands.
			pPage0001[2] = 0x00;
			pPage0001[3] = 0x10;	//LENGTH.
			//length+ {command + supported action + pad} * n.
			unsigned char Page0001Data[] = { 0x0d, 0x83, 0x03, 0x00, 0x01, 0x1c, 0x00, 0x84, 0x04, 0x00, 0x03, 0x04, 0x05 };
			memcpy(pPage0001 + 4, Page0001Data, sizeof(Page0001Data));

			unsigned char *pPage0004 = pPage0001 + 20;
			pPage0004[0] = 0x00;
			pPage0004[1] = 0x04;	//Parameters.
			pPage0004[2] = 0x00;
			pPage0004[3] = 0x1C;	//LENGTH.
			pPage0004[8] = 0x02;
			pPage0004[9] = 0x00;	//MAXIMUM CSCD DESCRIPTOR COUNT
			pPage0004[10] = 0x01;
			pPage0004[11] = 0x00;	//MAXIMUM SEGMENT DESCRIPTOR COUNT
			pPage0004[12] = 0x00;
			pPage0004[13] = 0x00;
			pPage0004[14] = 0x10;
			pPage0004[15] = 0x00;	//MAXIMUM DESCRIPTOR DESCRIPTOR COUNT
			pPage0004[16] = 0x00;
			pPage0004[17] = 0x00;
			pPage0004[18] = 0x00;
			pPage0004[19] = 0x00;	//MAXIMUM INLINE DATA LENGTH

			unsigned char *pPage8001 = pPage0004 + 32;
			pPage8001[0] = 0x80;
			pPage8001[1] = 0x01;	//Gernal Copy.
			pPage8001[2] = 0x00;
			pPage8001[3] = 0x20;	//LENGTH.
			pPage8001[7] = 0x08;	//TOTAL CONCURRENT COPIES
			pPage8001[11] = 0x08;	//TOTAL IDENTIFIED CONCURRENT COPIES
			pPage8001[13] = 0x01;	//MAXIMUM SEGMENTLENGTH, 1M
			//not finished.

			tio_len = data[3] + 4;
                }else if (scb[2] == 0xb0 && cmd->conn->target->vaai_enabled) {
                        data[1] = 0xb0;
                        data[3] = 64 - 4;

			data[4] = 0x01;	//WSNZ
			data[5] = 0x80;	//MAXIMUM COMPARE AND WRITE LENGTH
			
			*((uint32_t *)&data[20]) = htonl(2048 * 64);	//MAXIMUM UNMAP LBA COUNT
			*((uint32_t *)&data[24]) = htonl(1);	//MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT

			data[31] = 0x08;	//OPTIMAL UNMAP GRANULARITY, 4k
			data[41] = 0;//0x10;	//MAXIMUM WRITE SAME LENGTH, now 2M
                        data[42] = 0x10;
                        
			tio_len = 64;
                }else if (scb[2] == 0xb1 && cmd->conn->target->vaai_enabled) {
                        data[1] = 0xb1;
                        data[3] = 64 - 4;

                        //data[5] = htonl(1);
                        //data[6] = htonl(7);
			data[8] = 0x01;	//WSNZ
			
			tio_len = 64;
                }else if (scb[2] == 0xb2 && cmd->conn->target->vaai_enabled) {
                        data[1] = 0xb2;
                        data[3] = 64 - 4;

			data[4] = 0x1f;	//
			data[5] = 0x84;	//ANC_SUPP=0
			data[6] = 0x02;	//Ful prov.

			tio_len = 64;
                }

                //#endif

        }

        if (tio_len) {
                cmd->tio = tio_alloc(cmd->conn, 0);
                if (!cmd->lun)
                        data[0] = TYPE_NO_LUN;
                if(cmd->conn->target->vaai_enabled) // vaai mode device identry data is too long to report itself.
			mbuffer_appendmem(&cmd->tio->buffer, buf, tio_len);
		else {
			u32 len = (u32)scb[3] << 8 | (u32)scb[4];
                	mbuffer_appendmem(&cmd->tio->buffer, buf, min_t(u32, tio_len, len));
		}
                return;
        } else {
                //DWARN("the scb value is %d\n", (uint32_t)*scb);
                goto retry;
        }
        DWARN("invalid inquiry cmd\n");
//set_sense:
        /* Invalid field in CDB */
        iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
}

static void build_read_capacity_response(struct iscsi_cmd *cmd)
{
        u32 *data;
        char buf[MAX_BUF_LEN];

        YASSERT(!cmd->tio);

        data = (u32 *)buf;
        data[0] = (cmd->lun->blk_cnt >> 32) ? cpu_to_be32(0xffffffff) : cpu_to_be32(cmd->lun->blk_cnt - 1); 
        data[1] = cpu_to_be32(1U << cmd->lun->blk_shift); 

        cmd->tio = tio_alloc(cmd->conn, 0); 
        mbuffer_appendmem(&cmd->tio->buffer, buf, 8); 
}

static void build_mgr_in_response(struct iscsi_cmd *cmd)
{
        char buf[MAX_BUF_LEN] = {0};

        YASSERT(!cmd->tio);

        buf[3] = 0x0c;
        buf[5] = 0xcf;
        buf[11] = 1;
        buf[15] = 1;

        cmd->tio = tio_alloc(cmd->conn, 0); 
        mbuffer_appendmem(&cmd->tio->buffer, buf, 3064); 
}

static void build_pr_in_response(struct iscsi_cmd *cmd)
{
        char buf[8] = {0};

        YASSERT(!cmd->tio);

        cmd->tio = tio_alloc(cmd->conn, 0); 
        mbuffer_appendmem(&cmd->tio->buffer, buf, 8); 
}

#if 0
static void build_read_capacity16_response(struct iscsi_cmd *cmd)
{
        u64 *lba;
        u32 *block;
        char buf[MAX_BUF_LEN];

        YASSERT(!cmd->tio);

        lba = (u64 *)buf;
        block = (u32 *)(buf + 8);
        lba[0] = cpu_to_be64(cmd->lun->blk_cnt - 1);
        block[0] = cpu_to_be32(1U << cmd->lun->blk_shift);

        cmd->tio = tio_alloc(cmd->conn, 0);
        mbuffer_appendmem(&cmd->tio->buffer, buf, 12);
}

static inline int aio_read_callback(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        if (cmd->err) {
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
        }

        if (cmd->tracker.job) {
                job_timermark(cmd->tracker.job, "callback");
        }

        send_data_rsp(cmd, build_generic_response);

        /* Can't use @cmd->conn here!, cmd may has beed freed */
        conn_busy_put(conn);

        return 0;
}

static inline int aio_write_callback(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        if (cmd->err) {
                DWARN("errno (%d) %s\n", cmd->err, strerror(cmd->err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
                goto rsp;
        }

        if (cmd->tracker.job) {
                job_timermark(cmd->tracker.job, "callback");
        }

        /*
         * If the disk write cache is disabled, we must call the sync function
         * to make sure all the data is written to disk.
         */
        if (!LUWCache(cmd->lun)) {
                int err = tio_sync(cmd);
                if (err)
                        iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x03, 0x00);
        }

rsp:
        send_scsi_rsp(cmd, build_generic_response);
        /* Can't use @cmd->conn here!, cmd may has beed freed */
        conn_busy_put(conn);
        return 0;
}
#endif

static inline void __disk_aio_read(struct iscsi_cmd *cmd)
{
        //struct iscsi_conn *conn = cmd->conn;
        int err = tio_read(cmd);
        if (err) {
                DWARN("disk io read errno (%d) %s\n", err, strerror(err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
        }

        send_data_rsp(cmd, build_generic_response);

        /* Can't use @cmd->conn here!, cmd may has beed freed */
        //conn_busy_put(conn);
}

static inline void __disk_aio_write(struct iscsi_cmd *cmd)
{
        int err;
        //struct iscsi_conn *conn = cmd->conn;

        list_del_init(&cmd->entry);

        err = tio_write(cmd);
        if (err) {
                DWARN("disk io write errno (%d) %s\n", err, strerror(err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
                goto rsp;
        }

        /*
         * If the disk write cache is disabled, we must call the sync function
         * to make sure all the data is written to disk.
         */
        if (!LUWCache(cmd->lun)) {
                int err = tio_sync(cmd);
                if (err)
                        iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x03, 0x00);
        }

rsp:
        send_scsi_rsp(cmd, build_generic_response);

        /* Can't use @cmd->conn here!, cmd may has beed freed */
        //conn_busy_put(conn);
}

static inline void __disk_aio_write_same(struct iscsi_cmd *cmd)
{
        int err;
        //struct iscsi_conn *conn = cmd->conn;

        list_del_init(&cmd->entry);

        struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(cmd);
        if(req_hdr->scb[1] & (1 << 3)) //UNMAP
        {
                goto rsp;
                //did nothing.
        }

        loff_t offset;
        u32 length;

        set_offset_and_length(cmd->lun, req_hdr->scb, &offset, &length);

        uint8_t *newbuff = malloc(length);
        uint32_t data_len = cmd->pdu.datasize;

        DBUG("WRITE_SAME_16: %d:%d\r\n", length, cmd->pdu.datasize);

        mbuffer_get(&cmd->tio->buffer, newbuff, cmd->pdu.datasize);
        while(data_len < length)
        {
                memcpy(newbuff + data_len, newbuff, 512);
                data_len += 512;
        }

        mbuffer_copy1(&cmd->tio->buffer, newbuff, 0, length);
        free(newbuff);

        err = tio_write(cmd);
        if (err) {
                DWARN("disk io write errno (%d) %s\n", err, strerror(err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
                goto rsp;
        }

        /*
         * If the disk write cache is disabled, we must call the sync function
         * to make sure all the data is written to disk.
         */
        if (!LUWCache(cmd->lun)) {
                int err = tio_sync(cmd);
                if (err)
                        iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x03, 0x00);
        }

rsp:
        send_scsi_rsp(cmd, build_generic_response);

        /* Can't use @cmd->conn here!, cmd may has beed freed */
        //conn_busy_put(conn);
}

static inline void __disk_aio_compare_and_write(struct iscsi_cmd *cmd)
{
        int err;
        //struct iscsi_conn *conn = cmd->conn;

        list_del_init(&cmd->entry);

        struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(cmd);
        loff_t offset;
        u32 length, i;

        set_offset_and_length(cmd->lun, req_hdr->scb, &offset, &length);

        uint8_t *newbuff = malloc(cmd->pdu.datasize);
        uint8_t *compare_buff = malloc(length);

        mbuffer_get(&cmd->tio->buffer, newbuff, cmd->pdu.datasize);
        mbuffer_pop(&cmd->tio->buffer, NULL, cmd->pdu.datasize);

        DBUG("COMPARE_AND_WRITE_16\r\n");
        err = tio_read(cmd);
        if(err)
        {
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
                                
                goto rsp;
        }
        
        DBUG("COMPARE_AND_WRITE_16 1\r\n");

        mbuffer_get(&cmd->tio->buffer, compare_buff, length);

        for (i = 0; i < length; i++) //must be byte-by-byte comparation.
        {
                if (compare_buff[i] != newbuff[i])
                        break;
        }

        if (i !=  length)
        {
                iscsi_cmd_set_sense(cmd, MISCOMPARE, 0x11, 0x00);
                                
                cmd->sense_buf[8] = i;  //information.

		goto rsp;
        }

        mbuffer_copy1(&cmd->tio->buffer, newbuff + length, 0, length);
        DBUG("COMPARE_AND_WRITE_16 2\r\n");

        free(newbuff);
        free(compare_buff);

        err = tio_write(cmd);
        if (err) {
                DWARN("disk io write errno (%d) %s\n", err, strerror(err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
                goto rsp;
        }
        /*
         * If the disk write cache is disabled, we must call the sync function
         * to make sure all the data is written to disk.
         */
        if (!LUWCache(cmd->lun)) {
                int err = tio_sync(cmd);
                if (err)
                        iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x03, 0x00);
        }

rsp:
        send_scsi_rsp(cmd, build_generic_response);

        /* Can't use @cmd->conn here!, cmd may has beed freed */
        //conn_busy_put(conn);
}

static void build_sync_mcache_response(struct iscsi_cmd *cmd)
{
        int ret = tio_sync(cmd);
        if (unlikely(ret))
                /* Medium Error/Write Fault */
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x03, 0x00);
}

static void build_mode_sense_response(struct iscsi_cmd *cmd)
{
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        u8 *data, *scb = req->scb;
        int ret = 0, len = 4;
        u8 pcode;
        char buf[MAX_BUF_LEN];

        /* Changeable parameter mode pages are unsupported */
        if ((scb[2] & 0xc0) >> 6 == 0x01) {
		DWARN("unsuport scsi command\n");
                goto set_sense;
	}

        pcode = req->scb[2] & 0x3f;

        YASSERT(!cmd->tio);

        memset(buf, 0x0, sizeof(buf));
        data = (u8 *)buf;

        if (LUReadonly(cmd->lun))
                data[2] = 0x80;

        if ((scb[1] & 0x08))
                data[3] = 0;
        else {
                data[3] = 8;
                len += 8;
                *(u32 *)(data + 4) = (cmd->lun->blk_cnt >> 32) ?
                        cpu_to_be32(0xffffffff) : cpu_to_be32(cmd->lun->blk_cnt);
                *(u32 *)(data + 8) = cpu_to_be32(1 << cmd->lun->blk_shift);
        }

        /* See SPC-4 6.11 */
        switch (pcode) {
        case 0x00:
                break;
        case 0x02:
                len += insert_disconnect_pg(data + len);
                break;
        case 0x03:
                len += insert_format_m_pg(data + len, 1 << cmd->lun->blk_shift);
                break;
        case 0x04:
                len += insert_geo_m_pg(data + len, cmd->lun->blk_cnt);
                break;
        case 0x08:
                len += insert_caching_pg(data + len, LUWCache(cmd->lun), LURCache(cmd->lun));
                break;
        case 0x0a:
                len += insert_ctrl_m_pg(data + len);
                break;
        case 0x1c:
                len += insert_iec_m_pg(data + len);
                break;
        case 0x3f:
                len += insert_disconnect_pg(data + len);
                len += insert_format_m_pg(data + len, 1 << cmd->lun->blk_shift);
                len += insert_geo_m_pg(data + len, cmd->lun->blk_cnt);
                len += insert_caching_pg(data + len, LUWCache(cmd->lun), LURCache(cmd->lun));
                len += insert_ctrl_m_pg(data + len);
                len += insert_iec_m_pg(data + len);
                break;
        default:
                ret = 1;
        }

        if (!ret) {
                data[0] = len - 1;

                cmd->tio = tio_alloc(cmd->conn, 0);
                mbuffer_appendmem(&cmd->tio->buffer, buf, min((u32)len, cpu_to_be32(cmd_scsi_hdr(cmd)->data_length)));
                return;
        }

set_sense:
        /* Invalid field in CDB */
        iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
        return;
}

static void build_request_sense_response(struct iscsi_cmd *cmd)
{
        u8 *data;
        char buf[MAX_BUF_LEN];

        memset(buf, 0x0, sizeof(buf));
        data = (u8 *)buf;
        data[0] = 0xf0;
        data[1] = 0;
        data[2] = NO_SENSE;
        data[7] = 10;

        cmd->tio = tio_alloc(cmd->conn, 0);
        mbuffer_appendmem(&cmd->tio->buffer, buf, 18);
}

static void build_receive_copy_response(struct iscsi_cmd *cmd)
{
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);
        u8 *scb = req->scb;
        
        if (scb[1] == 3)
        {
                //max conccrent copies = 1
                //max size=64m
                unsigned char buf[] = { 0x00, 0x00, 0x00, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00
			, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			, 0x00, 0x00, 0x00, 0x01, 0x01, 0x09, 0x09, 0x09, 0x00, 0x00, 0x00, 0x02, 0x02, 0xe4 };

                YASSERT(!cmd->tio);

                cmd->tio = tio_alloc(cmd->conn, 0); 
                mbuffer_appendmem(&cmd->tio->buffer, buf, sizeof(buf)); 
        }
        else
        {
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x25, 0x00);
        }
}

static void build_service_action_in_response(struct iscsi_cmd *cmd)
{
        u32 *data;
        u64 *data64;
        char buf[MAX_BUF_LEN] = {0};

        /* Only READ_CAPACITY_16 service action is currently supported */
        if ((cmd_scsi_hdr(cmd)->scb[1] & 0x1f) != 0x10) {
                /* Invalid field in CDB */
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
                goto out;
        }

        memset(buf, 0x0, sizeof(buf));
        data = (u32 *)buf;
        data64 = (u64 *)data;
        data64[0] = cpu_to_be64(cmd->lun->blk_cnt - 1);
        data[2] = cpu_to_be32(1UL << cmd->lun->blk_shift);
        
#if ENABLE_VAAI
        if(cmd->conn->target->vaai_enabled && cmd->conn->target->thin_provisioning)
        {
                buf[13] = 0x03; //physical block.
                buf[14] = 0xc0; //thin provisioning.
        }
#endif 

        cmd->tio = tio_alloc(cmd->conn, 0);
        mbuffer_appendmem(&cmd->tio->buffer, buf, min((u32)32, cpu_to_be32(cmd_scsi_hdr(cmd)->data_length)));
out:
        return;
}

static void build_reserve_response(struct iscsi_cmd *cmd)
{
        int ret = volume_reserve(cmd->lun, cmd->conn->session->sid.id64);

        switch (ret) {
        case ENOENT:
                /* Logical Unit not supported (?) */
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x25, 0x00);
                break;
        case EBUSY:
                cmd->status = SAM_STAT_RESERVATION_CONFLICT;
                break;
        default:
                break;
        }
}

static void build_release_response(struct iscsi_cmd *cmd)
{
        int ret = volume_release(cmd->lun, cmd->conn->session->sid.id64, 0);

        switch (ret) {
        case ENOENT:
                /* Logical Unit not supported (?) */
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x25, 0x00);
                break;
        case EBUSY:
                cmd->status = SAM_STAT_RESERVATION_CONFLICT;
                break;
        default:
                break;
        }
}

int disk_execute_cmd(struct iscsi_cmd *cmd)
{
        int sync = 1;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);

        req->opcode &= ISCSI_OPCODE_MASK;

        if (disk_check_ua(cmd))
                goto out;

        if (disk_check_reservation(cmd))
                goto out;

        switch (req->scb[0]) {
        case INQUIRY:
                TRACKER_SET_NAME(cmd, "[SCSI] INQUIRY");
                send_data_rsp(cmd, build_inquiry_response);
                break;
        case REPORT_LUNS:
                TRACKER_SET_NAME(cmd, "[SCSI] REPORT_LUNS");
                send_data_rsp(cmd, build_report_luns_response);
                break;
        case READ_CAPACITY:
                TRACKER_SET_NAME(cmd, "[SCSI] READ_CAPACITY");
                (void) cops->rescan_lun(conn);
                send_data_rsp(cmd, build_read_capacity_response);
                break;
        case MODE_SENSE:
                TRACKER_SET_NAME(cmd, "[SCSI] MODE_SENSE");
                send_data_rsp(cmd, build_mode_sense_response);
                break;
        case REQUEST_SENSE:
                TRACKER_SET_NAME(cmd, "[SCSI] REQUEST_SENSE");
                send_data_rsp(cmd, build_request_sense_response);
                break;
        case SERVICE_ACTION_IN:
                TRACKER_SET_NAME(cmd, "[SCSI] REQUEST_SENSE");
                send_data_rsp(cmd, build_service_action_in_response);
                break;
        case PERSISTENT_RESERVE_IN:
                send_data_rsp(cmd, build_pr_in_response);
                break;

        case READ_6:
        case READ_10:
        case READ_16:
                TRACKER_SET_NAME(cmd, "[SCSI] READ");
                sync = 0;
                __disk_aio_read(cmd);
                break;
        case WRITE_6:
        case WRITE_10:
        case WRITE_16:
        case WRITE_VERIFY:
                TRACKER_SET_NAME(cmd, "[SCSI] WRITE");
                sync = 0;
                __disk_aio_write(cmd);
        
                break;
                
        case WRITE_SAME:
        case WRITE_SAME_16:
                
                __disk_aio_write_same(cmd);
                
                break;

        case COMPARE_AND_WRITE_16:
                TRACKER_SET_NAME(cmd, "[SCSI] COMPARE_AND_WRITE_16");
                sync = 0;
                __disk_aio_compare_and_write(cmd);

                break;
#if ENABLE_VAAI
        case EXTENDED_COPY:
                DINFO("EXTENDED_COPY\r\n");
                scsi_cm_parse_descriptors(cmd);
                //iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x25, 0x00);
                send_scsi_rsp(cmd, build_generic_response);
                break;
#endif
        case RECEIVE_COPY_RESULTS:
                DINFO("RECEIVE_COPY_RESULTS\r\n");
                //sync = 0;
                send_data_rsp(cmd, build_receive_copy_response);
                break;
        case SYNCHRONIZE_CACHE:
                TRACKER_SET_NAME(cmd, "[SCSI] SYNCHONIZIE");
                send_scsi_rsp(cmd, build_sync_mcache_response);
                break;
        case RESERVE:
                TRACKER_SET_NAME(cmd, "[SCSI] RESERVE");
                send_scsi_rsp(cmd, build_reserve_response);
                break;
        case RELEASE:
                TRACKER_SET_NAME(cmd, "[SCSI] RELEASE");
                send_scsi_rsp(cmd, build_release_response);
                break;
        case START_STOP:
                TRACKER_SET_NAME(cmd, "[SCSI] START_STOP");
                send_scsi_rsp(cmd, build_generic_response);
                break;
        case TEST_UNIT_READY:
                TRACKER_SET_NAME(cmd, "[SCSI] TEST_UNIT_READY");
                send_scsi_rsp(cmd, build_generic_response);
                break;
        case VERIFY:
                TRACKER_SET_NAME(cmd, "[SCSI] VERIFY");
                send_scsi_rsp(cmd, build_generic_response);
                break;
        case VERIFY_16:
                TRACKER_SET_NAME(cmd, "[SCSI] VERIFY_16");
                send_scsi_rsp(cmd, build_generic_response);
                break;
#if ENABLE_VAAI
        case UNMAP:
                TRACKER_SET_NAME(cmd, "[SCSI] UNMAP");
                DINFO("[SCSI] UNMAP\r\n");
                if(!disk_io_unmap(cmd))
                        send_scsi_rsp(cmd, build_generic_response);
                else
                {
                        iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
                }
                break;
#endif
        case MANAGEMENT_PROTOCOL_IN:
                DINFO("[SCSI] MANAGEMENT_PROTOCOL_IN\r\n");
                send_data_rsp(cmd, build_mgr_in_response);
                break;
        default:
                DWARN("Unsupported command! %x\n", req->scb[0]);
                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x25, 0x00);
                send_scsi_rsp(cmd, build_generic_response);
        }

out:
        if (sync) {
                //conn_busy_put(conn);
        }

        return 0;
}

static void __tio_read__(void *arg)
{
        struct iscsi_cmd *cmd = arg;
        int err = tio_read(cmd);
        if (unlikely(err)) {
                DWARN("disk io read errno (%d) %s\n", err, strerror(err));
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
        }

        cmd->callback(cmd);
}

static void __tio_write__(void *arg)
{
        struct iscsi_cmd *cmd = arg;
        int err = tio_write(cmd);
        if (unlikely(err)) {
                DWARN("disk io write errno (%d) %s\n", err, strerror(err));
              //  record_invalid_access(cmd);
                iscsi_cmd_set_sense(cmd, MEDIUM_ERROR, 0x11, 0x00);
        }

        cmd->callback(cmd);
}

int target_cmd_queue(struct iscsi_cmd *cmd)
{
        int sync = 1;
        struct iscsi_scsi_cmd_hdr *req = cmd_scsi_hdr(cmd);

        if (unlikely(cmd->sense_len))
                goto out;

        req->opcode &= ISCSI_OPCODE_MASK;

        if (unlikely(disk_check_ua(cmd)))
                goto out;

        if (unlikely(disk_check_reservation(cmd)))
                goto out;

        switch (req->scb[0]) {
        case INQUIRY:
                TRACKER_SET_NAME(cmd, "[SCSI] INQUIRY");
                build_inquiry_response(cmd);
                break;
        case REPORT_LUNS:
                TRACKER_SET_NAME(cmd, "[SCSI] REPORT_LUNS");
                build_report_luns_response(cmd);
                break;
        case READ_CAPACITY:
                TRACKER_SET_NAME(cmd, "[SCSI] READ_CAPACITY");
                build_read_capacity_response(cmd);
                break;
        case MODE_SENSE:
                TRACKER_SET_NAME(cmd, "[SCSI] MODE_SENSE");
                build_mode_sense_response(cmd);
                break;
        case REQUEST_SENSE:
                TRACKER_SET_NAME(cmd, "[SCSI] REQUEST_SENSE");
                build_request_sense_response(cmd);
                break;
        case SERVICE_ACTION_IN:
                TRACKER_SET_NAME(cmd, "[SCSI] REQUEST_SENSE");
                build_service_action_in_response(cmd);
                break;
        case READ_6:
        case READ_10:
        case READ_16:
                TRACKER_SET_NAME(cmd, "[SCSI] READ");
                sync = 0;
                schedule_task_new("iscsi_tio_read", __tio_read__, cmd, -1);
                break;
        case WRITE_6:
        case WRITE_10:
        case WRITE_16:
        case WRITE_VERIFY:
                TRACKER_SET_NAME(cmd, "[SCSI] WRITE");
                sync = 0;
                schedule_task_new("iscsi_tio_write", __tio_write__, cmd, -1);
                break;
        case SYNCHRONIZE_CACHE:
                TRACKER_SET_NAME(cmd, "[SCSI] SYNCHONIZIE");
                build_sync_mcache_response(cmd);
                break;
        case RESERVE:
                TRACKER_SET_NAME(cmd, "[SCSI] RESERVE");
                build_reserve_response(cmd);
                break;
        case RELEASE:
                TRACKER_SET_NAME(cmd, "[SCSI] RELEASE");
                build_release_response(cmd);
                break;
        case START_STOP:
                TRACKER_SET_NAME(cmd, "[SCSI] START_STOP");
                build_generic_response(cmd);
                break;
        case TEST_UNIT_READY:
                TRACKER_SET_NAME(cmd, "[SCSI] TEST_UNIT_READY");
                build_generic_response(cmd);
                break;
        case VERIFY:
                TRACKER_SET_NAME(cmd, "[SCSI] VERIFY");
                build_generic_response(cmd);
                break;
        case VERIFY_16:
                TRACKER_SET_NAME(cmd, "[SCSI] VERIFY_16");
                build_generic_response(cmd);
                break;
        default:
                DWARN("Unsupported command! %x\n", req->scb[0]);
		//if (cmd->conn->state != STATE_CLOSE && cmd->conn->state != STATE_CLOSED)
		//	cmd->conn->state = STATE_CLOSE; 

                iscsi_cmd_set_sense(cmd, ILLEGAL_REQUEST, 0x24, 0x00);
        }

out:
        if (sync)
                cmd->callback(cmd);

        return 0;
}
