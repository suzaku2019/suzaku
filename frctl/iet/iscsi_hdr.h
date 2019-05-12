#ifndef _ISCSI_HDR_H
#define _ISCSI_HDR_H

#define ISCSI_VERSION                   0
#define ISCSI_RESERVED_TAG              0xffffffff

/* Login stage (phase) codes for CSG, NSG */
#define ISCSI_INITIAL_LOGIN_STAGE                -1
#define ISCSI_SECURITY_NEGOTIATION_STAGE        0
#define ISCSI_OP_PARMS_NEGOTIATION_STAGE        1
#define ISCSI_FULL_FEATURE_PHASE                3

/* Login Status response classes */
#define ISCSI_STATUS_SUCCESS            0
#define ISCSI_STATUS_REDIRECT           0x01
#define ISCSI_STATUS_INITIATOR_ERR      0x02
#define ISCSI_STATUS_TARGET_ERR         0x03

/* Login Status response detail codes */

/* Class-0 (Success) */
#define ISCSI_STATUS_ACCEPT             0x00

/* Class-1 (Redirection) */
#define ISCSI_STATUS_TGT_MOVED_TEMP     0x01
#define ISCSI_STATUS_TGT_MOVED_PERM     0x02

/* Class-2 (Initiator Error) */
#define ISCSI_STATUS_INIT_ERR           0x00
#define ISCSI_STATUS_AUTH_FAILED        0x01
#define ISCSI_STATUS_TGT_FORBIDDEN      0x02
#define ISCSI_STATUS_TGT_NOT_FOUND      0x03
#define ISCSI_STATUS_TGT_REMOVED        0x04
#define ISCSI_STATUS_NO_VERSION         0x05
#define ISCSI_STATUS_TOO_MANY_CONN      0x06
#define ISCSI_STATUS_MISSING_FIELDS     0x07
#define ISCSI_STATUS_CONN_ADD_FAILED    0x08
#define ISCSI_STATUS_INV_SESSION_TYPE   0x09
#define ISCSI_STATUS_SESSION_NOT_FOUND  0x0a
#define ISCSI_STATUS_INV_REQ_TYPE       0x0b

/* Class-3 (Target Error) */
#define ISCSI_STATUS_TARGET_ERROR       0x00
#define ISCSI_STATUS_SVC_UNAVAILABLE    0x01
#define ISCSI_STATUS_NO_RESOURCES       0x02

/* Flags bit of PDU */
#define ISCSI_FLG_CONTINUE              0x40
#define ISCSI_FLG_FINAL                 0x80
#define ISCSI_FLG_TRANSIT               0x80
#define ISCSI_FLG_CSG_SECURITY          0x00
#define ISCSI_FLG_CSG_OPERATIONAL       0x04
#define ISCSI_FLG_CSG_FULL_FEATURE      0x0c
#define ISCSI_FLG_CSG_MASK              0x0c
#define ISCSI_FLG_NSG_SECURITY          0x00
#define ISCSI_FLG_NSG_OPERATIONAL       0x01
#define ISCSI_FLG_NSG_FULL_FEATURE      0x03
#define ISCSI_FLG_NSG_MASK              0x03

/* Opcode encoding bits */
#define ISCSI_OP_RETRY                  0x80
#define ISCSI_OP_IMMEDIATE              0x40
#define ISCSI_OPCODE_MASK               0x3F

/* Client to Server Message Opcode values */
#define ISCSI_OP_NOP_OUT                0x00
#define ISCSI_OP_SCSI_REQ               0x01
#define ISCSI_OP_SCSI_TASK_MGT_REQ      0x02
#define ISCSI_OP_LOGIN_REQ              0x03
#define ISCSI_OP_TEXT_REQ               0x04
#define ISCSI_OP_SCSI_DATA_OUT          0x05
#define ISCSI_OP_LOGOUT_REQ             0x06
#define ISCSI_OP_SNACK_REQ              0x10

/* 0x1c-0x1e Vendor specific codes */
#define ISCSI_OP_VENDOR1_CMD            0x1c
#define ISCSI_OP_VENDOR2_CMD            0x1d
#define ISCSI_OP_VENDOR3_CMD            0x1e
#define ISCSI_OP_VENDOR4_CMD            0x1f

#define ISCSI_OP_SCSI_REJECT            ISCSI_OP_VENDOR1_CMD
#define ISCSI_OP_PDU_REJECT             ISCSI_OP_VENDOR2_CMD
#define ISCSI_OP_DATA_REJECT            ISCSI_OP_VENDOR3_CMD

/* Server to Client Message Opcode values */
#define ISCSI_OP_NOP_IN                 0x20
#define ISCSI_OP_SCSI_RSP               0x21
#define ISCSI_OP_SCSI_TASK_MGT_RSP      0x22
#define ISCSI_OP_LOGIN_RSP              0x23
#define ISCSI_OP_TEXT_RSP               0x24
#define ISCSI_OP_SCSI_DATA_IN           0x25
#define ISCSI_OP_LOGOUT_RSP             0x26
#define ISCSI_OP_R2T                    0x31
#define ISCSI_OP_ASYNC                  0x32
#define ISCSI_OP_REJECT                 0x3f

#define ISCSI_OP_NR_MAX                 0x40

/* Max. number of Key=Value pairs in a text message */
#define MAX_KEY_VALUE_PAIRS        8192

/* maximum length for text keys/values */
#define KEY_MAXLEN                64
#define VALUE_MAXLEN                255
#define TARGET_NAME_MAXLEN        VALUE_MAXLEN

#define DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH        8192

#define ISCSI_LOGIN_CURRENT_STAGE(flags) \
        ((flags & ISCSI_FLG_CSG_MASK) >> 2)
#define ISCSI_LOGIN_NEXT_STAGE(flags) \
        (flags & ISCSI_FLG_NSG_MASK)

#define ISCSI_ASYNC_SCSI		0
#define ISCSI_ASYNC_LOGOUT		1
#define ISCSI_ASYNC_DROP_CONNECTION	2
#define ISCSI_ASYNC_DROP_SESSION	3
#define ISCSI_ASYNC_PARAM_REQUEST	4
#define ISCSI_ASYNC_VENDOR		255


#define __packed __attribute__((packed))

/*
 * ISCSI PDUs are padded to the closest integer number of four byte words, the
 * padding bytes SHOULD be sent as 0.
 * All PDU segments and digest are padded to the closet integer number of four
 * byte words, all PDU segments and digests start at a four byte word boundary
 * and the padding ranges from 0 to 3 bytes - RFC3720.
 */
#define iscsi_cmd_size_align(size) ({ (((size) + 3) & -4); })

struct iscsi_hdr {
        u8  opcode;                      /* 00 */
        u8  flags;
        u8  spec1[2];
        u8  ahssize;                     /* 04 */
        u8  datasize[3];
        u16 lun[4];                     /* 08 */
        u32 itt;                        /* 16 */
        u32 ttt;                        /* 20 */
        u32 sn;                         /* 24 */
        u32 exp_sn;                     /* 28 */
        u32 max_sn;                     /* 32 */
        u32 spec3[3];                   /* 48 */
} __packed;

#define BHS_SIZE                sizeof(struct iscsi_hdr)

#define ISCSI_AHSTYPE_CDB               1
#define ISCSI_AHSTYPE_RLENGTH           2

struct iscsi_ahs_hdr {
        u16 ahslength;
        u8  ahstype;
} __packed;

union iscsi_sid {
        struct {
                u8  isid[6];            /* Initiator Session ID */
                u16 tsih;               /* Target Session ID */
        } id;
        u64 id64;
} __packed;

#define sid64(isid, tsih)                                        \
({                                                                \
        (uint64_t) isid[0] <<  0 | (uint64_t) isid[1] <<  8 |        \
        (uint64_t) isid[2] << 16 | (uint64_t) isid[3] << 24 |        \
        (uint64_t) isid[4] << 32 | (uint64_t) isid[5] << 40 |        \
        (uint64_t) tsih << 48;                                        \
})

#define sid_to_tsih(sid) ((sid) >> 48)

/*
 * Reason field of Reject response message
 */
#define ISCSI_REASON_NO_FULL_FEATURE_PHASE      0x01
#define ISCSI_REASON_DATA_DIGEST_ERROR          0x02
#define ISCSI_REASON_DATA_SNACK_REJECT          0x03
#define ISCSI_REASON_PROTOCOL_ERROR             0x04
#define ISCSI_REASON_UNSUPPORTED_COMMAND        0x05
#define ISCSI_REASON_IMMEDIATE_COMMAND_REJECT   0x06
#define ISCSI_REASON_TASK_IN_PROGRESS           0x07
#define ISCSI_REASON_INVALID_SNACK              0x08
#define ISCSI_REASON_INVALID_PDU_FIELD          0x09
#define ISCSI_REASON_BOOKMARK_REJECT            0x0a
#define ISCSI_REASON_NEGOTIATION_RESET          0x0b
#define ISCSI_REASON_WAITING_LOGOUT             0x0c

struct iscsi_reject_hdr {
        u8  opcode;
        u8  flags;
        u8  reason;
        u8  rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 ffffffff;
        u32 rsvd3;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 data_sn;
        u32 rsvd4[2];
} __packed;

struct iscsi_login_req_hdr {
        u8  opcode;
        u8  flags;
        u8  max_version;            /* Max version supported */
        u8  min_version;            /* Min version supported */
        u8  ahslenght;
        u8  datalenght[3];
        union iscsi_sid sid;
        u32 itt;                   /* Initiator Task Tag */
        u16 cid;                   /* Connection ID */
        u16 rsvd1;
        u32 cmd_sn;
        u32 exp_stat_sn;
        u32 rsvd2[4];
} __packed;

struct iscsi_login_rsp_hdr {
        u8  opcode;
        u8  flags;
        u8  max_version;            /* Max version supported */
        u8  active_version;         /* Active version supported */
        u8  ahslenght;
        u8  datalenght[3];
        union iscsi_sid sid;
        u32 itt;                   /* Initiator Task Tag */
        u32 rsvd1;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u8  status_class;
        u8  status_detail;
        u8  rsvd2[10];
} __packed;

struct iscsi_text_req_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 itt;
        u32 ttt;
        u32 cmd_sn;
        u32 exp_stat_sn;
        u32 rsvd3[4];
} __packed;

struct iscsi_text_rsp_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 itt;
        u32 ttt;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 rsvd3[3];
} __packed;

#define ISCSI_CMD_FINAL         0x80
#define ISCSI_CMD_READ          0x40
#define ISCSI_CMD_WRITE         0x20
#define ISCSI_CMD_ATTR_MASK     0x07
#define ISCSI_CMD_UNTAGGED      0x00
#define ISCSI_CMD_SIMPLE        0x01
#define ISCSI_CMD_ORDERED       0x02
#define ISCSI_CMD_HEAD_OF_QUEUE 0x03
#define ISCSI_CMD_ACA           0x04

struct iscsi_scsi_cmd_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u16 lun[4];
        u32 itt;
        u32 data_length;
        u32 cmd_sn;
        u32 exp_stat_sn;
        u8  scb[16];
} __packed;

struct iscsi_cdb_ahdr {
        u16 ahslength;
        u8  ahstype;
        u8  reserved;
        u8  cdb[0];
} __packed;

struct iscsi_rlength_ahdr {
        u16 ahslength;
        u8  ahstype;
        u8  reserved;
        u32 read_length;
} __packed;

#define ISCSI_FLG_RESIDUAL_UNDERFLOW            0x02
#define ISCSI_FLG_RESIDUAL_OVERFLOW             0x04
#define ISCSI_FLG_BIRESIDUAL_UNDERFLOW          0x08
#define ISCSI_FLG_BIRESIDUAL_OVERFLOW           0x10

#define ISCSI_RESPONSE_COMMAND_COMPLETED        0x00
#define ISCSI_RESPONSE_TARGET_FAILURE           0x01

struct iscsi_scsi_rsp_hdr {
        u8  opcode;
        u8  flags;
        u8  response;
        u8  cmd_status;
        u8  ahslength;
        u8  datalenght[3];
        u32 revd1[2];
        u32 itt;
        u32 snack;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 exp_data_sn;
        u32 bi_residual_count;
        u32 residual_count;
} __packed;


struct iscsi_sense_data {
        u16 length;
        u8  data[0];
} __packed;

struct iscsi_r2t_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u16 lun[4];
        u32 itt;
        u32 ttt;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 r2t_sn;
        u32 buffer_offset;
        u32 data_length;
} __packed;

struct iscsi_data_out_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u16 lun[4];
        u32 itt;
        u32 ttt;
        u32 rsvd2;
        u32 exp_stat_sn;
        u32 rsvd3;
        u32 data_sn;
        u32 buffer_offset;
        u32 rsvd4;
} __packed;

#define ISCSI_FLG_STATUS        0x01

struct iscsi_data_in_hdr {
        u8  opcode;
        u8  flags;
        u8  rsvd1;
        u8  cmd_status;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 itt;
        u32 ttt;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 data_sn;
        u32 buffer_offset;
        u32 residual_count;
} __packed;

/* NOP-Out Message */
struct iscsi_nop_out_hdr {
        uint8_t opcode;
        uint8_t flags;
        uint16_t rsvd2;
        uint8_t rsvd3;
        uint8_t dlength[3];
        uint8_t lun[8];
        uint32_t itt;        /* Initiator Task Tag */
        uint32_t ttt;        /* Target Transfer Tag */
        uint32_t cmdsn;
        uint32_t exp_statsn;
        uint8_t rsvd4[16];
} __packed;

/* NOP-In Message */
struct iscsi_nop_in_hdr {
        uint8_t opcode;
        uint8_t flags;
        uint16_t rsvd2;
        uint8_t rsvd3;
        uint8_t dlength[3];
        uint8_t lun[8];
        uint32_t itt;        /* Initiator Task Tag */
        uint32_t ttt;        /* Target Transfer Tag */
        uint32_t statsn;
        uint32_t exp_cmdsn;
        uint32_t max_cmdsn;
        uint8_t rsvd4[12];
} __packed;

#define ABORT_TASK          0x0d
#define ABORT_TASK_SET      0x06
#define CLEAR_ACA           0x16
#define CLEAR_TASK_SET      0x0e
#define LOGICAL_UNIT_RESET  0x17
#define TASK_ABORTED         0x20
#define SAM_STAT_TASK_ABORTED    0x40

#define ISCSI_FUNCTION_MASK                     0x7f

#define ISCSI_FUNCTION_ABORT_TASK               1
#define ISCSI_FUNCTION_ABORT_TASK_SET           2
#define ISCSI_FUNCTION_CLEAR_ACA                3
#define ISCSI_FUNCTION_CLEAR_TASK_SET           4
#define ISCSI_FUNCTION_LOGICAL_UNIT_RESET       5
#define ISCSI_FUNCTION_TARGET_WARM_RESET        6
#define ISCSI_FUNCTION_TARGET_COLD_RESET        7
#define ISCSI_FUNCTION_TASK_REASSIGN            8

struct iscsi_task_mgt_hdr {
        u8  opcode;
        u8  function;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u16 lun[4];
        u32 itt;
        u32 rtt;
        u32 cmd_sn;
        u32 exp_stat_sn;
        u32 ref_cmd_sn;
        u32 exp_data_sn;
        u32 rsvd2[2];
} __packed;

#define ISCSI_RESPONSE_FUNCTION_COMPLETE        0
#define ISCSI_RESPONSE_UNKNOWN_TASK             1
#define ISCSI_RESPONSE_UNKNOWN_LUN              2
#define ISCSI_RESPONSE_TASK_ALLEGIANT           3
#define ISCSI_RESPONSE_FAILOVER_UNSUPPORTED     4
#define ISCSI_RESPONSE_FUNCTION_UNSUPPORTED     5
#define ISCSI_RESPONSE_NO_AUTHORIZATION         6
#define ISCSI_RESPONSE_FUNCTION_REJECTED        255

struct iscsi_task_rsp_hdr {
        u8  opcode;
        u8  flags;
        u8  response;
        u8  rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 itt;
        u32 rsvd3;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 rsvd4[3];
} __packed;

#define ISCSI_LOGOUT_SESSION                    0
#define ISCSI_LOGOUT_CONNECTION                 1
#define ISCSI_LOGOUT_CONNECTION_RECOVER         2

struct iscsi_logout_req_hdr {
        u8  opcode;
        u8  flags;
        u16 rsvd1;
        u8  ahslength;
        u8  datalength[3];
        u32 rsvd2[2];
        u32 itt;
        u16 cid;
        u16 rsvd3;
        u32 cmd_sn;
        u32 exp_stat_sn;
        u32 rsvd4[4];
} __packed;

struct iscsi_logout_rsp_hdr {
        u8  opcode;
        u8  flags;
        u8  response;
        u8  rsvd1;
        u8  ahslength;
        u8  datalenght[3];
        u32 rsvd2[2];
        u32 itt;
        u32 ttt;
        u32 stat_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 rsvd4;
        u32 beg_run;
        u32 run_length;
} __packed;

/*
 *      SCSI opcodes
 */

#define TEST_UNIT_READY       0x00
#define REZERO_UNIT           0x01
#define REQUEST_SENSE         0x03
#define FORMAT_UNIT           0x04
#define READ_BLOCK_LIMITS     0x05
#define REASSIGN_BLOCKS       0x07
#define INITIALIZE_ELEMENT_STATUS 0x07
#define READ_6                0x08
#define WRITE_6               0x0a
#define SEEK_6                0x0b
#define READ_REVERSE          0x0f
#define WRITE_FILEMARKS       0x10
#define SPACE                 0x11
#define INQUIRY               0x12
#define RECOVER_BUFFERED_DATA 0x14
#define MODE_SELECT           0x15
#define RESERVE               0x16
#define RELEASE               0x17
#define COPY                  0x18
#define ERASE                 0x19
#define MODE_SENSE            0x1a
#define START_STOP            0x1b
#define RECEIVE_DIAGNOSTIC    0x1c
#define SEND_DIAGNOSTIC       0x1d
#define ALLOW_MEDIUM_REMOVAL  0x1e

#define READ_FORMAT_CAPACITIES 0x23
#define SET_WINDOW            0x24
#define READ_CAPACITY         0x25
#define READ_10               0x28
#define WRITE_10              0x2a
#define SEEK_10               0x2b
#define POSITION_TO_ELEMENT   0x2b
#define WRITE_VERIFY          0x2e
#define VERIFY                0x2f
#define SEARCH_HIGH           0x30
#define SEARCH_EQUAL          0x31
#define SEARCH_LOW            0x32
#define SET_LIMITS            0x33
#define PRE_FETCH             0x34
#define READ_POSITION         0x34
#define SYNCHRONIZE_CACHE     0x35
#define LOCK_UNLOCK_CACHE     0x36
#define READ_DEFECT_DATA      0x37
#define MEDIUM_SCAN           0x38
#define COMPARE               0x39
#define COPY_VERIFY           0x3a
#define WRITE_BUFFER          0x3b
#define READ_BUFFER           0x3c
#define UPDATE_BLOCK          0x3d
#define READ_LONG             0x3e
#define WRITE_LONG            0x3f
#define CHANGE_DEFINITION     0x40
#define WRITE_SAME            0x41
#define UNMAP                      0x42
#define READ_TOC              0x43
#define READ_HEADER           0x44
#define GET_EVENT_STATUS_NOTIFICATION 0x4a
#define LOG_SELECT            0x4c
#define LOG_SENSE             0x4d
#define XDWRITEREAD_10        0x53
#define MODE_SELECT_10        0x55
#define RESERVE_10            0x56
#define RELEASE_10            0x57
#define MODE_SENSE_10         0x5a
#define PERSISTENT_RESERVE_IN 0x5e
#define PERSISTENT_RESERVE_OUT 0x5f
#define VARIABLE_LENGTH_CMD   0x7f
#define REPORT_LUNS           0xa0
#define SECURITY_PROTOCOL_IN  0xa2
#define MAINTENANCE_IN        0xa3
#define MAINTENANCE_OUT       0xa4
#define MOVE_MEDIUM           0xa5
#define EXCHANGE_MEDIUM       0xa6
#define READ_12               0xa8
#define WRITE_12              0xaa
#define READ_MEDIA_SERIAL_NUMBER 0xab
#define WRITE_VERIFY_12       0xae
#define VERIFY_12              0xaf
#define SEARCH_HIGH_12        0xb0
#define SEARCH_EQUAL_12       0xb1
#define SEARCH_LOW_12         0xb2
#define SECURITY_PROTOCOL_OUT 0xb5
#define READ_ELEMENT_STATUS   0xb8
#define SEND_VOLUME_TAG       0xb6
#define WRITE_LONG_2          0xea
#define EXTENDED_COPY         0x83
#define RECEIVE_COPY_RESULTS  0x84
#define ACCESS_CONTROL_IN     0x86
#define ACCESS_CONTROL_OUT    0x87
#define READ_16               0x88
#define COMPARE_AND_WRITE_16  0x89
#define WRITE_16              0x8a
#define READ_ATTRIBUTE        0x8c
#define WRITE_ATTRIBUTE              0x8d
#define VERIFY_16              0x8f
#define SYNCHRONIZE_CACHE_16  0x91
#define WRITE_SAME_16              0x93
#define SERVICE_ACTION_IN     0x9e
#define READ_CAPACITY_16      0x9e
#define PERSISTENT_RESERVE_IN 0x5e
#define PERSISTENT_RESERVE_OUT 0x5f

#define MANAGEMENT_PROTOCOL_IN  0xa3
/* values for service action in */
#define        SAI_READ_CAPACITY_16  0x10
#define SAI_GET_LBA_STATUS    0x12
/* values for VARIABLE_LENGTH_CMD service action codes
 * see spc4r17 Section D.3.5, table D.7 and D.8 */
#define VLC_SA_RECEIVE_CREDENTIAL 0x1800
/* values for maintenance in */
#define MI_REPORT_IDENTIFYING_INFORMATION 0x05
#define MI_REPORT_TARGET_PGS  0x0a
#define MI_REPORT_ALIASES     0x0b
#define MI_REPORT_SUPPORTED_OPERATION_CODES 0x0c
#define MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS 0x0d
#define MI_REPORT_PRIORITY   0x0e
#define MI_REPORT_TIMESTAMP  0x0f
#define MI_MANAGEMENT_PROTOCOL_IN 0x10
/* values for maintenance out */
#define MO_SET_IDENTIFYING_INFORMATION 0x06
#define MO_SET_TARGET_PGS     0x0a
#define MO_CHANGE_ALIASES     0x0b
#define MO_SET_PRIORITY       0x0e
#define MO_SET_TIMESTAMP      0x0f
#define MO_MANAGEMENT_PROTOCOL_OUT 0x10
/* values for variable length command */
#define XDREAD_32              0x03
#define XDWRITE_32              0x04
#define XPWRITE_32              0x06
#define XDWRITEREAD_32              0x07
#define READ_32                      0x09
#define VERIFY_32              0x0a
#define WRITE_32              0x0b
#define WRITE_SAME_32              0x0d


/* Values for T10/04-262r7 */
#define        ATA_16                      0x85        /* 16-byte pass-thru */
#define        ATA_12                      0xa1        /* 12-byte pass-thru */

/*
 * SENSE KEYS
 */

#define NO_SENSE            0x00
#define RECOVERED_ERROR     0x01
#define NOT_READY           0x02
#define MEDIUM_ERROR        0x03
#define HARDWARE_ERROR      0x04
#define ILLEGAL_REQUEST     0x05
#define UNIT_ATTENTION      0x06
#define DATA_PROTECT        0x07
#define BLANK_CHECK         0x08
#define COPY_ABORTED        0x0a
#define ABORTED_COMMAND     0x0b
#define VOLUME_OVERFLOW     0x0d
#define MISCOMPARE          0x0e

/*
 *  SCSI Architecture Model (SAM) Status codes. Taken from SAM-3 draft
 *  T10/1561-D Revision 4 Draft dated 7th November 2002.
 */

#define SAM_STAT_GOOD            0x00
#define SAM_STAT_CHECK_CONDITION 0x02
#define SAM_STAT_CONDITION_MET   0x04
#define SAM_STAT_BUSY            0x08
#define SAM_STAT_INTERMEDIATE    0x10
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14
#define SAM_STAT_RESERVATION_CONFLICT 0x18
#define SAM_STAT_COMMAND_TERMINATED 0x22        /* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL   0x28
#define SAM_STAT_ACA_ACTIVE      0x30
#define SAM_STAT_TASK_ABORTED    0x40

/*
 *  DEVICE TYPES
 *  Please keep them in 0x%02x format for $MODALIAS to work
 */

#define TYPE_DISK           0x00
#define TYPE_TAPE           0x01
#define TYPE_PRINTER        0x02
#define TYPE_PROCESSOR      0x03    /* HP scanners use this */
#define TYPE_WORM           0x04    /* Treated as ROM by our system */
#define TYPE_ROM            0x05
#define TYPE_SCANNER        0x06
#define TYPE_MOD            0x07    /* Magneto-optical disk -
                                     * - treated as TYPE_DISK */
#define TYPE_MEDIUM_CHANGER 0x08
#define TYPE_COMM           0x09    /* Communications device */
#define TYPE_RAID           0x0c
#define TYPE_ENCLOSURE      0x0d    /* Enclosure Services Device */
#define TYPE_RBC            0x0e
#define TYPE_OSD            0x11
#define TYPE_NO_LUN         0x7f

#endif /* _ISCSI_HDR_H */
