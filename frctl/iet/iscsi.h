#ifndef ISCSI_H
#define ISCSI_H

#include <sys/socket.h>
#include <netdb.h>

#include "types.h"
#include "misc.h"
#include "mem_cache.h"
#include "cache.h"
#include "sdfs_lib.h"
#include "iscsi_hdr.h"
#include "sdfs_list.h"
#include "atomic.h"
#include "sdfs_buffer.h"
#include "iscsi_config.h"
#include "volume.h"
#include "ynet_rpc.h"

#define LICHIO_RESET            1
#define USE_CORENET             1

#define YISCSI_VERSION_STRING   "0.1"

#define ISCSI_NR_EPOLL_FD       4096
#define ISCSI_NR_EPOLL_EV       128
#define ISCSI_NR_LISTEN_QUEUE   128

#define VENDOR_ID               "MDS"
#define PRODUCT_ID              "LICH-DISK"
#define PRODUCT_REV             "0"
#define CONFIRM_INTERVAL 20

#define ISCSI_IEEE_VEN_ID       0x60223344
/**
 * Memory cache
 */

#define ISCSI_MEM_CACHE_TARGET          0
#define ISCSI_MEM_CACHE_VOLUME          1
#define ISCSI_MEM_CACHE_CONN            2
#define ISCSI_MEM_CACHE_SESSION         3

#define ISCSI_MEM_CACHE_CMD             0
#define ISCSI_MEM_CACHE_TIO             1
#define ISCSI_MEM_CACHE_NR              2

#define MAX_QUEUE_CMD_MIN        1
#define MAX_QUEUE_CMD_DEF        128
#define MAX_QUEUE_CMD_MAX        512

extern struct iscsi_mem_cache *g_mem_cache[ISCSI_MEM_CACHE_NR];

/**
 * Parameter
 */

#define DIGEST_ALL              (DIGEST_NONE | DIGEST_CRC32C)
#define DIGEST_NONE             (1 << 0)
#define DIGEST_CRC32C           (1 << 1)

enum {
        key_initial_r2t,
        key_immediate_data,
        key_max_connections,
        key_max_recv_data_length,
        key_max_xmit_data_length,
        key_max_burst_length,
        key_first_burst_length,
        key_default_wait_time,
        key_default_retain_time,
        key_max_outstanding_r2t,
        key_data_pdu_inorder,
        key_data_sequence_inorder,
        key_error_recovery_level,
        key_header_digest,
        key_data_digest,
        key_ofmarker,
        key_ifmarker,
        key_ofmarkint,
        key_ifmarkint,

        /* iSCSI Extensions for RDMA (RFC5046) */
        key_rdma_extensions,
        key_target_recv_data_length,
        key_initiator_recv_data_length,
        key_max_outstanding_unexpected_pdus,

        /* must always be last */
        session_key_last,
};

struct iscsi_sess_param {
        int initial_r2t;
        int immediate_data;
        int max_connections;
        u32 max_recv_data_length;
        u32 max_xmit_data_length;
        int max_burst_length;
        u32 first_burst_length;
        int default_wait_time;
        int default_retain_time;
        u32 max_outstanding_r2t;
        int data_pdu_inorder;
        int data_sequence_inorder;
        int error_recovery_level;
        int header_digest;
        int data_digest;
        int ofmarker;
        int ifmarker;
        int ofmarkint;
        int ifmarkint;
        int rdma_extensions;
        int target_recv_data_length;
        int initiator_recv_data_length;
        int max_outstanding_unexpected_pdus;
};

#define DEFAULT_NR_QUEUED_CMDS          32
#define MIN_NR_QUEUED_CMDS              1
#define MAX_NR_QUEUED_CMDS              256

#define ISCSI_TARGET_TYPE_DISK          0
#define ISCSI_TARGET_TYPE_NR_MAX        1

struct iscsi_trgt_param {
        int target_type;
        int queued_cmds;
};

struct iscsi_param {
        int state;
        unsigned int val;
};

struct iscsi_param_node {
        struct list_head entry;
        char *key;
        char *val;
};

/**
 * tio
 */
struct iscsi_tio {
        /* Use for Read/Write */
        u64 io_off;
        u64 io_len;

        buffer_t buffer;

        int count;
        struct iscsi_tio *next_tio; 
};

/**
 * Key
 */

#define KEY_STATE_START         0
#define KEY_STATE_REQUEST       1
#define KEY_STATE_DONE          2

struct iscsi_key;

struct iscsi_key_ops {
        int (*val_to_str)(unsigned int, char *);
        int (*str_to_val)(char *, unsigned int *);
        int (*check_val)(struct iscsi_key *, unsigned int *);
        int (*set_val)(struct iscsi_param *, int, unsigned int *);
};

struct iscsi_key {
        char *name;
        unsigned int def;
        unsigned int min;
        unsigned int max;
        struct iscsi_key_ops *ops;
        unsigned int mask;
};

extern struct iscsi_key session_keys[];
extern struct iscsi_key target_keys[];

/**
 * command
 */

#define cmd_opcode(cmd)         ((cmd)->pdu.bhs.opcode & ISCSI_OPCODE_MASK)
#define cmd_itt(cmd)            cpu_to_be32((cmd)->pdu.bhs.itt)
#define cmd_ttt(cmd)            cpu_to_be32((cmd)->pdu.bhs.ttt)
#define cmd_immediate(cmd)      ((cmd)->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE)
#define cmd_scsi_hdr(cmd)       ((struct iscsi_scsi_cmd_hdr *)(&((cmd)->pdu.bhs)))
#define cmd_scsicode(cmd)       cmd_scsi_hdr(cmd)->scb[0]

struct iscsi_pdu {
        struct iscsi_hdr bhs;
        void *ahs;
        u32 ahssize;
        u32 datasize;
};

#define ISCSI_SENSE_BUF_SIZE    18

/**
 * COMMAND FLAGS
 */

#define CMD_FLG_HASHED          0x0001
#define CMD_FLG_QUEUED          0x0002
#define CMD_FLG_FINAL           0x0004
#define CMD_FLG_WAITIO          0x0008
#define CMD_FLG_CLOSE           0x0010
#define CMD_FLG_CLOSE_SESSION   0x0020
#define CMD_FLG_LUNIT           0x0040
#define CMD_FLG_PENDING         0x0080
#define CMD_FLG_TMF_ABORT       0x0100
#define CMD_FLG_RX_START        0x0200

typedef struct {
        fileid_t fileid;
        void *vm;
} lichbd_ioctx_t;


struct iscsi_cmd {
        struct list_head entry;
        struct list_head conn_entry;

        unsigned long flags;

        /**
         * For any ISCSI request issued over a TCP connection, the corresponding
         * response and/or other related PDU(s)  MUST  be  send  over  the  same
         * connection, this called "connection allegiance" - RFC3720
         */
        struct iscsi_conn *conn;
        struct iscsi_volume *lun;

        struct iscsi_pdu pdu;

        /**
         * List used to link the request cmd and all the corresponding
         * response cmds.
         */
        struct list_head rsp_list;

        struct list_head hash_entry;

        time_t time;
        /**
         * Used for aio
         */

        lichbd_ioctx_t *ioctx;

        struct iscsi_tio *tio;
        //int err;
        uint32_t retry;
        int (*callback)(struct iscsi_cmd *self);

        u8 status;

        u32 r2t_sn;
        u32 r2t_length;
        u32 exp_offset;
        u32 is_unsolicited_data;
        u32 target_task_tag;
        u32 outstanding_r2t;

        u32 hdigest;
        u32 ddigest;

        struct iscsi_cmd *req;

        unsigned char sense_buf[ISCSI_SENSE_BUF_SIZE];
        int sense_len;
};

/**
 * Target
 */

/**
 * Initiators and targets MUST support the receipt of ISCSI name of up to the
 * maximum length of 223 bytes - RFC3720.
 */
#define RESERVE_TID             0
#define TARGET_MAX_LUNS         256

enum iscsi_target_state {
        ITGT_RUNNING,
        ITGT_DEL,
};

struct iscsi_target {
        struct list_head entry;
        u32 tid;
        uint32_t loaded;
        uint8_t         vaai_enabled;
        uint8_t         thin_provisioning;
        char name[ISCSI_IQN_NAME_MAX];
        char pool[MAX_NAME_LEN];
        char path[MAX_NAME_LEN];
        fileid_t fileid;        /* The fileid of target directory in sdfs */

        enum iscsi_target_state stat;

        struct redirect_addr {
                char addr[NI_MAXHOST + 1];
                char port[NI_MAXSERV + 1];
                u8 type;
        } redirect;

        time_t confirm;
        time_t last_scan;
        time_t ctime;

        struct iscsi_sess_param sess_param;
        struct iscsi_trgt_param trgt_param;

        atomic_t nr_volumes;
        struct list_head volume_list;
#if ENABLE_ISCSI_CACHE_REUSE
        mcache_entry_t *volume_entrys[TARGET_MAX_LUNS];
#endif

        volume_t *volume;
        lichbd_ioctx_t ioctx;
};

/**
 * IO Type
 */

struct iotype {
        /**
         * Allocate iotype's private data and point it by the volume's
         * `priv' member, also initialize some volume's parameters.
         */
        int (*attach)(struct iscsi_volume *, void *);

        /** Release the resources allocated in @attach */
        int (*detach)(struct iscsi_volume *);

        int (*update)(struct iscsi_volume *, void *);

        /*
         * IOType's aio interface, when this IO request is done,
         * `cb' will be called.
         */
        int (*aio_read)(struct iscsi_cmd *);
        int (*aio_write)(struct iscsi_cmd *);

        /*
        * Unload data chunks from sepcific volume.
        */
        int (*unmap)(struct iscsi_cmd *, uint64_t, uint32_t);

        /**
         * Flush the data described by `cmd->tio' to disk,
         * sync all data if tio is NULL.
         */
        int (*sync)(struct iscsi_cmd *);
};

/**
 * Logical Unit
 */

enum iscsi_device_state {
        IDEV_RUNNING,
        IDEV_DEL,
};

struct iscsi_queue {
        struct iscsi_cmd *ordered_cmd;
        struct list_head wait_list;
        int active_cnt;
};

#define LU_READONLY             0x00000001
#define LU_WCACHE               0x00000002
#define LU_RCACHE               0x00000004
#define LU_VAAI_ENABLED         0x00000008

#define LUReadonly(lu)          ((lu)->flags & LU_READONLY)
#define SetLUReadonly(lu)       ((lu)->flags |= LU_READONLY)

#define LUWCache(lu)            ((lu)->flags & LU_WCACHE)
#define SetLUWCache(lu)         ((lu)->flags |= LU_WCACHE)
#define ClearLUWCache(lu)       ((lu)->flags & ~LU_WCACHE)

#define LURCache(lu)            ((lu)->flags & LU_RCACHE)
#define SetLURCache(lu)         ((lu)->flags |= LU_RCACHE)
#define ClearLURCache(lu)       ((lu)->flags & ~LU_RCACHE)

#define LUVaai(lu)              ((lu)->flags & LU_VAAI_ENABLED)
#define SetLUVaai(lu)           ((lu)->flags |= LU_VAAI_ENABLED)

#define SCSI_ID_LEN             16
#define SCSI_SN_LEN             (SCSI_ID_LEN * 2)

struct iscsi_volume {
        struct list_head entry;
        struct iscsi_target *target;

        char tname[ISCSI_IQN_NAME_MAX];
        u32 lun;
        fileid_t fileid;

        u32 flags;

        enum iscsi_device_state stat;
        atomic_t count;

        struct iscsi_queue queue;

        u8 scsi_id[SCSI_ID_LEN];
        u8 scsi_sn[SCSI_SN_LEN + 1];

        u32 blk_shift;
        u64 blk_cnt;
        u64 blk_size;

        u64 reserve_sid;

        time_t unavailable;
        struct iotype *iotype;
        void *private;
};

/**
 * Session
 */

#define ISCSI_HASH_ORDER        8
#define ISCSI_UA_HASH_LEN       8

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32   0x9e370001UL

static inline u32 hash_long(u32 val, unsigned int bits)
{
        /* On some cpus multiply is faster, on others gcc will do shifts */
        u32 hash = val * GOLDEN_RATIO_PRIME_32;

        /* High bits are more random, so use them. */
        return hash >> (32 - bits);
}
#define cmd_hashfn(itt)         (hash_long((itt), ISCSI_HASH_ORDER))

#define SESSION_NORMAL          0
#define SESSION_DISCOVERY       1

struct iscsi_session {
        struct list_head entry;
        struct iscsi_target *target;

        u8 type;
        union iscsi_sid sid;

        char *initiator;

        u32 exp_cmd_sn;
        u32 max_cmd_sn;

        struct iscsi_sess_param param;

        u32 max_queued_cmds;

        pthread_spinlock_t conn_lock;
        struct list_head conn_list;
        struct list_head pending_list;

        struct list_head cmd_hash[1 << ISCSI_HASH_ORDER];

        struct list_head ua_hash[ISCSI_UA_HASH_LEN];

        u32 next_ttt;

        /* links all tasks (task->c_hlist) */
        struct list_head cmd_list;
        /* links pending tasks (task->c_list) */
        struct list_head pending_cmd_list;
        /* if this session uses rdma connections */
        int rdma;
};

/**
 * AUTH
 */

#define AUTH_UNKNOWN            -1
#define AUTH_NONE               0
#define AUTH_CHAP               1
#define DIGEST_UNKNOWN          -1

#define AUTH_DIR_INCOMING       0
#define AUTH_DIR_OUTGOING       1

/**
 * Connection
 */

#define STATE_FREE              0
#define STATE_SECURITY          1
#define STATE_SECURITY_AUTH     2
#define STATE_SECURITY_DONE     3
#define STATE_SECURITY_LOGIN    4
#define STATE_SECURITY_FULL     5
#define STATE_LOGIN             6
#define STATE_LOGIN_FULL        7
#define STATE_FULL              8
#define STATE_CLOSE             9
#define STATE_EXIT              10
#define STATE_CLOSED	 	11

#define STATE_SCSI                12
#define STATE_INIT                13
#define STATE_START                14
#define STATE_READY                15

#define IOSTATE_FREE            0
#define IOSTATE_READ_BHS        1
#define IOSTATE_READ_AHS_DATA   2
#define IOSTATE_WRITE_BHS       3
#define IOSTATE_WRITE_AHS       4
#define IOSTATE_WRITE_DATA      5

#define AUTH_STATE_START        0

#define ISCSI_CONN_IOV_MAX      8192

struct iscsi_conn {
        struct list_head entry;
        struct iscsi_session *session;
#if ENABLE_ISCSI_MEM
        struct iscsi_mem_cache *mem_cache[ISCSI_MEM_CACHE_NR];
#endif
        struct iscsi_target *target;

        u16 cid;

        u32 tid;
        char tname[ISCSI_IQN_NAME_MAX];
        union iscsi_sid sid;
        char *initiator;

        unsigned long state;
#if 0
        vm_t *vm;
#endif
        sockid_t sockid;

        u32 stat_sn;
        u32 exp_stat_sn;
        u32 cmd_sn;
        u32 exp_cmd_sn;
        u32 max_cmd_sn;
        u32 ttt;

        int hdigest_type;
        int ddigest_type;

        int conn_fd;
        int login_state;
        int closed;
        buffer_t *buf;
        struct sockaddr_in peer;
        struct sockaddr_in self;

        struct iscsi_param session_param[session_key_last];

        int session_type;

        int auth_method;
        unsigned long auth_state;
        union {
                struct {
                        int digest_alg;
                        int id;
                        int challenge_size;
                        unsigned char *challenge;
                } chap;
        } auth;
        char auth_username[MAX_NAME_LEN];
        char auth_password[MAX_NAME_LEN];

        /**
         * Counter of request cmds and response cmds of this connection, increased
         * when cmd create and decreased when cmd release.
         */
        atomic_t nr_cmds;

        /**
         * Counter of the cmds processing by thread, increased when a cmd insert
         * into thread pool and decreased when thread finish it.
         */
        //atomic_t nr_busy_cmds;

        time_t close_time;
        time_t ltime;
        int waiting_free;

        /**
         * @List of request commands
         * the request cmds is inserted into this list by their @conn_entry member,
         * note that the response cmds _NOT_ in this list, however,  they increase
         * the @nr_cmds counter.
         * (all the response cmds linked into the corresponding request cmds's @rsp_list)
         */
        struct list_head cmd_list;

        /**
         * @List of response commands to be send
         */
        struct list_head write_list;

        /**
         * @List used for text negotiate
         */
        struct list_head param_list;

        struct iscsi_cmd *read_cmd;
        struct msghdr read_msg;
        struct iovec read_iov[ISCSI_CONN_IOV_MAX];
        u32 read_size;
        u32 read_overflow;
        int read_state;

        struct iscsi_cmd *write_cmd;
        struct msghdr write_msg;
        struct iovec write_iov[ISCSI_CONN_IOV_MAX];
        char __align[4];
        u32 write_size;
        int write_state;

        struct iscsi_tio *write_tio;
        u32 write_tio_off;
        u32 write_tio_size;

        int in_check;

        int refcount;
        struct iscsi_transport *tp;
        int rdma;
};

struct ua_entry {
        struct list_head entry;
        struct iscsi_session *session; /* Only used for debugging ATM */
        u32 lun;
        u8 asc;
        u8 ascq;
};

/**
 * Command Hook
 *
 *   @req_op: request  opcode of command, -1 if none.
 *   @rsp_op: response opcode of command, -1 if none.
 * @rx_start: function be called just after the header receive complete and before
 *            data receive.
 *   @rx_end: function be called after data receive done. for the command before
 *            session is established, execute it here directly; otherwise, the
 *            function @iscsi_session_push_command should be called, and do the
 *            real process in @cmd_exec
 * @cmd_exec: see @rx_end
 * @tx_start: set StatSN, ExpCmdSN, MaxCmdSN and other thing here.
 *   @tx_end: command respective process.
 */
struct iscsi_cmd_hook {
        char name[MAX_NAME_LEN];
        char path[MAX_NAME_LEN];
        int req_op, rsp_op;
        int (*rx_start)(struct iscsi_cmd *);
        int (*rx_end)(struct iscsi_cmd *);
        int (*cmd_exec)(struct iscsi_cmd *);
        int (*tx_start)(struct iscsi_cmd *);
        int (*tx_end)(struct iscsi_cmd *);
};

struct sdfs_tgt_entry {
        struct list_head entry;

        char iqn[ISCSI_IQN_NAME_MAX + 1];
        char pool[MAX_NAME_LEN];
        char path[MAX_PATH_LEN];
        fileid_t fileid;

        /*
         * Uss may return errno EAGAIN when call raw_getattr() to a lun,
         * in this case, we set this flag and judge whether discard this
         * lun backwards.
         */
        int delay_check;
};

struct config_operations {
        int (*init)(void);
        int (*scan_target)(struct list_head *tgt_head, struct iscsi_conn *conn);
        int (*free_target)(struct list_head *tgt_head);
        int (*build_target)(const char *, struct sdfs_tgt_entry *);
        int (*scan_lun)(struct iscsi_conn *conn);
        int (*rescan_lun)(struct iscsi_conn *conn);
        int (*scan_async)(void);
        int (*account_query)(struct iscsi_conn *conn, int, char *, char *);
};

#define MAX_LVNAME MAX_NAME_LEN

typedef struct {
        //volumeid_t volid;
        //uint64_t   msize;
        fileid_t   fileid;
        char       vname[MAX_LVNAME];   /* key */
} lv_entry_t;

struct sdfs_ns_entry {
        struct list_head entry;

        lv_entry_t ns;
};

struct load_tgt_entry {
        struct list_head entry;
        fileid_t oid;
        char name[MAX_NAME_LEN];
};

struct sdfs_lun_entry {
        struct list_head entry;

        char path[MAX_PATH_LEN];
        char pool[MAX_PATH_LEN];
        fileid_t fileid;
        uint32_t lun;

        uint32_t blk_shift;
        uint64_t blk_size;

        /*
         * Uss may return errno EAGAIN when call raw_getattr() to a lun,
         * in this case, we set this flag and judge whether discard this
         * lun backwards.
         */
        int delay_check;
};

/**
 * config.c
 */
extern struct config_operations *cops;
extern void sdfs_tgt_free(struct sdfs_tgt_entry *);
extern void sdfs_lun_free(struct sdfs_lun_entry *);
extern struct sdfs_tgt_entry *sdfs_tgt_find(struct list_head *, const char *, fileid_t *);
extern struct sdfs_lun_entry *sdfs_lun_find(struct list_head *, uint32_t, fileid_t *);

/**
 * target.c
 */
extern void target_put(struct iscsi_target *);
extern void target_del(struct iscsi_target *);
extern int target_free(struct iscsi_target *target);
extern int target_alloc_by_name(const char *name, struct iscsi_target **_tgt);
extern void target_list_entry_build(struct iscsi_cmd *, char *);

extern void target_add_lun_nolock(struct iscsi_target *, struct iscsi_volume *);
extern void target_del_lun_nolock(struct iscsi_target *, struct iscsi_volume *);

extern int target_lichbd_connect(struct iscsi_target *target);

extern int target_redirect(int, struct iscsi_target *);
extern int target_redirected(struct iscsi_conn *, struct iscsi_target *);

extern int iser_target_redirect(struct iscsi_conn *, struct iscsi_target *);

extern int target_islocal(struct iscsi_target *);
extern int target_localize_confirm(struct iscsi_target *);

extern int target_connect(struct iscsi_target *, const char *addr, int port);
extern int target_disconnect(struct iscsi_target *, const char *addr, int port);

/**
 * worker.c
 */
extern int worker_thread_init(void);
extern int worker_thread_queue(struct iscsi_cmd *);

/**
 * volume.c
 */
extern struct iscsi_volume *volume_get(struct iscsi_target *, u32);
extern void volume_put(struct iscsi_volume *);
extern void volume_del(struct iscsi_volume *);
extern int volume_is_reserved(struct iscsi_volume *, u64);
extern int volume_reserve(struct iscsi_volume *, u64);
extern int volume_release(struct iscsi_volume *, u64, int);
extern void volume_apply_change(struct iscsi_target *, struct list_head *);
extern void volume_apply_lun0(struct iscsi_target *target, struct sdfs_lun_entry *lu);

/**
 * event.c
 */
extern int iscsi_listen(void);

/**
 * session.c
 */
extern int session_init();
extern int session_create(struct iscsi_conn *);
extern int session_remove(struct iscsi_session *sess);
extern void session_free(struct iscsi_session *);
extern struct iscsi_session *session_find_by_id(u64);
extern struct iscsi_session *session_find_by_name(char *, union iscsi_sid, chkid_t *chkid);

/**
 * conn.c
 */
extern int conn_alloc(struct iscsi_conn **);
extern int conn_add(struct iscsi_session *, struct iscsi_conn *);
extern int conn_empty(struct iscsi_session *sess);
extern void conn_close(struct iscsi_conn *);
extern struct iscsi_conn *conn_find(struct iscsi_session *, u16);
extern void conn_busy_get(struct iscsi_conn *);
extern int conn_busy_put(struct iscsi_conn *);
extern void conn_busy_tryfree(struct iscsi_conn *);
extern void conn_update_stat_sn(struct iscsi_cmd *);

/**
 * param.c
 */
extern int param_list_build(struct list_head *, struct iscsi_cmd *);
extern void param_list_destroy(struct list_head *);
extern char *param_list_find(struct list_head *, char *);
extern int param_index_by_name(char *, struct iscsi_key *, int *);
extern void param_set_defaults(struct iscsi_param *, struct iscsi_key *);
extern void param_partial_set(struct iscsi_sess_param *, int, u32);
extern void param_adjust_sess(struct iscsi_param *, struct iscsi_sess_param *);
extern int param_val_to_str(struct iscsi_key *, int, unsigned int, char *);
extern int param_str_to_val(struct iscsi_key *, int, char *, unsigned int *);
extern int param_check_val(struct iscsi_key *, int, unsigned int *);
extern int param_set_val(struct iscsi_key *, struct iscsi_param *, int, unsigned int *);

/**
 * cmds.c
 */
extern int iscsi_cmd_hook_init(void);
extern struct iscsi_cmd_hook *iscsi_cmd_hook_get(int);

extern struct iscsi_cmd *create_sense_rsp(struct iscsi_cmd *req,
                                          u8 sense_key, u8 asc, u8 ascq);
extern void set_offset_and_length(struct iscsi_volume *lu, u8 *cmd, loff_t *off, u32 *len);
extern void cmd_skip_data(struct iscsi_cmd *req);
/**
 * target_disk.c
 */
extern int disk_execute_cmd(struct iscsi_cmd *cmd);
extern struct iscsi_cmd *create_scsi_rsp(struct iscsi_cmd *req);
extern int target_cmd_queue(struct iscsi_cmd *cmd);

/**
 * IO type supported
 */
extern struct iotype lich_io;
int lichio_init(void);

/**
 * tio.c
 */
extern struct iscsi_tio *tio_alloc(struct iscsi_conn *conn, int);
extern void tio_free(struct iscsi_conn *conn, struct iscsi_tio *tio);
extern void tio_get(struct iscsi_tio *);
extern void tio_put(struct iscsi_conn *conn, struct iscsi_cmd *);
extern void tio_add_param(struct iscsi_cmd *, char *, char *);
extern void tio_set_diskseek(struct iscsi_tio *tio, u64 off, u64 len);
extern int tio_read(struct iscsi_cmd *);
extern int tio_write(struct iscsi_cmd *);
extern int tio_sync(struct iscsi_cmd *);

/**
 * ua.c
 */
extern int ua_pending(struct iscsi_session *, u32);
extern struct ua_entry *ua_get_first(struct iscsi_session *, u32);
extern struct ua_entry *ua_get_match(struct iscsi_session *, u32, u8, u8);
extern void ua_free(struct ua_entry *);
extern void ua_establish_for_session(struct iscsi_session *, u32 lun, u8, u8);

/**
 * digest.c
 */
extern int digest_rx_header(struct iscsi_cmd *);
extern int digest_tx_header(struct iscsi_cmd *);
extern int digest_rx_data(struct iscsi_cmd *);
extern int digest_tx_data(struct iscsi_cmd *);

/**
 * chap.c
 */
extern int cmd_exec_auth_chap(struct iscsi_cmd *, struct iscsi_cmd *);
extern int ns_build_auth_chap(char *name, char *pass, struct iscsi_conn *conn);

/**
 * iscsi.c
 */
extern u32 translate_lun(u16 *);

extern int iser_tio_pool_init();
extern struct iscsi_cmd *iscsi_cmd_alloc(struct iscsi_conn *, int);
extern int iscsi_cmd_release(struct iscsi_cmd *, int);
extern int iscsi_cmd_remove(struct iscsi_cmd *);
extern int iscsi_cmd_check_sn(struct iscsi_cmd *cmd);
extern void iscsi_cmd_set_sn(struct iscsi_cmd *, int);
extern struct iscsi_cmd *iscsi_cmd_find_hash(struct iscsi_session *, u32 itt, u32);
extern int iscsi_cmd_insert_hash(struct iscsi_cmd *);
extern void iscsi_cmd_remove_hash(struct iscsi_cmd *);
extern void iscsi_cmd_init_write(struct iscsi_cmd *);
extern void iscsi_cmd_list_init_write(struct list_head *);
extern void iscsi_cmd_alloc_data_tio(struct iscsi_cmd *cmd);
extern struct iscsi_cmd *iscsi_cmd_create_rsp_cmd(struct iscsi_cmd *, int);
extern struct iscsi_cmd *iscsi_cmd_get_rsp_cmd(struct iscsi_cmd *);
extern void iscsi_cmd_set_sense(struct iscsi_cmd *, u8, u8, u8);
extern void iscsi_cmd_skip_pdu(struct iscsi_cmd *);
extern void iscsi_cmd_reject(struct iscsi_cmd *, int);
extern int iscsi_cmd_recv_pdu(struct iscsi_conn *conn, struct iscsi_tio *tio, u32 offset, u32 size);
extern void iscsi_cmd_send_pdu(struct iscsi_conn *, struct iscsi_cmd *);
extern void iscsi_cmd_send_pdu_tio(struct iscsi_conn *, struct iscsi_tio *, u32, u32);
extern void iscsi_cmd_set_length(struct iscsi_pdu *);
extern void iscsi_cmd_get_length(struct iscsi_pdu *);
extern u32 iscsi_cmd_read_size(struct iscsi_cmd *);
extern u32 iscsi_cmd_write_size(struct iscsi_cmd *);
extern void iscsi_session_push_cmd(struct iscsi_cmd *);
extern int cmd_rx_start(struct iscsi_cmd *cmd);
extern int cmd_rx_end(struct iscsi_cmd *cmd);
extern int cmd_tx_start(struct iscsi_cmd *);
extern int cmd_tx_end(struct iscsi_cmd *);

/**
 * iscsid.c
 */
extern void iscsid_send(struct iscsi_conn *conn);
extern void iscsid_recv(struct iscsi_conn *conn);
extern void iscsid_exec(struct iscsi_cmd *cmd);
extern int iscsi_connection_check(struct iscsi_conn *conn);
extern int iscsi_session_check(struct iscsi_conn *conn);
extern int iscsi_check_vip(struct iscsi_conn *conn);
extern void iscsid_close(struct iscsi_conn *conn);

/**
 * debug.c
 */
extern void iscsi_dump_pdu(struct iscsi_pdu *);
extern void iscsi_dump_pdu_list(struct iscsi_cmd *);
extern void iscsi_dump_tio(struct iscsi_tio *);
extern void iscsi_dump_ua(struct ua_entry *, struct iscsi_session *, u32);
extern void iscsi_dump_session_param(struct iscsi_sess_param *param);

int tio_unmap(struct iscsi_cmd *cmd, uint64_t lba, uint32_t len);

/**
 * Extra
 */
extern int rdma_running;
extern int srv_running;

#endif /* ISCSI_H */
