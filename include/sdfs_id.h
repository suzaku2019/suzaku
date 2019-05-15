#ifndef __SDFS_ID_H__
#define __SDFS_ID_H__

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

//do not add new include here
#include "sdfs_conf.h"

extern int srv_running;

#pragma pack(8)

#define ROOT_ID  1
#define ROOT_PID  0
#define ROOT_IDX 0
//#define ftype_pool (LLU)1
#define ROOT_NAME "/"

#define INVALID_UID ((uid_t)-1)
#define INVALID_GID ((gid_t)-1)

#define KB 1024
#define MB 1048576
#define GB 1073741824 //1024^3
#define TB 1099511627776

#define MINUTE 60
#define HOUR 3600
#define DAY 86400
#define MONTH 2592000
#define YEAR 31104000

#ifndef IN
#define IN
#endif
#ifndef INOUT
#define INOUT
#endif
#ifndef OUT
#define OUT
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#ifndef ERROR_FAILED
#define ERROR_FAILED -1
#endif

typedef struct __task_t {
        int16_t taskid;
        int16_t scheduleid;
        uint32_t fingerprint;
        //void *schedule;
} task_t;

#pragma pack(8)

typedef struct {
        uintptr_t local_addr;
        uintptr_t remote_addr;
        uint32_t  lkey;
        uint32_t  rkey;
        uint32_t  size;
} data_prop_t;

typedef struct {
        uint32_t idx;
        uint32_t figerprint;
        uint16_t tabid;
        uint32_t opcode;
#if ENABLE_RDMA
        data_prop_t data_prop;
#endif
} msgid_t;

#pragma pack()

typedef struct {
        uint64_t id;
        uint32_t status; /*dirty*/
} verid64_t;

typedef struct {
        uint64_t volid;
        uint64_t snapvers;
} volid_t;

typedef uint32_t chkidx_t;

typedef struct {
        uint64_t id;
        uint64_t poolid;
        chkidx_t idx; /*chunk idx*/
        uint16_t type;
        uint16_t __pad__;
} chkid_t;

typedef enum {
        ftype_null = 0,
        ftype_root = 1,
        ftype_pool = 2,
        ftype_dir = 3,
        ftype_file = 4,
        ftype_sub = 5,
        ftype_raw = 6,
        ftype_max = 7,
} ftype_t;

static inline const char *ftype(const chkid_t *t)
{
        char *array[] = {"null", "raw", "pool", "dir", "vol", "subvol", "raw"};

        if (t->type > ftype_max) {
                return array[0];
        } else {
                return array[t->type];
        }
}

static inline int stype(int type)
{
        if (type == ftype_null) {
                return 0;
        } else if (type == ftype_pool) {
                return __S_IFDIR;
        } else if (type == ftype_dir) {
                return __S_IFDIR;
        } else if (type == ftype_file) {
                return __S_IFREG;
        } else if (type == ftype_root) {
                return 0;
        } else {
                return 0;
        }
}

typedef chkid_t fileid_t;
typedef chkid_t dirid_t;
typedef chkid_t poolid_t;

typedef struct {
        uint32_t crc;
        uint32_t version; /*yfs meta version*/
        char buf[0];
} crc_t;

#pragma pack()

#define OBJID_FORMAT " %llu_v%llu[%u]"
#define OBJID_ARG(__id__) (LLU)(__id__)->id, (LLU)(__id__)->poolid, (__id__)->idx

#define FID_FORMAT " %llu_v%llu[%u]"
#define FID_ARG(__id__) (LLU)(__id__)->id, (LLU)(__id__)->poolid, (__id__)->idx

#define DISKID_FORMAT "%llu"
#define DISKID_ARG(_id) (LLU)(_id)->id

#define NID_FORMAT "%llu"
#define NID_ARG(_id) (LLU)(_id)->id

#define CHKID_FORMAT "%s-%llu-%llu-%u"
#define CHKID_ARG(_id) ftype((_id)), (LLU)(_id)->poolid, (LLU)(_id)->id, (_id)->idx

#define FILEID_FORMAT "%s-%llu-%llu"
#define FILEID_ARG(_id) ftype((_id)), (LLU)(_id)->poolid, (LLU)(_id)->id

#define JOBID_FORMAT " %u[%u] "
#define JOBID_ARG(__id__) (__id__)->idx, (__id__)->seq

#define RPCID_FORMAT " %u[%u]-[%u] "
#define RPCID_ARG(__id__) (__id__)->tabid, (__id__)->idx, (__id__)->figerprint

#define ID_VID_FORMAT " %llu_v%llu"
#define ID_VID_ARG(__id__) (LLU)(__id__)->id, (LLU)(__id__)->poolid

#define NEED_EAGAIN(ret) (ret == EAGAIN || ret == EBUSY || ret == ETIMEDOUT || ret == ENONET || ret == ENOTCONN)
#define NEED_RETRY(ret) NEED_EAGAIN(ret)

static inline void cid2fid(fileid_t *fileid, const chkid_t *chkid)
{
        *fileid = *chkid;
        fileid->idx = 0;
        fileid->type = ftype_file;
}

static inline void fid2cid(chkid_t *chkid, const fileid_t *fileid, int chkno)
{
        *chkid = *fileid;
        chkid->idx = chkno;
        chkid->type = ftype_raw;
}

static inline void id2vid(uint64_t volid, fileid_t *fileid)
{
    fileid->id = volid;
    fileid->poolid = volid;
    fileid->idx = 0;
    fileid->type = ftype_pool;
}

static inline void fid2str(const fileid_t *fileid, char *str)
{
        assert(fileid->idx == 0);
        assert(fileid->type == ftype_pool
               || fileid->type == ftype_dir
               || fileid->type == ftype_file);
        snprintf(str, MAX_NAME_LEN, FILEID_FORMAT, FILEID_ARG(fileid));
}

static inline void cid2str(const chkid_t *chkid, char *str)
{
        snprintf(str, MAX_NAME_LEN, CHKID_FORMAT, CHKID_ARG(chkid));
}

static inline int chkid_null(const chkid_t *id)
{
        if ((id->poolid == 0) && (id->id == 0) && (id->idx == 0)) {
            return 1;
        } else {
            return 0;
        }
}

static inline int chkid_cmp(const chkid_t *keyid, const chkid_t *dataid)
{
        int ret;

        if (keyid->poolid < dataid->poolid) {
                ret = -1;
        } else if (keyid->poolid > dataid->poolid) {
                ret = 1;
        } else {
                if (keyid->id < dataid->id)
                        ret = -1;
                else if (keyid->id > dataid->id)
                        ret = 1;
                else {
                        if (keyid->type < dataid->type) {
                                ret = -1;
                        } else if (keyid->type > dataid->type) {
                                ret = 1;
                        } else {
                                if (keyid->idx < dataid->idx)
                                        ret = -1;
                                else if (keyid->idx > dataid->idx)
                                        ret = 1;
                                else
                                        ret = 0;
                        }
                }
        }

        return ret;
}

#define fileid_cmp chkid_cmp

#pragma pack(8)

typedef struct {
        uint16_t id;
} ynet_net_nid_t;

typedef ynet_net_nid_t nid_t;
typedef ynet_net_nid_t diskid_t;

typedef struct {
        diskid_t id;
        uint16_t status;
} reploc_t;

typedef struct {
        nid_t nid;
        uint16_t idx;
} coreid_t;

#pragma pack()

typedef enum {
        NET_HANDLE_NULL,
        NET_HANDLE_PERSISTENT, /*constant connect*/
        NET_HANDLE_TRANSIENT, /*temporary connect*/
} net_handle_type_t;

typedef struct {
        uint32_t addr;
        uint32_t seq;
        int sd;
        int type;
} sockid_t;

typedef struct {
        net_handle_type_t type;
        union {
                ynet_net_nid_t nid;
                sockid_t  sd;
        } u;
} net_handle_t;

typedef struct {
        uint64_t vfm;
        uint64_t clock;
} vclock_t;

typedef struct {
        uint32_t master;
        uint64_t seq;
} ltoken_t;

typedef struct {
        vclock_t vclock;
        uint16_t dirty;
        uint16_t lost;
} clockstat_t;

typedef struct {
        chkid_t id;
        uint64_t snapvers;
        vclock_t vclock;
        ltoken_t ltoken;
        union {
                uint64_t offset;
                struct {
                        uint32_t chunk_off:20;  // 1M
                        uint32_t chunk_id:32;
                        uint32_t __pad:12;
                };
        };
        uint32_t size;
        uint32_t flags;
        uint32_t sessid;
        //uint64_t lsn;
        void *buf;
} io_t;


typedef struct {
        uint32_t addr;
        uint32_t port;
} addr_t;

static inline int sockid_cmp(const sockid_t *sock1, const sockid_t *sock2)
{
        if (sock1->addr < sock2->addr)
                return -1;
        else if (sock1->addr > sock2->addr)
                return 1;

        if (sock1->seq < sock2->seq)
                return -1;
        else if (sock1->seq > sock2->seq)
                return 1;

        if (sock1->sd < sock2->sd)
                return -1;
        else if (sock1->sd > sock2->sd)
                return 1;

        return 0;
}

static inline int ynet_nid_cmp(const ynet_net_nid_t *lhs, const ynet_net_nid_t *rhs)
{
        if (lhs->id < rhs->id)
                return -1;
        else if (lhs->id > rhs->id)
                return 1;
        return 0;
}

static inline int net_handle_cmp(const net_handle_t *lhs, const  net_handle_t *rhs)
{
        if (lhs->type == rhs->type) {
                if (lhs->type == NET_HANDLE_PERSISTENT) {
                        return ynet_nid_cmp(&lhs->u.nid, &rhs->u.nid);
                } else {
                        return sockid_cmp(&lhs->u.sd, &rhs->u.sd);
                }
        } else {
                if (lhs->type < rhs->type)
                        return -1;
                else if (lhs->type > rhs->type)
                        return 1;

                if (lhs->u.nid.id < rhs->u.nid.id)
                        return -1;
                else if (lhs->u.nid.id > rhs->u.nid.id)
                        return 1;

                return 0;
        }
}

static inline void id2nh(net_handle_t *nh, const nid_t *id)
{
        nh->u.nid = *id;
        nh->type = NET_HANDLE_PERSISTENT;
}

static inline void sock2nh(net_handle_t *nh, const sockid_t *id)
{
        nh->u.sd = *id;
        nh->type = NET_HANDLE_TRANSIENT;
}

static inline void net_handle_reset(void *_nh)
{
        net_handle_t *nh = (net_handle_t *)_nh;

        nh->type = NET_HANDLE_NULL;
}

static inline void str2nid(nid_t *nid, const char *str)
{
        sscanf(str, "%hu", &nid->id);
}

static inline void str2diskid(diskid_t *diskid, const char *str)
{
        sscanf(str, "%hu", &diskid->id);
}

static inline void nid2str(char *str, const nid_t *nid)
{
        snprintf(str, MAX_NAME_LEN, "%u", nid->id);
}

static inline void io_init(io_t *io, const chkid_t *chkid,
                           uint32_t size, uint64_t offset, uint32_t flags)
{
        memset(io, 0 ,sizeof(io_t));

        if(chkid)
                io->id = *chkid;

        io->offset = offset;
        io->size = size;
        io->flags = flags;

        /*
        io->lsn = 0;
        io->lease = -1;
        */
        io->snapvers = 0;
}

#define VOLUMEID_NULL 0

/* file id 0 means no that file, all file id begins from 1 */
#define FILEID_NULL 0
#define FILEID_FROM 1
#define FILEVER_NULL  0

#endif
