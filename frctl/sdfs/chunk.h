#ifndef __CHUNK_H__
#define __CHUNK_H__

#include <stdint.h>

#include "ylib.h"
#include "chk_proto.h"
#include "net_proto.h"
#include "mds.h"
#include "yfs_md.h"
#include "dbg.h"

#define CHKSTAT_SIZE(__repnum__) (sizeof(chkstat_t) + sizeof(repstat_t) * __repnum__)

#define CHKINFO_MAX (CHKINFO_SIZE(SDFS_REPLICA_MAX))
#define CHKSTAT_MAX (CHKSTAT_SIZE(SDFS_REPLICA_MAX))

#define CHKINFO_CP(__to__, __from__) (memcpy(__to__, __from__, CHKINFO_SIZE(__from__->repnum)))
#define CHKSTAT_CP(__to__, __from__, __count__) (memcpy(__to__, __from__, CHKSTAT_SIZE(__count__)))

#define CHKINFO_STR(__chkinfo__, __buf__)                             \
        do {                                                            \
                int i;                                                  \
                char *chkinfo_str_buf;                                  \
                const char *stat;                                       \
                const reploc_t *diskid;                                 \
                chkinfo_str_buf = __malloc(MAX_BUF_LEN);                \
                chkinfo_str_buf[0] = '\0';                                          \
                for (i = 0; i < (int)__chkinfo__->repnum; ++i) {        \
                        diskid = &__chkinfo__->diskid[i];               \
                        if (ng.daemon) {                                \
                                network_connect(&diskid->id, NULL, 0, 0); \
                        } else {                                        \
                                network_connect(&diskid->id, NULL, 1, 0); \
                        }                                               \
                        if (diskid->status == __S_DIRTY) {              \
                                stat = "dirty";                         \
                        } else if (diskid->status == __S_CHECK) {       \
                                stat = "check";                         \
                        } else if (netable_connected(&diskid->id) == 0) { \
                                stat = "offline";                       \
                        } else {                                        \
                                stat = "clean";                         \
                        }                                               \
                        snprintf(chkinfo_str_buf + strlen(chkinfo_str_buf), MAX_NAME_LEN, "%s:%s ", \
                                 network_rname(&diskid->id), stat);      \
                }                                                       \
                snprintf(__buf__, MAX_BUF_LEN, "chunk "CHKID_FORMAT" info_version %llu @ [%s]", \
                         CHKID_ARG(&__chkinfo__->chkid), (LLU)__chkinfo__->md_version, chkinfo_str_buf); \
                __free(chkinfo_str_buf);                                \
        } while (0);


typedef struct {
        time_t ltime;
        uint32_t sessid;
} repstat_t;

typedef struct {
        uint64_t chkstat_clock;
        repstat_t repstat[0];
} chkstat_t;

typedef struct {
        diskid_t diskid;
        uint32_t sessid;
} repsess_t;

typedef struct {
        chkid_t id;
        ec_t ec;
        ltoken_t ltoken;
        vclock_t vclock;
        int repnum;
        repsess_t repsess[0];
} io_token_t;

typedef struct {
        nid_t nid;
        uint16_t type;
} vfmid_t;

typedef struct {
        uint64_t clock;
        int count;
        vfmid_t array[0];
} vfm_t;

typedef struct __chunk__ {
        plock_t plock;
        ltoken_t ltoken;
        chkinfo_t *chkinfo;
        chkstat_t *chkstat;
        ec_t ec;
        uint64_t version;
        char __chkinfo__[CHKINFO_MAX];
        char __chkstat__[CHKSTAT_MAX];

        int (*read)(const io_token_t *, io_t *);
        int (*write)(const io_token_t *, io_t *);
        int (*recovery)(const vfm_t *vfm, struct __chunk__ *);
} chunk_t;

#define IO_TOKEN_SIZE(__repnum__) (sizeof(io_token_t) + sizeof(repsess_t) * __repnum__)

#define IO_TOKEN_MAX (IO_TOKEN_SIZE(SDFS_REPLICA_MAX))

#define OP_WRITE 1
#define OP_READ 2

int chunk_replica_write(const io_token_t *token, io_t *io);
int chunk_replica_read(const io_token_t *token, io_t *io);

int chunk_replica_recovery(const vfm_t *vfm, chunk_t *chunk);

int chunk_recovery_sync(const vfm_t *vfm, const chkinfo_t *chkinfo);

int chunk_update(chunk_t *chunk, const chkinfo_t *chkinfo, uint64_t version);
int chunk_write(const vfm_t *vfm, chunk_t *chunk, io_t *io);
int chunk_read(const vfm_t *vfm, chunk_t *chunk, io_t *io);
int chunk_open(chunk_t **_chunk, const chkinfo_t *chkinfo, uint64_t version,
               const ltoken_t *ltoken, const ec_t *ec, int flag);
void chunk_close(chunk_t **_chunk);
int chunk_get_token(const vfm_t *vfm, chunk_t *chunk, int op, io_token_t *token);
int chunk_recovery(const vfm_t *vfm, chunk_t *chunk);

void chkinfo2str(const chkinfo_t *chkinfo, char *buf);

#endif
