#include <sys/statvfs.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/statfs.h>

#define DBG_SUBSYS S_LIBYLIB

#include "configure.h"
#include "net_global.h"
#include "ylib.h"
#include "schedule.h"
#include "chunk.h"
#include "diskid.h"
#include "yfs_md.h"
#include "mds.h"
#include "network.h"
#include "disk.h"
#include "diskmap.h"
#include "cds_rpc.h"
#include "dbg.h"

void chkinfo2str(const chkinfo_t *chkinfo, char *buf)
{
        int i;
        const char *stat;
        const reploc_t *diskid;

        snprintf(buf, MAX_BUF_LEN, "chunk "CHKID_FORMAT" info_version %llu @ ",
                 CHKID_ARG(&chkinfo->chkid), (LLU)chkinfo->md_version);

        for (i = 0; i < (int)chkinfo->repnum; ++i) {
                diskid = &chkinfo->diskid[i];

                if (unlikely(!disktab_online(&diskid->id))) {
                        stat = "offline";
                } else if (diskid->status == __S_DIRTY) {
                        stat = "dirty";
                } else {
                        stat = "clean";
                }

                snprintf(buf + strlen(buf), MAX_NAME_LEN, "%s:%s ",
                         disk_rname(&diskid->id), stat);
        }
}

int chunk_open(chunk_t **_chunk, const chkinfo_t *chkinfo, uint64_t version,
               const ltoken_t *ltoken, const ec_t *ec, int flag)
{
        int ret;
        chunk_t *chunk;

        (void) flag;
        
        ret = huge_malloc((void **)&chunk, sizeof(*chunk));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_init(&chunk->plock, "chunk");
        if (unlikely(ret))
                GOTO(err_free, ret);

        if (chkinfo) {
                YASSERT(chkinfo->size == SDFS_CHUNK_SPLIT);
                chunk->chkinfo = (void *)chunk->__chkinfo__;
                chunk->chkstat = (void *)chunk->__chkstat__;

                CHKINFO_CP(chunk->chkinfo, chkinfo);
                memset(chunk->chkstat, 0x0, CHKSTAT_SIZE(chkinfo->repnum));
        } else {
                chunk->chkinfo = NULL;
                chunk->chkstat = NULL;
        }

        chunk->version = version;

        if (ltoken) {
                chunk->ltoken = *ltoken;
        } else {
                memset(&chunk->ltoken, 0x0, sizeof(chunk->ltoken));
        }
        
        if (ec && ec->plugin) {
                chunk->ec = *ec;
                UNIMPLEMENTED(__DUMP__);
        } else {
                memset(&chunk->ec, 0x0, sizeof(chunk->ec));
                chunk->read = chunk_replica_read;
                chunk->write = chunk_replica_write;
                chunk->recovery = chunk_replica_recovery;
        }

        *_chunk = chunk;

        return 0;
err_free:
        huge_free((void **)chunk);
err_ret:
        return ret;
}

int chunk_update(chunk_t *chunk, const chkinfo_t *chkinfo, uint64_t version)
{
        chunk->chkinfo = (void *)chunk->__chkinfo__;
        chunk->chkstat = (void *)chunk->__chkstat__;
        chunk->version = version;

        CHKINFO_CP(chunk->chkinfo, chkinfo);
        memset(chunk->chkstat, 0x0, CHKSTAT_SIZE(chkinfo->repnum));
        
        return 0;
}


void chunk_close(chunk_t **_chunk)
{
        chunk_t *chunk = *_chunk;

        int ret = plock_trywrlock(&chunk->plock);
        YASSERT(ret == 0);
        plock_unlock(&chunk->plock);

        huge_free((void **)&chunk);
        *_chunk = NULL;
}

static int IO_FUNC __chunk_consistent(const chkid_t *chkid, const reploc_t *reploc,
                                  time_t _ltime)
{
        int ret, offline = 0, reset = 0;
        time_t ltime = 0;
        nid_t nid;

        ret = d2n_nid(&reploc->id, &nid);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);
        
        ret = network_connect(&nid, &ltime, 1, 0);
        if (unlikely(ret)) {
                offline = 1;
                ltime = 0;
        } else {
                if (_ltime != ltime) {
                        reset = 1;
                }
        }

        if (likely(offline == 0 && reset == 0
                   && reploc->status == __S_CLEAN)) {
                DINFO("chunk "CHKID_FORMAT" @ %s offline %d reset"
                     " %d (%lu %lu) status %d\n",
                     CHKID_ARG(chkid), network_rname(&nid),
                     offline, reset, _ltime, ltime, reploc->status);

                return 1;
        }

        if (likely(reset == 0 && reploc->status == __S_DIRTY)) {
                DINFO("chunk "CHKID_FORMAT" @ %s status %d, reset %u\n",
                     CHKID_ARG(chkid), network_rname(&nid),
                     reploc->status, reset);

                return 1;
        }

        DINFO("chunk "CHKID_FORMAT" @ %s offline %d reset"
             " %d (%lu %lu) status %d\n",
             CHKID_ARG(chkid), network_rname(&nid),
             offline, reset, _ltime, ltime, reploc->status);

        return 0;
}

int IO_FUNC chunk_consistent(const vfm_t *vfm, const chunk_t *chunk)
{
        int i, consistent;
        const chkinfo_t *chkinfo = chunk->chkinfo;
        const chkstat_t *chkstat = chunk->chkstat;

        (void) vfm;
        
        DINFO("chunk "CHKID_FORMAT" check\n", CHKID_ARG(&chkinfo->chkid));
        for (i = 0; i < (int)chkinfo->repnum; i++) {
                consistent = __chunk_consistent(&chkinfo->chkid,
                                                &chkinfo->diskid[i],
                                                chkstat->repstat[i].ltime);
                if (unlikely(!consistent)) {
                        return 0;
                }
        }

        return 1;
}

static int __chunk_replica_connect(const diskid_t *diskid, const chkid_t *chkid,
                                   const ltoken_t *token, clockstat_t *clockstat,
                                   repstat_t *repstat, int resuse)
{
        int ret;
        uint32_t sessid;
        time_t ltime;

        ANALYSIS_BEGIN(0);

        if (unlikely(!disktab_online(diskid))) {
                ret = ENODEV;
                GOTO(err_ret, ret);
        }

        nid_t nid;
        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, &ltime, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (resuse) {
                sessid = repstat->sessid;
        } else {
                sessid = fastrandom();
        }
retry:
        ret = cds_rpc_connect(diskid, chkid, token, sessid, clockstat, resuse);
        if (unlikely(ret)) {
                DBUG("connect chunk "CHKID_FORMAT" at %s, ret (%u) %s\n",
                     CHKID_ARG(chkid), disk_rname(diskid),
                     ret, strerror(ret));

                ret = (ret == ENOENT) ? ENODATA : ret;
                if (ret == EKEYEXPIRED) {
                        goto retry;
                } else if (ret == EPERM) {
                        goto err_ret;
                } else {
                        GOTO(err_ret, ret);
                }
        }

#if ENABLE_CHUNK_DEBUG
        DWARN("connect chunk "CHKID_FORMAT" at %s, clock (%u) dirty:%d\n",
              CHKID_ARG(chkid), disk_rname(diskid), clockstat->vclock.clock,
              clockstat->dirty);
#endif

        YASSERT(repstat);
        repstat->ltime = ltime;
        repstat->sessid = sessid;

        ANALYSIS_QUEUE(0, IO_WARN, "chunk_connect");

        return 0;
err_ret:
        return ret;
}

STATIC int __chunk_connect__(chunk_t *chunk)
{
        int ret;
        chkinfo_t *chkinfo = chunk->chkinfo;
        clockstat_t clockstat[SDFS_REPLICA_MAX];
        char _chkstat[CHKSTAT_MAX];
        chkstat_t *chkstat = (void *)_chkstat;

        for (int i = 0; i < (int)chkinfo->repnum; i++) {
                reploc_t *reploc = &chkinfo->diskid[i];
                repstat_t *repstat = &chkstat->repstat[i];

                int consistent = __chunk_consistent(&chkinfo->chkid, reploc,
                                                    repstat->ltime);

                ret = __chunk_replica_connect(&reploc->id, &chkinfo->chkid,
                                              &chunk->ltoken, &clockstat[i],
                                              repstat, consistent);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }

                if (clockstat[i].lost || clockstat[i].dirty) {
                        ret = EAGAIN;
                        GOTO(err_ret, ret);
                }

                YASSERT(repstat->sessid != 0);
        }

        for (int i = 1; i < (int)chkinfo->repnum; i++) {
                if (clockstat[i].vclock.vfm != clockstat[i - 1].vclock.vfm
                    || clockstat[i].vclock.clock != clockstat[i - 1].vclock.clock) {
                        ret = EAGAIN;
                        DINFO("%ju %ju %ju %ju\n", clockstat[i].vclock.vfm,
                              clockstat[i - 1].vclock.vfm,
                              clockstat[i].vclock.clock,
                              clockstat[i - 1].vclock.clock)
                        GOTO(err_ret, ret);
                }
        }

        chkstat->chkstat_clock = clockstat[0].vclock.clock;
        CHKSTAT_CP(chunk->chkstat, chkstat, chkinfo->repnum);

        return 0;
err_ret:
        return ret;
}

STATIC int __chunk_reset(chunk_t *chunk)
{
        int ret;
        chkinfo_t *chkinfo = chunk->chkinfo;
        char _chkstat[CHKSTAT_MAX];
        chkstat_t *chkstat = (void *)_chkstat;

        for (int i = 0; i < (int)chkinfo->repnum; i++) {
                reploc_t *reploc = &chkinfo->diskid[i];
                repstat_t *repstat = &chkstat->repstat[i];
                memset(repstat, 0x0, sizeof(*repstat));
                
                ret = cds_rpc_reset(&reploc->id, &chkinfo->chkid);
                if (unlikely(ret))
                        continue;
        }

        chkstat->chkstat_clock = -1;

        return 0;
}

static int __chunk_recovery(const vfm_t *vfm, chunk_t *chunk)
{
        int ret;

        if (likely(chunk_consistent(vfm, chunk))) {
                DINFO(CHKID_FORMAT"\n", CHKID_ARG(&chunk->chkinfo->chkid));
                goto out;
        }

        ret = __chunk_reset(chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = chunk->recovery(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __chunk_connect__(chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

out:
        return 0;
err_ret:
        return ret;
}

static int __chunk_session_check(const vfm_t *vfm, chunk_t *chunk)
{
        int ret;

        ret = plock_rdlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (chunk->chkinfo == NULL && chunk->chkstat == NULL) {
                ret = ENOENT;
                GOTO(err_lock, ret);
        }
        
        if (likely(chunk_consistent(vfm, chunk))) {
                DINFO(CHKID_FORMAT"\n", CHKID_ARG(&chunk->chkinfo->chkid));
                goto out;
        }

        plock_unlock(&chunk->plock);
        
        ret = plock_wrlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __chunk_recovery(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_lock, ret);

out:
        plock_unlock(&chunk->plock);
        
        return 0;
err_lock:
        plock_unlock(&chunk->plock);
err_ret:
        return ret;
}

static int __chunk_get_token(chunk_t *chunk, int op, io_token_t *token)
{
        int ret;
        chkinfo_t *chkinfo = chunk->chkinfo;
        chkstat_t *chkstat = chunk->chkstat;
        reploc_t *reploc;

        if (chkinfo == NULL) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }
        
        memset(token, 0x0, sizeof(*token));

        int count = 0;
        for (int i = 0; i < (int)chkinfo->repnum; i++) {
                reploc = &chkinfo->diskid[i];
                if (reploc->status & __S_DIRTY) {
                        continue;
                }

                token->repsess[count].diskid = reploc->id;
                YASSERT(token->repsess[count].diskid.id);
                token->repsess[count].sessid = chkstat->repstat[i].sessid;
                YASSERT(token->repsess[count].sessid);
                count++;
        }

        token->repnum = count;
        token->vclock.vfm = 0;
        token->ec = chunk->ec;
        token->id = chkinfo->chkid;

        if (op == OP_WRITE) {
                token->vclock.clock = ++chkstat->chkstat_clock;
        } else {
                token->vclock.clock = chkstat->chkstat_clock;
        }
        
        return 0;
err_ret:
        return ret;
}

int chunk_read(const vfm_t *vfm, chunk_t *chunk, io_t *io)
{
        int ret;
        io_token_t *token;
        char buf[IO_TOKEN_MAX];

        ret = __chunk_session_check(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = plock_rdlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        token = (void *)buf;
        ret = __chunk_get_token(chunk, OP_READ, token);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        ret = chunk->read(token, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&chunk->plock);

        return 0;
err_lock:
        plock_unlock(&chunk->plock);
err_ret:
        return ret;
}

int chunk_write(const vfm_t *vfm, chunk_t *chunk, io_t *io)
{
        int ret;
        io_token_t *token;
        char buf[IO_TOKEN_MAX];

        ret = __chunk_session_check(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = plock_rdlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        token = (void *)buf;
        ret = __chunk_get_token(chunk, OP_WRITE, token);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        ret = chunk->write(token, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&chunk->plock);

        return 0;
err_lock:
        plock_unlock(&chunk->plock);
err_ret:
        return ret;
}

int chunk_get_token(const vfm_t *vfm, chunk_t *chunk, int op, io_token_t *token)
{
        int ret;

        ret = __chunk_session_check(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __chunk_get_token(chunk, op, token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&chunk->plock);
        
        return 0;
err_lock:
        plock_unlock(&chunk->plock);
err_ret:
        return ret;
}

int chunk_recovery(const vfm_t *vfm, chunk_t *chunk)
{
        int ret;

        ret = plock_wrlock(&chunk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __chunk_recovery(vfm, chunk);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&chunk->plock);
        
        return 0;
err_lock:
        plock_unlock(&chunk->plock);
err_ret:
        return ret;
}
