#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define DBG_SUBSYS S_YFSLIB

#include "sdfs_id.h"
#include "ylib.h"
#include "md_lib.h"
#include "chk_proto.h"
#include "network.h"
#include "net_global.h"
#include "chk_proto.h"
#include "net_global.h"
#include "net_table.h"
#include "redis.h"
#include "sdfs_lib.h"
#include "sdfs_chunk.h"
#include "network.h"
#include "yfs_limit.h"
#include "cds_rpc.h"
#include "diskid.h"
#include "disk.h"
#include "schedule.h"
#include "chunk.h"
#include "dbg.h"

typedef struct {
        io_t io;
        const diskid_t *diskid;
        const buffer_t *buf;
        task_t *task;
        int size;
        int offset;
        int *sub_task;
        int retval;
} chunk_write_ctx_t;

static void __chunk_replica_write__(void *arg)
{
        int ret;
        chunk_write_ctx_t *ctx = arg;
        
        ret = disk_connect(ctx->diskid, NULL, 1, 0);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        ret = cds_rpc_write(ctx->diskid, &ctx->io, ctx->buf);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        ctx->retval = 0;
        *ctx->sub_task = *ctx->sub_task - 1;
        if (*ctx->sub_task == 0)
                schedule_resume(ctx->task, 0, NULL);

        return;
err_ret:
        ctx->retval = ret;
        *ctx->sub_task = *ctx->sub_task - 1;
        if (*ctx->sub_task == 0)
                schedule_resume(ctx->task, 0, NULL);

        return;
}

int chunk_replica_write(const io_token_t *token, io_t *io)
{
        int ret, i, success = 0, sub_task = 0;
        chunk_write_ctx_t _ctx[YFS_CHK_REP_MAX], *ctx;
        task_t task;

        ANALYSIS_BEGIN(0);

        DINFO("write "CHKID_FORMAT", size %u, offset %ju\n", CHKID_ARG(&io->id),
              io->size, io->offset); 

        io->vclock = token->vclock;
        io->ltoken = token->ltoken;
        YASSERT(io->vclock.clock);
        
        task = schedule_task_get();
        sub_task = token->repnum;
        for (i = 0; i < token->repnum; i++) {
                ctx = &_ctx[i];
                ctx->buf = io->buf;
                YASSERT(io->buf);
                ctx->diskid = &token->repsess[i].diskid;
                DBUG("write "CHKID_FORMAT" replica[%u] disk %u\n",
                     CHKID_ARG(&io->id), i, ctx->diskid->id);
                YASSERT(ctx->diskid->id);
                ctx->task = &task;
                ctx->sub_task = &sub_task;
                ctx->io = *io;
                schedule_task_new("replica_write", __chunk_replica_write__, ctx, -1);
        }

        ret = schedule_yield("replica_wait", NULL, NULL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        for (i = 0; i < token->repnum; i++) {
                ctx = &_ctx[i];
                if (ctx->retval == 0)
                        success++;
        }

        if (unlikely(success != token->repnum)) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        ANALYSIS_QUEUE(0, IO_WARN, NULL);
        
        return 0;
err_ret:
        return ret;
}

int chunk_replica_read(const io_token_t *token, io_t *io)
{
        int ret, i, repnum;
        diskid_t array[YFS_CHK_REP_MAX];

        ANALYSIS_BEGIN(0);
        
        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
             CHKID_ARG(&io->id), io->offset, io->size);

        io->vclock = token->vclock;
        io->ltoken = token->ltoken;
        
        repnum = 0;
        for (i = 0; i < token->repnum; i++) {
                array[i] = token->repsess[i].diskid;
                repnum++;
        }

        if (repnum == 0) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }
        
        netable_sort(array, repnum);
        
        for (i = 0; i < repnum; i++) {
                ret = cds_rpc_read(&array[i], io, io->buf);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }

                break;
        }

        if (i == repnum) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }

        DBUG("read "CHKID_FORMAT" success\n", CHKID_ARG(&io->id));

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_ret:
        DBUG("read "CHKID_FORMAT" fail\n", CHKID_ARG(&io->id));
        return ret;
}

int chunk_replica_recovery(chunk_t *chunk)
{
        (void) chunk;

        UNIMPLEMENTED(__DUMP__);

        return 0;
#if 0
        int ret, repmin, i;
        fileid_t fileid;
        fileinfo_t md;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_SIZE(YFS_CHK_REP_MAX)];
        time_t begin, now;
        reploc_t *reploc;

        DINFO("recovery "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        chkinfo = (void *)_chkinfo;
        cid2fid(&fileid, chkid);
        ret = md_getattr(NULL, &fileid, (void *)&md);
        if (ret)
                GOTO(err_ret, ret);

        repmin = (md.plugin != PLUGIN_NULL) ? md.k : 1;

        begin = gettime();
        ret = klock(NULL, chkid, 20, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = md_chunk_newdisk(chkid, chkinfo, repmin, NEWREP_NORMAL);
        if (ret) {
                GOTO(err_lock, ret);
        }

        if (md.plugin == PLUGIN_NULL) {
                ret = __sdfs_chunk_sync(&md, chkinfo);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                ret = __sdfs_chunk_sync_ec(&md, chkinfo);
                if (ret)
                        GOTO(err_lock, ret);
        }

        for (i = 0; i < (int)chkinfo->repnum; i++) {
                reploc = &chkinfo->diskid[i];
                reploc->status &= (~__S_DIRTY);

                //YASSERT(reploc->status == 0);
                DBUG("status %u\n", reploc->status);
        }

        now = gettime();
        if (now - begin > 10) {
                ret = ETIMEDOUT;
                GOTO(err_lock, ret);
        }
        
        ret = md_chunk_update(chkinfo);
        if (ret)
                GOTO(err_lock, ret);
        
        ret = kunlock(NULL, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DINFO("recovery "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        
        return 0;
err_lock:
        kunlock(NULL, chkid);
err_ret:
        DWARN("recovery "CHKID_FORMAT" fail\n", CHKID_ARG(chkid));
        return ret;
#endif
}

