/*Volume Session*/

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#define DBG_SUBSYS S_YFSMDS

#include "ylib.h"
#include "net_table.h"
#include "configure.h"
#include "net_global.h"
#include "mem_cache.h"
#include "yfs_md.h"
#include "pa_srv.h"
#include "plock.h"
#include "variable.h"
#include "cds_rpc.h"
#include "chunk.h"
#include "md_lib.h"
#include "partition.h"
#include "ringlock.h"
#include "range.h"
#include "chunk.h"
#include "vs_chunk.h"
#include "core.h"
#include "dbg.h"

static int __vs_chunk_connect(vs_range_t *range, const chkid_t *chkid, uint32_t *magic)
{
        int ret;
        
        if (likely(range->coreid.nid.id)) {
                goto out;
        }

        ret = range_chunk_location(chkid, &range->coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        range->magic = fastrandom();
        if (likely(range->ec.plugin == 0)) {
                range->read = chunk_replica_read;
                range->write = chunk_replica_write;
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

out:
        *magic = range->magic;
        
        return 0;
err_ret:
        return ret;
}

static void __vs_chunk_reset(vs_range_t *range, uint32_t magic)
{
        if (range->magic != magic) {
                return;
        }

        range->coreid.nid.id = 0;
        range->coreid.idx = 0;
        range->magic = 0;
}

static int __vs_range_token(vs_range_t *range, const chkid_t *chkid,
                            int op, io_token_t *token)
{
        int ret;
        uint32_t magic;

        ret = __vs_chunk_connect(range, chkid, &magic);
        if (ret)
                GOTO(err_ret, ret);

        if (core_islocal(&range->coreid)) {
                ret = range_ctl_get_token(chkid, op, token);
                if (ret)
                        GOTO(err_reset, ret);
        } else {
                ret = range_rpc_get_token(&range->coreid, chkid, op, token);
                if (ret)
                        GOTO(err_reset, ret);
        }

        return 0;
err_reset:
        __vs_chunk_reset(range, magic);
err_ret:
        return ret;
}

int vs_chunk_write(vs_range_t *range, const chkid_t *chkid, const buffer_t *buf,
                   int size, uint64_t offset)
{
        int ret;
        io_token_t *token;
        char _token[IO_TOKEN_MAX];
        io_t io;

        DINFO("write "CHKID_FORMAT", size %u, offset %ju\n", CHKID_ARG(chkid),
              size, offset);
        
        ANALYSIS_BEGIN(0);

        token = (void *)_token;
        ret = __vs_range_token(range, chkid, OP_WRITE, token);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        io_init(&io, &token->id, size, offset, 0);
        io.buf = (void *)buf;
        ret = range->write(token, &io);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_ret:
        return ret;
}

int vs_chunk_read(vs_range_t *range, const chkid_t *chkid, buffer_t *buf,
                   int size, uint64_t offset)
{
        int ret;
        io_token_t *token;
        char _token[IO_TOKEN_MAX];
        io_t io;

        DINFO("read "CHKID_FORMAT", size %u, offset %ju\n", CHKID_ARG(chkid),
              size, offset);

        ANALYSIS_BEGIN(0);

        token = (void *)_token;
        ret = __vs_range_token(range, chkid, OP_READ, token);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        io_init(&io, &token->id, size, offset, 0);
        io.buf = (void *)buf;
        ret = range->read(token, &io);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_ret:
        return ret;
}

