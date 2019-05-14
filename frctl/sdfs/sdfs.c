#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define DBG_SUBSYS S_YFSLIB

#include "ylib.h"
#include "net_global.h"
#include "network.h"
#include "main_loop.h"
#include "schedule.h"
#include "md_lib.h"
#include "sdfs_lib.h"
#include "sdfs_chunk.h"
#include "io_analysis.h"
#include "core.h"
#include "volume.h"
#include "dbg.h"

int sdfs_read_sync(sdfs_ctx_t *ctx, const fileid_t *fileid,
                   buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        volume_t *volume;

        (void) ctx;

        ret = volume_open(&volume, fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = volume_read1(volume, _buf, size, offset);
        if (ret)
                GOTO(err_close, ret);
        
        volume_close(&volume);
        
        return size;
err_close:
        volume_close(&volume);
err_ret:
        return -ret;
}

int sdfs_write_sync(sdfs_ctx_t *ctx, const fileid_t *fileid,
                    const buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        volume_t *volume;

        (void) ctx;

        ret = volume_open(&volume, fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = volume_write1(volume, _buf, size, offset);
        if (ret)
                GOTO(err_close, ret);
        
        volume_close(&volume);
        
        return size;
err_close:
        volume_close(&volume);
err_ret:
        return -ret;
}

int sdfs_truncate(sdfs_ctx_t *ctx, const fileid_t *fileid, uint64_t length)
{
        int ret;

        (void) ctx;

        volid_t volid = {fileid->poolid, ctx ? ctx->snapvers : 0};
        int retry = 0;
retry:
        ret = md_truncate(&volid, fileid, length);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int sdfs_getxattr(sdfs_ctx_t *ctx, const fileid_t *fileid, const char *name,
                  void *value, size_t *size)
{
        int ret, retry = 0;

        io_analysis(ANALYSIS_OP_READ, 0);

        volid_t volid = {fileid->poolid, ctx ? ctx->snapvers : 0};
retry:
        ret = md_getxattr(&volid, fileid, name, value, size);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int sdfs_removexattr(sdfs_ctx_t *ctx, const fileid_t *fileid, const char *name)
{
        int ret, retry = 0;

        io_analysis(ANALYSIS_OP_WRITE, 0);

        volid_t volid = {fileid->poolid, ctx ? ctx->snapvers : 0};
retry:
        ret = md_removexattr(&volid, fileid, name);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int sdfs_listxattr(sdfs_ctx_t *ctx, const fileid_t *fileid, char *list, size_t *size)
{
        int ret, retry = 0;

        (void) ctx;
        
        io_analysis(ANALYSIS_OP_READ, 0);

        volid_t volid = {fileid->poolid, ctx ? ctx->snapvers : 0};
retry:
        ret = md_listxattr(&volid, fileid, list, size);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int sdfs_setxattr(sdfs_ctx_t *ctx, const fileid_t *fileid, const char *name, const void *value,
                  size_t size, int flags)
{
        int ret, retry = 0;

        (void) ctx;
        md_proto_t *md;
        char buf[MAX_BUF_LEN];

        io_analysis(ANALYSIS_OP_WRITE, 0);
        md = (void *)buf;

        volid_t volid = {fileid->poolid, ctx ? ctx->snapvers : 0};
retry:
        ret = md_getattr(&volid, fileid, md);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        if ((!S_ISREG(md->at_mode)) && (!S_ISDIR(md->at_mode))) {
                ret = EOPNOTSUPP;
                GOTO(err_ret, ret);
        }

        ret = md_setxattr(&volid, fileid, name, value, size, flags);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        USLEEP_RETRY(err_ret, ret, retry, retry, 100, (1000 * 1000));
                } else
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int sdfs_localize(const fileid_t *fileid)
{
        (void) fileid;
        
        UNIMPLEMENTED(__WARN__);

        return 0;
}

