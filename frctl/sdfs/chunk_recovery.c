#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define DBG_SUBSYS S_YFSLIB

#include "sdfs_id.h"
#include "md_lib.h"
#include "chk_proto.h"
#include "network.h"
#include "net_global.h"
#include "chk_proto.h"
#include "job_dock.h"
#include "ylib.h"
#include "net_global.h"
#include "redis.h"
#include "sdfs_lib.h"
#include "sdfs_chunk.h"
#include "network.h"
#include "cds_rpc.h"
#include "main_loop.h"
#include "md_proto.h"
#include "dbg.h"

static int __sdfs_chunk_pull(const nid_t *nid, const chkid_t *chkid, int *_fd, int chksize)
{
        int ret, fd;
        io_t io;
        buffer_t buf;
        int offset;
        char path[MAX_PATH_LEN];

        DINFO("pull chunk "OBJID_FORMAT"\n", OBJID_ARG(chkid));
        sprintf(path, "/dev/shm/sdfs/l-XXXXXX");

        fd = mkstemp(path);
        if (fd < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        unlink(path);
        
        mbuffer_init(&buf, 0);
        offset = 0;
        while (offset < chksize) {
                io_init(&io, chkid, Y_BLOCK_MAX, offset, 0);
                ret = cds_rpc_read(nid, &io, &buf);
                if (ret) {
                        if (ret == ENOENT) {
                                DWARN("pull chunk "OBJID_FORMAT" ENOENT\n", OBJID_ARG(chkid));
                                YASSERT(offset == 0);
                                mbuffer_appendzero(&buf, chksize);
                        } else {
                                GOTO(err_fd, ret);
                        }
                }

                offset += buf.len;
                //YASSERT(offset > 0 && offset <= chksize);

                ret = mbuffer_writefile(&buf, fd, buf.len);
                if (ret)
                        GOTO(err_fd, ret);

                mbuffer_free(&buf);

                if (buf.len < Y_BLOCK_MAX) {
                        break;
                }
        }

        DINFO("pull chunk "OBJID_FORMAT" success, size %u\n", OBJID_ARG(chkid), offset);
        *_fd = fd;

        return 0;
err_fd:
        *_fd = fd;
err_ret:
        return ret;
}

static int __sdfs_chunk_push(const nid_t *nid, const chkid_t *chkid, int fd, int count)
{
        int ret, offset, size, left;
        void *_buf;
        buffer_t buf;
        io_t io;

        ret = cds_rpc_create(nid, chkid, count, 0);
        if (ret) {
                if (ret == EEXIST) {
                        DWARN(CHKID_FORMAT" @ %s already exist\n",
                              CHKID_ARG(chkid), disk_rname(nid));
                } else 
                        GOTO(err_ret, ret);
        }
        
        ret = ymalloc((void**)&_buf, Y_BLOCK_MAX);
        if (ret)
                GOTO(err_ret, ret);

        left = count;
        offset = 0;
        while (left) {
                size = Y_BLOCK_MAX < left ? Y_BLOCK_MAX : left;
                mbuffer_init(&buf, 0);

                ret = _pread(fd, _buf, size, offset);
                if (ret < 0) {
                        ret = -ret;
                        GOTO(err_free, ret);
                }

                ret = mbuffer_copy(&buf, _buf, size);
                if (ret)
                        GOTO(err_free, ret);

                io_init(&io, chkid, size, offset, 0);
                ret = cds_rpc_sync(nid, &io, &buf);
                if (ret)
                        GOTO(err_free1, ret);

                mbuffer_free(&buf);

                left -= size;
                offset += size;
        }

        yfree((void **)&_buf);

        return 0;
err_free1:
        mbuffer_free(&buf);
err_free:
        yfree((void **)&_buf);
err_ret:
        return ret;
}

int chunk_recovery_sync(const chkinfo_t *chkinfo)
{
        int ret, fd = -1, i;
        int dist_count = 0, src_count = 0;
        nid_t dist[YFS_CHK_REP_MAX], src[YFS_CHK_REP_MAX];
        const reploc_t *reploc;

        for (i = 0; i < (int)chkinfo->repnum; i++) {
                reploc = &chkinfo->diskid[i];

                if (reploc->status & __S_DIRTY) {
                        dist[dist_count] = reploc->id;
                        dist_count++;
                        continue;
                }

                ret = disk_connect(&reploc->id, NULL, 1, 1);
                if (ret)
                        GOTO(err_ret, ret);

                src[src_count] = reploc->id;
                src_count++;
        }

        YASSERT((int)chkinfo->repnum == dist_count + src_count);

        for (i = 0; i < src_count; i++) {
                ret = __sdfs_chunk_pull(&src[i], &chkinfo->chkid, &fd, chkinfo->size);
                if (ret)
                        continue;

                break;
        }

        if (i == src_count) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }

        for (i = 0; i < dist_count; i++) {
                ret = __sdfs_chunk_push(&dist[i], &chkinfo->chkid, fd, chkinfo->size);
                if (ret)
                        GOTO(err_fd, ret);
        }

        close(fd);
        
        return 0;
err_fd:
        close(fd);
err_ret:
        return ret;
}

#if 0
static int __sdfs_chunk_ec_pull_off(buffer_t *recover, unsigned char *src_in_err,
                                   const chkinfo_t *chkinfo, size_t size, off_t offset)
{
        int ret, i;
        io_t io;
        const reploc_t *reploc;

        DINFO("pull chunk "OBJID_FORMAT" repnum %u, size %u\n",
              OBJID_ARG(&chkinfo->chkid), chkinfo->repnum, size);

        io_init(&io, &chkinfo->chkid, size, offset, 0);
        for (i = 0; i < (int)chkinfo->repnum; i++) {
                if (src_in_err[i]) {
                        continue;
                }

                YASSERT(recover[i].len == 0);

                reploc = &chkinfo->diskid[i];
                ret = cds_rpc_read(&reploc->id, &io, &recover[i]);
                if (ret) {
                        if (ret == ENOENT) {
                                mbuffer_appendzero(&recover[i], size);
                        } else
                                GOTO(err_ret, ret);
                } else {
                        if (recover[i].len < size) {
                                DWARN("chunk "OBJID_FORMAT" repnum %u, align %u\n",
                                      OBJID_ARG(&chkinfo->chkid), i, size - recover[i].len);
                                mbuffer_appendzero(&recover[i], size - recover[i].len);
                        }
                }
        }

        return 0;
err_ret:
        return ret;
}

static int __sdfs_chunk_ec_recode_off(buffer_t *recover, unsigned char *src_in_err,
                                      const chkinfo_t *chkinfo, size_t size, const ec_t *ec)
{
        int ret;
        uint32_t i, j, m, k;
        char *buffs[YFS_CHK_REP_MAX];
        char *buf;
        buffer_t tmpbuf;

        mbuffer_init(&tmpbuf, 0);
        m = ec->m;
        k = ec->k;

        YASSERT(m >= k);
        YASSERT((size % STRIP_BLOCK) == 0);

        for (i = 0; i < YFS_CHK_REP_MAX; i++) {
                ret = posix_memalign((void **)&buf, STRIP_ALIGN, STRIP_BLOCK);
                if (ret)
                        GOTO(err_free, ret);

                buffs[i] = buf;
        }

        for (i = 0; i < size / STRIP_BLOCK; i++) {
                for(j = 0; j < chkinfo->repnum; j++) {
                        if (!src_in_err[j]) {
                                mbuffer_get(&recover[j], buffs[j], STRIP_BLOCK);
                                mbuffer_pop(&recover[j], &tmpbuf, STRIP_BLOCK);
                                mbuffer_free(&tmpbuf);
                        }
                }

                ret = ec_decode(src_in_err, &buffs[0], &buffs[k], STRIP_BLOCK, m, k);
                if (ret)
                        GOTO(err_free, ret);

                for(j = 0; j < chkinfo->repnum; j++) {
                        if (src_in_err[j])
                                mbuffer_copy(&recover[j], buffs[j], STRIP_BLOCK);
                }
        }

        for (i = 0; i < YFS_CHK_REP_MAX; i++) {
                if (buffs[i])
                        free(buffs[i]);
        }

        return 0;
err_free:
        mbuffer_free(&tmpbuf);
        for (i = 0; i < YFS_CHK_REP_MAX; i++) {
                if (buffs[i])
                        free(buffs[i]);
        }
        return ret;
}

static int __sdfs_chunk_ec_pull(buffer_t *recover, unsigned char *src_in_err,
                                  const chkinfo_t *chkinfo, const ec_t *ec, int chksize)
{
        int ret;
        size_t left, size;
        off_t offset;

        left = chksize;

        offset = 0;
        while (left) {
                size = Y_BLOCK_MAX < left ? Y_BLOCK_MAX : left;

                ret = __sdfs_chunk_ec_pull_off(recover, src_in_err, chkinfo, size, offset);
                if (ret)
                        GOTO(err_ret, ret);

                ret = __sdfs_chunk_ec_recode_off(recover, src_in_err, chkinfo, size, ec);
                if (ret)
                        GOTO(err_ret, ret);

                left -= size;
                offset += size;
        }

        return 0;
err_ret:
        return ret;
}

static int __sdfs_chunk_ec_push__(const nid_t *nid, const chkid_t *chkid, buffer_t *_buf)
{
        int ret, offset, size, left, count;
        buffer_t buf;
        io_t io;

        mbuffer_init(&buf, 0);

        count = _buf->len;
        left = count;
        offset = 0;
        while (left) {
                size = Y_BLOCK_MAX < left ? Y_BLOCK_MAX : left;
                ret = mbuffer_pop(_buf, &buf, size);
                if (ret)
                        GOTO(err_ret, ret);

                io_init(&io, chkid, size, offset, 0);
                ret = cds_rpc_sync(nid, &io, &buf);
                if (ret)
                        GOTO(err_ret, ret);

                mbuffer_free(&buf);

                left -= size;
                offset += size;
        }

        DBUG("commit chunk "CHKID_FORMAT"\n", CHKID_ARG(chkid));

        return 0;
err_ret:
        mbuffer_free(&buf);
        return ret;
}

static int __sdfs_chunk_ec_push(buffer_t *recover, unsigned char *src_in_err,
                               const chkinfo_t *chkinfo)
{
        int ret, i;
        const fileid_t *id;
        const diskid_t *diskid;

        id = &chkinfo->chkid;

        DBUG("push chunk "FID_FORMAT" count %u\n",
                        FID_ARG(id), chkinfo->repnum);

        for (i = 0; i < (int)chkinfo->repnum; i++) {
                diskid = &chkinfo->diskid[i].id;
                if (!src_in_err[i])
                        continue;
                
                DBUG("push chunk "FID_FORMAT" count %u\n",
                     FID_ARG(id), chkinfo->repnum);

                ret = __sdfs_chunk_ec_push__(diskid, id, &recover[i]);
                if (ret) {
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        return ret;
}

static int __sdfs_chunk_sync_ec__(const chkinfo_t *chkinfo, unsigned char *src_in_err,
                                  const ec_t *ec, int chksize)
{
        int ret, i;
        buffer_t recover[YFS_CHK_REP_MAX];

        for (i = 0; i < ec->m; i++) {
                mbuffer_init(&recover[i], 0);
        }

        ret = __sdfs_chunk_ec_pull(recover, src_in_err, chkinfo, ec, chksize);
        if (ret) {
                GOTO(err_ret, ret);
        }

        ret = __sdfs_chunk_ec_push(recover, src_in_err, chkinfo);
        if (ret) {
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        for (i = 0; i < (int)chkinfo->repnum; i++) {
                mbuffer_free(&recover[i]);
        }
        return ret;
}

int chunk_recovery_sync_ec(const ec_t *ec, const chkinfo_t *chkinfo)
{
        int ret, i;
        unsigned char src_in_err[YFS_CHK_REP_MAX];
        int dist_count = 0, src_count = 0;
        const reploc_t *reploc;
        
        for (i = 0; i < (int)chkinfo->repnum; i++) {
                reploc = &chkinfo->diskid[i];

                if (reploc->status & __S_DIRTY) {
                        dist_count++;
                        src_in_err[i] = 1;
                } else {
                        src_count++;
                        src_in_err[i] = 0;

                        ret = disk_connect(&reploc->id, NULL, 1, 1);
                        if (ret)
                                GOTO(err_ret, ret);
                }
        }

        if (src_count == 0) {
                ret = EBUSY;
                DWARN("chunk "OBJID_FORMAT" not online\n", OBJID_ARG(&chkinfo->chkid));
                goto err_ret;
        } else if ((ec->m - src_count) > (ec->m - ec->k)) {
                ret = EBUSY;
                DWARN("src_count: %d, ec->m: %d, ec->k: %d\n", src_count, ec->m, ec->k);
                GOTO(err_ret, ret);
        }

        YASSERT((int)chkinfo->repnum == dist_count + src_count);
        
        ret = __sdfs_chunk_sync_ec__(chkinfo, src_in_err, ec, chkinfo->size);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
#endif
