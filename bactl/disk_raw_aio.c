#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSCDS

#include "network.h"
#include "cds.h"
#include "disk.h"
#include "md_proto.h"
#include "ylib.h"
#include "ynet_rpc.h"
#include "sdfs_lib.h"
#include "aio.h"
#include "diskid.h"
#include "md_lib.h"
#include "bh.h"
#include "net_global.h"
#include "nodeid.h"
#include "mds_rpc.h"
#include "mem_cache.h"
#include "adt.h"
#include "schedule.h"
#include "dbg.h"

#define SECTOR_SIZE 512

typedef disk_entry_t entry_t;

int IO_FUNC disk_raw_aio_write(disk_t *disk, entry_t *ent,
                                      const io_t *io, const buffer_t *buf)
{
        int ret, fd, iov_count;
        task_t task;
        struct iocb iocb;
        struct iovec iov[Y_MSG_MAX / BUFFER_SEG_SIZE + 1];
        buffer_t tmp;
        char path[MAX_PATH_LEN];

        (void) ent;

        ANALYSIS_BEGIN(0);
        
        mbuffer_init(&tmp, 0);
        mbuffer_clone1(&tmp, buf);

        iov_count = Y_MSG_MAX / BUFFER_SEG_SIZE + 1;
        ret = mbuffer_trans(iov, &iov_count, &tmp);
        YASSERT(ret == (int)buf->len);

        if (io->offset % SECTOR_SIZE == 0 && io->size % SECTOR_SIZE == 0) {
                fd = disk->direct_fd;

                for (int i = 0; i < iov_count; i++) {
                        YASSERT(iov[i].iov_len % SECTOR_SIZE == 0);
                        YASSERT((uint64_t)iov[i].iov_base % SECTOR_SIZE == 0);
                }
        } else {
                fd = disk->sync_fd;
        }

        YASSERT(ent->page_count == 1);
        io_prep_pwritev(&iocb, fd, iov, iov_count, io->offset + ent->offset[0]
                        + DISK_RAW_OFFSET);

        iocb.aio_reqprio = 0;
        task = schedule_task_get();
        iocb.aio_data = (__u64)&task;

        ret = aio_commit(&iocb, 0);
        if (ret < 0) {
                ret = -ret;
                UNIMPLEMENTED(__DUMP__);
                GOTO(err_ret, ret);
        }

        mbuffer_free(&tmp);

        if (ret != (int)buf->len) {
                DWARN("%s, ret %u buflen %u\n", path, ret, buf->len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        ANALYSIS_QUEUE(0, IO_INFO, NULL);
        
        return 0;
err_ret:
        mbuffer_free(&tmp);
        return ret;
}

int IO_FUNC disk_raw_aio_read(disk_t *disk, entry_t *ent,
                              const io_t *io, buffer_t *buf)
{
        int ret, iov_count;
        int fd;
        task_t task;
        struct iocb iocb;
        struct iovec iov[Y_MSG_MAX / BUFFER_SEG_SIZE + 1];

        (void) ent;
        
        ANALYSIS_BEGIN(0);
        
        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
             CHKID_ARG(&io->id), io->offset, io->size);

        YASSERT(buf->len == 0);
        mbuffer_init(buf, io->size);
        iov_count = Y_MSG_MAX / BUFFER_SEG_SIZE + 1;
        ret = mbuffer_trans(iov, &iov_count, buf);
        DBUG("ret %u %u\n", ret, buf->len);
        YASSERT(ret == (int)buf->len);

        if (io->offset % SECTOR_SIZE == 0 && io->size % SECTOR_SIZE == 0) {
                fd = disk->direct_fd;

                for (int i = 0; i < iov_count; i++) {
                        YASSERT(iov[i].iov_len % SECTOR_SIZE == 0);
                        YASSERT((uint64_t)iov[i].iov_base % SECTOR_SIZE == 0);
                }
        } else {
                fd = disk->sync_fd;
        }
        
        YASSERT(ent->page_count == 1);
        io_prep_preadv(&iocb, fd, iov, iov_count, io->offset + ent->offset[0]
                       + DISK_RAW_OFFSET);

        iocb.aio_reqprio = 0;
        task = schedule_task_get();
        iocb.aio_data = (__u64)&task;

        ret = aio_commit(&iocb, 0);
        if (ret < 0) {
                ret = -ret;
                UNIMPLEMENTED(__DUMP__);
                GOTO(err_ret, ret);
        }

        ANALYSIS_QUEUE(0, IO_INFO, NULL);
        
        return 0;
err_ret:
        return ret;
}

int disk_raw_aio_read1(const char *path, void *buf, size_t size, off_t offset)
{
        int ret, fd;
        
        fd = open(path, O_RDONLY);
        if (fd < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = pread(fd, buf, size, offset);
        if (ret < 0) {
                ret = errno;
                GOTO(err_close, ret);
        }

        close(fd);

        return ret;
err_close:
        close(fd);
err_ret:
        return -ret;
}

int disk_raw_aio_write1(const char *path, const void *buf, size_t size, off_t offset)
{
        int ret, fd;
        
        fd = open(path, O_RDWR);
        if (fd < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = pwrite(fd, buf, size, offset);
        if (ret < 0) {
                ret = errno;
                GOTO(err_close, ret);
        }

        close(fd);

        return ret;
err_close:
        close(fd);
err_ret:
        return -ret;
}
