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

static int __seq__ = 0;

static inline void chkid2path(const char *home, const chkid_t *chkid, char *path)
{
        char cpath[MAX_PATH_LEN];

        (void) cascade_id2path(cpath, MAX_PATH_LEN, chkid->id);

        (void) snprintf(path, MAX_PATH_LEN, "%s/chunk/%s/%u.%s",
                        home, cpath, chkid->idx,
                        ftype(chkid));

}

static int __disk_path(int idx, const chkid_t *chkid, char *path)
{
        int ret;
        __disk_t *disk;
        
        ret = disk_slot_ref(idx, &disk);
        if (ret)
                GOTO(err_ret, ret);
        
        chkid2path(disk->home, chkid, path);

        disk_slot_deref(disk->idx);
        
        ret = path_validate(path, YLIB_NOTDIR, YLIB_DIRCREATE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG("path %s\n", path);
        
        return 0;
err_ret:
        return ret;
}

static int __disk_getfd__(va_list ap)
{
        int ret, fd, idx;
        char path[MAX_PATH_LEN];
        const diskid_t *diskid = va_arg(ap, const diskid_t *);
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        uint32_t size = va_arg(ap, uint32_t);
        int *_fd = va_arg(ap, int *);
        char *_path = va_arg(ap, char *);
        int flag = va_arg(ap, int);

        va_end(ap);
        
        ANALYSIS_BEGIN(1);

        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __disk_path(idx, chkid, path);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG("path %s\n", path);
        
        fd = open(path, flag, 0600);
        if (fd < 0) {
                ret = errno;
                DWARN("open %s fail\n", path);
                GOTO(err_ret, ret);
        }

        if (size != (uint32_t)-1) {
                ret = ftruncate(fd, size);
                if (ret < 0) {
                        ret = errno;
                        GOTO(err_close, ret);
                }
        }

        ANALYSIS_QUEUE(1, IO_WARN, NULL);
        
        *_fd = fd;
        if (_path) {
                strcpy(_path, path);
        }
        
        return 0;
err_close:
        close(fd);
err_ret:
        return ret;
}


static int __disk_getfd(const diskid_t *diskid, const chkid_t *chkid,
                        uint32_t size, int *_fd, char *path, int flag)
{
        return schedule_newthread(SCHE_THREAD_DISK, ++__seq__, FALSE,
                                  "getfd", -1, __disk_getfd__,
                                  diskid, chkid, size, _fd, path, flag);
}


static void __disk_release(int fd)
{
        close(fd);
}

static int IO_FUNC __disk_fs_write(disk_t *disk, entry_t *ent, const io_t *io,
                                   const buffer_t *buf)
{
        int ret, fd, iov_count, flag = 0;
        task_t task;
        struct iocb iocb;
        struct iovec iov[Y_MSG_MAX / BUFFER_SEG_SIZE + 1];
        buffer_t tmp;
        char path[MAX_PATH_LEN];

        (void) ent;

        ANALYSIS_BEGIN(0);
        
        mbuffer_init(&tmp, 0);
        mbuffer_clone1(&tmp, buf);

        if (io->offset % SECTOR_SIZE == 0 && io->size % SECTOR_SIZE == 0) {
                flag = O_DIRECT;
        } else {
                flag = O_SYNC;
        }
                
        ret = __disk_getfd(&disk->diskid, &io->id, -1, &fd, path, O_RDWR | flag);
        if (ret)
                GOTO(err_ret, ret);

        iov_count = Y_MSG_MAX / BUFFER_SEG_SIZE + 1;
        ret = mbuffer_trans(iov, &iov_count, &tmp);
        YASSERT(ret == (int)buf->len);

        if (flag == O_DIRECT) {
                for (int i = 0; i < iov_count; i++) {
                        YASSERT(iov[i].iov_len % SECTOR_SIZE == 0);
                        YASSERT((uint64_t)iov[i].iov_base % SECTOR_SIZE == 0);
                }
        }
        
        io_prep_pwritev(&iocb, fd, iov, iov_count, io->offset);

        iocb.aio_reqprio = 0;
        task = schedule_task_get();
        iocb.aio_data = (__u64)&task;

        ret = aio_commit(&iocb, 0);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_fd, ret);
        }

        mbuffer_free(&tmp);
        __disk_release(fd);

        if (ret != (int)buf->len) {
                DWARN("%s, ret %u buflen %u\n", path, ret, buf->len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        ANALYSIS_QUEUE(0, IO_INFO, NULL);
        
        return 0;
err_fd:
        __disk_release(fd);
err_ret:
        mbuffer_free(&tmp);
        return ret;
}

static int IO_FUNC __disk_fs_read(disk_t *disk, entry_t *ent, const io_t *io, buffer_t *buf)
{
        int ret, iov_count, flag = 0;
        int fd;
        task_t task;
        struct iocb iocb;
        struct iovec iov[Y_MSG_MAX / BUFFER_SEG_SIZE + 1];

        (void) ent;
        
        ANALYSIS_BEGIN(0);
        
        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
             CHKID_ARG(&io->id), io->offset, io->size);

        if (io->offset % SECTOR_SIZE == 0 && io->size % SECTOR_SIZE == 0) {
                flag = O_DIRECT;
        } else {
                flag = O_SYNC;
        }
        
        ret = __disk_getfd(&disk->diskid, &io->id, -1, &fd, NULL,
                              O_RDONLY | flag);
        if (ret)
                GOTO(err_ret, ret);

        YASSERT(buf->len == 0);
        mbuffer_init(buf, io->size);
        iov_count = Y_MSG_MAX / BUFFER_SEG_SIZE + 1;
        ret = mbuffer_trans(iov, &iov_count, buf);
        DBUG("ret %u %u\n", ret, buf->len);
        YASSERT(ret == (int)buf->len);

        io_prep_preadv(&iocb, fd, iov, iov_count, io->offset);

        iocb.aio_reqprio = 0;
        task = schedule_task_get();
        iocb.aio_data = (__u64)&task;

        ret = aio_commit(&iocb, 0);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_fd, ret);
        }

        __disk_release(fd);

        ANALYSIS_QUEUE(0, IO_INFO, NULL);
        
        return 0;
err_fd:
        __disk_release(fd);
err_ret:
        return ret;
}

static int IO_FUNC __disk_fs_open(disk_t *disk, const chkid_t *chkid,
                                  size_t size, entry_t **_ent)
{
        int ret;
        char path[MAX_PATH_LEN];
        struct stat stbuf;
        entry_t *ent;

        ret = __disk_path(disk->idx, chkid, path);
        if (ret)
                GOTO(err_ret, ret);

        ret = stat(path, &stbuf);
        if (ret < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = disk_entry_create(chkid, &ent);
        if (ret)
                GOTO(err_ret, ret);

        ent->chunk_size = size;
        *_ent = ent;
        
        return 0;
err_ret:
        return ret;
}

static void __disk_fs_close(disk_t *disk, entry_t *ent)
{
        (void) disk;

        YASSERT(ent->writing == 0);
        YASSERT(ent->ref == 0);
        YASSERT(list_empty(&ent->wlist));
        disk_entry_free(ent);
}

static int IO_FUNC __disk_fs_create(disk_t *disk, const chkid_t *chkid,
                                    size_t size, int initzero)
{
        int ret, fd;
        char path[MAX_PATH_LEN];

        (void) initzero;
        
        ret = __disk_getfd(&disk->diskid, chkid, size, &fd, path, O_RDWR | O_CREAT);
        if (ret)
                GOTO(err_ret, ret);

        __disk_release(fd);

        return 0;
err_ret:
        return ret;
}

struct sche_thread_ops disk_ops = {
        .type           = SCHE_THREAD_DISK,
        .begin_trans    = NULL,
        .commit_trans   = NULL,
};

int disk_fs_thread_init()
{
        int ret;
        
        ret = sche_thread_ops_register(&disk_ops, disk_ops.type, 7);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int disk_fs_create_private(const diskid_t *diskid, disk_t **_disk)
{
        int ret;
        disk_t *disk;

        ret = disk_create(diskid, &disk);
        if (ret)
                GOTO(err_ret, ret);

        disk->write = __disk_fs_write;
        disk->read = __disk_fs_read;
        disk->open = __disk_fs_open;
        disk->close = __disk_fs_close;
        disk->create = __disk_fs_create;

        *_disk = disk;
        
        return 0;
err_ret:
        return ret;
}

static int __disk_fs_create__(__disk_t *disk, int idx)
{
        int ret;
        char path[MAX_PATH_LEN], buf[MAX_BUF_LEN];
        const char *dir = disk->home;

        ret = disk_newid(idx, &disk->diskid);
        if (ret)
                GOTO(err_ret, ret);

        nid2str(buf, &disk->diskid);
        
        snprintf(path, MAX_PATH_LEN, "%s/diskid", dir);
        ret = _set_text(path, buf, strlen(buf) + 1, O_EXCL | O_CREAT);
        if (ret) {
                UNIMPLEMENTED(__DUMP__);
                GOTO(err_ret, ret);
        }

        snprintf(path, MAX_PATH_LEN, "%s/uuid", dir);
        ret = _set_text(path, disk->uuid, strlen(disk->uuid) + 1, O_EXCL | O_CREAT);
        if (ret) {
                UNIMPLEMENTED(__DUMP__);
                GOTO(err_ret, ret);
        }
        
        return 0;
err_ret:
        return ret;
}

static int __disk_fs_load(__disk_t *disk)
{
        int ret;
        char path[MAX_PATH_LEN], buf[MAX_BUF_LEN];
        const char *dir = disk->home;

        snprintf(path, MAX_PATH_LEN, "%s/diskid", dir);

        ret = _get_text(path, buf, MAX_NAME_LEN);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_ret, ret);
        } else {
                str2nid(&disk->diskid, buf);
                YASSERT(disk->diskid.id);
        }

        snprintf(path, MAX_PATH_LEN, "%s/uuid", dir);
        ret = _get_text(path, buf, MAX_NAME_LEN);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_ret, ret);
        }

        if (strncmp(disk->uuid, buf, sizeof(disk->uuid))) {
                ret = EIO;
                GOTO(err_ret, ret);
        }
        
        return 0;
err_ret:
        return ret;
}

static int __disk_fs_stat(__disk_t *disk, disk_info_t *stat)
{
        int ret;
        struct statvfs fsbuf;

        ret = statvfs(disk->home, &fsbuf);
        if (ret)
                GOTO(err_ret, ret);

        stat->capacity = (LLU)fsbuf.f_blocks * fsbuf.f_bsize;
        stat->used = (LLU)fsbuf.f_blocks * fsbuf.f_bavail;
        stat->latency = 0;
        
        return 0;
err_ret:
        return ret;
}

int disk_fs_load(__disk_t *disk, const char *home)
{
        int ret;
        struct stat stbuf;
        char device[MAX_PATH_LEN], pool[MAX_NAME_LEN];

        ret = disk_config_load(home, disk->idx,
                              "device", device,
                              "pool", pool,
                              "faultdomain", disk->faultdomain,
                              "uuid", disk->uuid,
                              NULL);
        if (ret)
                GOTO(err_ret, ret);

        disk->poolid = atoll(pool);
        snprintf(disk->home, MAX_PATH_LEN, "%s/filesystem/%s", home, disk->uuid);
        
        ret = stat(disk->home, &stbuf);
        if (ret < 0) {
                ret = errno;
                goto err_ret;
        }
        
        ret = __disk_fs_load(disk);
        if (ret) {
                if (ret == ENOENT) {
                        ret = __disk_fs_create__(disk, disk->idx);
                        if (ret)
                                GOTO(err_ret, ret);
                } else {
                        GOTO(err_ret, ret);
                }
        }

        DINFO("load disk[%u] id %d\n", disk->idx, disk->diskid.id);

        disk->stat = __disk_fs_stat;
        
        return 0;
err_ret:
        return ret;
}
