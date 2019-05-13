#include <sys/types.h>
#include <limits.h>
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
#include <sys/eventfd.h>
#include <hiredis/hiredis.h>
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
#include "bmap.h"
#include "schedule.h"
#include "dbg.h"


static int __disk_alloc_load_bitmap(const char *path, size_t size, disk_alloc_t *disk_alloc)
{
        int ret;
        struct stat stbuf;

        ret = stat(path, &stbuf);
        if (ret < 0) {
                ret = errno;
                DWARN("path %s\n", path);
                GOTO(err_ret, ret);
        }
 
        YASSERT((size_t)stbuf.st_size == size / CHAR_BIT);

        int fd = open(path, O_RDWR, 0);
        if (fd < 0) {
                ret = errno;
                DWARN("path %s\n", path);
                GOTO(err_ret, ret);
        }

        void *addr = mmap(0, stbuf.st_size, PROT_WRITE | PROT_READ,
                        MAP_LOCKED | MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
                ret = errno;
                GOTO(err_fd, ret);
        }

        bmap_load(&disk_alloc->bmap, addr, stbuf.st_size);
        disk_alloc->map_fd = fd;
        disk_alloc->map_size = stbuf.st_size;
        
        return 0;
err_fd:
        close(fd);
err_ret:
        return ret;
}

int disk_alloc_create(size_t disk_size, size_t page_size, disk_alloc_t **_disk_alloc)
{
        int ret;
        disk_alloc_t *disk_alloc;
        size_t bmap_size;
        
        ret = ymalloc((void **)&disk_alloc, sizeof(*disk_alloc));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        bmap_size = _align_down((disk_size - DISK_RAW_OFFSET) / page_size, CHAR_BIT);

        disk_alloc->map_fd = -1;
        disk_alloc->map_size = bmap_size;
        disk_alloc->page_size = page_size;
        disk_alloc->disk_size = disk_size;
        ret = bmap_create(&disk_alloc->bmap, bmap_size);
        if (unlikely(ret))
                GOTO(err_free, ret);

        *_disk_alloc = disk_alloc;
        
        return 0;
err_free:
        yfree((void **)&disk_alloc);
err_ret:
        return ret;
}

int disk_alloc_flush(const char *uuid, const disk_alloc_t *disk_alloc)
{
        int ret;
        char path[MAX_PATH_LEN], tmp[MAX_PATH_LEN];
        struct stat stbuf;

        YASSERT(disk_alloc->map_fd == -1);
        
        snprintf(path, MAX_PATH_LEN, "/dev/shm/%s/bitmap/%s", SYSYTEM_NAME, uuid);

        ret = path_validate(path, YLIB_NOTDIR, YLIB_DIRCREATE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        sprintf(tmp, "%s.tmp", path);

        ret = stat(path, &stbuf);
        YASSERT(ret != 0);

        int fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
                ret = errno;
                if (ret == EEXIST) {
                        DERROR("create %s exist\n", tmp);
                        YASSERT(0 && "why?");
                }
                GOTO(err_ret, ret);
        }

        ret = _pwrite(fd, disk_alloc->bmap.bits, disk_alloc->bmap.len, 0);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_fd, ret);
        }

        fsync(fd);
        close(fd);

        ret = rename(tmp, path);
        if (ret < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        return 0;
err_fd:
        close(fd);
err_ret:
        return ret;
}

void disk_alloc_close(disk_alloc_t *disk_alloc)
{
        if (disk_alloc->map_fd != -1) {
                munmap(disk_alloc->bmap.bits, disk_alloc->map_size);
                close(disk_alloc->map_fd);
        }
                
        bmap_destroy(&disk_alloc->bmap);
        yfree((void **)&disk_alloc);
}

int disk_alloc_set(disk_alloc_t *disk_alloc, const uint64_t *offset, int count)
{
        int ret;

        YASSERT(disk_alloc->map_fd == -1);
        
        for (int i = 0; i < (int)count; i++) {
                ret = bmap_set(&disk_alloc->bmap, offset[i]);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int disk_alloc_open(const char *uuid, size_t disk_size, size_t page_size,
                    disk_alloc_t **_disk_alloc)
{
        int ret;
        char path[MAX_PATH_LEN];
        disk_alloc_t *disk_alloc;
        size_t bmap_size;

        snprintf(path, MAX_PATH_LEN, "/dev/shm/%s/bitmap/%s", SYSYTEM_NAME, uuid);

        ret = ymalloc((void **)&disk_alloc, sizeof(*disk_alloc));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = sy_rwlock_init(&disk_alloc->rwlock, "disk_alloc");
        if (unlikely(ret))
                GOTO(err_ret, ret);

        bmap_size = _align_down((disk_size - DISK_RAW_OFFSET) / page_size, CHAR_BIT);
        disk_alloc->page_size = page_size;
        disk_alloc->disk_size = disk_size;

        ret = __disk_alloc_load_bitmap(path, bmap_size, disk_alloc);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        *_disk_alloc = disk_alloc;
        
        return 0;
err_ret:
        return ret;
}

int disk_alloc_new(disk_alloc_t *disk_alloc, uint64_t *offset, int count)
{
        int ret;
        uint64_t p;

        YASSERT(disk_alloc->map_fd != -1);
        
        ret = sy_rwlock_wrlock(&disk_alloc->rwlock);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }
        
        for (int i = 0; i < (int)count; i++) {
                p = bmap_get_empty(&disk_alloc->bmap);
                if (p == (uint64_t)-1) {
                        ret = ENOSPC;
                        GOTO(err_lock, ret);
                }

                ret = bmap_set(&disk_alloc->bmap, p);
                YASSERT(ret == 0);
                
                offset[i] = p * disk_alloc->page_size;
        }

        sy_rwlock_unlock(&disk_alloc->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&disk_alloc->rwlock);
err_ret:
        return ret;
}

int disk_alloc_free(disk_alloc_t *disk_alloc, const uint64_t *offset, int count)
{
        int ret;

        YASSERT(disk_alloc->map_fd != -1);
        
        ret = sy_rwlock_wrlock(&disk_alloc->rwlock);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }
        
        for (int i = 0; i < (int)count; i++) {
                if (offset[i] != (uint64_t)-1) {
                        ret = bmap_del(&disk_alloc->bmap, offset[i]);
                        if (unlikely(ret))
                                GOTO(err_lock, ret);
                }
        }

        sy_rwlock_unlock(&disk_alloc->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&disk_alloc->rwlock);
err_ret:
        return ret;
}

