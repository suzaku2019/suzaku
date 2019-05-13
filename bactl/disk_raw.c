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

typedef struct {
        uint32_t magic;
        uuid_t uuid;
        diskid_t diskid;
        uint64_t page_size;
        uint64_t disk_size;
} diskinfo_t;

typedef disk_entry_t entry_t;

static int __disk_raw_hget(int idx, const chkid_t *chkid,
                           uint64_t *offset, size_t *count)
{
        int ret;
        __disk_t *disk;
        char hash[MAX_NAME_LEN], key[MAX_NAME_LEN];
        fileid_t fileid;
        size_t size;

        cid2fid(&fileid, chkid);
        fid2str(&fileid, hash);
        cid2str(chkid, key);

        ret = disk_slot_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        size = (*count) * sizeof(*offset);
        ret = disk_redis_hget(disk->disk_kv, hash, key, offset, &size);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        *count = size / sizeof(*offset);
        
        disk_slot_deref(idx);

        return 0;
err_ref:
        disk_slot_deref(idx);
err_ret:
        return ret;
}

static int __disk_raw_open(disk_t *disk, const chkid_t *chkid,
                           size_t size, entry_t **_ent)
{
        int ret;
        char buf[MAX_BUF_LEN];
        uint64_t *offset;
        size_t count;
        entry_t *ent;
        
        offset = (void *)buf;
        count = MAX_BUF_LEN / sizeof(*offset);

        ret = __disk_raw_hget(disk->idx, chkid, offset, &count);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        YASSERT(disk->page_size * count == size);
        YASSERT(count == 1);
        ret = disk_entry_create(chkid, &ent);
        if (ret)
                GOTO(err_ret, ret);

        ret = huge_malloc((void **)&ent->offset, sizeof(*offset) * count);
        if (ret)
                GOTO(err_free,ret);

        ent->page_count = count;
        ent->page_size = disk->page_size;
        ent->chunk_size = size;
        memcpy(ent->offset, offset, sizeof(*offset) * count);
        *_ent = ent;
        
        return 0;
err_free:
        disk_entry_free(ent);
err_ret:
        return ret;
}

static void __disk_raw_close(disk_t *disk, entry_t *ent)
{
        (void) disk;

        YASSERT(ent->writing == 0);
        YASSERT(ent->ref == 0);
        YASSERT(list_empty(&ent->wlist));
        huge_free((void **)&ent->offset);
        disk_entry_free(ent);
}

static int __disk_raw_hset(int idx, const chkid_t *chkid,
                           uint64_t *offset, size_t count)
{
        int ret;
        __disk_t *disk;
        char hash[MAX_NAME_LEN], key[MAX_NAME_LEN];
        fileid_t fileid;

        cid2fid(&fileid, chkid);
        fid2str(&fileid, hash);
        cid2str(chkid, key);

        ret = disk_slot_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = disk_alloc_new(disk->disk_alloc, offset, count);
        if (ret)
                GOTO(err_ref, ret);
        
        ret = disk_redis_hset(disk->disk_kv, hash, key, offset,
                              sizeof(*offset) * count, O_CREAT);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        disk_slot_deref(idx);

        return 0;
err_ref:
        disk_slot_deref(idx);
err_ret:
        return ret;
}

static int __disk_raw_initzero(disk_t *disk, const chkid_t *chkid,
                               size_t size, const uint64_t *offset, int count)
{
        int ret;
        entry_t *ent;
        io_t io;
        buffer_t buf;

        ret = disk_entry_create(chkid, &ent);
        if (ret)
                GOTO(err_ret, ret);

        ent->page_count = count;
        ent->page_size = disk->page_size;
        ent->chunk_size = size;
        ent->offset = (void *)offset;

        ret = mbuffer_init(&buf, 0);
        if (ret)
                GOTO(err_free, ret);

        ret = mbuffer_appendzero(&buf, size);
        if (ret)
                GOTO(err_free, ret);

        io_init(&io, chkid, size, 0, 0);
        ret = disk->write(disk, ent, &io, &buf);
        if (ret)
                GOTO(err_free1,ret);

        mbuffer_free(&buf);
        disk_entry_free(ent);

        return 0;
err_free1:
        mbuffer_free(&buf);
err_free:
        disk_entry_free(ent);
err_ret:
        return ret;
}

static int __disk_raw_create(disk_t *disk, const chkid_t *chkid,
                                     size_t size, int initzero)
{
        int ret;
        char buf[MAX_BUF_LEN];
        uint64_t *offset;
        size_t count;

        count = size / disk->page_size;
        offset = (void *)buf;
        ret = __disk_raw_hset(disk->idx, chkid, offset, count);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (initzero) {
                ret = __disk_raw_initzero(disk, chkid, size, offset, count);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int disk_raw_create_private(const diskid_t *diskid, disk_t **_disk)
{
        int ret, idx, sync_fd, direct_fd;
        disk_t *disk;
        __disk_t *__disk;
        uint64_t disk_size, page_size;

        ret = disk2idx(diskid, &idx);
        if (ret)
                GOTO(err_ret, ret);

        ret = disk_slot_ref(idx, &__disk);
        if (ret)
                GOTO(err_ret, ret);

        disk_size = __disk->disk_size;
        page_size = __disk->page_size;

        if (__disk->type == DISK_RAW_AIO) {
                direct_fd = open(__disk->device, O_RDWR | O_DIRECT);
                if (direct_fd < 0) {
                        ret = errno;
                        UNIMPLEMENTED(__DUMP__);
                }

                sync_fd = open(__disk->device, O_RDWR | O_SYNC);
                if (sync_fd < 0) {
                        ret = errno;
                        UNIMPLEMENTED(__DUMP__);
                }
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        disk_slot_deref(idx);
        
        ret = disk_create(diskid, &disk);
        if (ret)
                GOTO(err_fd, ret);

        disk->sync_fd = sync_fd;
        disk->direct_fd = direct_fd;
        disk->page_size = page_size;
        disk->disk_size = disk_size;
        disk->write = disk_raw_aio_write;
        disk->read = disk_raw_aio_read;
        disk->open = __disk_raw_open;
        disk->close = __disk_raw_close;
        disk->create = __disk_raw_create;

        *_disk = disk;

        return 0;
err_fd:
        close(sync_fd);
        close(direct_fd);
err_ret:
        return ret;
}

static void __disk_raw_rebuild_alloc__(void *_key, void *_value, void *_size, void *_ctx)
{
        int ret, count;
        const uint64_t *offset = _value;
        const size_t *size = _size;
        disk_alloc_t *disk_alloc = _ctx;

        (void) _key;
        
        count = (*size) % sizeof(*offset);
        ret = disk_alloc_set(disk_alloc, offset, count);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

}

static int __disk_raw_rebuild_alloc(__disk_t *disk)
{
        int ret;
        disk_alloc_t *disk_alloc;

        ret = disk_alloc_create(disk->disk_size, disk->page_size,
                                &disk_alloc);
        if (ret)
                GOTO(err_ret, ret);

        ret = disk_redis_itor(disk->disk_kv, NULL, __disk_raw_rebuild_alloc__,
                              disk_alloc);
        if (ret)
                GOTO(err_close, ret);

        ret= disk_alloc_flush(disk->uuid, disk_alloc);
        if (ret)
                GOTO(err_close, ret);

        disk_alloc_close(disk_alloc);

        return 0;
err_close:
        disk_alloc_close(disk_alloc);
err_ret:
        return ret;
}

static int __disk_raw_load_alloc(__disk_t *disk)
{
        int ret;

retry:
        ret = disk_alloc_open(disk->uuid, disk->disk_size, disk->page_size,
                              (disk_alloc_t **)&disk->disk_alloc);
        if (ret) {
                if (ret == ENOENT) {
                        ret = __disk_raw_rebuild_alloc(disk);
                        if (ret)
                                GOTO(err_ret, ret);

                        goto retry;
                } else {
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        return ret;
}

static int __disk_raw_create__(__disk_t *disk, diskinfo_t *diskinfo)
{
        int ret;

        ret = disk_newid(disk->idx, &disk->diskid);
        if (ret)
                GOTO(err_ret, ret);

        diskinfo->diskid = disk->diskid;
        diskinfo->magic = DISK_RAW_MAGIC;
        diskinfo->page_size = disk->page_size;
        diskinfo->disk_size = disk->disk_size;
        uuid_parse(disk->uuid, diskinfo->uuid);

        if (disk->type == DISK_RAW_AIO) {
                ret = disk_raw_aio_write1(disk->device, (void *)diskinfo,
                                          sizeof(*diskinfo), DISK_RAW_CONFIG);
                if (ret < 0) {
                        ret = -ret;
                        GOTO(err_ret, ret);
                }
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        return 0;
err_ret:
        return ret;
}

static int __disk_raw_load_info(__disk_t *disk)
{
        int ret;
        diskinfo_t diskinfo;
        uuid_t uuid;

        if (disk->type == DISK_RAW_AIO) {
                ret = disk_raw_aio_read1(disk->device, &diskinfo,
                                         sizeof(diskinfo), DISK_RAW_CONFIG);
                if (ret < 0) {
                        ret = -ret;
                        GOTO(err_ret, ret);
                }
        } else {
                UNIMPLEMENTED(__DUMP__);
        }
        
        if (ret < (int)sizeof(diskinfo)) {
                ret = EIO;
                GOTO(err_ret, ret);
        }

        if (diskinfo.magic != DISK_RAW_MAGIC) {
                DINFO("new disk, need init\n");
                ret = __disk_raw_create__(disk, &diskinfo);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                uuid_parse(disk->uuid, uuid);

                if (uuid_compare(uuid, diskinfo.uuid)) {
                        ret = EIO;
                        GOTO(err_ret, ret);
                }

                YASSERT(disk->page_size == diskinfo.page_size);
        }

        disk->diskid = diskinfo.diskid;
        
        DINFO("load disk[%u] id %d\n", disk->idx, diskinfo.diskid.id);

        return 0;
err_ret:
        return ret;
}

static int __disk_raw_load(__disk_t *disk)
{
        int ret;
        char path[MAX_PATH_LEN];

        ret = __disk_raw_load_info(disk);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(path, MAX_PATH_LEN, "%s/redis/%s/redis.socket", ng.home, disk->uuid);
        ret = disk_redis_connect(path, (disk_redis_t **)&disk->disk_kv);
        if (ret)
                GOTO(err_ret, ret);

        ret = __disk_raw_load_alloc(disk);
        if (ret)
                GOTO(err_conn, ret);

        return 0;
err_conn:
        disk_redis_close((disk_redis_t *)disk->disk_kv);
err_ret:
        return ret;
}

static int __disk_raw_stat(__disk_t *disk, disk_info_t *stat)
{
        disk_alloc_t *disk_alloc = disk->disk_alloc;
        bmap_t *bmap = &disk_alloc->bmap;
        
        stat->capacity = (LLU)disk->page_size * bmap->size;
        stat->used = (LLU)disk->page_size * bmap->nr_one;
        stat->latency = 0;

        return 0;
}

int disk_raw_load(__disk_t *disk, const char *home)
{
        int ret;
        struct stat stbuf;
        char pool[MAX_NAME_LEN], disk_size[MAX_NAME_LEN], page_size[MAX_NAME_LEN];

        ret = disk_config_load(home, disk->idx,
                               "device", disk->device,
                               "pool", pool,
                               "faultdomain", disk->faultdomain,
                               "uuid", disk->uuid,
                               "disk_size", disk_size,
                               "page_size", page_size,
                               NULL);
        if (ret)
                GOTO(err_ret, ret);

        if (strcmp(disk->device, "null") == 0
            || strcmp(disk_size, "null") == 0
            || strcmp(page_size, "null") == 0
            || strcmp(disk->uuid, "null") == 0) {
                ret = ENODEV;
                GOTO(err_ret, ret);
        }

        disk->poolid = atoll(pool);
        disk->disk_size = atoll(disk_size);
        disk->page_size = atoll(page_size);
        YASSERT(disk->page_size == DISK_RAW_PAGE); //multi page not support this version

        ret = stat(disk->device, &stbuf);
        if (ret < 0) {
                ret = errno;
                goto err_ret;
        }
        
        ret = __disk_raw_load(disk);
        if (ret) {
                GOTO(err_ret, ret);
        }

        disk->stat = __disk_raw_stat;
        
        return 0;
err_ret:
        return ret;
}
