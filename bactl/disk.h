#ifndef __DISK_H__
#define __DISK_H__

#include <stdint.h>
#include <semaphore.h>
#include <hiredis/hiredis.h>

#include "sdfs_conf.h"
#include "bmap.h"
#include "sdfs_buffer.h"

#define MAX_SUBMIT 256
#define MAX_DISK 256
#define DISK_RAW_CONFIG (1048576)
#define DISK_RAW_PAGE (SDFS_CHUNK_SPLIT)
#define DISK_RAW_OFFSET (DISK_RAW_CONFIG + 1048576)
#define DISK_RAW_MAGIC (0x1427B5AE)

typedef struct {
        struct list_head hook;
        chkid_t chkid;
        vclock_t vclock;
        time_t begin;
        uint32_t sessid;
        task_t task;
        void *entry;
} wlist_t;

typedef struct {
        chkid_t chkid;
        plock_t plock;
        sy_spinlock_t spin;
        vclock_t vclock;
        uint32_t sessid;
        uint16_t writing;
        uint16_t ref;
        struct list_head wlist;

        //for disk raw
        uint64_t *offset;
        uint16_t page_count;
        uint32_t page_size;
        uint32_t chunk_size;
} disk_entry_t;

typedef struct {
        uint64_t capacity;
        uint64_t used;
        uint64_t latency;
} disk_info_t;

typedef struct __disk {
        int type;
        int idx;
        int lockfd;
        uint64_t disk_size;
        uint64_t page_size;
        uint64_t poolid;
        diskid_t diskid;
        char device[MAX_PATH_LEN];
        char faultdomain[MAX_PATH_LEN];
        char home[MAX_PATH_LEN];
        char uuid[UUID_LEN];
        void *disk_alloc;
        void *disk_kv;
        int (*stat)(struct __disk *, disk_info_t *stat);
} __disk_t;

typedef struct __disk__ {
        int idx;
        diskid_t diskid;
        plock_t plock;
        htab_t htab;
        uint64_t disk_size;
        uint64_t page_size;


        union {
                uint64_t xxx;
                struct {
                        int sync_fd;
                        int direct_fd;
                };
        };
        
        int (*read)(struct __disk__ *, disk_entry_t *, const io_t *io, buffer_t *buf);
        int (*write)(struct __disk__ *, disk_entry_t *, const io_t *io, const buffer_t *buf);

        int (*create)(struct __disk__ *, const chkid_t *chkid, size_t size, int initzero);
        int (*open)(struct __disk__ *, const chkid_t *chkid, size_t size, disk_entry_t **);
        void (*close)(struct __disk__ *, disk_entry_t *);
} disk_t;

typedef enum {
        DISK_FS,
        DISK_RAW_AIO, //raw with aio
        DISK_RAW_SPDK,//raw with spdk
} disk_type_t;

int disk_newid(int idx, diskid_t *diskid);
int disk_stat(const diskid_t *diskid, disk_info_t *stat);
int disk_ref(disk_t *disk, const chkid_t *chkid, disk_entry_t **_ent);
int disk_deref(disk_t *disk, disk_entry_t *ent);
int disk_slot_private_ref(int idx, disk_t **_disk);
void disk_slot_private_deref(int idx);
int disk_slot_ref(int idx, __disk_t **_disk);
void disk_slot_deref(int idx);
int disk_entry_create(const chkid_t *chkid, disk_entry_t **_ent);
void disk_entry_free(disk_entry_t *ent);
int disk_create(const diskid_t *diskid, disk_t **_disk);
void disk_destroy(disk_t *disk);
int disk_config_load(const char *home, int idx, ...);

int disk_io_read(const diskid_t *diskid, const io_t *io, buffer_t *buf);
int disk_io_write(const diskid_t *diskid, const io_t *io, const buffer_t *buf);
int disk_io_create(const diskid_t *diskid, const chkid_t *chkid, uint32_t size,
                   int initzero);
int disk_io_connect(const diskid_t *diskid, const chkid_t *chkid,
                    const ltoken_t *ltoken, uint32_t sessid,
                    clockstat_t *clockstat, int force);

int disk_init(const char *home);
int disk_statvfs(const char *home, struct statvfs *_stbuf);
int disk_connect(const diskid_t *diskid, time_t *ltime, int timeout, int force);
const char *disk_rname(const diskid_t *diskid);

/*disk_fs.c*/
int disk_fs_thread_init();
int disk_fs_create_private(const diskid_t *diskid, disk_t **_disk);
int disk_fs_load(__disk_t *disk, const char *home);

/*disk_raw_aio.c*/
int disk_raw_create_private(const diskid_t *diskid, disk_t **_disk);
int disk_raw_load(__disk_t *disk, const char *home);
int disk_raw_aio_read1(const char *path, void *buf, size_t size, off_t offset);
int disk_raw_aio_write1(const char *path, const void *buf, size_t size, off_t offset);
int disk_raw_aio_read(disk_t *disk, disk_entry_t *ent, const io_t *io,
                      buffer_t *buf);
int disk_raw_aio_write(disk_t *disk, disk_entry_t *ent, const io_t *io,
                       const buffer_t *buf);


typedef struct {
        bmap_t bmap;
        sy_rwlock_t rwlock;
        int map_fd;
        int map_size;
        uint64_t disk_size;
        uint64_t page_size;
} disk_alloc_t;

int disk_alloc_open(const char *uuid, size_t disk_size, size_t page_size,
                    disk_alloc_t **_disk_alloc);
int disk_alloc_create(size_t disk_size, size_t page_size, disk_alloc_t **_disk_alloc);
int disk_alloc_flush(const char *uuid, const disk_alloc_t *disk_alloc);
void disk_alloc_close(disk_alloc_t *disk_alloc);
int disk_alloc_set(disk_alloc_t *disk_alloc, const uint64_t *offset, int count);
int disk_alloc_new(disk_alloc_t *disk_alloc, uint64_t *offset, int count);

typedef struct {
        int running;
        sy_spinlock_t spin;
        sem_t sem;
        int eventfd;
        sy_spinlock_t lock;
        struct list_head queue;
        redisContext *conn;
} disk_redis_t;

int disk_redis_itor(disk_redis_t *disk_redis, const char *match, func3_t func,
                    void *arg);
int disk_redis_connect(const char *path, disk_redis_t **_disk_redis);
void disk_redis_close(disk_redis_t *disk_redis);
int disk_redis_hget(disk_redis_t *disk_redis, const char *hash, const char *key,
                    void *buf, size_t *len);
int disk_redis_hset(disk_redis_t *disk_redis, const char *hash, const char *key,
                    const void *value, size_t size, int flag);


#endif
