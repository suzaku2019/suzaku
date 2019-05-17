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
#include <regex.h>
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
#include "diskmap.h"
#include "net_global.h"
#include "nodeid.h"
#include "mds_rpc.h"
#include "mem_cache.h"
#include "adt.h"
#include "schedule.h"
#include "variable.h"
#include "core.h"
#include "dbg.h"

typedef struct {
        char home[MAX_PATH_LEN];
} disk_scanner_t;

typedef struct {
        plock_t plock;
        disk_t *disk;
} disk_slot_private_t;

typedef struct {
        sy_rwlock_t rwlock;
        __disk_t *disk;
} disk_slot_t;

static disk_slot_t *__slot__;

#if 0
static int __disk_worker__(__disk_t *disk)
{
        //int ret;

        (void) disk;
        
        while (1) {
                sleep(5);
        }

        return 0;
//err_ret:
        //disk2idx_offline(&disk->diskid);
        //return ret;
}

static void *__disk_worker(void *arg)
{
        int ret;
        __disk_t *disk = arg;

        ret = __disk_worker__(disk);
        if (ret)
                GOTO(err_ret, ret);

        UNIMPLEMENTED(__DUMP__);
        pthread_exit(NULL);
err_ret:
        UNIMPLEMENTED(__DUMP__);
        pthread_exit(NULL);
}
#endif

static int __disk_config_get__(const char *buf, const char *key, char *res1)
{
        int ret;
        regex_t reg;
        regmatch_t match;
        char errorbuf[MAX_BUF_LEN], regstr[MAX_NAME_LEN], tmp[MAX_NAME_LEN];

        snprintf(regstr, MAX_PATH_LEN, "%s=[^; ]\\+", key);
        ret = regcomp(&reg, regstr, 0);
        if (unlikely(ret)) {
                regerror(ret, &reg, errorbuf, MAX_BUF_LEN);
                DERROR("%s %d\n", errorbuf, ret);
                GOTO(err_ret, ret);
        }

        ret = regexec(&reg, buf, 1, &match, 0);
        if (unlikely(ret)) {
                if (ret == REG_NOMATCH) {
                        ret = ENOKEY;
                        DINFO("key %s buf %s\n", regstr, buf);
                        GOTO(err_free,ret);
                } else {
                        regerror(ret, &reg, errorbuf, MAX_BUF_LEN);
                        DERROR("%s %d\n", errorbuf, ret);
                        GOTO(err_free, ret);
                }
        }

        memcpy(tmp, &buf[match.rm_so], match.rm_eo - match.rm_so);
        tmp[match.rm_eo - match.rm_so] = '\0';
        strcpy(res1, tmp + strlen(key) + 1);
        
        regfree(&reg);

        return 0;
err_free:
        regfree(&reg);
err_ret:
        return ret;
}

static void __disk_config_get(const char *buf, va_list ap)
{
        int ret;

        while (1) {
                const char *key = va_arg(ap, const char *);
                char *value = va_arg(ap, char *);

                if (key == NULL)
                        break;

                ret = __disk_config_get__(buf, key, value);
                if (ret == ENOKEY) {
                        DWARN("%s not found\n", key);
                        strcpy(value, "null");
                        continue;
                }

                DINFO("get %s %s\n", key, value);
        }
}

int disk_config_load(const char *home, int idx, ...)
{
        int ret;
        va_list ap;
        char path[MAX_PATH_LEN], buf[MAX_BUF_LEN];

        va_start(ap, idx);
        
        snprintf(path, MAX_PATH_LEN, "%s/config/%d.config", home, idx);

        ret = _get_text(path, buf, MAX_BUF_LEN);
        if (ret < 0) {
                ret = -ret;
                if (ret == ENOENT)
                        goto err_ret;
                else
                        GOTO(err_ret, ret);
        }

        __disk_config_get(buf, ap);

        va_end(ap);

        return 0;
err_ret:
        return ret;
}

int disk_config_get(const char *buf, ...)
{
        va_list ap;

        va_start(ap, buf);

        __disk_config_get(buf, ap);
        
        va_end(ap);

        return 0;
}


static int __disk_init__(__disk_t **_disk, int idx, int fd)
{
        int ret;
        __disk_t *disk;

        ret = ymalloc((void **)&disk, sizeof(__disk_t));
        if (ret)
                GOTO(err_ret, ret);

        memset(disk, 0x0, sizeof(*disk));
        disk->idx = idx;
        disk->lockfd = fd;

        *_disk = disk;
        
        return 0;
err_ret:
        return ret;
}


static int __disk_init(const char *home, int idx, __disk_t **_disk)
{
        int ret;
        char driver[MAX_NAME_LEN], device[MAX_NAME_LEN];
        __disk_t *disk;

        ret = disk_config_load(home, idx,
                               "driver", driver,
                               "device", device,
                               NULL);
        if (ret) {
                if (ret == ENOENT)
                        goto err_ret;
                else
                        GOTO(err_ret, ret);
        }

        DINFO("init driver %s, device %s\n", driver, device);

        int fd = -1;
        if (strcmp(device, "null")) {
                fd = _lock_file(device, LOCK_EX | LOCK_NB, 0);
                if (fd < 0) {
                        ret = -fd;
                        GOTO(err_ret, ret);
                }
        }

        ret = __disk_init__(&disk, idx, fd);
        if (ret)
                GOTO(err_lock, ret);

        if (strcmp(driver, "filesystem") == 0) {
                disk->type = DISK_FS;
                ret = disk_fs_load(disk, home);
                if (ret)
                        GOTO(err_free, ret);
        } else if (strcmp(driver, "raw_aio") == 0) {
                disk->type = DISK_RAW_AIO;
                ret = disk_raw_load(disk, home);
                if (ret)
                        GOTO(err_free, ret);
        } else if (strcmp(driver, "raw_spdk") == 0) {
                disk->type = DISK_RAW_SPDK;
                ret = disk_raw_load(disk, home);
                if (ret)
                        GOTO(err_free, ret);
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        while (1) {
                ret = d2n_register(&disk->diskid);
                if (ret) {
                        DWARN("register fail\n");
                        sleep(5);
                }

                break;
        }

        disk2idx_online(&disk->diskid, disk->idx);
        DINFO("disk[%u] id %u driver %s, device %s online\n",
              disk->idx, disk->diskid.id, driver, device);
        
        *_disk = disk;

#if 0
        ret = sy_thread_create2(__disk_worker, disk, "disk");
        if (ret)
                UNIMPLEMENTED(__DUMP__);
#endif

        return 0;
err_free:
        yfree((void **)&disk);
err_lock:
        close(fd);
err_ret:
        return ret;
}


static int __disk_init_module__(disk_slot_private_t *disk_slot)
{
        int ret;

        ret = plock_init(&disk_slot->plock, 0);
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

static int __disk_init_module(va_list ap)
{
        int ret;
        disk_slot_private_t *disk_slot;

        va_end(ap);

        int size = sizeof(*disk_slot) * MAX_DISK;
        ret = huge_malloc((void **)&disk_slot, size);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(disk_slot, 0x0, size);

        for (int i = 0; i < MAX_DISK; i++) {
                ret = __disk_init_module__(&disk_slot[i]);
                if (ret) {
                        if (ret == ENOENT)
                                continue;
                        else
                                GOTO(err_ret, ret);
                }
        }

        variable_set(VARIABLE_DISK, disk_slot);

        return 0;
err_ret:
        return ret;
}

static int __disk_scanner__(disk_scanner_t *disk_scanner)
{
        int ret;
        disk_slot_t *slot = __slot__;
        __disk_t *disk;
        
        for (int i = 0; i < MAX_DISK; i++) {
                disk = slot[i].disk;
                        
                if (disk) {
                        DBUG("disk[%d] already online\n", i);
                        continue;
                }
                
                DBUG("disk[%d] check\n", i);
                
                ret = __disk_init(disk_scanner->home, i, &slot[i].disk);
                if (ret) {
                        if (ret != ENOENT) {
                                DINFO("init disk[%d] fail\n", i);
                        }
                        continue;
                }
        }

        return 0;
}


static int __disk_register()
{
        int ret;
        disk_slot_t *slot;
        __disk_t *disk;
        
        for (int i = 0; i < MAX_DISK; i++) {
                slot = &__slot__[i];
                
                ret = sy_rwlock_rdlock(&slot->rwlock);
                if (ret)
                        GOTO(err_ret, ret);

                disk = slot->disk;
                if (disk == NULL) {
                        DBUG("disk[%d] not online\n", i);
                        continue;
                }

                ret = diskmap_disk_register(disk->poolid, net_getnid(),
                                              &disk->diskid, disk->faultdomain);
                if (ret)
                        GOTO(err_lock, ret);

                sy_rwlock_unlock(&slot->rwlock);
        }

        return 0;
err_lock:
        sy_rwlock_unlock(&slot->rwlock);
err_ret:
        return ret;
}



static void *__disk_scanner(void *arg)
{
        disk_scanner_t *disk_scanner = arg;

        DINFO("scan %s\n", disk_scanner->home);

        while (1) {
                __disk_scanner__(disk_scanner);
                __disk_register();

                sleep(5);
        }

        pthread_exit(NULL);
}

int disk_init(const char *home)
{
        int ret, size;
        disk_slot_t *slot;

        size = sizeof(*slot) * MAX_DISK;
        ret = ymalloc((void **)&slot, size);
        if (ret)
                GOTO(err_ret, ret);

        memset(slot, 0x0, size);
        for (int i = 0; i < MAX_DISK; i++) {
                ret = sy_rwlock_init(&slot[i].rwlock, NULL);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);
        }
        
        __slot__ = slot;

        ret = core_init_modules("disk", __disk_init_module, NULL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        disk_scanner_t *disk_scanner;
        ret = ymalloc((void **)&disk_scanner, sizeof(*disk_scanner));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        strcpy(disk_scanner->home, home);
        ret = sy_thread_create2(__disk_scanner, disk_scanner, "disk_scanner");
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

int disk_statvfs(const char *home, struct statvfs *_stbuf)
{
        int ret;

        ret = statvfs(home, _stbuf);
        if (ret == -1) {
                ret = errno;
                DERROR("statvfs(%s, ...) ret (%d) %s\n", home,
                       ret, strerror(ret));
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int disk_connect(const diskid_t *diskid, time_t *ltime, int timeout, int force)
{
        int ret;
        nid_t nid;

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, ltime, timeout, force);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

const char *disk_rname(const diskid_t *diskid)
{
        int ret;
        nid_t nid;

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        return network_rname(&nid);
}

typedef disk_entry_t entry_t;

static int __disk_ref____(entry_t *ent)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ent->ref++;
        YASSERT(ent->ref < 1024);
        
        sy_spin_unlock(&ent->spin);

        return 0;
err_ret:
        return ret;
}

static int IO_FUNC __disk_ref__(disk_t *disk, const chkid_t *chkid, entry_t **_ent)
{
        int ret;
        entry_t *ent;

        ret = plock_rdlock(&disk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ent = htab_find(disk->htab, (void *)chkid);
        if (unlikely(ent == NULL)) {
                ret = ENOENT;
                goto err_lock;
        }

        ret = __disk_ref____(ent);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        *_ent = ent;
        
        plock_unlock(&disk->plock);

        return 0;
err_lock:
        plock_unlock(&disk->plock);
err_ret:
        return ret;
}

static int __disk_load__(disk_t *disk, const chkid_t *chkid)
{
        int ret;
        entry_t *ent;

        if (disk->open == NULL) {
                ret = ENOENT;
                GOTO(err_ret, ret);
        }

        ret = disk->open(disk, chkid, SDFS_CHUNK_SPLIT, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(ent);
        ret = htab_insert(disk->htab, (void *)ent, &ent->chkid, 0);
        if (unlikely(ret)) {
                if (ret == EEXIST) {
                        disk->close(disk, ent);
                        goto out;
                } else {
                        GOTO(err_free, ret);
                }
        }
                        
out:
        return 0;
err_free:
        disk->close(disk, ent);
err_ret:
        return ret;
}

int IO_FUNC disk_ref(disk_t *disk, const chkid_t *chkid, entry_t **_ent)
{
        int ret;

retry:
        ret = __disk_ref__(disk, chkid, _ent);
        if (unlikely(ret)) {
                if (ret == ENOENT) {
                        ret = __disk_load__(disk, chkid);
                        if (unlikely(ret))
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

static int IO_FUNC __disk_unref__(entry_t *ent)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(ent->ref > 0);
        ent->ref--;
        
        sy_spin_unlock(&ent->spin);

        return 0;
err_ret:
        return ret;
}

int IO_FUNC disk_deref(disk_t *disk, entry_t *ent)
{
        int ret;

        ret = plock_rdlock(&disk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __disk_unref__(ent);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&disk->plock);

        return 0;
err_lock:
        plock_unlock(&disk->plock);
err_ret:
        return ret;
}

static int __disk_slot_connect__(int idx, disk_t **_disk)
{
        int ret;
        disk_slot_t *slot = &__slot__[idx];
        __disk_t *disk = slot->disk;

        if (disk == NULL) {
                ret = ENODEV;
                GOTO(err_ret, ret);
        }
        
        if (disk->type == DISK_FS) {
                ret = disk_fs_create_private(&disk->diskid, _disk);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        } else if (disk->type == DISK_RAW_AIO) {
                ret = disk_raw_create_private(&disk->diskid, _disk);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        return 0;
err_ret:
        return ret;
}

static int __disk_slot_connect(int idx, disk_slot_private_t *disk)
{
        int ret;

        ret = plock_wrlock(&disk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (disk->disk) {
                goto out;
        }

        ret = __disk_slot_connect__(idx, &disk->disk);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
out:
        plock_unlock(&disk->plock);

        return 0;
err_lock:
        plock_unlock(&disk->plock);
err_ret:
        return ret;
}

int IO_FUNC disk_slot_private_ref(int idx, disk_t **_disk)
{
        int ret;
        disk_slot_private_t *disk, *array = variable_get(VARIABLE_DISK);

        disk = &array[idx];

retry:
        ret = plock_rdlock(&disk->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (disk->disk == NULL) {
                plock_unlock(&disk->plock);
                ret = __disk_slot_connect(idx, disk);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                goto retry;
        }
        
        *_disk = disk->disk;
        
        return 0;
err_ret:
        return ret;
}

void IO_FUNC disk_slot_private_deref(int idx)
{
        disk_slot_private_t *disk, *array = variable_get(VARIABLE_DISK);

        disk = &array[idx];
        YASSERT(disk->disk);
        plock_unlock(&disk->plock);
}

int disk_slot_ref(int idx, __disk_t **_disk)
{
        int ret;
        disk_slot_t *slot = &__slot__[idx];

        ret = sy_rwlock_rdlock(&slot->rwlock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (slot->disk == NULL) {
                ret = ENODEV;
                GOTO(err_lock, ret);
        }
        
        *_disk = slot->disk;
        
        return 0;
err_lock:
        sy_rwlock_unlock(&slot->rwlock);
err_ret:
        return ret;
}

void disk_slot_deref(int idx)
{
        disk_slot_t *slot = &__slot__[idx];

        YASSERT(slot->disk);
        sy_rwlock_unlock(&slot->rwlock);
}

int disk_entry_create(const chkid_t *chkid, entry_t **_ent)
{
        int ret;
        entry_t *ent;
        
        ret = huge_malloc((void **)&ent, sizeof(*ent));
        if (ret)
                GOTO(err_ret, ret);

        memset(ent, 0x0, sizeof(*ent));
        
        ret = plock_init(&ent->plock, 0);
        if (ret)
                GOTO(err_free, ret);

        ret = sy_spin_init(&ent->spin);
        if (ret)
                GOTO(err_free, ret);
        
        ent->chkid = *chkid;
        INIT_LIST_HEAD(&ent->wlist);
        *_ent = ent;
        
        return 0;
err_free:
        yfree((void **)&ent);
err_ret:
        return ret;
}

void disk_entry_free(entry_t *ent)
{
        huge_free((void **)&ent);
}

static int __disk_cmp(const void *v1, const void *v2)
{
        const entry_t *ent = v1;
        const chkid_t *chkid = v2;

        return chkid_cmp(&ent->chkid, chkid);
}

static uint32_t __disk_key(const void *args)
{
        const chkid_t *id = args;

        return id->id * (1 + id->idx);
}

int disk_create(const diskid_t *diskid, disk_t **_disk)
{
        int ret, idx;
        disk_t *disk;
        char name[MAX_NAME_LEN];

        ret = disk2idx(diskid, &idx);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = huge_malloc((void **)&disk, sizeof(*disk));
        if (ret)
                GOTO(err_ret, ret);

        ret = plock_init(&disk->plock, 0);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(name, MAX_PATH_LEN, "disk[%u]", idx);
        disk->htab = htab_create(__disk_cmp, __disk_key, name);
        if (disk->htab == NULL) {
                ret = ENOMEM;
                GOTO(err_ret, ret);
        }
        
        disk->diskid = *diskid;
        disk->idx = idx;
        *_disk = disk;
        
        return 0;
err_ret:
        return ret;
}

void disk_destroy(disk_t *disk)
{
        UNIMPLEMENTED(__DUMP__);
        huge_free((void **)&disk);
}

int disk_stat(const diskid_t *diskid, disk_info_t *stat)
{
        int ret, idx;
        disk_slot_t *slot;
        __disk_t *disk;

        ret = disk2idx(diskid, &idx);
        if (ret)
                GOTO(err_ret, ret);

        slot = &__slot__[idx];
        ret = sy_rwlock_rdlock(&slot->rwlock);
        if (ret)
                GOTO(err_ret, ret);

        disk = slot->disk;
        if (disk == NULL) {
                ret = ENODEV;
                GOTO(err_lock, ret);
        }
        
        ret = disk->stat(disk, stat);
        if (ret)
                GOTO(err_lock, ret);

        sy_rwlock_unlock(&slot->rwlock);
        
        return 0;
err_lock:
        sy_rwlock_unlock(&slot->rwlock);
err_ret:
        return ret;
}

int disk_newid(int idx, diskid_t *diskid)
{
        int ret;
        char nodename[MAX_NAME_LEN], hostname[MAX_NAME_LEN];
        nodeid_t id;
        nid_t nid;

        ret = net_gethostname(hostname, MAX_NAME_LEN);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(nodename, MAX_NAME_LEN, "%s:disk/%d", hostname, idx);
        ret = nodeid_newid(&id, nodename);
        if (ret)
                GOTO(err_ret, ret);

        DINFO("create disk[%d] --> %d\n", idx, id);
        nid.id = id;
        YASSERT(nid.id);
        *diskid = nid;
        
        return 0;
err_ret:
        return ret;
}
