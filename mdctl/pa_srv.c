/*Persistence Array */

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
#include "core.h"
#include "dbg.h"

#pragma pack(4)

typedef struct {
        uint16_t size;
        uint16_t magic;
        uint32_t crc;
        uint64_t version;
        char buf[0];
} record_t;

#pragma pack()

#define __MAGIC__  0xba3c
#define PA_LOCK 128

typedef struct {
        plock_t plock;
        htab_t htab;
} pa_srv_t;

typedef struct {
        chkid_t tid;
        uint32_t ref;
        plock_t plock;
        plock_t infolock;
        ltoken_t token;
        uint64_t info_array[PA_INFO_COUNT];
        plock_t record_lock[PA_LOCK];
        chunk_t *chunk;
        uint64_t chunk_array[PA_ITEM_COUNT];
        chkinfo_t *array[PA_ITEM_COUNT];
} pa_entry_t;

static int __pa_srv_cmp(const void *v1, const void *v2)
{
        const pa_entry_t *ent = v1;
        const chkid_t *chkid = v2;

        return chkid_cmp(&ent->tid, chkid);
}

static uint32_t __pa_srv_key(const void *args)
{
        const chkid_t *id = args;

        return id->id * (1 + id->idx);
}

static int __pa_srv_create__(pa_srv_t *pa_srv)
{
        int ret;

        pa_srv->htab = htab_create(__pa_srv_cmp, __pa_srv_key, "pa_srv");
        if (pa_srv->htab == NULL) {
                UNIMPLEMENTED(__DUMP__);
        }

        ret = plock_init(&pa_srv->plock, "pa_srv");
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __pa_srv_create(va_list ap)
{
        int ret;
        pa_srv_t *pa_srv;

        va_end(ap);

        ret = ymalloc((void **)&pa_srv, sizeof(*pa_srv) * PA_HASH);
        if (ret)
                GOTO(err_ret, ret);

        for (int i = 0; i < PA_HASH; i++) {
                ret = __pa_srv_create__(&pa_srv[i]);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);
        }

        variable_set(VARIABLE_PA_SRV, pa_srv);

        return 0;
err_ret:
        return ret;
}

int pa_srv_create()
{
        int ret;

        ret = core_init_modules("pa_srv_create", __pa_srv_create, NULL);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static void __pa_cid2off(const chkid_t *chkid, uint64_t *offset)
{
        *offset = (chkid->idx % PA_ITEM_COUNT)
                * PA_ITEM_SIZE + PA_INFO_AREA;
}

static int __pa_srv_write(pa_entry_t *ent, const char *_buf, int buflen,
                          uint64_t offset, uint64_t version)
{
        int ret;
        io_t io;
        buffer_t buf;
        record_t *record;
        char tmp[MAX_BUF_LEN];

        record = (void *)tmp;
        record->magic = __MAGIC__;
        record->size = buflen + sizeof(*record);
        record->version = version;
        memcpy(record->buf, _buf, buflen);
        record->crc = crc32_sum(record->buf, buflen);

        mbuffer_init(&buf, 0);
        mbuffer_appendmem(&buf, record, record->size);
        io_init(&io, &ent->tid, record->size, offset, 0);
        io.buf = &buf;
        ret = chunk_write(NULL, ent->chunk, &io);
        if (ret)
                GOTO(err_ret, ret);

        mbuffer_free(&buf);
        
        return 0;
err_ret:
        mbuffer_free(&buf);
        return ret;
}

static int __pa_srv_read(pa_entry_t *ent, char *_buf, int *buflen,
                         uint64_t offset, uint64_t *version)
{
        int ret;
        io_t io;
        buffer_t buf;
        record_t *record;
        char tmp[MAX_BUF_LEN];

        YASSERT(sizeof(*record) + *buflen < MAX_BUF_LEN);

        mbuffer_init(&buf, 0);
        io_init(&io, &ent->tid, sizeof(*record) + *buflen, offset, 0);
        io.buf = &buf;
        ret = chunk_read(NULL, ent->chunk, &io);
        if (ret)
                GOTO(err_ret, ret);

        mbuffer_get(&buf, tmp, buf.len);
        mbuffer_free(&buf);

        record = (void *)tmp;
        if (record->magic != __MAGIC__) {
                ret = ENODATA;
                YASSERT(record->magic == 0);
                GOTO(err_ret, ret);
        }

        *buflen = record->size - sizeof(*record);
        *version = record->version;
        YASSERT(record->crc == crc32_sum(record->buf, *buflen));
        memcpy(_buf, record->buf, *buflen);
        
        return 0;
err_ret:
        return ret;
}

static int __pa_srv_set__(pa_entry_t *ent, const chkinfo_t *chkinfo,
                          uint64_t *_version)
{
        int ret;
        uint64_t offset, version;
        chkinfo_t *prev;
        record_t *record;
        const chkid_t *chkid = &chkinfo->chkid;
        int idx = chkid->idx % PA_ITEM_COUNT;

        version = *_version;
        prev = ent->array[idx];
        if (prev == NULL) {
                YASSERT(version == (LLU)-1);
        } else if (version != ent->chunk_array[idx]) {
                ret = ESTALE;
                DINFO("version %ju -> %ju\n", version,
                      ent->chunk_array[idx]);
                GOTO(err_ret, ret);
        }

        __pa_cid2off(chkid, &offset);

        static_assert((int)(CHKINFO_MAX + sizeof(*record)) <= PA_ITEM_SIZE, "pa_set");

        version++;
        ret = __pa_srv_write(ent, (void *)chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                             offset, version);
        if (ret)
                GOTO(err_ret, ret);

        ent->chunk_array[idx] = version;
        
        if (prev == NULL) {
                ret = huge_malloc((void **)&prev, CHKINFO_SIZE(chkinfo->repnum));
                if (ret)
                        UNIMPLEMENTED(__DUMP__);

                ent->array[idx] = prev;
        }

        CHKINFO_CP(prev, chkinfo);
        *_version = version;
        
        return 0;
err_ret:
        return ret;
}

static int __pa_srv_set(pa_entry_t *ent, const chkinfo_t *chkinfo,
                        uint64_t *version)
{
        int ret;
        const chkid_t *chkid = &ent->tid;

        ret = plock_wrlock(&ent->record_lock[chkid->idx % PA_LOCK]);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __pa_srv_set__(ent, chkinfo, version);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);

        return 0;
err_lock:
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);
err_ret:
        return ret;
}

static void __pa_srv_load_info(pa_entry_t *ent, const char *buf)
{
        record_t *record;

        for (int i = 0; i < PA_INFO_COUNT; i++) {
                record = (void *)buf + (PA_INFO_SIZE * i);
                if (record->magic == 0) {
                        ent->info_array[i] = -1;
                } else {
                        DINFO("load "CHKID_FORMAT"[%d]\n", CHKID_ARG(&ent->tid), i);
                        YASSERT(record->magic == __MAGIC__); 
                        YASSERT(record->crc == crc32_sum(record->buf,
                                                         record->size
                                                         - sizeof(*record)));
                        ent->info_array[i] = record->version;
                }
        }
}

static int __pa_srv_load_item__(buffer_t *_buf, pa_entry_t *ent)
{
        int ret;
        char *buf;
        record_t *record;
        chkinfo_t *chkinfo;
        
        ret = ymalloc((void **)&buf, SDFS_CHUNK_SPLIT);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_get(_buf, buf, SDFS_CHUNK_SPLIT);

        __pa_srv_load_info(ent, buf);
        
        for (int i = 0; i < PA_ITEM_COUNT; i++) {
                record = (void *)buf + PA_INFO_AREA + (PA_ITEM_SIZE * i);
                if (record->magic == 0) {
                        YASSERT(record->size == 0);
                        YASSERT(record->crc == 0);
                        ent->array[i] = NULL;
                        ent->chunk_array[i] = 0;
                        continue;
                }

                YASSERT(record->magic == __MAGIC__);
                YASSERT(record->crc == crc32_sum(record->buf, record->size - sizeof(*record)));
                ent->chunk_array[i] = record->version;

                ret = huge_malloc((void **)&chkinfo, record->size);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);

                memcpy(chkinfo, record->buf, record->size);

                ent->array[i] = chkinfo;
        }

        yfree((void **)&buf);
        
        return 0;
err_ret:
        return ret;
}

static int __pa_srv_chunk_create(const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        fileinfo_t md;
        fileid_t fileid;

        cid2fid(&fileid, chkid);

        DINFO("create "CHKID_FORMAT"\n", CHKID_ARG(chkid));

        ret = md_getattr(NULL, &fileid, (void *)&md);
        if (unlikely(ret))
                GOTO(err_ret, ret);
                        
        ret = md_chunk_create(&md, chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __pa_srv_load_item(pa_entry_t *ent, const chkinfo_t *chkinfo, uint64_t version)
{
        int ret;
        io_t io;
        buffer_t buf;
        chunk_t *chunk;
        const chkid_t *chkid = &chkinfo->chkid;

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (ent->chunk) {
                goto out;
        }
        
        ret = chunk_open(&chunk, chkinfo, version, NULL, NULL, 0);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        mbuffer_init(&buf, 0);
        io_init(&io, chkid, SDFS_CHUNK_SPLIT, 0, 0);
        io.buf = &buf;
        ret = chunk_read(NULL, chunk, &io);
        if (unlikely(ret))
                GOTO(err_close, ret);

        ret = __pa_srv_load_item__(&buf, ent);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        mbuffer_free(&buf);

        ent->chunk = chunk;

out:
        plock_unlock(&ent->plock);
        
        return 0;
err_free:
        mbuffer_free(&buf);
err_close:
        chunk_close(&chunk);
err_lock:
        plock_unlock(&ent->plock);
err_ret:
        return ret;
}

static void __pa_srv_entry_free(pa_entry_t *ent)
{
        for (int i = 0; i < PA_ITEM_COUNT; i++) {
                if (ent->array[i]) {
                        huge_free((void **)&ent->array[i]);
                }
        }


        if (ent->chunk) {
                chunk_close(&ent->chunk);
        }
        
        huge_free((void **)&ent);
}

static int __pa_srv_entry_create(const chkid_t *tid, pa_entry_t **_ent)
{
        int ret;
        pa_entry_t *ent;
        ltoken_t token;

        ret = ringlock_check(tid, TYPE_MDCTL, O_CREAT, &token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = huge_malloc((void **)&ent, sizeof(*ent));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(ent, 0x0, sizeof(*ent));
        ent->tid = *tid;
        ent->token = token;

        ret = plock_init(&ent->plock, "pa_entry");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ret = plock_init(&ent->infolock, "info_lock");
        if (ret)
                GOTO(err_ret, ret);
        
        for (int i = 0; i < PA_LOCK; i++) {
                ret = plock_init(&ent->record_lock[i], "record_lock");
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }

        *_ent = ent;
        
        return 0;
err_ret:
        return ret;
}

static int __pa_srv_load(pa_srv_t *pa_srv, const chkid_t *tid)
{
        int ret;
        pa_entry_t *ent;
        char _chkinfo[CHKINFO_MAX];
        chkinfo_t *chkinfo = (void *)_chkinfo;
        uint64_t version;

        DINFO("load "CHKID_FORMAT"\n", CHKID_ARG(tid));

retry:
        ret = md_chunk_load(tid, chkinfo, &version);
        if (unlikely(ret)) {
                if (ret == ENOENT) {
                        ret = __pa_srv_chunk_create(tid, chkinfo);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);

                        goto retry;
                } else 
                        GOTO(err_ret, ret);
        }
        
        ret = plock_wrlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __pa_srv_entry_create(tid, &ent);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = htab_insert(pa_srv->htab, (void *)ent, &ent->tid, 0);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        plock_unlock(&pa_srv->plock);

#if 0
        ret = plock_rdlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(pa_srv->htab, (void *)tid);
        YASSERT(ent);

        ret = __pa_srv_load_item(ent, chkinfo, version);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&pa_srv->plock);
#endif
        
        return 0;
err_free:
        UNIMPLEMENTED(__DUMP__);
err_lock:
        plock_unlock(&pa_srv->plock);
err_ret:
        return ret;
}

static pa_srv_t *__pa_srv(const chkid_t *tid)
{
        pa_srv_t *pa_srv = variable_get(VARIABLE_PA_SRV);

        return &pa_srv[(tid->id * tid->idx) / PA_HASH];
}

STATIC int __pa_srv_check(pa_srv_t *pa_srv, const chkid_t *tid,
                          pa_entry_t *ent)
{
        int ret;

        (void) pa_srv;
        
        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = ringlock_check(tid, TYPE_MDCTL, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&ent->plock);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ret:
        return ret;
}

STATIC int __pa_srv_drop(pa_srv_t *pa_srv, const chkid_t *tid,
                            pa_entry_t *ent)
{
        int ret;
        pa_entry_t *tmp;

        DINFO(CHKID_FORMAT" drop %p\n", CHKID_ARG(tid), ent);
        
        ret = plock_wrlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(ent->ref == 0);

        ret = htab_remove(pa_srv->htab, (void *)tid, (void **)&tmp);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        YASSERT(ent == tmp);
        
        __pa_srv_entry_free(ent);
        
        plock_unlock(&pa_srv->plock);

        return 0;
err_lock:
        plock_unlock(&pa_srv->plock);
err_ret:
        return ret;
}

static void __pa_srv_deref(pa_srv_t *pa_srv, pa_entry_t *ent)
{
        (void) pa_srv;
        YASSERT(ent->ref > 0);
        ent->ref--;
}

STATIC int __pa_srv_load__(pa_entry_t *ent, const chkid_t *tid)
{
        int ret;
        char _chkinfo[CHKINFO_MAX];
        chkinfo_t *chkinfo = (void *)_chkinfo;
        uint64_t version;

        ret = md_chunk_load(tid, chkinfo, &version);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }
                
        ret = __pa_srv_load_item(ent, chkinfo, version);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __pa_srv_ref(pa_srv_t *pa_srv, const chkid_t *tid, pa_entry_t **_ent)
{
        int ret;
        pa_entry_t *ent;

retry:
        ret = plock_rdlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(pa_srv->htab, (void *)tid);
        if (ent == NULL) {
                plock_unlock(&pa_srv->plock);

                ret = __pa_srv_load(pa_srv, tid);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                goto retry;
        }

        ent->ref++;//single thread
        plock_unlock(&pa_srv->plock);
        
        if (unlikely(ent->chunk == NULL)) {
                ret = __pa_srv_load__(ent, tid);
                if (unlikely(ret))
                        GOTO(err_ref, ret);
        }

        ret = __pa_srv_check(pa_srv, tid, ent);
        if (unlikely(ret)) {
                __pa_srv_deref(pa_srv, ent);
                if (ret == ESTALE) {
                        ret = __pa_srv_drop(pa_srv, tid, ent);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);

                        goto retry;
                } else
                        GOTO(err_ret, ret);
        }
        
        *_ent = ent;

        return 0;
err_ref:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}

int pa_srv_set(const chkid_t *chkid, const chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;
        pa_entry_t *ent;
        chkid_t tid;

        cid2tid(chkid, &tid);

        DINFO("set "CHKID_FORMAT" @ "CHKID_FORMAT", prev version %llu\n", CHKID_ARG(chkid),
              CHKID_ARG(&tid), *version);
        
        pa_srv_t *pa_srv = __pa_srv(&tid);
        ret = __pa_srv_ref(pa_srv, &tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_set(ent, chkinfo, version);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);
        __pa_srv_deref(pa_srv, ent);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}

static int __pa_srv_get__(pa_entry_t *ent, const chkid_t *chkid,
                          chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;
        const chkinfo_t *tmp;
        uint64_t idx = chkid->idx % PA_ITEM_COUNT;

        tmp = ent->array[idx];
        if (tmp == NULL) {
                ret = ENOENT;
                GOTO(err_ret, ret);
        }

        CHKINFO_CP(chkinfo, tmp);
        YASSERT(ent->chunk_array[idx] != (uint64_t)-1);
        *version = ent->chunk_array[idx];
        
        return 0;
err_ret:
        return ret;
}


static int __pa_srv_get(pa_entry_t *ent, const chkid_t *chkid,
                        chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;

        ret = plock_rdlock(&ent->record_lock[chkid->idx % PA_LOCK]);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __pa_srv_get__(ent, chkid, chkinfo, version);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);

        return 0;
err_lock:
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);
err_ret:
        return ret;
}

int pa_srv_get(const chkid_t *chkid, chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;
        pa_entry_t *ent;
        chkid_t tid;

        cid2tid(chkid, &tid);

        DINFO("get "CHKID_FORMAT" @ "CHKID_FORMAT"\n",
              CHKID_ARG(chkid), CHKID_ARG(&tid));
        
        pa_srv_t *pa_srv = __pa_srv(&tid);
        ret = __pa_srv_ref(pa_srv, &tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_get(ent, chkid, chkinfo, version);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);
        __pa_srv_deref(pa_srv, ent);

        DINFO("get "CHKID_FORMAT" @ "CHKID_FORMAT" success\n",
              CHKID_ARG(chkid), CHKID_ARG(&tid));
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}

static int __pa_srv_recovery(pa_entry_t *ent)
{
        int ret;

        DINFO("recovery "CHKID_FORMAT"\n", CHKID_ARG(&ent->tid));
        
        ret = chunk_recovery(NULL, ent->chunk);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }
        
        return 0;
err_ret:
        return ret;
}

int pa_srv_recovery(const chkid_t *chkid)
{
        int ret;
        pa_entry_t *ent;
        chkid_t tid;

        tid = *chkid;

        DINFO("recovery "CHKID_FORMAT" @ "CHKID_FORMAT"\n",
              CHKID_ARG(chkid), CHKID_ARG(&tid));
        
        pa_srv_t *pa_srv = __pa_srv(&tid);
        ret = __pa_srv_ref(pa_srv, &tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_recovery(ent);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);
        __pa_srv_deref(pa_srv, ent);

        DINFO("recovery "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}

static int __pa_srv_setinfo(pa_entry_t *ent, int idx, const char *buf,
                            int buflen, uint64_t *_version)
{
        int ret;
        uint64_t newversion;
        uint64_t prev_version = *_version;

        if (buflen + sizeof(record_t) > PA_INFO_SIZE) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        ret = plock_wrlock(&ent->infolock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        if ((ent->info_array[idx] != (uint64_t)-1 && prev_version != (uint64_t)-1)
            && (prev_version != ent->info_array[idx])) {
                ret = EPERM;
                DINFO(CHKID_FORMAT" idx %d version %ju -> %ju\n",
                      CHKID_ARG(&ent->tid), idx, prev_version,  ent->info_array[idx]);
                GOTO(err_lock, ret);
        }
        
        newversion = ent->info_array[idx] + 1;
        
        ret = __pa_srv_write(ent, buf, buflen, idx * PA_INFO_SIZE, newversion);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        YASSERT(newversion == ent->info_array[idx] + 1);
        ent->info_array[idx] = newversion;
        *_version = newversion;

        plock_unlock(&ent->infolock);
        
        return 0;
err_lock:
        plock_unlock(&ent->infolock);
err_ret:
        return ret;
}

int pa_srv_setinfo(const chkid_t *tid, int idx, const char *buf,
                   int buflen, uint64_t *version)
{
        int ret;
        pa_entry_t *ent;

        DINFO("setinfo "CHKID_FORMAT" @ %u, prev version %ju\n",
              CHKID_ARG(tid), idx, *version);
        
        pa_srv_t *pa_srv = __pa_srv(tid);
        ret = __pa_srv_ref(pa_srv, tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_setinfo(ent, idx, buf, buflen, version);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);
        __pa_srv_deref(pa_srv, ent);

        DINFO("setinfo "CHKID_FORMAT" @ %u, version %ju success\n",
              CHKID_ARG(tid), idx, *version);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}

static int __pa_srv_getinfo(pa_entry_t *ent, int idx, char *buf,
                            int *_buflen, uint64_t *version)
{
        int ret;

        ret = plock_rdlock(&ent->infolock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        if (ent->info_array[idx] == 0) {
                ret = ENODATA;
                GOTO(err_lock, ret);
        }

        ret = __pa_srv_read(ent, buf, _buflen, idx * PA_INFO_SIZE, version);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        YASSERT(*version == ent->info_array[idx]);

        plock_unlock(&ent->infolock);
        
        return 0;
err_lock:
        plock_unlock(&ent->infolock);
err_ret:
        return ret;
}

int pa_srv_getinfo(const chkid_t *tid, int idx, char *buf, int *buflen,
                   uint64_t *version)
{
        int ret;
        pa_entry_t *ent;

        DINFO("getinfo "CHKID_FORMAT" @ %u\n", CHKID_ARG(tid), idx);
        
        pa_srv_t *pa_srv = __pa_srv(tid);
        ret = __pa_srv_ref(pa_srv, tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_getinfo(ent, idx, buf, buflen, version);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);
        __pa_srv_deref(pa_srv, ent);

        DINFO("getinfo "CHKID_FORMAT" @ %u, version %ju success\n",
              CHKID_ARG(tid), idx, *version);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_deref(pa_srv, ent);
err_ret:
        return ret;
}
