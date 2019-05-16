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
        chkid_t id;
        plock_t plock;
        ltoken_t token;
        plock_t record_lock[PA_LOCK];
        chunk_t *chunk;
        chkinfo_t *array[PA_ITEM_COUNT];
} pa_entry_t;

static int __pa_srv_cmp(const void *v1, const void *v2)
{
        const pa_entry_t *ent = v1;
        const chkid_t *chkid = v2;

        return chkid_cmp(&ent->id, chkid);
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

static void __pa_cid2tid(const chkid_t *chkid, chkid_t *tid)
{
        *tid = *chkid;

        tid->idx = chkid->idx / PA_ITEM_COUNT;

        if (chkid->type == ftype_raw) 
                tid->type = ftype_sub;
        else if (chkid->type == ftype_sub)
                tid->type = ftype_file;
        else {
                UNIMPLEMENTED(__DUMP__);
        }
}

static void __pa_cid2off(const chkid_t *chkid, uint64_t *offset)
{
        *offset = (chkid->idx % PA_ITEM_COUNT)
                * PA_ITEM_SIZE + PA_INFO_AREA;
}

static int __pa_srv_set__(pa_entry_t *ent, const chkinfo_t *chkinfo,
                          uint64_t prev_version)
{
        int ret;
        io_t io;
        uint64_t offset;
        buffer_t buf;
        chkinfo_t *prev;
        record_t *record;
        char _buf[MAX_BUF_LEN];
        const chkid_t *chkid = &chkinfo->chkid;
        
        prev = ent->array[chkid->idx % PA_ITEM_COUNT];
        if (prev == NULL) {
                YASSERT(prev_version == (LLU)-1);
        } else {
                if (prev_version != (uint64_t)-1
                    && prev->md_version != prev_version) {
                        ret = ESTALE;
                        GOTO(err_ret, ret);
                }
        }

        __pa_cid2off(chkid, &offset);

        static_assert((int)(CHKINFO_MAX + sizeof(*record)) <= PA_ITEM_SIZE, "pa_set");
        record = (void *)_buf;
        record->magic = __MAGIC__;
        record->size = CHKINFO_SIZE(chkinfo->repnum) + sizeof(*record);
        CHKINFO_CP(record->buf, chkinfo);
        record->crc = crc32_sum(record->buf, CHKINFO_SIZE(chkinfo->repnum));

        mbuffer_init(&buf, 0);
        mbuffer_appendmem(&buf, record, record->size);
        io_init(&io, &ent->id, record->size, offset, 0);
        io.buf = &buf;
        ret = chunk_write(ent->chunk, &io);
        if (ret)
                GOTO(err_free, ret);

        if (prev == NULL) {
                ret = ymalloc((void **)&prev, CHKINFO_SIZE(chkinfo->repnum));
                if (ret)
                        UNIMPLEMENTED(__DUMP__);

                ent->array[chkid->idx % PA_ITEM_COUNT] = prev;
        }

        CHKINFO_CP(prev, chkinfo);
        
        mbuffer_free(&buf);
        
        return 0;
err_free:
        mbuffer_free(&buf);
err_ret:
        return ret;
}

static int __pa_srv_set(pa_entry_t *ent, const chkinfo_t *chkinfo,
                        uint64_t prev_version)
{
        int ret;
        const chkid_t *chkid = &ent->id;

        ret = plock_wrlock(&ent->record_lock[chkid->idx % PA_LOCK]);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = ringlock_check(chkid, RINGLOCK_MDS, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = __pa_srv_set__(ent, chkinfo, prev_version);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);

        return 0;
err_lock:
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);
err_ret:
        return ret;
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

        for (int i = 0; i < PA_ITEM_COUNT; i++) {
                record = (void *)buf + PA_INFO_AREA + (PA_ITEM_SIZE * i);
                if (record->magic == 0) {
                        YASSERT(record->size == 0);
                        YASSERT(record->crc == 0);
                        ent->array[i] = NULL;
                        continue;
                }

                YASSERT(record->magic == __MAGIC__);
                YASSERT(record->crc == crc32_sum(record->buf, record->size - sizeof(*record)));

                ret = ymalloc((void **)&chkinfo, record->size);
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

static int __pa_srv_load_item(pa_entry_t *ent, const chkinfo_t *chkinfo)
{
        int ret;
        io_t io;
        buffer_t buf;
        chunk_t *chunk;
        const chkid_t *chkid = &chkinfo->chkid;

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = chunk_open(&chunk, chkinfo, NULL, NULL, 0);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        mbuffer_init(&buf, 0);
        io_init(&io, chkid, SDFS_CHUNK_SPLIT, 0, 0);
        io.buf = &buf;
        ret = chunk_read(chunk, &io);
        if (unlikely(ret))
                GOTO(err_close, ret);

        ret = __pa_srv_load_item__(&buf, ent);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        mbuffer_free(&buf);

        ent->chunk = chunk;
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

static int __pa_srv_entry_create(const chkid_t *chkid, pa_entry_t **_ent)
{
        int ret;
        pa_entry_t *ent;
        ltoken_t token;

        ret = ringlock_check(chkid, RINGLOCK_MDS, O_CREAT, &token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = ymalloc((void **)&ent, sizeof(*ent));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(ent, 0x0, sizeof(*ent));
        ent->id = *chkid;
        ent->token = token;

        ret = plock_init(&ent->plock, "pa_entry");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);
        
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

static int __pa_srv_load(pa_srv_t *pa_srv, const chkid_t *chkid)
{
        int ret;
        pa_entry_t *ent;
        char _chkinfo[CHKINFO_MAX];
        chkinfo_t *chkinfo = (void *)_chkinfo;

        DINFO("load "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        ret = md_chunk_load(chkid, chkinfo);
        if (unlikely(ret)) {
                if (ret == ENOENT) {
                        ret = __pa_srv_chunk_create(chkid, chkinfo);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);
                } else 
                        GOTO(err_ret, ret);
        }
        
        ret = plock_wrlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __pa_srv_entry_create(chkid, &ent);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = htab_insert(pa_srv->htab, (void *)ent, &ent->id, 0);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        plock_unlock(&pa_srv->plock);

        ret = plock_rdlock(&pa_srv->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(pa_srv->htab, (void *)chkid);
        YASSERT(ent);

        ret = __pa_srv_load_item(ent, chkinfo);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&pa_srv->plock);
        
        return 0;
err_free:
        UNIMPLEMENTED(__DUMP__);
err_lock:
        plock_unlock(&pa_srv->plock);
err_ret:
        return ret;
}

static pa_srv_t *__pa_srv(const chkid_t *chkid)
{
        pa_srv_t *pa_srv = variable_get(VARIABLE_PA_SRV);

        return &pa_srv[(chkid->id * chkid->idx) / PA_HASH];
}

static int __pa_srv_entry_get(pa_srv_t *pa_srv, const chkid_t *tid, pa_entry_t **_ent)
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

        if (ent->chunk == NULL) {
                char _chkinfo[CHKINFO_MAX];
                chkinfo_t *chkinfo = (void *)_chkinfo;

                ret = md_chunk_load(tid, chkinfo);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }
                
                ret = __pa_srv_load_item(ent, chkinfo);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }
        
        *_ent = ent;

        return 0;
err_ret:
        return ret;
}

static void __pa_srv_entry_release(pa_srv_t *pa_srv)
{
        plock_unlock(&pa_srv->plock);
}

int pa_srv_set(const chkinfo_t *chkinfo, uint64_t prev_version)
{
        int ret;
        pa_entry_t *ent;
        const chkid_t *chkid = &chkinfo->chkid;
        chkid_t tid;

        __pa_cid2tid(chkid, &tid);

        DINFO("set "CHKID_FORMAT" @ "CHKID_FORMAT", prev version %llu\n", CHKID_ARG(chkid),
              CHKID_ARG(&tid), prev_version);
        
        pa_srv_t *pa_srv = __pa_srv(&tid);
        ret = __pa_srv_entry_get(pa_srv, &tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_set(ent, chkinfo, prev_version);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }
        
        plock_unlock(&ent->plock);
        __pa_srv_entry_release(pa_srv);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_entry_release(pa_srv);
err_ret:
        return ret;
}

static int __pa_srv_get__(pa_entry_t *ent, const chkid_t *chkid,
                          chkinfo_t *chkinfo)
{
        int ret;
        const chkinfo_t *tmp;

        tmp = ent->array[chkid->idx % PA_ITEM_COUNT];
        if (tmp == NULL) {
                ret = ENOENT;
                GOTO(err_ret, ret);
        }

        CHKINFO_CP(chkinfo, tmp);
        
        return 0;
err_ret:
        return ret;
}


static int __pa_srv_get(pa_entry_t *ent, const chkid_t *chkid,
                        chkinfo_t *chkinfo)
{
        int ret;

        ret = plock_rdlock(&ent->record_lock[chkid->idx % PA_LOCK]);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = ringlock_check(chkid, RINGLOCK_MDS, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = __pa_srv_get__(ent, chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);

        return 0;
err_lock:
        plock_unlock(&ent->record_lock[chkid->idx % PA_LOCK]);
err_ret:
        return ret;
}

int pa_srv_get(const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        pa_entry_t *ent;
        chkid_t tid;

        __pa_cid2tid(chkid, &tid);

        DINFO("get "CHKID_FORMAT" @ "CHKID_FORMAT"\n",
              CHKID_ARG(chkid), CHKID_ARG(&tid));
        
        pa_srv_t *pa_srv = __pa_srv(&tid);
        ret = __pa_srv_entry_get(pa_srv, &tid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_release, ret);
        
        ret = __pa_srv_get(ent, chkid, chkinfo);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        plock_unlock(&ent->plock);

        DINFO("get "CHKID_FORMAT" @ "CHKID_FORMAT" success\n",
              CHKID_ARG(chkid), CHKID_ARG(&tid));
        
        __pa_srv_entry_release(pa_srv);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_entry_release(pa_srv);
err_ret:
        return ret;
}

static int __pa_srv_recovery(pa_entry_t *ent)
{
        int ret;

        DINFO("recovery "CHKID_FORMAT"\n", CHKID_ARG(&ent->id));
        
        ret = ringlock_check(&ent->id, RINGLOCK_MDS, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = chunk_recovery(ent->chunk);
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
        ret = __pa_srv_entry_get(pa_srv, &tid, &ent);
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

        DINFO("recovery "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        
        __pa_srv_entry_release(pa_srv);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_release:
        __pa_srv_entry_release(pa_srv);
err_ret:
        return ret;
}
