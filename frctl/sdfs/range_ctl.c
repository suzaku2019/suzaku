/*Range Controller*/

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
#include "range.h"
#include "chunk.h"
#include "core.h"
#include "dbg.h"

#define VOL_LOCK 128
#define VOL_HASH (32)

typedef struct {
        plock_t plock;
        htab_t htab;
} range_ctl_t;

typedef struct {
        chkid_t id;
        plock_t plock;
        ec_t ec;
        ltoken_t token;
        vfm_t *vfm[RANGE_CHUNK_COUNT];
        plock_t record_lock[VOL_LOCK];
        chunk_t *chunk[RANGE_ITEM_COUNT];
} range_entry_t;

STATIC int __range_ctl_cmp(const void *v1, const void *v2)
{
        const range_entry_t *ent = v1;
        const chkid_t *chkid = v2;

        return chkid_cmp(&ent->id, chkid);
}

STATIC uint32_t __range_ctl_key(const void *args)
{
        const chkid_t *id = args;

        return id->id * (1 + id->idx);
}

STATIC int __range_ctl_create__(range_ctl_t *range_ctl)
{
        int ret;

        range_ctl->htab = htab_create(__range_ctl_cmp, __range_ctl_key, "range_ctl");
        if (range_ctl->htab == NULL) {
                UNIMPLEMENTED(__DUMP__);
        }

        ret = plock_init(&range_ctl->plock, "range_ctl");
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_create(va_list ap)
{
        int ret;
        range_ctl_t *range_ctl;

        va_end(ap);

        ret = ymalloc((void **)&range_ctl, sizeof(*range_ctl) * VOL_HASH);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        for (int i = 0; i < VOL_HASH; i++) {
                ret = __range_ctl_create__(&range_ctl[i]);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);
        }

        variable_set(VARIABLE_RANGE_SRV, range_ctl);

        return 0;
}

int range_ctl_create()
{
        int ret;

        ret = core_init_modules("range_ctl_create", __range_ctl_create, NULL);
        if (ret)
                GOTO(err_ret, ret);

        //scan not implimented
        UNIMPLEMENTED(__WARN__);
        
        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_entry_create(const chkid_t *chkid, range_entry_t **_ent)
{
        int ret;
        range_entry_t *ent;
        fileinfo_t md;
        fileid_t fileid;
        ltoken_t token;

        ret = ringlock_check(chkid, RINGLOCK_FRCTL, O_CREAT, &token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = ymalloc((void **)&ent, sizeof(*ent));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(ent, 0x0, sizeof(*ent));
        ent->id = *chkid;
        ent->token = token;

        cid2fid(&fileid, chkid);
        ret = md_getattr(NULL, &fileid, (void *)&md);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        md2ec((void *)&md, &ent->ec);

        ret = plock_init(&ent->plock, "pa_entry");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);
        
        for (int i = 0; i < VOL_LOCK; i++) {
                ret = plock_init(&ent->record_lock[i], "record_lock");
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }

        *_ent = ent;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_entry_free(range_entry_t **_ent)
{
        int ret;
        range_entry_t *ent = *_ent;

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        for (uint64_t i = 0; i < RANGE_ITEM_COUNT; i++) {
                if (ent->chunk[i]) {
                        chunk_close(&ent->chunk[i]);
                }
        }
        
        plock_unlock(&ent->plock);
        yfree((void **)&ent);
        *_ent = NULL;

        return 0;
}

STATIC int __range_ctl_load(range_ctl_t *range_ctl, const rid_t *rid)
{
        int ret;
        range_entry_t *ent;

        DINFO("load "CHKID_FORMAT"\n", CHKID_ARG(rid));

        ret = plock_wrlock(&range_ctl->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __range_ctl_entry_create(rid, &ent);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = htab_insert(range_ctl->htab, (void *)ent, &ent->id, 0);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        plock_unlock(&range_ctl->plock);

        ret = plock_rdlock(&range_ctl->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(range_ctl->htab, (void *)rid);
        YASSERT(ent);

        plock_unlock(&range_ctl->plock);
        
        return 0;
err_free:
        UNIMPLEMENTED(__DUMP__);
err_lock:
        plock_unlock(&range_ctl->plock);
err_ret:
        return ret;
}

STATIC int __range_ctl_entry(range_ctl_t *range_ctl, const chkid_t *tid,
                                 range_entry_t **_ent)
{
        int ret;
        range_entry_t *ent;

retry:
        ret = plock_rdlock(&range_ctl->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(range_ctl->htab, (void *)tid);
        if (ent == NULL) {
                plock_unlock(&range_ctl->plock);

                ret = __range_ctl_load(range_ctl, tid);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                goto retry;
        }

        plock_unlock(&range_ctl->plock);

        *_ent = ent;

        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_chunk_create__(const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        fileinfo_t md;
        fileid_t fileid;

        DINFO("create "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        cid2fid(&fileid, chkid);
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

STATIC int __range_ctl_chunk_load(const chkid_t *chkid, const ec_t *ec,
                                  chunk_t **_chunk, int flags)
{
        int ret;
        chunk_t *chunk;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];
        uint64_t version;

        chkinfo = (void *)_chkinfo;
        ret = md_chunk_load(chkid, chkinfo, &version);
        if (unlikely(ret)) {
                if (ret == ENOENT) {
                        if (flags & O_CREAT) {
                                ret = __range_ctl_chunk_create__(chkid, chkinfo);
                                if (unlikely(ret))
                                        GOTO(err_ret, ret);
                        } else {
                                chkinfo = NULL;
                                version = 0;
                        }
                } else
                        GOTO(err_ret, ret);
        }

        ret = chunk_open(&chunk, chkinfo, version, NULL, ec, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        *_chunk = chunk;
        
        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_chunk_create(const chkid_t *chkid, chunk_t *chunk)
{
        int ret;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];

        chkinfo = (void *)_chkinfo;
        ret = __range_ctl_chunk_create__(chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = chunk_update(chunk, chkinfo, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_rec_rdlock(range_entry_t *ent, const chkid_t *chkid)
{
        return plock_rdlock(&ent->record_lock[chkid->idx % VOL_LOCK]);
}

STATIC int __range_ctl_rec_wrlock(range_entry_t *ent, const chkid_t *chkid)
{
        return plock_wrlock(&ent->record_lock[chkid->idx % VOL_LOCK]);
}

STATIC void __range_ctl_rec_unlock(range_entry_t *ent, const chkid_t *chkid)
{
        plock_unlock(&ent->record_lock[chkid->idx % VOL_LOCK]);
}

STATIC int __range_ctl_get_token(range_entry_t *ent, const chkid_t *chkid,
                                 int op, io_token_t *token, int flags)
{
        int ret, idx;
        chunk_t *chunk;

        idx = chkid->idx % RANGE_ITEM_COUNT;
        ret = __range_ctl_rec_wrlock(ent, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(ent->chunk[idx] == NULL)) {
                ret = __range_ctl_chunk_load(chkid, &ent->ec,
                                             &ent->chunk[idx], flags);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        }

        chunk = ent->chunk[idx];
retry:
        ret = chunk_get_token(NULL, chunk, op, token);
        if (unlikely(ret)) {
                if (ret == ENOENT && flags == O_CREAT) {
                        ret = __range_ctl_chunk_create(chkid, chunk);
                        if (unlikely(ret))
                                GOTO(err_lock, ret);

                        goto retry;
                } else {
                        GOTO(err_lock, ret);
                }
        }
        
        __range_ctl_rec_unlock(ent, chkid);

        return 0;
err_lock:
        __range_ctl_rec_unlock(ent, chkid);
err_ret:
        return ret;
}

int range_ctl_get_token(const chkid_t *chkid, int op, io_token_t *token)
{
        int ret;
        range_ctl_t *range_ctl = variable_get(VARIABLE_RANGE_SRV);
        chkid_t rangeid;
        range_entry_t *ent;

        cid2rid(chkid, &rangeid);

        ret = __range_ctl_entry(range_ctl, &rangeid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = ringlock_check(chkid, RINGLOCK_FRCTL, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __range_ctl_get_token(ent, chkid, op, token,
                                    op == OP_WRITE ? O_CREAT : 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __range_ctl_chunk_recovery(range_entry_t *ent, const chkid_t *chkid)
{
        int ret, idx;

        idx = chkid->idx % RANGE_ITEM_COUNT;
        ret = __range_ctl_rec_wrlock(ent, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(ent->chunk[idx] == NULL)) {
                ret = __range_ctl_chunk_load(chkid, &ent->ec,
                                             &ent->chunk[idx], 0);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        }

        chunk_t *chunk = ent->chunk[idx];
        //vfm_t *vfm = ent->vfm[idx % PA_ITEM_COUNT];
        ret = chunk_recovery(NULL, chunk);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }
        
        __range_ctl_rec_unlock(ent, chkid);

        return 0;
err_lock:
        __range_ctl_rec_unlock(ent, chkid);
err_ret:
        return ret;
}

int range_ctl_chunk_recovery(const chkid_t *chkid)
{
        int ret;
        range_ctl_t *range_ctl = variable_get(VARIABLE_RANGE_SRV);
        chkid_t rangeid;
        range_entry_t *ent;

        YASSERT(chkid->type == ftype_raw);
        cid2rid(chkid, &rangeid);

        ret = __range_ctl_entry(range_ctl, &rangeid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = ringlock_check(chkid, RINGLOCK_FRCTL, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __range_ctl_chunk_recovery(ent, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

#if 0
STATIC int __range_ctl_chunk_getinfo(range_entry_t *ent, const chkid_t *chkid,
                                     chkinfo_t *chkinfo)
{
        int ret, idx;
        chunk_t *chunk;

        idx = chkid->idx % RANGE_ITEM_COUNT;
        ret = __range_ctl_rec_wrlock(ent, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(ent->chunk[idx] == NULL)) {
                ret = __range_ctl_chunk_load(chkid, &ent->ec,
                                             &ent->chunk[idx], 0);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        }

        chunk = ent->chunk[idx];
        CHKINFO_CP(chkinfo, chunk->chkinfo);
        
        __range_ctl_rec_unlock(ent, chkid);

        return 0;
err_lock:
        __range_ctl_rec_unlock(ent, chkid);
err_ret:
        return ret;
}

int range_ctl_chunk_getinfo(const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        range_ctl_t *range_ctl = variable_get(VARIABLE_RANGE_SRV);
        chkid_t rangeid;
        range_entry_t *ent;

        cid2rid(chkid, &rangeid);

        ret = __range_ctl_entry(range_ctl, &rangeid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = ringlock_check(chkid, RINGLOCK_FRCTL, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __range_ctl_chunk_getinfo(ent, chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
#endif
