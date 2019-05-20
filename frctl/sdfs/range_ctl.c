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
#include "diskmap.h"
#include "range.h"
#include "chunk.h"
#include "mds_rpc.h"
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
        uint32_t ref;
        plock_t plock;
        ec_t ec;
        ltoken_t token;
        struct {
                vfm_t *vfm;
                plock_t plock;
                uint64_t version;
        } vfm[RANGE_CHUNK_COUNT];
        plock_t record_lock[VOL_LOCK];
        chunk_t *chunk[RANGE_ITEM_COUNT];
} range_entry_t;

#if 1

#define VFM_SIZE(__count__) (sizeof(vfm_t) + sizeof(vfmid_t) * __count__)
#define VFM_COUNT_MAX 32

static inline int vfm_exist(const vfm_t *vfm, const nid_t *nid) {
        int i;

        if (unlikely(!vfm)) {
                return 0;
        }

        for (i = 0; i < vfm->count; i++) {
                if (nid->id == vfm->array[i].nid.id)
                        return 1;
        }

        return 0;
}

static inline int vfm_add(vfm_t *vfm, const nid_t *nid)
{
        YASSERT(vfm);

        if (vfm_exist(vfm, nid)) {
                return EEXIST;
        }

        if (vfm->count + 1 > VFM_COUNT_MAX) {
                return EIO;
        }

        vfm->array[vfm->count].nid = *nid;
        vfm->count++;
        vfm->clock++;

        return 0;
}

static int __range_ctl_vfm_load(range_entry_t *ent, int idx)
{
        int ret;
        char info[PA_INFO_SIZE];
        int infolen = PA_INFO_SIZE;
        uint64_t version;
        vfm_t *vfm;

retry:
        ret = mds_rpc_getinfo(&ent->id, PA_INFO_VFM, info,
                              &infolen, &version);
        if (unlikely(ret)) {
                if (ret == ENODATA) {
                        memset(info, 0x0, PA_INFO_SIZE);
                        ret = mds_rpc_setinfo(&ent->id, PA_INFO_VFM, info,
                                              VFM_SIZE(0), NULL);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);

                        goto retry;
                } else
                        GOTO(err_ret, ret);
        }
        
        ret = huge_malloc((void **)&vfm, PA_INFO_SIZE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memcpy(vfm, info, infolen);
        ent->vfm[idx % PA_ITEM_COUNT].vfm = vfm;
        ent->vfm[idx % PA_ITEM_COUNT].version = version;

        return 0;
err_ret:
        return ret;
}

static int __range_ctl_vfm_update(range_entry_t *ent, int idx, chunk_t **_chunk,
                                  vfm_t *_vfm)
{
        int ret, vfm_idx = idx % PA_ITEM_COUNT;
        chunk_t *chunk = ent->chunk[idx];
        const chkinfo_t *chkinfo = chunk->chkinfo;
        vfm_t *vfm;
        uint64_t *version;
        
        ret = plock_wrlock(&ent->vfm[vfm_idx].plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (chkinfo == NULL) {
                goto out;
        }

retry:
        vfm = ent->vfm[vfm_idx].vfm;
        version = &ent->vfm[vfm_idx].version;
        if (vfm == NULL) {
                ret = __range_ctl_vfm_load(ent, idx);
                if (unlikely(ret))
                        GOTO(err_lock, ret);

                goto retry;
        }

        
        int update = 0;
        for (int i = 0; i < (int)chkinfo->repnum; i++) {
                const reploc_t *reploc = &chkinfo->diskid[i];

                if (unlikely(!disktab_online(&reploc->id))) {
                        ret = vfm_add(vfm, &reploc->id);
                        if (unlikely(ret)) {
                                continue;
                        }

                        update++;
                }
        }

        if (unlikely(update)) {
                ret = mds_rpc_setinfo(&ent->id, PA_INFO_VFM, vfm,
                                      VFM_SIZE(vfm->count), version);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        }

        
out:
        *_chunk = chunk;
        memcpy(_vfm, vfm, VFM_SIZE(vfm->count));

        plock_unlock(&ent->vfm[vfm_idx].plock);
        
        return 0;
err_lock:
        plock_unlock(&ent->vfm[vfm_idx].plock);
err_ret:
        return ret;
}
#endif

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

        ret = ringlock_check(chkid, TYPE_FRCTL, O_CREAT, &token);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = huge_malloc((void **)&ent, sizeof(*ent));
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

        for (int i = 0; i < RANGE_CHUNK_COUNT; i++) {
                ret = plock_init(&ent->vfm[i].plock, "vfm");
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }
        
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

        for (int i = 0; i < RANGE_CHUNK_COUNT; i++) {
                if (ent->vfm[i].vfm) {
                        huge_free((void **)&ent->vfm[i].vfm);
                }
        }
        
        plock_unlock(&ent->plock);
        huge_free((void **)&ent);
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

STATIC int __range_ctl_check(range_ctl_t *range_ctl, const chkid_t *tid,
                             range_entry_t *ent)
{
        int ret;

        (void) range_ctl;
        
        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = ringlock_check(tid, TYPE_FRCTL, 0, &ent->token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&ent->plock);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ret:
        return ret;
}

STATIC int __range_ctl_drop(range_ctl_t *range_ctl, const chkid_t *tid,
                            range_entry_t *ent)
{
        int ret;
        range_entry_t *tmp;

        ret = plock_wrlock(&range_ctl->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(ent->ref == 0);

        ret = htab_remove(range_ctl->htab, (void *)tid, (void **)&tmp);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        YASSERT(ent == tmp);
        
        __range_ctl_entry_free(&ent);
        
        plock_unlock(&range_ctl->plock);

        return 0;
err_lock:
        plock_unlock(&range_ctl->plock);
err_ret:
        return ret;
}

STATIC void __range_ctl_deref(range_ctl_t *range_ctl, range_entry_t *ent)
{
        (void) range_ctl;
        YASSERT(ent->ref > 0);
        ent->ref--;
}

STATIC int __range_ctl_ref(range_ctl_t *range_ctl, const chkid_t *tid,
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

        ent->ref++;//single thread
        plock_unlock(&range_ctl->plock);

        ret = __range_ctl_check(range_ctl, tid, ent);
        if (unlikely(ret)) {
                __range_ctl_deref(range_ctl, ent);
                if (ret == ESTALE) {
                        ret = __range_ctl_drop(range_ctl, tid, ent);
                        if (unlikely(ret))
                                GOTO(err_ret, ret);

                        goto retry;
                } else
                        GOTO(err_ret, ret);
        }

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
retry:
        ret = md_chunk_load(chkid, chkinfo, &version);
        if (unlikely(ret)) {
                if (ret == ENOENT) {
                        if (flags & O_CREAT) {
                                ret = __range_ctl_chunk_create__(chkid, chkinfo);
                                if (unlikely(ret))
                                        GOTO(err_ret, ret);

                                goto retry;
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
        char _vfm[PA_INFO_SIZE];
        vfm_t *vfm = (void *)_vfm;

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

        ret = __range_ctl_vfm_update(ent, idx, &chunk, vfm);
        if (unlikely(ret))
                GOTO(err_lock, ret);
retry:
        ret = chunk_get_token(vfm, chunk, op, token);
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

        ret = __range_ctl_ref(range_ctl, &rangeid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);
        
        ret = __range_ctl_get_token(ent, chkid, op, token,
                                    op == OP_WRITE ? O_CREAT : 0);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&ent->plock);
        __range_ctl_deref(range_ctl, ent);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ref:
        __range_ctl_deref(range_ctl, ent);
err_ret:
        return ret;
}


STATIC int __range_ctl_chunk_recovery(range_entry_t *ent, const chkid_t *chkid)
{
        int ret, idx;
        chunk_t *chunk;
        char _vfm[PA_INFO_SIZE];
        vfm_t *vfm = (void *)_vfm;

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

        ret = __range_ctl_vfm_update(ent, idx, &chunk, vfm);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = chunk_recovery(vfm, chunk);
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

        ret = __range_ctl_ref(range_ctl, &rangeid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);
        
        ret = __range_ctl_chunk_recovery(ent, chkid);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&ent->plock);
        __range_ctl_deref(range_ctl, ent);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ref:
        __range_ctl_deref(range_ctl, ent);
err_ret:
        return ret;
}
