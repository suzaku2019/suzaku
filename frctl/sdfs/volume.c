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
#include "vs_chunk.h"
#include "vss.h"
#include "volume.h"
#include "core.h"
#include "dbg.h"

typedef struct {
        chkop_type_t op;
        uint64_t offset;
        uint32_t size;
} wseg_head_t;

typedef struct {
        wseg_head_t head;
        buffer_t buf;
        vss_t *vss;
} wseg_t;

inline static uint64_t size2chknum(uint64_t size, uint64_t split)
{
        uint64_t chknum = 0;
        
        chknum = size / split;
        if (size % split)
                chknum++;

        return chknum;
}

inline static size_t chunk_size(const ec_t *ec, uint32_t split)
{
        if (ec && ec->plugin == PLUGIN_EC_ISA) {
                return ec->k * split;
        } else
                return split;
}

#define VSS_SEG_MAX 8

static int __volume_resize(volume_t *volume, const fileinfo_t *md, uint64_t newsize)
{
        int ret;
        uint32_t newcount;
        ec_t ec;

        md2ec((void *)md, &ec);

        if (newsize < volume->size) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        newcount = size2chknum(newsize, volume->vss_split);

        ret = yrealloc((void **)&volume->array, sizeof(vss_t *) * volume->vss_count,
                       sizeof(vss_t *) * newcount);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        for (uint32_t i = volume->vss_count; i < newcount; i++) {
                ret = vss_create(&volume->id, &ec, volume->chunk_split,
                                 volume->real_split, &volume->array[i]);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);
        }

        volume->vss_count = newcount;
        volume->size = newsize;
        
        return 0;
err_ret:
        return ret;
}

static int __volume_check_size(volume_t *volume, uint32_t size, uint64_t offset, int op)
{
        int ret;
        fileinfo_t md;
        uint64_t newsize = offset + size;

        if (likely(newsize <= volume->size)) {
                goto out;
        }

        ret = plock_wrlock(&volume->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = md_getattr(NULL, &volume->id, (void *)&md);
        if (ret)
                GOTO(err_lock, ret);
        
        if (op == OP_WRITE) {
                DINFO("extend %ju\n", newsize);
                ret = md_extend(NULL, &volume->id, newsize);
                if (ret)
                        GOTO(err_lock, ret);
        } else {
                if (offset + size > md.at_size) {
                        ret = EINVAL;
                        GOTO(err_lock, ret);
                }

                newsize = md.at_size;
        }

        ret = __volume_resize(volume, &md, newsize);
        if (ret)
                GOTO(err_lock, ret);

        plock_unlock(&volume->plock);

out:
        return 0;
err_lock:
        plock_unlock(&volume->plock);
err_ret:
        return ret;
}

static int __volume_write_split(volume_t *volume, wseg_t *segs, int *count, buffer_t *buf,
                                uint32_t _size, uint64_t _offset)
{
        int ret, i;
        uint32_t size;
        uint64_t offset, split = volume->vss_split;
        wseg_t *seg;
        

        offset = _offset;
        size = _size;
        YASSERT(buf->len == _size);

        for (i = 0; size > 0; i++) {
                YASSERT(i < VSS_SEG_MAX);
                YASSERT(volume->vss_count > (offset / split));

                seg = &segs[i];
                seg->vss = volume->array[offset / split];
                seg->head.op = CHKOP_WRITE;
                seg->head.offset = offset % split;
                seg->head.size = (seg->head.offset + size) < split
                        ? size : (split - seg->head.offset);
                seg->head.size = seg->head.size < Y_BLOCK_MAX
                        ? seg->head.size: Y_BLOCK_MAX;
                size -= seg->head.size;
                offset += seg->head.size;

                YASSERT(seg->head.size + seg->head.offset <= split);

                mbuffer_init(&seg->buf, 0);

                ret = mbuffer_pop(buf, &seg->buf, seg->head.size);
                if (ret)
                        GOTO(err_ret, ret);

                YASSERT(seg->buf.len == seg->head.size);
        }

        YASSERT(buf->len == 0);

        *count = i;

        YASSERT(*count);

        return 0;
err_ret:
        return ret;
}

static int __volume_open(volume_t **_volume, const fileid_t *fileid)
{
        int ret;
        volume_t *volume;
        fileinfo_t md;
        ec_t ec;

        DINFO("open "CHKID_FORMAT"\n", CHKID_ARG(fileid));
        
        ret = md_getattr(NULL, fileid, (void *)&md);
        if (ret)
                GOTO(err_ret, ret);

        md2ec((void *)&md, &ec);
        ret = ymalloc((void **)&volume, sizeof(*volume));
        if (ret)
                GOTO(err_ret, ret);

        volume->size = md.at_size;
        volume->ec = ec;
        volume->id = md.fileid;
        volume->chunk_split = md.split;
        volume->real_split = chunk_size(&volume->ec, volume->chunk_split);
        volume->vss_count = size2chknum(volume->size, volume->real_split * VSS_ITEM_COUNT);
        volume->vss_split = volume->real_split * VSS_ITEM_COUNT;

        ret = plock_init(&volume->plock, "volume");
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        if (volume->vss_count == 0) {
                volume->array = NULL;
        } else {
                ret = ymalloc((void **)&volume->array, sizeof(vss_t *) * volume->vss_count);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);

                memset(volume->array, 0x0, sizeof(vss_t *) * volume->vss_count);

                for (uint32_t i = 0; i < volume->vss_count; i++) {
                        ret = vss_create(fileid, &ec, volume->chunk_split,
                                         volume->real_split, &volume->array[i]);
                        if (ret)
                                UNIMPLEMENTED(__DUMP__);
                }
        }
        
        *_volume = volume;

        return 0;
err_ret:
        return ret;
}

static void __volume_close(volume_t **_volume)
{
        int ret;
        volume_t *volume;

        volume = *_volume;
 
        DINFO("close "CHKID_FORMAT"\n", CHKID_ARG(&volume->id));
       
        ret = plock_wrlock(&volume->plock);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        if (volume->vss_count) {
                for (uint32_t i = 0; i < volume->vss_count; i++) {
                        vss_close(&volume->array[i]);
                }

                yfree((void **)&volume->array);
        }

        plock_unlock(&volume->plock);

        yfree((void **)&volume);
        
        *_volume = NULL;
}

int volume_write(volume_t *volume, const buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        wseg_t seg_array[VSS_SEG_MAX], *seg;
        int i, seg_count;
        buffer_t newbuf;
        const fileid_t *fileid = &volume->id;

        ANALYSIS_BEGIN(0);
        
        YASSERT(_buf->len == size);

        DINFO("write "CHKID_FORMAT", size %u, offset %ju\n",
              CHKID_ARG(fileid), size, offset);

        mbuffer_init(&newbuf, 0);
        mbuffer_reference(&newbuf, _buf);

        ret = __volume_check_size(volume, size, offset, OP_WRITE);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&volume->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __volume_write_split(volume, seg_array, &seg_count, &newbuf,
                                   size, offset);
        if (ret)
                GOTO(err_lock, ret);

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                ret = vss_write(seg->vss, &seg->buf, seg->head.size,
                                seg->head.offset);
                if (ret) {
                        GOTO(err_free, ret);
                }
        }

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_free(&seg->buf);
        }

        plock_unlock(&volume->plock);
        mbuffer_free(&newbuf);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_free:
        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_free(&seg->buf);
        }
err_lock:
        plock_unlock(&volume->plock);
err_ret:
        mbuffer_free(&newbuf);
        return ret;
}

static int __volume_read_split(volume_t *volume, wseg_t *segs, int *count,
                               uint32_t _size, uint64_t _offset)
{
        int i;
        uint32_t size;
        uint64_t offset, split = volume->vss_split;
        wseg_t *seg;
        
        offset = _offset;
        size = _size;

        for (i = 0; size > 0; i++) {
                YASSERT(i < VSS_SEG_MAX);
                YASSERT(volume->vss_count > (offset / split));

                seg = &segs[i];
                seg->vss = volume->array[offset / split];
                seg->head.op = CHKOP_WRITE;
                seg->head.offset = offset % split;
                seg->head.size = (seg->head.offset + size) < split
                        ? size : (split - seg->head.offset);
                seg->head.size = seg->head.size < Y_BLOCK_MAX
                        ? seg->head.size: Y_BLOCK_MAX;
                size -= seg->head.size;
                offset += seg->head.size;

                YASSERT(seg->head.size + seg->head.offset <= split);
        }

        *count = i;

        YASSERT(*count);

        return 0;
}


int volume_read(volume_t *volume, buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        buffer_t buf;
        wseg_t seg_array[VSS_SEG_MAX], *seg;
        int i, seg_count;

        ANALYSIS_BEGIN(0);
        
        DBUG("fileid "FID_FORMAT" size %llu off %llu size %u\n", FID_ARG(&volume->id),
             (LLU)volume->size, (LLU)offset, size);

        ret = __volume_check_size(volume, size, offset, OP_READ);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
             CHKID_ARG(&volume->id), offset, size);

        ret = plock_rdlock(&volume->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __volume_read_split(volume, seg_array, &seg_count,
                                  size, offset);
        if (ret)
                GOTO(err_lock, ret);

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_init(&buf, 0);
                ret = vss_read(seg->vss, &buf, seg->head.size,
                               seg->head.offset);
                if (ret) {
                        GOTO(err_free, ret);
                }

                YASSERT(buf.len == seg->head.size);
                mbuffer_merge(_buf, &buf);
        }

        plock_unlock(&volume->plock);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);
        
        return 0;
err_free:
        mbuffer_free(&buf);
err_lock:
        plock_unlock(&volume->plock);
err_ret:
        return ret;
}

static int __volume_open_va(va_list ap)
{
        volume_t **_volume = va_arg(ap, volume_t **);
        const fileid_t *fileid = va_arg(ap, fileid_t *);

        va_end(ap);

        return volume_open(_volume, fileid);
}


int volume_open(volume_t **_volume, const fileid_t *fileid)
{
        int ret;

        if (likely(core_self())) {
                ret = __volume_open(_volume, fileid);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = core_request(0, -1, "volume_open1",
                                   __volume_open_va, _volume, fileid);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __volume_close_va(va_list ap)
{
        volume_t **_volume = va_arg(ap, volume_t **);

        va_end(ap);

        volume_close(_volume);

        return 0;
}

void volume_close(volume_t **_volume)
{
        int ret;

        if (likely(core_self())) {
                __volume_close(_volume);
        } else {
                ret = core_request(0, -1, "volume_close1",
                                   __volume_close_va, _volume);
                if (ret)
                        UNIMPLEMENTED(__DUMP__);
        }
}

static int __volume_write(va_list ap)
{
        volume_t *volume = va_arg(ap, volume_t *);
        const buffer_t *buf = va_arg(ap, const buffer_t *);
        uint32_t size = va_arg(ap, uint32_t);
        uint64_t offset = va_arg(ap, uint64_t);

        va_end(ap);

        return volume_write(volume, buf, size, offset);
}


int volume_write1(volume_t *volume, const buffer_t *buf, uint32_t size, uint64_t offset)
{
        int ret;

        ret = core_request(0, -1, "volume_write1",
                           __volume_write, volume, buf, size, offset);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __volume_read(va_list ap)
{
        volume_t *volume = va_arg(ap, volume_t *);
        buffer_t *buf = va_arg(ap, buffer_t *);
        uint32_t size = va_arg(ap, uint32_t);
        uint64_t offset = va_arg(ap, uint64_t);

        va_end(ap);

        return volume_read(volume, buf, size, offset);
}


int volume_read1(volume_t *volume, buffer_t *buf, uint32_t size, uint64_t offset)
{
        int ret;

        ret = core_request(0, -1, "volume_read1",
                           __volume_read, volume, buf, size, offset);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __volume_chunk_iterator(volume_t *volume, const chkid_t *_chkid, func1_t func, void *arg)
{
        int ret;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];
        chkid_t chkid;
        chkidx_t begin, end;

        chkid = *_chkid;
        if (_chkid->type == ftype_sub) {
                chkid.type = ftype_raw;
                begin = _chkid->idx * PA_ITEM_COUNT * PA_ITEM_COUNT;
                end = _get_chknum(volume->size, volume->real_split);
                end = end < (begin + PA_ITEM_COUNT) ? end : (begin + PA_ITEM_COUNT);
        } else if (_chkid->type == ftype_file) {
                chkid.type = ftype_sub;
                begin = _chkid->idx * PA_ITEM_COUNT;
                end = _get_chknum(_get_chknum(volume->size, volume->real_split), PA_ITEM_COUNT);
                end = end < (begin + PA_ITEM_COUNT) ? end : (begin + PA_ITEM_COUNT);
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        chkinfo = (void *)_chkinfo;
        for (chkidx_t i = begin; i < end; i++) {
                chkid.idx = i;
                
                ret = md_chunk_load(&chkid, chkinfo, NULL);
                if (ret) {
                        if (ret == ENOENT) {
                                continue;
                        } else
                                GOTO(err_ret, ret);
                }

                func(arg, chkinfo);
        }
        
        return 0;
err_ret:
        return ret;
}

static int __volume_chunk_iterator_va(va_list ap)
{
        volume_t *volume = va_arg(ap, volume_t *);
        const chkid_t *chkid = va_arg(ap, chkid_t *);
        func1_t func = va_arg(ap, func1_t);
        void *arg = va_arg(ap, void *);

        va_end(ap);

        return __volume_chunk_iterator(volume, chkid, func, arg);
}

int volume_chunk_iterator(volume_t *volume, const chkid_t *chkid, func1_t func, void *arg)
{
        int ret;

        if (likely(core_self())) {
                ret = __volume_chunk_iterator(volume, chkid, func, arg);
                if (ret) {
                        GOTO(err_ret, ret);
                }
        } else {
                ret = core_request(0, -1, "volume_chunk_iterator",
                                   __volume_chunk_iterator_va, volume, chkid, func, arg);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}
