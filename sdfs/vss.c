/*Volume Segment Session*/

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
#include "core.h"
#include "dbg.h"

typedef struct {
        chkop_type_t op;
        chkid_t chkid;
        uint64_t offset;
        uint32_t size;
} wseg_head_t;

typedef struct {
        wseg_head_t head;
        buffer_t buf;
        vs_range_t *range;
} wseg_t;

#define CHUNK_SEG_MAX 8

int vss_create(const fileid_t *fileid, const ec_t *ec, uint32_t chunk_split,
               uint32_t real_split, vss_t **_vss)
{
        int ret;
        vss_t *vss;

        ret = ymalloc((void **)&vss, sizeof(*vss));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(vss, 0x0, sizeof(*vss));
        ret = plock_init(&vss->plock, "vss");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        vss->range_count = VSS_ITEM_COUNT / RANGE_ITEM_COUNT;
        vss->id = *fileid;
        vss->ec = *ec;
        vss->chunk_split = chunk_split;
        vss->real_split = real_split;

        ret = ymalloc((void **)&vss->array, sizeof(vs_range_t) * vss->range_count);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        memset(vss->array, 0x0, sizeof(vs_range_t) * vss->range_count);

        for (uint32_t i = 0; i < vss->range_count; i++) {
                vss->array[i].ec = *ec;
        }
        
        *_vss = vss;

        return 0;
err_ret:
        return ret;
}

void vss_close(vss_t **_vss)
{
        vss_t *vss = *_vss;
        
        yfree((void **)&vss->array);
        yfree((void **)&vss);

        *_vss = NULL;
}

static int __vss_write_split(vss_t *vss, wseg_t *segs, int *count,
                             buffer_t *buf, uint32_t _size, uint64_t _offset,
                             const fileid_t *fileid)
{
        int ret, i;
        uint32_t size, idx;
        uint64_t offset, split = vss->real_split;
        wseg_t *seg;

        offset = _offset;
        size = _size;
        YASSERT(buf->len == _size);

        for (i = 0; size > 0; i++) {
                idx = (offset / (RANGE_ITEM_COUNT * split));
                
                YASSERT(i < CHUNK_SEG_MAX);
                YASSERT(vss->range_count > idx);

                seg = &segs[i];
                seg->range = &vss->array[idx];
                fid2cid(&seg->head.chkid, fileid, offset / split);
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

int vss_write(vss_t *vss, const buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        wseg_t seg_array[CHUNK_SEG_MAX], *seg;
        int i, seg_count;
        buffer_t newbuf;
        const fileid_t *fileid = &vss->id;

        ANALYSIS_BEGIN(0);
        
        YASSERT(_buf->len == size);

        DINFO("write "CHKID_FORMAT", size %u, offset %ju\n", CHKID_ARG(fileid),
              size, offset);

        mbuffer_init(&newbuf, 0);
        mbuffer_reference(&newbuf, _buf);

        ret = plock_rdlock(&vss->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __vss_write_split(vss, seg_array, &seg_count, &newbuf, size,
                                offset, fileid);
        if (ret)
                GOTO(err_lock, ret);

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                ret = vs_chunk_write(seg->range, &seg->head.chkid, &seg->buf,
                                     seg->head.size, seg->head.offset);
                if (ret) {
                        GOTO(err_free, ret);
                }
        }

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_free(&seg->buf);
        }

        plock_unlock(&vss->plock);
        mbuffer_free(&newbuf);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_free:
        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_free(&seg->buf);
        }
err_lock:
        plock_unlock(&vss->plock);
err_ret:
        mbuffer_free(&newbuf);
        return ret;
}

static int __vss_read_split(vss_t *vss, wseg_t *segs, int *count,
                            uint32_t _size, uint64_t _offset,
                            const fileid_t *fileid)
{
        int i;
        uint32_t size, idx;
        uint64_t offset, split = vss->real_split;
        wseg_t *seg;

        offset = _offset;
        size = _size;

        for (i = 0; size > 0; i++) {
                idx = (offset / (RANGE_ITEM_COUNT * split));
                
                YASSERT(i < CHUNK_SEG_MAX);
                YASSERT(vss->range_count > idx);

                seg = &segs[i];
                seg->range = &vss->array[idx];
                fid2cid(&seg->head.chkid, fileid, offset / split);
                seg->head.op = CHKOP_READ;
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

int vss_read(vss_t *vss, buffer_t *_buf, uint32_t size, uint64_t offset)
{
        int ret;
        wseg_t seg_array[CHUNK_SEG_MAX], *seg;
        int i, seg_count;
        buffer_t newbuf;
        const fileid_t *fileid = &vss->id;

        ANALYSIS_BEGIN(0);
        
        DINFO("read "CHKID_FORMAT", size %u, offset %ju\n", CHKID_ARG(fileid), size, offset);

        ret = plock_rdlock(&vss->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = __vss_read_split(vss, seg_array, &seg_count, size,
                                offset, fileid);
        if (ret)
                GOTO(err_lock, ret);

        for (i = 0; i < seg_count; i++) {
                seg = &seg_array[i];
                mbuffer_init(&newbuf, 0);
                ret = vs_chunk_read(seg->range, &seg->head.chkid, &newbuf,
                                    seg->head.size, seg->head.offset);
                if (ret) {
                        if (ret == ENOENT) {
                                mbuffer_appendzero(&newbuf, seg->head.size);
                                mbuffer_merge(_buf, &newbuf);
                                continue;
                        } else
                                GOTO(err_free, ret);
                }

                YASSERT(newbuf.len == seg->head.size);
                mbuffer_merge(_buf, &newbuf);
        }

        plock_unlock(&vss->plock);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_free:
        mbuffer_free(&newbuf);
err_lock:
        plock_unlock(&vss->plock);
err_ret:
        return ret;
}
