#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <unistd.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <semaphore.h>
#include <poll.h> 
#include <pthread.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSLIB

#include "ynet_rpc.h"
#include "job_dock.h"
#include "net_global.h"
#include "ynet_rpc.h"
#include "rpc_proto.h"
#include "cds_rpc.h"
#include "md_lib.h"
#include "diskid.h"
#include "network.h"
#include "diskmap.h"
#include "mem_cache.h"
#include "disk.h"
#include "schedule.h"
#include "corenet_connect.h"
#include "corerpc.h"
#include "dbg.h"

extern net_global_t ng;

typedef enum {
        CDS_NULL = 400,
        CDS_DISKSTAT,
        CDS_SYNC,
        CDS_WRITE,
        CDS_READ,
        CDS_CONNECT,
        CDS_GETCLOCK,
        CDS_CREATE,
        CDS_RESET,
        CDS_MAX,
} cds_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t  chkid;
        char buf[0];
} msg_t;

static __request_handler_func__  __request_handler__[CDS_MAX - CDS_NULL];
static char  __request_name__[CDS_MAX - CDS_NULL][__RPC_HANDLER_NAME__ ];

static void __request_set_handler(int op, __request_handler_func__ func, const char *name)
{
        YASSERT(strlen(name) + 1 < __RPC_HANDLER_NAME__ );
        strcpy(__request_name__[op - CDS_NULL], name);
        __request_handler__[op - CDS_NULL] = func;
}

static void __request_get_handler(int op, __request_handler_func__ *func, const char **name)
{
        *func = __request_handler__[op - CDS_NULL];
        *name = __request_name__[op - CDS_NULL];
}

static void __getmsg(buffer_t *buf, msg_t **_req, int *buflen, char *_buf)
{
        msg_t *req;

        YASSERT(buf->len <= MEM_CACHE_SIZE4K);

        req = (void *)_buf;
        *buflen = buf->len - sizeof(*req);
        mbuffer_get(buf, req, buf->len);

        *_req = req;
}

static void __request_handler(void *arg)
{
        int ret;
        msg_t req;
        sockid_t sockid;
        msgid_t msgid;
        buffer_t buf;
        __request_handler_func__ handler;
        const char *name;

        request_trans(arg, NULL, &sockid, &msgid, &buf, NULL);

        if (buf.len < sizeof(req)) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        mbuffer_get(&buf, &req, sizeof(req));

        DBUG("new op %u from %s, id (%u, %x)\n", req.op,
             _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);

#if 0
        if (!netable_connected(net_getadmin())) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }
#endif

        __request_get_handler(req.op, &handler, &name);
        if (handler == NULL) {
                ret = ENOSYS;
                DWARN("error op %u\n", req.op);
                GOTO(err_ret, ret);
        }

        schedule_task_setname(name);

        ret = handler(&sockid, &msgid, &buf);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_free(&buf);

        DBUG("reply op %u from %s, id (%u, %x)\n", req.op,
              _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);

        return ;
err_ret:
        mbuffer_free(&buf);
        corerpc_reply_error(&sockid, &msgid, ret);
        DBUG("error op %u from %s, id (%u, %x)\n", req.op,
             _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);
        return;
}

static int __cds_srv_read(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const io_t *io;
        buffer_t reply;
        const nid_t *reader;
        const diskid_t *diskid;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &reader, NULL,
                       &diskid, NULL,
                       &io, NULL,
                       NULL);

        mbuffer_init(&reply, 0);

        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
              CHKID_ARG(&io->id), io->offset, io->size);
        
        ret = disk_io_read(diskid, io, &reply);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        corerpc_reply_buffer(sockid, msgid, &reply);

        mbuffer_free(&reply);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_read(const diskid_t *diskid, const io_t *io, buffer_t *_buf)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        if (unlikely(!disktab_online(diskid))) {
                ret = ENODEV;
                GOTO(err_ret, ret);
        }
        
        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        DBUG("read "CHKID_FORMAT" offset %ju size %u\n",
              CHKID_ARG(&io->id), io->offset, io->size);
        
        req = (void *)buf;
        req->op = CDS_READ;
        req->chkid = io->id;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       io, sizeof(*io),
                       NULL);

        coreid_t coreid;
        ret = chkid2coreid(&io->id, &nid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = corerpc_postwait("cds_rpc_read", &coreid,
                                req, sizeof(*req) + count, NULL,
                                _buf, MSG_REPLICA, io->size, _get_timeout());
        if (unlikely(ret)) {
                YASSERT(ret != EINVAL);
                GOTO(err_ret, ret);
        }

        DBUG("read return\n");
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_write(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *writer;
        const io_t *io;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &writer, NULL,
                       &diskid, NULL,
                       &io, NULL,
                       NULL);

        DBUG("write chunk "CHKID_FORMAT", off %llu, len %u:%u\n",
              CHKID_ARG(&req->chkid), (LLU)io->offset, io->size, _buf->len);

        YASSERT(_buf->len == io->size);

        ret = disk_io_write(diskid, io, _buf);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        corerpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_write(const diskid_t *diskid, const io_t *io, const buffer_t *_buf)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        if (unlikely(!disktab_online(diskid))) {
                ret = ENODEV;
                GOTO(err_ret, ret);
        }
        
        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        YASSERT(_buf->len == io->size);

        req = (void *)buf;
        req->op = CDS_WRITE;
        req->chkid = io->id;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       io, sizeof(*io),
                       NULL);

        req->buflen = count;

        DBUG("write %u\n", sizeof(*req) + count + _buf->len);
        
        coreid_t coreid;
        ret = chkid2coreid(&io->id, &nid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG("corenet write\n");
        ret = corerpc_postwait("cds_rpc_write", &coreid,
                               req, sizeof(*req) + count, _buf,
                               NULL, MSG_REPLICA, io->size, _get_timeout());
        if (unlikely(ret)) {
                YASSERT(ret != EINVAL);
                GOTO(err_ret, ret);
        }

        DBUG("write return\n");
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_connect(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const ltoken_t *ltoken;
        const uint32_t *magic;
        const int *resuse;
        clockstat_t clockstat;
        const nid_t *nid;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &diskid, NULL,
                       &ltoken, NULL,
                       &magic, NULL,
                       &resuse, NULL,
                       NULL);

        ret = disk_io_connect(nid, diskid, &req->chkid, ltoken,
                              *magic, &clockstat, *resuse);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        rpc_reply(sockid, msgid, &clockstat, sizeof(clockstat));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_connect(const diskid_t *diskid, const chkid_t *chkid, const ltoken_t *ltoken,
                    uint32_t magic, clockstat_t *clockstat, int resuse)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = CDS_CONNECT;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       ltoken, sizeof(*ltoken),
                       &magic, sizeof(magic),
                       &resuse, sizeof(resuse),
                       NULL);

        req->buflen = count;

        DBUG("connect %u\n", sizeof(*req) + count);
        
        ret = rpc_request_wait("cds_rpc_connect", &nid,
                               req, sizeof(*req) + count,
                               clockstat, NULL,
                               MSG_REPLICA, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_create(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const int *initzero;
        const uint32_t *size;
        const nid_t *nid;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &diskid, NULL,
                       &size, NULL,
                       &initzero, NULL,
                       NULL);

        ret = disk_io_create(diskid, &req->chkid, *size, *initzero);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        rpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_create(const diskid_t *diskid, const chkid_t *chkid,
                   uint32_t size, int initzero)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = CDS_CREATE;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       &size, sizeof(size),
                       &initzero, sizeof(initzero),
                       NULL);

        req->buflen = count;

        DBUG("create %u\n", sizeof(*req) + count);
        
        ret = rpc_request_wait("cds_rpc_create", &nid,
                               req, sizeof(*req) + count,
                               NULL, NULL,
                               MSG_REPLICA, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_diskstat(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const diskid_t *diskid;
        disk_info_t stat;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &diskid, NULL,
                       NULL);

        ret = disk_stat(diskid, &stat);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        rpc_reply(sockid, msgid, &stat, sizeof(stat));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_diskstat(const diskid_t *diskid, disk_info_t *stat)
{
        int ret, replen = sizeof(*stat);
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;
        
        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = CDS_DISKSTAT;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       NULL);

        req->buflen = count;

        DBUG("stat %u\n", sizeof(*req) + count);
        
        ret = rpc_request_wait("cds_rpc_diskstat", &nid,
                               req, sizeof(*req) + count,
                               stat, &replen,
                               MSG_REPLICA, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_sync(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *writer;
        const io_t *io;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &writer, NULL,
                       &diskid, NULL,
                       &io, NULL,
                       NULL);

        DINFO("sync chunk "CHKID_FORMAT", off %llu, len %u:%u\n",
              CHKID_ARG(&req->chkid), (LLU)io->offset, io->size, _buf->len);

        YASSERT(_buf->len == io->size);

        ret = disk_io_sync(diskid, io, _buf);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        corerpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_sync(const diskid_t *diskid, const io_t *io, const buffer_t *_buf)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        YASSERT(_buf->len == io->size);

        req = (void *)buf;
        req->op = CDS_SYNC;
        req->chkid = io->id;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       io, sizeof(*io),
                       NULL);

        req->buflen = count;

        DBUG("sync %u\n", sizeof(*req) + count + _buf->len);
        
        coreid_t coreid;
        ret = chkid2coreid(&io->id, &nid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DBUG("corenet sync\n");
        ret = corerpc_postwait("cds_rpc_sync", &coreid,
                               req, sizeof(*req) + count, _buf,
                               NULL, MSG_REPLICA, io->size, _get_timeout());
        if (unlikely(ret)) {
                YASSERT(ret != EINVAL);
                GOTO(err_ret, ret);
        }

        DBUG("sync return\n");
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_getclock(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        clockstat_t clockstat;
        const nid_t *nid;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &diskid, NULL,
                       NULL);

        ret = disk_io_getclock(diskid, &req->chkid, &clockstat);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        corerpc_reply(sockid, msgid, &clockstat, sizeof(clockstat));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_getclock(const diskid_t *diskid, const chkid_t *chkid, clockstat_t *clockstat)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = CDS_GETCLOCK;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       NULL);

        req->buflen = count;

        coreid_t coreid;
        ret = chkid2coreid(chkid, &nid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        buffer_t _buf;
        mbuffer_init(&_buf, 0);
        ret = corerpc_postwait("cds_rpc_read", &coreid,
                               req, sizeof(*req) + count, NULL,
                               &_buf, MSG_REPLICA, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_popmsg(&_buf, clockstat, _buf.len);
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __cds_srv_reset(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const diskid_t *diskid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &diskid, NULL,
                       NULL);

        ret = disk_io_reset(diskid, &req->chkid);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        corerpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int cds_rpc_reset(const diskid_t *diskid, const chkid_t *chkid)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid;        

        ret = d2n_nid(diskid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = CDS_RESET;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       diskid, sizeof(*diskid),
                       NULL);

        req->buflen = count;

        coreid_t coreid;
        ret = chkid2coreid(chkid, &nid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = corerpc_postwait("cds_rpc_read", &coreid,
                               req, sizeof(*req) + count, NULL,
                               NULL, MSG_REPLICA, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}


int cds_rpc_init()
{
        DINFO("replica rpc init\n");

        __request_set_handler(CDS_READ, __cds_srv_read, "cds_srv_read");
        __request_set_handler(CDS_WRITE, __cds_srv_write, "cds_srv_write");
        __request_set_handler(CDS_SYNC, __cds_srv_sync, "cds_srv_sync");
        __request_set_handler(CDS_CONNECT, __cds_srv_connect, "cds_srv_connect");
        __request_set_handler(CDS_GETCLOCK, __cds_srv_getclock, "cds_srv_getclock");
        __request_set_handler(CDS_RESET, __cds_srv_reset, "cds_srv_reset");
        __request_set_handler(CDS_CREATE, __cds_srv_create, "cds_srv_create");
        __request_set_handler(CDS_DISKSTAT, __cds_srv_diskstat, "cds_srv_diskstat");
        
        if (ng.daemon) {
                rpc_request_register(MSG_REPLICA, __request_handler, NULL);
                corerpc_register(MSG_REPLICA, __request_handler, NULL);
        }

        return 0;
}
