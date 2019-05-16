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
#include "range.h"
#include "md_lib.h"
#include "network.h"
#include "mem_cache.h"
#include "schedule.h"
#include "corenet_connect.h"
#include "corerpc.h"
#include "dbg.h"

extern net_global_t ng;

typedef enum {
        RANGE_NULL = 500,
        RANGE_GET_TOKEN,
        RANGE_CHUNK_RECOVERY,
        RANGE_CHUNK_GETINFO,
        RANGE_MAX,
} range_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t  chkid;
        char buf[0];
} msg_t;

static __request_handler_func__  __request_handler__[RANGE_MAX - RANGE_NULL];
static char  __request_name__[RANGE_MAX - RANGE_NULL][__RPC_HANDLER_NAME__ ];

static void __request_set_handler(int op, __request_handler_func__ func, const char *name)
{
        YASSERT(strlen(name) + 1 < __RPC_HANDLER_NAME__ );
        strcpy(__request_name__[op - RANGE_NULL], name);
        __request_handler__[op - RANGE_NULL] = func;
}

static void __request_get_handler(int op, __request_handler_func__ *func, const char **name)
{
        *func = __request_handler__[op - RANGE_NULL];
        *name = __request_name__[op - RANGE_NULL];
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
        corerpc_reply_error_union(&sockid, &msgid, ret);

        DBUG("error op %u from %s, id (%u, %x)\n", req.op,
             _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);
        return;
}

#if 0
static int __range_ctl_get_token__(va_list ap)
{
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        int op = va_arg(ap, int);
        io_token_t *token = va_arg(ap, io_token_t *);

        va_end(ap);
        
        return range_ctl_get_token(chkid, op, token);
}

static int __range_ctl_get_token(const coreid_t *coreid, const chkid_t *chkid, int op,
                                 io_token_t *token)
{
        int ret;

        ret = core_request(coreid->idx, -1, __FUNCTION__,
                           __range_ctl_get_token__, chkid, op, token);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
#endif

static int __range_srv_get_token(const sockid_t *sockid, const msgid_t *msgid,
                                 buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const uint32_t *op;
        const nid_t *nid;
        const coreid_t *coreid;
        io_token_t *token;
        char _token[IO_TOKEN_MAX];

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &coreid, NULL,
                       &op, NULL,
                       NULL);

        token = (void *)_token;
        ret = range_ctl_get_token(&req->chkid, *op, token);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DBUG("corenet write\n");
        corerpc_reply_union(sockid, msgid, token, IO_TOKEN_SIZE(token->repnum));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int range_rpc_get_token(const coreid_t *coreid, const chkid_t *chkid, uint32_t op,
                        io_token_t *token)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect(&coreid->nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = RANGE_GET_TOKEN;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       coreid, sizeof(*coreid),
                       &op, sizeof(op),
                       NULL);

        req->buflen = count;

        DBUG("connect %u\n", sizeof(*req) + count);

        buffer_t _buf;
        mbuffer_init(&_buf, 0);

        ret = corerpc_postwait_union("range_rpc_get_token", coreid,
                               req, sizeof(*req) + count, NULL,
                               &_buf, MSG_RANGE, 0, _get_timeout());
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        mbuffer_popmsg(&_buf, token, _buf.len);

        //YASSERT(_buf.len == sizeof(*token));

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

#if 0
static int __range_ctl_chunk_recovery__(va_list ap)
{
        const chkid_t *chkid = va_arg(ap, const chkid_t *);

        va_end(ap);
        
        return range_ctl_chunk_recovery(chkid);
}


static int __range_ctl_chunk_recovery(const coreid_t *coreid, const chkid_t *chkid)
{
        int ret;

        ret = core_request(coreid->idx, -1, __FUNCTION__,
                           __range_ctl_chunk_recovery__, chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

#endif

static int __range_srv_recovery(const sockid_t *sockid, const msgid_t *msgid,
                                 buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const nid_t *nid;
        const coreid_t *coreid;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &coreid, NULL,
                       NULL);

        ret = range_ctl_chunk_recovery(&req->chkid);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        corerpc_reply_union(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int range_rpc_chunk_recovery(const coreid_t *coreid, const chkid_t *chkid)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        YASSERT(chkid->type == ftype_raw);
        
        ret = network_connect(&coreid->nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = RANGE_CHUNK_RECOVERY;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       coreid, sizeof(*coreid),
                       NULL);

        req->buflen = count;

        DBUG("connect %u\n", sizeof(*req) + count);

        ret = corerpc_postwait_union("range_rpc_chunk_recovery", coreid,
                               req, sizeof(*req) + count, NULL,
                               NULL, MSG_RANGE, 0, _get_timeout());
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

#if 0
static int __range_ctl_chunk_getinfo__(va_list ap)
{
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        chkinfo_t *chkinfo = va_arg(ap, chkinfo_t *);

        va_end(ap);
        
        return range_ctl_chunk_getinfo(chkid, chkinfo);
}

static int __range_ctl_chunk_getinfo(const coreid_t *coreid, const chkid_t *chkid,
                                     chkinfo_t *chkinfo)
{
        int ret;

        ret = core_request(coreid->idx, -1, __FUNCTION__,
                           __range_ctl_chunk_getinfo__, chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __range_srv_chunk_getinfo(const sockid_t *sockid, const msgid_t *msgid,
                                 buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const uint32_t *op;
        const nid_t *nid;
        const coreid_t *coreid;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &coreid, NULL,
                       &op, NULL,
                       NULL);

        chkinfo = (void *)_chkinfo;
        ret = range_ctl_chunk_getinfo(&req->chkid, chkinfo);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DBUG("corenet write\n");
        corerpc_reply_union(sockid, msgid, chkinfo, CHKINFO_SIZE(chkinfo->repnum));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int range_rpc_chunk_getinfo(const coreid_t *coreid, const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect(&coreid->nid, NULL, 1, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = RANGE_CHUNK_GETINFO;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       net_getnid(), sizeof(nid_t),
                       coreid, sizeof(*coreid),
                       NULL);

        req->buflen = count;

        DBUG("connect %u\n", sizeof(*req) + count);

        buffer_t _buf;
        mbuffer_init(&_buf, 0);

        ret = corerpc_postwait_union("range_rpc_chunk_getinfo", coreid,
                               req, sizeof(*req) + count, NULL,
                               &_buf, MSG_RANGE, 0, _get_timeout());
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        mbuffer_popmsg(&_buf, chkinfo, _buf.len);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}
#endif

int range_rpc_init()
{
        DINFO("range rpc init\n");

        __request_set_handler(RANGE_GET_TOKEN, __range_srv_get_token,
                              "range_ctl_get_token");
        __request_set_handler(RANGE_CHUNK_RECOVERY, __range_srv_recovery,
                              "range_ctl_chunk_recovery");

#if 0
        __request_set_handler(RANGE_CHUNK_GETINFO, __range_srv_chunk_getinfo,
                              "range_ctl_chunk_getinfo");
#endif
        
        rpc_request_register(MSG_RANGE, __request_handler, NULL);
        corerpc_register(MSG_RANGE, __request_handler, NULL);

        return 0;
}
