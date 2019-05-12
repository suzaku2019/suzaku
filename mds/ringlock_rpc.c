#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define DBG_SUBSYS S_YFSMDS

#include "limits.h"
#include "adt.h"
#include "ynet_rpc.h"
#include "ylib.h"
#include "net_table.h"
#include "configure.h"
#include "net_global.h"
#include "ringlock_srv.h"
#include "ringlock_rpc.h"
#include "rpc_proto.h"
#include "network.h"
#include "ylog.h"
#include "schedule.h"
#include "timer.h"
#include "ringlock_rpc.h"
#include "dbg.h"


typedef enum {
        RINGLOCK_NULL = 500,
        RINGLOCK_LOCK,
        RINGLOCK_UNLOCK,
        RINGLOCK_GET,
        RINGLOCK_MAX,
} ringlock_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t  chkid;
        char buf[0];
} msg_t;


static __request_handler_func__  __request_handler__[RINGLOCK_MAX - RINGLOCK_NULL];
static char  __request_name__[RINGLOCK_MAX - RINGLOCK_NULL][__RPC_HANDLER_NAME__ ];

static void __request_set_handler(int op, __request_handler_func__ func, const char *name)
{
        YASSERT(strlen(name) + 1 < __RPC_HANDLER_NAME__ );
        strcpy(__request_name__[op - RINGLOCK_NULL], name);
        __request_handler__[op - RINGLOCK_NULL] = func;
}

static void __request_get_handler(int op, __request_handler_func__ *func, const char **name)
{
        *func = __request_handler__[op - RINGLOCK_NULL];
        *name = __request_name__[op - RINGLOCK_NULL];
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

static int __ringlock_srv_lock(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const coreid_t *coreid;
        ltoken_t token;
        const range_t *range;
        const uint32_t *type;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &range, NULL,
                       &coreid, NULL,
                       &type, NULL,
                       NULL);

        ret = ringlock_srv_lock(range, *type, coreid, &token);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        rpc_reply(sockid, msgid, &token, sizeof(token));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int ringlock_rpc_lock(const nid_t *srv, const range_t *range, uint32_t type,
                      const coreid_t *coreid, ltoken_t *token)
{
        int ret, len = sizeof(*token);
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
 
        DINFO(""RANGE_FORMAT" lock @ %s/%d\n", RANGE_ARG(range),
              network_rname(&coreid->nid), coreid->idx);
       
        req = (void *)buf;
        req->op = RINGLOCK_LOCK;
        _opaque_encode(req->buf, &count,
                       range, sizeof(*range),
                       coreid, sizeof(*coreid),
                       &type, sizeof(type),
                       NULL);

        ret = rpc_request_wait("ringlock_rpc_lock", srv,
                               req, sizeof(*req) + count,
                               token, &len,
                               MSG_RINGLOCK, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __ringlock_srv_unlock(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const coreid_t *coreid;
        const range_t *range;
        const uint32_t *type;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen,
                       &range, NULL,
                       &coreid, NULL,
                       &type, NULL,
                       NULL);

        ret = ringlock_srv_unlock(range, *type, coreid);
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

int ringlock_rpc_unlock(const nid_t *srv, const range_t *range, uint32_t type,
                        const coreid_t *coreid)
{
        int ret;
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);

        req = (void *)buf;
        req->op = RINGLOCK_UNLOCK;
        _opaque_encode(req->buf, &count,
                       range, sizeof(*range),
                       coreid, sizeof(*coreid),
                       &type, sizeof(type),
                       NULL);

        ret = rpc_request_wait("ringlock_rpc_unlock", srv,
                               req, sizeof(*req) + count,
                               NULL, NULL,
                               MSG_RINGLOCK, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

#if 0
static int __ringlock_srv_get(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        nid_t *nid;
        ltoken_t *token;
        char tmp[MAX_BUF_LEN];
        const range_t *range;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen, &range, NULL, NULL);
        
        nid = (void *)tmp;
        token = (void *)tmp + sizeof(*nid);
        ret = ringlock_srv_get(range, nid, token);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        rpc_reply(sockid, msgid, tmp, sizeof(*nid) + sizeof(*token));

        DINFO(CHKID_FORMAT" nid %s token %x\n", CHKID_ARG(&req->chkid),
              network_rname(nid), token->seq);
        
        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}
#endif

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

        DBUG("set op %u from %s, id (%u, %x)\n", req.op,
             _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);

        if (!netable_connected(net_getadmin())) {
                ret = ENONET;
                GOTO(err_ret, ret);
        }

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
        rpc_reply_error(&sockid, &msgid, ret);
        DBUG("error op %u from %s, id (%u, %x)\n", req.op,
             _inet_ntoa(sockid.addr), msgid.idx, msgid.figerprint);
        return;
}

int ringlock_rpc_init()
{
        if (gloconf.lease_timeout < 4) {
                DERROR("gloconf.ringlock_timeout must bigger than 3\n");
                EXIT(EINVAL);
        }

        __request_set_handler(RINGLOCK_LOCK, __ringlock_srv_lock, "ringlock_srv_lock");
        //__request_set_handler(RINGLOCK_GET, __ringlock_srv_get, "ringlock_srv_get");
        __request_set_handler(RINGLOCK_UNLOCK, __ringlock_srv_unlock, "ringlock_srv_unlock");

        if (ng.daemon) {
                rpc_request_register(MSG_RINGLOCK, __request_handler, NULL);
        }

        return 0;
}

int ringlock_rpc_destroy()
{
        if (ng.daemon) {
                rpc_request_register(MSG_RINGLOCK, NULL, NULL);
        }

        return 0;
}

#if 0
int ringlock_rpc_get(const nid_t *srv, const chkid_t *chkid,
                  nid_t *nid, ltoken_t *token)
{
        int ret, len = sizeof(*nid) + sizeof(*token);
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        char tmp[MAX_BUF_LEN];

        req = (void *)buf;
        req->op = RINGLOCK_GET;
        req->chkid = *chkid;
        count = 0;

        ret = rpc_request_wait("ringlock_rpc_get", srv,
                               req, sizeof(*req) + count,
                               tmp, &len,
                               MSG_RINGLOCK, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);
 
        *nid = *(nid_t *)tmp;
        *token = *(ltoken_t *)((void *)tmp + sizeof(*nid));

        DINFO(CHKID_FORMAT" nid %s token %x\n", CHKID_ARG(&req->chkid),
              network_rname(nid), token->seq);
        
        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}
#endif
