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
#include "mds_lease.h"
#include "rpc_proto.h"
#include "network.h"
#include "ylog.h"
#include "schedule.h"
#include "timer.h"
#include "lease_rpc.h"
#include "dbg.h"


typedef enum {
        LEASE_NULL = 500,
        LEASE_SET,
        LEASE_FREE,
        LEASE_GET,
        LEASE_MAX,
} lease_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t  chkid;
        char buf[0];
} msg_t;


static __request_handler_func__  __request_handler__[LEASE_MAX - LEASE_NULL];
static char  __request_name__[LEASE_MAX - LEASE_NULL][__RPC_HANDLER_NAME__ ];

static void __request_set_handler(int op, __request_handler_func__ func, const char *name)
{
        YASSERT(strlen(name) + 1 < __RPC_HANDLER_NAME__ );
        strcpy(__request_name__[op - LEASE_NULL], name);
        __request_handler__[op - LEASE_NULL] = func;
}

static void __request_get_handler(int op, __request_handler_func__ *func, const char **name)
{
        *func = __request_handler__[op - LEASE_NULL];
        *name = __request_name__[op - LEASE_NULL];
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

static int __lease_srv_set(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const nid_t *nid;
        ltoken_t token;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen, &nid, NULL, NULL);

        ret = mds_lease_set(&req->chkid, nid, &token);
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

static int __lease_srv_free(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        const nid_t *nid;

        __getmsg(_buf, &req, &buflen, buf);

        _opaque_decode(req->buf, buflen, &nid, NULL, NULL);

        ret = mds_lease_free(&req->chkid, nid);
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

static int __lease_srv_get(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, buflen;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        nid_t *nid;
        ltoken_t *token;
        char tmp[MAX_BUF_LEN];

        __getmsg(_buf, &req, &buflen, buf);

        //_opaque_decode(req->buf, buflen, &nid, NULL, NULL);

        nid = (void *)tmp;
        token = (void *)tmp + sizeof(*nid);
        ret = mds_lease_get(&req->chkid, nid, token);
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

int lease_rpc_init()
{
        if (gloconf.lease_timeout < 4) {
                DERROR("gloconf.lease_timeout must bigger than 3\n");
                EXIT(EINVAL);
        }

        __request_set_handler(LEASE_SET, __lease_srv_set, "lease_srv_set");
        __request_set_handler(LEASE_GET, __lease_srv_get, "lease_srv_get");
        __request_set_handler(LEASE_FREE, __lease_srv_free, "lease_srv_free");

        if (ng.daemon) {
                rpc_request_register(MSG_LEASE, __request_handler, NULL);
        }

        return 0;
}

int lease_rpc_destroy()
{
        if (ng.daemon) {
                rpc_request_register(MSG_LEASE, NULL, NULL);
        }

        return 0;
}

int lease_rpc_get(const nid_t *srv, const chkid_t *chkid,
                  nid_t *nid, ltoken_t *token)
{
        int ret, len = sizeof(*nid) + sizeof(*token);
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        char tmp[MAX_BUF_LEN];

        req = (void *)buf;
        req->op = LEASE_GET;
        req->chkid = *chkid;
        //_opaque_encode(req->buf, &count,
        //nid, sizeof(*nid), NULL);
        count = 0;

        ret = rpc_request_wait("lease_rpc_get", srv,
                               req, sizeof(*req) + count,
                               tmp, &len,
                               MSG_LEASE, 0, _get_timeout());
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

int lease_rpc_set(const nid_t *srv, const chkid_t *chkid,
                  const nid_t *nid, ltoken_t *token)
{
        int ret, len = sizeof(*token);
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
 
        DBUG(""CHKID_FORMAT" set @ %s\n", CHKID_ARG(chkid), network_rname(nid));
       
        req = (void *)buf;
        req->op = LEASE_SET;
        req->chkid = *chkid;
        _opaque_encode(req->buf, &count,
                       nid, sizeof(*nid), NULL);

        ret = rpc_request_wait("lease_rpc_set", srv,
                               req, sizeof(*req) + count,
                               token, &len,
                               MSG_LEASE, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}


int lease_rpc_free(const nid_t *srv, const chkid_t *chkid, const nid_t *nid)
{
        int ret;
        uint32_t count;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);

        req = (void *)buf;
        req->op = LEASE_FREE;
        req->chkid = *chkid;
        _opaque_encode(req->buf, &count,
                       nid, sizeof(*nid), NULL);

        ret = rpc_request_wait("lease_rpc_free", srv,
                               req, sizeof(*req) + count,
                               NULL, NULL,
                               MSG_LEASE, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}
