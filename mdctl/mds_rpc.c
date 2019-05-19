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
#include "mds_rpc.h"
#include "md_lib.h"
#include "network.h"
#include "mds_kv.h"
#include "pa_srv.h"
#include "corerpc.h"
#include "partition.h"
#include "mem_cache.h"
#include "schedule.h"
#include "dbg.h"

extern net_global_t ng;

typedef enum {
        MDS_NULL = 400,
        MDS_GETSTAT,
        MDS_SET,
        MDS_GET,
        MDS_GETINFO,
        MDS_SETINFO,
        MDS_PASET,
        MDS_PAGET,
        MDS_RECOVERY,
        MDS_MAX,
} mds_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t chkid;
        char buf[0];
} msg_t;

extern int mds_ismaster();

static __request_handler_func__  __request_handler__[MDS_MAX - MDS_NULL];
static char  __request_name__[MDS_MAX - MDS_NULL][__RPC_HANDLER_NAME__ ];

static void __request_set_handler(int op, __request_handler_func__ func, const char *name)
{
        YASSERT(strlen(name) + 1 < __RPC_HANDLER_NAME__ );
        strcpy(__request_name__[op - MDS_NULL], name);
        __request_handler__[op - MDS_NULL] = func;
}

static void __request_get_handler(int op, __request_handler_func__ *func, const char **name)
{
        *func = __request_handler__[op - MDS_NULL];
        *name = __request_name__[op - MDS_NULL];
}

inline static void __getmsg(buffer_t *buf, msg_t **_req, int *buflen, char *_buf)
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

static int __mds_srv_getstat(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        instat_t instat;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen, &nid, NULL, NULL);

        DBUG("getstat of %s\n", network_rname(nid));

        instat.nid = *nid;
        ret = network_connect(nid, NULL, 0, 0);
        if (unlikely(ret)) {
                instat.online = 0;
        } else {
                instat.online = 1;
        }

        rpc_reply(sockid, msgid, &instat, sizeof(instat));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_getstat(const nid_t *nid, instat_t *instat)
{
        int ret, size = sizeof(*instat);
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_GETSTAT;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       NULL);

        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_getstat", net_getadmin(),
                               req, sizeof(*req) + count, instat, &size,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_null(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (!mds_ismaster()) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }
        
        rpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_null(const nid_t *mds)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_NULL;
        count = 0;
        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_null", mds,
                               req, sizeof(*req) + count, NULL, NULL,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_set(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const char *path;
        const char *value;
        uint32_t valuelen;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &path, NULL,
                       &value, &valuelen,
                       NULL);

        DBUG("set %s, valuelen %u\n", path, valuelen);

        ret = mds_kv_set(path, value, valuelen);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        rpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_set(const char *path, const char *value, uint32_t valuelen)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid = *net_getnid();

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_SET;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       path, strlen(path) + 1,
                       value, valuelen,
                       NULL);

        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_set", net_getadmin(),
                               req, sizeof(*req) + count, NULL, NULL,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_get(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const char *path;
        const uint64_t *offset;
        char *value;
        uint32_t valuelen;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &path, NULL,
                       &offset, NULL,
                       NULL);

        DINFO("get %s\n", path);

        ret = ymalloc((void **)&value, MON_ENTRY_MAX);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = mds_kv_get(path, *offset, value, &valuelen);
        if (unlikely(ret))
                GOTO(err_free, ret);
        
        rpc_reply(sockid, msgid, value, valuelen);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_free:
        yfree((void **)&value);
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_get(const char *path, uint64_t offset, void *value, int *valuelen)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        nid_t nid = *net_getnid();

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_GET;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       path, strlen(path) + 1,
                       &offset, sizeof(offset),
                       NULL);

        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_get", net_getadmin(),
                               req, sizeof(*req) + count, value, valuelen,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_paset(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const chkinfo_t *chkinfo;
        const uint64_t *prev_version;
        const nid_t *nid;
        uint64_t version;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &chkinfo, NULL,
                       &prev_version, NULL,
                       NULL);

        version = *prev_version;
        ret = pa_srv_set(&req->chkid, chkinfo, &version);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        corerpc_reply(sockid, msgid, &version, sizeof(version));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_paset(const chkid_t *chkid, const chkinfo_t *chkinfo, uint64_t *version)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        nid_t nid = *net_getnid();
        uint64_t prev_version = version ? *version : 0;

        ret = part_location(chkid, TYPE_MDCTL, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_PASET;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                       &prev_version, sizeof(prev_version),
                       NULL);

        req->buflen = count;

        buffer_t rbuf;
        mbuffer_init(&rbuf, 0);
        ret = corerpc_postwait("mds_rpc_paset", &coreid,
                               req, sizeof(*req) + count,
                               NULL, &rbuf,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(rbuf.len == sizeof(*version));
        if (version) {
                mbuffer_popmsg(&rbuf, version, sizeof(*version));
        } else {
                mbuffer_free(&rbuf);
        }
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_paget(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const coreid_t *coreid;
        chkinfo_t *chkinfo;
        const nid_t *nid;
        uint64_t *version;
        char tmp[CHKINFO_MAX + sizeof(uint64_t)];

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &coreid, NULL,
                       NULL);

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(&req->chkid));

        version = (void *)tmp;
        chkinfo = (void *)tmp + sizeof(uint64_t);
        ret = pa_srv_get(&req->chkid, chkinfo, version);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        corerpc_reply(sockid, msgid, tmp, CHKINFO_SIZE(chkinfo->repnum) + sizeof(uint64_t));

        DINFO("pa get "CHKID_FORMAT" success\n", CHKID_ARG(&req->chkid));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_paget(const chkid_t *chkid, chkinfo_t *chkinfo, uint64_t *_version)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        nid_t nid = *net_getnid();
        uint64_t version;

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        YASSERT(chkid->type != ftype_file);
        
        ret = part_location(chkid, TYPE_MDCTL, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_PAGET;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       &coreid, sizeof(coreid),
                       NULL);

        req->buflen = count;

        buffer_t rbuf;
        mbuffer_init(&rbuf, 0);
        ret = corerpc_postwait("mds_rpc_paget", &coreid,
                               req, sizeof(*req) + count,
                               NULL, &rbuf,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_popmsg(&rbuf, &version, sizeof(uint64_t));
        mbuffer_popmsg(&rbuf, chkinfo, rbuf.len);

        if (_version) {
                *_version = version;
        }
        
        DINFO("pa get "CHKID_FORMAT" success, version %ju\n", CHKID_ARG(chkid), version);
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_recovery(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       NULL);

        DINFO("recovery "CHKID_FORMAT"\n", CHKID_ARG(&req->chkid));

        ret = pa_srv_recovery(&req->chkid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        corerpc_reply(sockid, msgid, NULL, 0);

        DINFO("recovery "CHKID_FORMAT" success\n", CHKID_ARG(&req->chkid));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_recovery(const chkid_t *chkid)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        nid_t nid = *net_getnid();

        DINFO("recovery "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        YASSERT(chkid->type == ftype_file
                || chkid->type == ftype_sub);
        
        ret = part_location(chkid, TYPE_MDCTL, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_RECOVERY;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       NULL);

        req->buflen = count;

        ret = corerpc_postwait("mds_rpc_recovery", &coreid,
                               req, sizeof(*req) + count,
                               NULL, NULL,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DINFO("recovery "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_setinfo(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, *idx;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen, infolen;
        const void *info;
        const uint64_t *prev_version;
        const nid_t *nid;
        uint64_t version;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &idx, NULL,
                       &info, &infolen,
                       &prev_version, NULL,
                       NULL);

        version = *prev_version;
        ret = pa_srv_setinfo(&req->chkid, *idx, buf, infolen, &version);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        corerpc_reply(sockid, msgid, &version, sizeof(version));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_setinfo(const chkid_t *chkid, int idx, const void *info,
                    int buflen, uint64_t *version)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        nid_t nid = *net_getnid();
        uint64_t prev_version = version ? *version : 0;

        ret = part_location(chkid, TYPE_MDCTL, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_SETINFO;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       &idx, sizeof(idx),
                       info, buflen,
                       &prev_version, sizeof(prev_version),
                       NULL);

        req->buflen = count;

        buffer_t rbuf;
        mbuffer_init(&rbuf, 0);
        ret = corerpc_postwait("mds_rpc_setinfo", &coreid,
                               req, sizeof(*req) + count,
                               NULL, &rbuf,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(rbuf.len == sizeof(*version));
        if (version) {
                mbuffer_popmsg(&rbuf, version, sizeof(*version));
        } else {
                mbuffer_free(&rbuf);
        }
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

static int __mds_srv_getinfo(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret, *idx;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const coreid_t *coreid;
        char *info;
        const nid_t *nid;
        uint64_t *version;
        char tmp[PA_INFO_SIZE + sizeof(uint64_t)];

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &idx, NULL,
                       &coreid, NULL,
                       NULL);

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(&req->chkid));

        version = (void *)tmp;
        info = (void *)tmp + sizeof(uint64_t);
        int infolen = PA_INFO_SIZE;
        ret = pa_srv_getinfo(&req->chkid, *idx, info, &infolen, version);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        corerpc_reply(sockid, msgid, tmp, infolen + sizeof(uint64_t));

        DINFO("getinfo "CHKID_FORMAT"[%u] success\n", CHKID_ARG(&req->chkid), idx);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_getinfo(const chkid_t *chkid, int idx, void *info, int *infolen,
                    uint64_t *_version)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        nid_t nid = *net_getnid();
        uint64_t version;

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        YASSERT(chkid->type != ftype_file);
        
        ret = part_location(chkid, TYPE_MDCTL, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_GETINFO;
        req->chkid = *chkid;
        _opaque_encode(&req->buf, &count,
                       &nid, sizeof(nid),
                       &idx, sizeof(idx),
                       &coreid, sizeof(coreid),
                       NULL);

        req->buflen = count;

        buffer_t rbuf;
        mbuffer_init(&rbuf, 0);
        ret = corerpc_postwait("mds_rpc_getinfo", &coreid,
                               req, sizeof(*req) + count,
                               NULL, &rbuf,
                               MSG_MDS, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_popmsg(&rbuf, &version, sizeof(uint64_t));
        YASSERT((int)rbuf.len <= *infolen);
        *infolen = rbuf.len;
        mbuffer_popmsg(&rbuf, info, rbuf.len);

        if (_version) {
                *_version = version;
        }
        
        DINFO("pa get "CHKID_FORMAT" success, version %ju\n", CHKID_ARG(chkid), version);
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}



int mds_rpc_init()
{
        int ret;
        
        DINFO("mds rpc init\n");

        ret = mds_kv_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        //__request_set_handler(MDS_READ, __mds_srv_read, "mds_srv_read");
        __request_set_handler(MDS_NULL, __mds_srv_null, "mds_srv_null");
        __request_set_handler(MDS_GETSTAT, __mds_srv_getstat, "mds_srv_getstat");

        __request_set_handler(MDS_GET, __mds_srv_get, "mds_srv_get");
        __request_set_handler(MDS_SET, __mds_srv_set, "mds_srv_set");
        __request_set_handler(MDS_SETINFO, __mds_srv_setinfo, "mds_srv_setinfo");
        __request_set_handler(MDS_GETINFO, __mds_srv_getinfo, "mds_srv_getinfo");
        __request_set_handler(MDS_PAGET, __mds_srv_paget, "mds_srv_paget");
        __request_set_handler(MDS_PASET, __mds_srv_paset, "mds_srv_paset");
        __request_set_handler(MDS_RECOVERY, __mds_srv_recovery, "mds_srv_recovery");

        rpc_request_register(MSG_MDS, __request_handler, NULL);
        corerpc_register(MSG_MDS, __request_handler, NULL);
        
        return 0;
err_ret:
        return ret;
}
