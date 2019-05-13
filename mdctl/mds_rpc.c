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
#if 0
        MDS_DISKHB,
        MDS_NEWDISK,
        MDS_DISKJOIN,
        MDS_STATVFS,
#endif
        
        MDS_SET,
        MDS_GET,
        MDS_PASET,
        MDS_PAGET,
        MDS_MAX,
} mds_op_t;

typedef struct {
        uint32_t op;
        uint32_t buflen;
        chkid_t  chkid;
        char buf[0];
} msg_t;

extern int mds_ismaster();

extern disk_stat_t getdiskstat(const diskinfo_stat_t *diskstat);

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
        if (sockid.type == SOCKID_CORENET) {
                DBUG("corenet\n");
                corerpc_reply_error(&sockid, &msgid, ret);
        } else {
                rpc_reply_error(&sockid, &msgid, ret);
        }

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
        _opaque_encode(&req->buf, &count, nid, sizeof(*nid), NULL);

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

#if 0
static int __mds_srv_diskhb(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        int *tier;
        const diskinfo_stat_diff_t *diff;
        const uuid_t *uuid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &tier, NULL,
                       &uuid, NULL,
                       &diff, NULL,
                       NULL);

        char _uuid[MAX_NAME_LEN];
        uuid_unparse(*uuid, _uuid);
        DBUG("hb disk %s uuid %s\n", network_rname(nid), _uuid);
        
        ret = diskpool_hb(nid, *tier, diff, uuid);
        if (ret)
                GOTO(err_ret, ret);
        
        rpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_diskhb(const nid_t *nid, int tier, const uuid_t *uuid,
                    const diskinfo_stat_diff_t *diff)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        char _uuid[MAX_NAME_LEN];
        uuid_unparse(*uuid, _uuid);
        DBUG("hb disk %s uuid %s\n", network_rname(nid), _uuid);
        
        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);
        
        req = (void *)buf;
        req->op = MDS_DISKHB;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       &tier, sizeof(tier),
                       uuid, sizeof(*uuid),
                       diff, sizeof(*diff),
                       NULL);

        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_diskhb", net_getadmin(),
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

static int __mds_srv_newdisk(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const uint32_t *repnum, *hardend, *tier;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &tier, NULL,
                       &repnum, NULL,
                       &hardend, NULL,
                       NULL);

        char _array[MAX_BUF_LEN], _diskid[MAX_BUF_LEN];
        net_handle_t *array = (void *)_array;
        diskid_t *diskid = (void *)_diskid;

        DBUG("repnum %u hardend %u tier %u\n", *repnum, *hardend, *tier);

        YASSERT(*tier == 0);
        
        ret = nodepool_get(*repnum, array, *hardend, *tier);
        if (ret) {
                GOTO(err_ret, ret);
        }

        for (uint32_t i = 0; i < *repnum; i++) {
                diskid[i] = array[i].u.nid;
        }
        
        rpc_reply(sockid, msgid, diskid, sizeof(*diskid) * (*repnum));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_newdisk(const nid_t *nid, uint32_t tier, uint32_t repnum,
                     uint32_t hardend, diskid_t *disks)
{
        int ret, replen;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ANALYSIS_BEGIN(0);
        
        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        req = (void *)buf;
        req->op = MDS_NEWDISK;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       &tier, sizeof(tier),
                       &repnum, sizeof(repnum),
                       &hardend, sizeof(hardend),
                       NULL);

        req->buflen = count;

        replen = sizeof(*disks) * repnum;
        ret = rpc_request_wait("mds_rpc_newdisk", net_getadmin(),
                               req, sizeof(*req) + count, disks, &replen,
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

static int __mds_srv_diskjoin(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        int *tier;
        const uuid_t *uuid;
        const diskinfo_stat_t *stat;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &tier, NULL,
                       &uuid, NULL,
                       &stat, NULL,
                       NULL);

        char _uuid[MAX_NAME_LEN];
        uuid_unparse(*uuid, _uuid);
        DINFO("hb disk %s uuid %s\n", network_rname(nid), _uuid);

        ret = diskpool_join(nid, stat);
        if (ret) {
                GOTO(err_ret, ret);
        }

        disk_stat_t diskstat;
        diskstat = getdiskstat(stat);
        if (diskstat == DISK_STAT_FREE) {
                ret = nodepool_addisk(uuid, nid, *tier);
                if (ret)
                        GOTO(err_ret, ret);
        }
        
        rpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_diskjoin(const nid_t *nid, uint32_t tier, const uuid_t *uuid,
                      const diskinfo_stat_t *stat)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        char _uuid[MAX_NAME_LEN];
        uuid_unparse(*uuid, _uuid);
        DINFO("join disk %s uuid %s\n", network_rname(nid), _uuid);
        
        req = (void *)buf;
        req->op = MDS_DISKJOIN;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       &tier, sizeof(tier),
                       uuid, sizeof(*uuid),
                       stat, sizeof(*stat),
                       NULL);

        req->buflen = count;

        ret = rpc_request_wait("mds_rpc_diskjoin", net_getadmin(),
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

static int __mds_srv_statvfs(const sockid_t *sockid, const msgid_t *msgid, buffer_t *_buf)
{
        int ret;
        msg_t *req;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t buflen;
        const nid_t *nid;
        const fileid_t *fileid;
        struct statvfs svbuf;
        diskinfo_stat_t stat;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &fileid, NULL,
                       NULL);
  
        _memset(&stat, 0x0, sizeof(diskinfo_stat_t));

        ret = diskpool_statvfs(&stat);
        if (ret)
                GOTO(err_ret, ret);

        DUMP_DISKSTAT(&stat);

        DBUG("frsize %llu, bsize %llu\n", (LLU)stat.ds_frsize, (LLU)stat.ds_bsize);
        if (stat.ds_frsize == 0) {
                memset(&stat, 0x0, sizeof(struct statvfs));
        }

        DISKSTAT2FSTAT(&stat, &svbuf);
        DBUG("total %llu free %llu avail %llu\n", (LLU)stat.ds_bsize * stat.ds_blocks,
             (LLU)stat.ds_bfree * stat.ds_bsize, (LLU)stat.ds_bavail*stat.ds_bsize);

        rpc_reply(sockid, msgid, &svbuf, sizeof(svbuf));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_statvfs(const nid_t *nid, const fileid_t *fileid, struct statvfs *stbuf)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_STATVFS;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       fileid, sizeof(*fileid),
                       NULL);

        req->buflen = count;

        int replen = sizeof(*stbuf);
        ret = rpc_request_wait("mds_rpc_statvfs", net_getadmin(),
                               req, sizeof(*req) + count, stbuf, &replen,
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
#endif

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

int mds_rpc_set(const nid_t *nid, const char *path, const char *value, uint32_t valuelen)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_SET;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
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

int mds_rpc_get(const nid_t *nid, const char *path, uint64_t offset, void *value, int *valuelen)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;

        ret = network_connect_mds(0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_GET;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
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

        ret = pa_srv_set(chkinfo, *prev_version);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        corerpc_reply(sockid, msgid, NULL, 0);

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_paset(const nid_t *nid, const chkinfo_t *chkinfo, uint64_t prev_version)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;

        ret = part_location(&chkinfo->chkid, PART_MDS, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_PASET;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       chkinfo, CHKINFO_SIZE(chkinfo->repnum),
                       &prev_version, sizeof(prev_version),
                       NULL);

        req->buflen = count;

        ret = corerpc_postwait("mds_rpc_paset", &coreid,
                               req, sizeof(*req) + count,
                               NULL, NULL,
                               MSG_MDS_CORE, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

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
        const chkid_t *chkid;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];
        const nid_t *nid;

        req = (void *)buf;
        mbuffer_get(_buf, req, sizeof(*req));
        buflen = req->buflen;
        ret = mbuffer_popmsg(_buf, req, buflen + sizeof(*req));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        _opaque_decode(req->buf, buflen,
                       &nid, NULL,
                       &chkid, NULL,
                       NULL);

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        chkinfo = (void *)_chkinfo;
        ret = pa_srv_get(chkid, chkinfo);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        DINFO("pa get "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        corerpc_reply(sockid, msgid, chkinfo, CHKINFO_SIZE(chkinfo->repnum));

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int mds_rpc_paget(const nid_t *nid, const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        uint32_t count;
        msg_t *req;
        coreid_t coreid;
        buffer_t rbuf;

        DINFO("pa get "CHKID_FORMAT"\n", CHKID_ARG(chkid));
        
        YASSERT(chkid->type != ftype_file);
        
        ret = part_location(chkid, PART_MDS, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = network_connect(&coreid.nid, NULL, 0, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ANALYSIS_BEGIN(0);

        req = (void *)buf;
        req->op = MDS_PAGET;
        _opaque_encode(&req->buf, &count,
                       nid, sizeof(*nid),
                       chkid, sizeof(*chkid),
                       NULL);

        req->buflen = count;

        mbuffer_init(&rbuf, 0);
        ret = corerpc_postwait("mds_rpc_paget", &coreid,
                               req, sizeof(*req) + count,
                               NULL, &rbuf,
                               MSG_MDS_CORE, 0, _get_timeout());
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mbuffer_popmsg(&rbuf, chkinfo, rbuf.len);
        DINFO("pa get "CHKID_FORMAT" success\n", CHKID_ARG(chkid));
        
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

#if 0
        __request_set_handler(MDS_DISKHB, __mds_srv_diskhb, "mds_srv_diskhb");
        __request_set_handler(MDS_NEWDISK, __mds_srv_newdisk, "mds_srv_newdisk");
        __request_set_handler(MDS_DISKJOIN, __mds_srv_diskjoin, "mds_srv_diskjoin");
        __request_set_handler(MDS_STATVFS, __mds_srv_statvfs, "mds_srv_statvfs");
#endif
        __request_set_handler(MDS_GET, __mds_srv_get, "mds_srv_get");
        __request_set_handler(MDS_SET, __mds_srv_set, "mds_srv_set");
#if 1
        __request_set_handler(MDS_PASET, __mds_srv_paset, "mds_srv_paset");
        __request_set_handler(MDS_PAGET, __mds_srv_paget, "mds_srv_paget");
#endif
        
        if (ng.daemon) {
                rpc_request_register(MSG_MDS, __request_handler, NULL);

#if 1
                corerpc_register(MSG_MDS_CORE, __request_handler, NULL);
#endif
        }
        
        return 0;
err_ret:
        return ret;
}
