#include <limits.h>
#include <time.h>
#include <string.h>
#include <sys/epoll.h>
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

#define DBG_SUBSYS S_LIBSCHEDULE

#include "sysutil.h"
#include "net_proto.h"
#include "ylib.h"
#include "../net/xnect.h"
#include "net_table.h"
#include "rpc_table.h"
#include "configure.h"
#include "net_global.h"
#include "job_dock.h"
#include "main_loop.h"
#include "schedule.h"
#include "conn.h"
#include "timer.h"
#include "adt.h"
#include "network.h"
#include "../../ynet/sock/sock_tcp.h"
#include "core.h"
#include "corenet_connect.h"
#include "corerpc.h"
#include "mem_cache.h"
#include "corenet_maping.h"
#include "corenet.h"
#include "dbg.h"

typedef struct {
        coreid_t from;
        coreid_t to;
        char uuid[UUID_LEN];
} corenet_msg_t;

typedef struct {
        coreid_t coreid;
        int sd;
} __corenet_tcp_t;

extern int nofile_max;

/**
 * 包括两步骤：
 * - 建立连接: nid
 * - 协商core hash
 *
 * @param nid
 * @param sockid
 * @return
 */
int corenet_tcp_connect(const coreid_t *coreid, uint32_t addr, uint32_t port,
                        sockid_t *sockid)
{
        int ret;
        net_handle_t nh;
        corenet_msg_t msg;
        corerpc_ctx_t *ctx;
        struct sockaddr_in sin;

        _memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

        sin.sin_addr.s_addr = addr;
        sin.sin_port = port;

        DINFO("connect %s:%u\n", inet_ntoa(sin.sin_addr), ntohs(port));

        ret = core_getid(&msg.from);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = tcp_sock_connect(&nh, &sin, 0, 3, 0);
        if (unlikely(ret)) {
                DINFO("try to connect %s:%u (%u) %s\n", inet_ntoa(sin.sin_addr),
                      ntohs(port), ret, strerror(ret));
                GOTO(err_ret, ret);
        }
        
        YASSERT(strlen(gloconf.uuid) < UUID_LEN);

        msg.to = *coreid;
        strncpy(msg.uuid, gloconf.uuid, UUID_LEN);

        ret = send(nh.u.sd.sd, &msg, sizeof(msg), 0);
        if (ret < 0) {
                ret = errno;
                UNIMPLEMENTED(__DUMP__);
        }

        sockid->sd = nh.u.sd.sd;
        sockid->addr = nh.u.sd.addr;
        sockid->seq = _random();
        sockid->type = SOCKID_CORENET;
        ret = ymalloc((void **)&ctx, sizeof(*ctx));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = tcp_sock_tuning(sockid->sd, 1, YNET_RPC_NONBLOCK);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ctx->running = 0;
#if ENABLE_RDMA
        sockid->rdma_handler = 0;
#endif
        ctx->sockid = *sockid;
        ctx->coreid = *coreid;
        ret = corenet_tcp_add(NULL, sockid, ctx, corerpc_recv, corerpc_close,
                              NULL, NULL, network_rname(&coreid->nid));
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        YASSERT(sockid->sd < nofile_max);
        
        return 0;
err_ret:
        return ret;
}

STATIC void *__corenet_accept__(void *arg)
{
        int ret;
        char buf[MAX_BUF_LEN];
        corenet_msg_t *msg;
        sockid_t *sockid;
        core_t *core;
        corerpc_ctx_t *ctx = arg;

        sockid = &ctx->sockid;

        DINFO("accept from %s, sd %d\n",  _inet_ntoa(sockid->addr), sockid->sd);

        ret = sock_poll_sd(sockid->sd, 1000 * 1000, POLLIN);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = recv(sockid->sd, buf, sizeof(*msg), 0);
        if (ret < 0) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        if (ret == 0) {
                DWARN("peer closed\n");
                ret = ECONNRESET;
                GOTO(err_ret, ret);
        }

        msg = (void*)buf;
        if (strcmp(gloconf.uuid, msg->uuid)) {
                DERROR("get wrong msg from %s\n", _inet_ntoa(sockid->addr));
                ret = ECONNRESET;
                GOTO(err_ret, ret);
        }

        YASSERT(sizeof(*msg) == ret);
        YASSERT(coreid_cmp(&msg->to, &ctx->local) == 0);

        ret = tcp_sock_tuning(sockid->sd, 1, YNET_RPC_NONBLOCK);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        core = core_get(msg->to.idx);
#if ENABLE_RDMA
        sockid->rdma_handler = 0;
#endif
        ctx->coreid = msg->from;

        DINFO("core[%d] %p maping:%p, sd %u\n", msg->to.idx, core,
              core->maping, sockid->sd);
        
        ret = corenet_attach(core->corenet, sockid, ctx, corerpc_recv,
                             corerpc_close, NULL, NULL, network_rname(&ctx->coreid.nid));
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        schedule_post(core->schedule);

        return NULL;
err_ret:
        close(sockid->sd);
        return NULL;
}

static int __corenet_accept(const __corenet_tcp_t *corenet_tcp)
{
        int ret, sd;
        socklen_t alen;
        struct sockaddr_in sin;
        corerpc_ctx_t *ctx;

        _memset(&sin, 0, sizeof(sin));
        alen = sizeof(struct sockaddr_in);

        sd = accept(corenet_tcp->sd, &sin, &alen);
        if (sd < 0 ) {
                ret = errno;
		GOTO(err_ret, ret);
        }

        ret = ymalloc((void **)&ctx, sizeof(*ctx));
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ctx->running = 0;
        ctx->sockid.sd = sd;
        ctx->sockid.type = SOCKID_CORENET;
        ctx->sockid.seq = _random();
        ctx->sockid.addr = sin.sin_addr.s_addr;
        ctx->coreid.nid.id = 0;
        ctx->local = corenet_tcp->coreid;

        ret = sy_thread_create2(__corenet_accept__, ctx, "__corenet_accept");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        return 0;
err_ret:
        return ret;
}

static void *__corenet_passive(void *_arg)
{
        int ret;
        __corenet_tcp_t *corenet_tcp = _arg;

        DINFO("start...\n");

        main_loop_hold();

        while (1) {
                ret = sock_poll_sd(corenet_tcp->sd, 1000 * 1000, POLLIN);
                if (unlikely(ret)) {
                        if (ret == ETIMEDOUT || ret == ETIME)
                                continue;
                        else
                                GOTO(err_ret, ret);
                }

                DINFO("got new event\n");

                __corenet_accept(corenet_tcp);
        }

        return NULL;
err_ret:
        UNIMPLEMENTED(__DUMP__);
        return NULL;
}

#define NETINFO_TIMEOUT (10 * 60)

int corenet_tcp_getaddr(uint32_t port, corenet_addr_t *addr)
{
        int ret;
        char *buf = mem_cache_calloc1(MEM_CACHE_4K, PAGE_SIZE);
        ynet_net_info_t *info;
        uint32_t buflen = MAX_BUF_LEN;

        ret = core_getid(&addr->coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        info = (ynet_net_info_t *)buf;
        ret = net_getinfo(buf, &buflen, port);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        for (int i = 0; i < info->info_count; i++) {
                addr->info[i] = info->info[i];
                DINFO("core[%u] port %d addr %u:%u\n", addr->coreid.idx,
                      port, addr->info[i].addr, addr->info[i].port);
        }

        addr->info_count = info->info_count;
        addr->len = sizeof(*addr) + sizeof(ynet_sock_info_t) * info->info_count;

        mem_cache_free(MEM_CACHE_4K, buf);

        return 0;
err_ret:
        mem_cache_free(MEM_CACHE_4K, buf);
        return ret;
}

int corenet_tcp_passive(const coreid_t *coreid, uint32_t *_port, int *_sd)
{
        int ret, sd, port;
        char tmp[MAX_LINE_LEN];
        
        port = YNET_PORT_RANDOM;
        while (srv_running) {
                port = (uint16_t)(YNET_SERVICE_BASE
                                  + (random() % YNET_SERVICE_RANGE));

                YASSERT(port > YNET_SERVICE_RANGE && port < 65535);
                snprintf(tmp, MAX_LINE_LEN, "%u", port);

                ret = tcp_sock_hostlisten(&sd, NULL, tmp,
                                          YNET_QLEN, YNET_RPC_BLOCK, 1);
                if (unlikely(ret)) {
                        if (ret == EADDRINUSE) {
                                DBUG("port (%u + %u) %s\n", YNET_SERVICE_BASE,
                                     port - YNET_SERVICE_BASE, strerror(ret));
                                continue;
                        } else
                                GOTO(err_ret, ret);
                } else {
                        break;
                }
        }

        *_port = port;
        *_sd = sd;

        __corenet_tcp_t *corenet_tcp;
        ret = ymalloc((void **)&corenet_tcp, sizeof(*corenet_tcp));
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        corenet_tcp->coreid = *coreid;
        corenet_tcp->sd = sd;
        
        ret = sy_thread_create2(__corenet_passive, corenet_tcp, "corenet_passive");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        //DINFO("listen %u, nid %u\n", port, net_getnid()->id);

        return 0;
err_ret:
        return ret;
}
