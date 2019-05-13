#include <limits.h>
#include <time.h>
#include <string.h>
#include <sys/epoll.h>
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <errno.h>

#define DBG_SUBSYS S_LIBSCHEDULE

#include "sysutil.h"
#include "net_proto.h"
#include "ylib.h"
#include "corenet.h"
#include "corenet_connect.h"
#include "../net/xnect.h"
#include "../sock/sock_tcp.h"
#include "net_table.h"
#include "rpc_table.h"
#include "core.h"
#include "corerpc.h"
#include "configure.h"
#include "net_global.h"
#include "job_dock.h"
#include "schedule.h"
#include "timer.h"
#include "adt.h"
#include "mem_cache.h"
#include "variable.h"
#include "dbg.h"


typedef struct {
        int sd;
        coreid_t coreid;
        uint32_t port;
        time_t last_check;
        void *tcp_net;

#if ENABLE_RDMA
        void *rdma_net;
        struct list_head rdma_dev_list;

        rdma_info_t *active_dev;
        struct rdma_event_channel *iser_evt_channel;
#endif
} __corenet_t;

inline static void __corenet_routine(void *_core, void *var, void *_corenet)
{
        core_t *core = _core;
        //__corenet_t *corenet = _corenet;

        (void) _corenet;
        
        corenet_tcp_commit(var);
        schedule_run(core->schedule);

        if (!gloconf.rdma || sanconf.tcp_discovery) {
                corenet_tcp_check();
        }
        
        return;
}

inline static void __corenet_poller(void *_core, void *var, void *_corenet)
{
        core_t *core = _core;
        //__corenet_t *corenet = _corenet;

        (void) _corenet;
        
        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
        } else {
                int tmo = core->main_core ? 0 : 1;
                corenet_tcp_poll(var, tmo);
        }

        return;
}

inline static void __corenet_destroy(void *_core, void *var, void *_corenet)
{
        core_t *core = _core;
        __corenet_t *corenet = _corenet;

        (void) _corenet;
        (void) var;
        (void) core;
        
        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
        } else {
                corenet_tcp_destroy(&corenet->tcp_net);
        }

        return;
}

inline static void __core_interrupt_eventfd_func(void *arg)
{
        int ret;
        char buf[MAX_BUF_LEN];

        (void) arg;

        ret = read(core_self()->interrupt_eventfd, buf, MAX_BUF_LEN);
        if (ret < 0) {
                ret = errno;
                UNIMPLEMENTED(__DUMP__);
        }
}

static int __corenet_tcp_init(core_t *core, __corenet_t *corenet)
{
        int ret;

        ret = corenet_tcp_init(32768, (corenet_tcp_t **)&corenet->tcp_net);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (core->interrupt_eventfd != -1) {
                sockid_t sockid;
                sockid.sd = core->interrupt_eventfd;
                sockid.seq = _random();
                sockid.type = SOCKID_CORENET;
                sockid.addr = 123;
                ret = corenet_tcp_add(corenet->tcp_net, &sockid, NULL, NULL, NULL, NULL,
                                      __core_interrupt_eventfd_func, "interrupt_fd");
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }
                
        ret = corenet_tcp_passive(&corenet->coreid, &corenet->port,
                                  &corenet->sd);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __corenet_init(va_list ap)
{
        int ret;
        __corenet_t *corenet;
        core_t *core = core_self();

        va_end(ap);
        
        ret = huge_malloc((void **)&corenet, sizeof(*corenet));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = core_getid(&corenet->coreid);
        if (unlikely(ret))
                GOTO(err_free, ret);

        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
        } else {
                ret = __corenet_tcp_init(core, corenet);
                if (unlikely(ret))
                        GOTO(err_free, ret);
        }

#if 1
        ret = core_register_poller("corenet", __corenet_poller, corenet);
        if (unlikely(ret))
                GOTO(err_close, ret);

        ret = core_register_routine("corenet", __corenet_routine, corenet);
        if (unlikely(ret))
                GOTO(err_close, ret);

        ret = core_register_destroy("corenet", __corenet_destroy, corenet);
        if (unlikely(ret))
                GOTO(err_close, ret);
#endif
        
        core->corenet = corenet;

        return 0;
err_close:
        UNIMPLEMENTED(__DUMP__);
err_free:
        huge_free((void **)&corenet);
err_ret:
        return ret;
}

int corenet_init()
{
        int ret;
                
        ret = core_init_modules("corenet", __corenet_init, NULL);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

static int __corenet_getaddr(va_list ap)
{
        int ret;
        core_t *core = core_self();
        __corenet_t *corenet = core->corenet;
        corenet_addr_t *addr = va_arg(ap, corenet_addr_t *);        

        va_end(ap);
        
        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
        } else {
                ret = corenet_tcp_getaddr(corenet->port, addr);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

int corenet_getaddr(const coreid_t *coreid, corenet_addr_t *addr)
{
        int ret;

        ret = core_request(coreid->idx, -1, "corenet_gedaddr",
                           __corenet_getaddr, addr);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int corenet_attach(void *_corenet, const sockid_t *sockid, void *ctx,
                   core_exec exec, func_t reset, func_t check, func_t recv,
                   const char *name)
{
        __corenet_t *corenet = _corenet;

        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
                return 0;
        } else {
                return corenet_tcp_add(corenet->tcp_net, sockid, ctx, exec,
                                       reset, check, recv, name);
        }
}


int corenet_send(void *ctx, const sockid_t *sockid, buffer_t *buf, int flag)
{
        
        if (gloconf.rdma) {
                UNIMPLEMENTED(__DUMP__);
                return 0;
        } else {
                return corenet_tcp_send(ctx, sockid, buf, flag);
        }
}
