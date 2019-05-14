#include <limits.h>
#include <time.h>
#include <string.h>
#include <sys/epoll.h>
#include <semaphore.h>
#include <pthread.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <stdarg.h>
#include <errno.h>

#define DBG_SUBSYS S_LIBSCHEDULE

#include "sysutil.h"
#include "net_proto.h"
#include "ylib.h"
#include "sdevent.h"
#include "../net/xnect.h"
#include "net_table.h"
#include "nodectl.h"
#include "timer.h"
#include "mem_cache.h"
#include "mem_hugepage.h"
#include "rpc_table.h"
#include "configure.h"
#include "core.h"
#include "corenet_maping.h"
#include "corenet_connect.h"
#include "corenet.h"
#include "corerpc.h"
#include "aio.h"
#include "schedule.h"
#include "bh.h"
#include "net_global.h"
#include "cpuset.h"
#include "variable.h"
#include "ylib.h"
#include "adt.h"
#include "mem_pool.h"
#include "dbg.h"

#define CORE_MAX 256

typedef struct {
        task_t task;
        sem_t sem;
        func_va_t exec;
        va_list ap;
        int type;
        int retval;
} arg1_t;

typedef struct {
        task_t task;
        sem_t sem;
        func_t exec;
        void *ctx;
        int type;
} arg_t;

#define REQUEST_SEM 1
#define REQUEST_TASK 2

#define CORE_CHECK_KEEPALIVE_INTERVAL 1
#define CORE_CHECK_CALLBACK_INTERVAL 5
#define CORE_CHECK_HEALTH_INTERVAL 30
#define CORE_CHECK_HEALTH_TIMEOUT 180

static core_t *__core_array__[256];

core_t *core_self()
{
        return variable_get(VARIABLE_CORE);
}

STATIC void *__core_check_health__(void *_arg)
{
        int ret, i;
        core_t *core = NULL;
        time_t now;
        (void)_arg;

        while (1) {
                sleep(CORE_CHECK_HEALTH_INTERVAL);

                now = gettime();
                for (i = 0; i < cpuset_useable(); i++) {
                        core = core_get(i);
                        if (unlikely(core == NULL))
                                continue;

                        ret = sy_spin_lock(&core->keepalive_lock);
                        if (unlikely(ret))
                                continue;

                        if (unlikely(now - core->keepalive > CORE_CHECK_HEALTH_TIMEOUT)) {
                                sy_spin_unlock(&core->keepalive_lock);
                                DERROR("polling core[%d] block !!!!!\n", core->hash);
                                YASSERT(0);
                                EXIT(EAGAIN);
                        }

                        sy_spin_unlock(&core->keepalive_lock);
                }
        }
}

static void __core_check_keepalive(core_t *core, time_t now)
{
        int ret;

        if (now - core->keepalive < CORE_CHECK_KEEPALIVE_INTERVAL) {
                return;
        }

        ret = sy_spin_lock(&core->keepalive_lock);
        if (unlikely(ret))
                return;

        core->keepalive = now;

        sy_spin_unlock(&core->keepalive_lock);
}

static void __core_check(core_t *core)
{
        time_t now;

        now = gettime();

        __core_check_keepalive(core, now);
}

static inline void IO_FUNC __core_worker_run(core_t *core, void *ctx)
{
        struct list_head *pos;
        routine_t *routine;
        
        list_for_each(pos, &core->poller_list) {
                routine = (void *)pos;
                routine->func(core, ctx, routine->ctx);
        }

        schedule_run(core->schedule);

        list_for_each(pos, &core->routine_list) {
                routine = (void *)pos;
                routine->func(core, ctx, routine->ctx);
        }

        schedule_scan(core->schedule);

        __core_check(core);

        gettime_refresh(ctx);
        timer_expire(ctx);
        analysis_merge(ctx);
}

static int __core_worker_init(core_t *core)
{
        int ret;
        char name[MAX_NAME_LEN];

        DINFO("core[%u] init begin, polling %s\n", core->hash,
              core->flag & CORE_FLAG_POLLING ? "on" : "off");

        INIT_LIST_HEAD(&core->poller_list);
        INIT_LIST_HEAD(&core->routine_list);
        INIT_LIST_HEAD(&core->destroy_list);

        if (ng.daemon && core->flag & CORE_FLAG_POLLING) {
                cpuset_getcpu(&core->main_core, &core->aio_core);
                if (core->main_core) {
                        snprintf(name, sizeof(name), "%s[%u]", core->name, core->hash);
                        ret = cpuset(name, core->main_core->cpu_id);
                        if (unlikely(ret)) {
                                DWARN("set cpu fail\n");
                        }

                        DINFO("%s[%u] cpu set\n", core->name, core->hash);
                } else {
                        core->flag ^= CORE_FLAG_POLLING;
                        DWARN("%s[%u] polling fail, flag 0x%o\n", core->name,
                              core->hash, core->flag);
                }
        } else {
                core->main_core = NULL;
        }

        core->interrupt_eventfd = -1;
        int *interrupt = !core->main_core ? &core->interrupt_eventfd : NULL;

        snprintf(name, sizeof(name), core->name);
        ret = schedule_create(interrupt, name, &core->idx, &core->schedule, NULL);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DINFO("%s[%u] schedule inited\n", core->name, core->hash);

        ret = timer_init(1, core->main_core ? 1 : 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DINFO("%s[%u] timer inited\n", core->name, core->hash);

        ret = gettime_private_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = mem_cache_private_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = mem_hugepage_private_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        DINFO("%s[%u] mem inited\n", core->name, core->hash);

        snprintf(name, sizeof(name), "%s[%u]", core->name, core->hash);
        ret = analysis_private_create(name);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DINFO("%s[%u] analysis inited\n", core->name, core->hash);

#if 0
        ret = fastrandom_private_init();
        if (unlikely(ret)) {
                UNIMPLEMENTED(__DUMP__);
        }

        DINFO("%s[%u] fastrandom inited\n", core->name, core->hash);
#endif

        variable_set(VARIABLE_CORE, core);
        //core_register_tls(VARIABLE_CORE, private_mem);

        sem_post(&core->sem);

        return 0;
err_ret:
        return ret;
}

static void * IO_FUNC __core_worker(void *_args)
{
        int ret;
        core_t *core = _args;

        DINFO("start %s idx %d\n", core->name, core->hash);

        ret = __core_worker_init(core);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        void *ctx = variable_get_ctx();
        YASSERT(ctx);
        
        while (1) {
                __core_worker_run(core, ctx);
        }

        DFATAL("name %s idx %d hash %d\n", core->name, core->idx, core->hash);
        return NULL;
}

static int __core_create(core_t **_core, const char *name, int hash, int flag)
{
        int ret;
        core_t *core;

        ret = ymalloc((void **)&core, sizeof(*core));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        memset(core, 0x0, sizeof(*core));

        strcpy(core->name, name);
        core->idx = -1;
        core->hash = hash;
        core->flag = flag;
        core->keepalive = gettime();

        ret = sy_spin_init(&core->keepalive_lock);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ret = sem_init(&core->sem, 0, 0);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ret = sy_thread_create2(__core_worker, core, "__core_worker");
        if (ret == -1) {
                ret = errno;
                GOTO(err_free, ret);
        }

        *_core = core;

        return 0;
err_free:
        yfree((void **)&core);
err_ret:
        return ret;
}

int core_init(int polling_core, int flag)
{
        int ret, i;
        core_t *core = NULL;
        
        ret = cpuset_init(polling_core);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        DINFO("core init begin %u %u\n", polling_core, cpuset_useable());
        YASSERT(cpuset_useable() > 0 && cpuset_useable() < 64);

#if 0
        ret = global_private_mem_init();
        if (ret)
                UNIMPLEMENTED(__DUMP__);
#endif

        DINFO("core global private mem inited\n");
        for (i = 0; i < cpuset_useable(); i++) {
                ret = __core_create(&core, "core", i, flag);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);

                __core_array__[i] = core;

                DINFO("core[%d] hash %d idx %d\n",
                      i, core->hash, core->idx);
        }

        for (i = 0; i < cpuset_useable(); i++) {
                core = __core_array__[i];
                ret = _sem_wait(&core->sem);
                if (unlikely(ret)) {
                        UNIMPLEMENTED(__DUMP__);
                }
        }

        ret = sy_thread_create2(__core_check_health__, NULL, "core_check_health");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ret = corenet_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (flag & CORE_FLAG_AIO) {
                ret = aio_create();
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        ret = corerpc_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = corenet_maping_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = core_latency_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}

int core_hash(const fileid_t *fileid)
{
        return (fileid->id + fileid->idx) % cpuset_useable();
}

int core_attach(int hash, const sockid_t *sockid, const char *name,
                void *ctx, core_exec func, func_t reset, func_t check)
{
        int ret;
        core_t *core;

        DINFO("attach hash %d fd %d name %s\n", hash, sockid->sd, name);

        core = __core_array__[hash % cpuset_useable()];
        YASSERT(core);

        ret = corenet_attach(core->corenet, sockid, ctx, func, reset, check, NULL, name);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        schedule_post(core->schedule);

        return 0;
err_ret:
        return ret;
}

core_t *core_get(int hash)
{
        return __core_array__[hash % cpuset_useable()];
}

static void __core_request__(void *_ctx)
{
        arg1_t *ctx = _ctx;

        ctx->retval = ctx->exec(ctx->ap);

        if (ctx->type == REQUEST_SEM) {
                sem_post(&ctx->sem);
        } else {
                schedule_resume(&ctx->task, 0, NULL);
        }
}

int core_request_va(int hash, int priority, const char *name, func_va_t exec, va_list ap)
{
        int ret;
        core_t *core;
        schedule_t *schedule;
        arg1_t ctx;

        if (unlikely(__core_array__[0] == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }
        
        core = __core_array__[hash % cpuset_useable()];
        schedule = core->schedule;
        if (unlikely(schedule == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }

        ctx.exec = exec;
        va_copy(ctx.ap, ap);

        if (schedule_running()) {
                ctx.type = REQUEST_TASK;
                ctx.task = schedule_task_get();
        } else {
                ctx.type = REQUEST_SEM;
                ret = sem_init(&ctx.sem, 0, 0);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }

        ret = schedule_request(schedule, priority, __core_request__, &ctx, name);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (schedule_running()) {
                ret = schedule_yield1(name, NULL, NULL, NULL, -1);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }
        } else {
                ret = _sem_wait(&ctx.sem);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }
        }

        return ctx.retval;
err_ret:
        return ret;
}

int core_request(int hash, int priority, const char *name, func_va_t exec, ...)
{
        va_list ap;

        va_start(ap, exec);

        return core_request_va(hash, priority, name, exec, ap);
}

int core_request_new(core_t *core, int priority, const char *name, func_va_t exec, ...)
{
        int ret;
        schedule_t *schedule;
        arg1_t ctx;

        schedule = core->schedule;
        if (unlikely(schedule == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }

        ctx.exec = exec;
        va_start(ctx.ap, exec);

        if (schedule_running()) {
                ctx.type = REQUEST_TASK;
                ctx.task = schedule_task_get();
        } else {
                ctx.type = REQUEST_SEM;
                ret = sem_init(&ctx.sem, 0, 0);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }

        ret = schedule_request(schedule, priority, __core_request__, &ctx, name);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (schedule_running()) {
                ret = schedule_yield1(name, NULL, NULL, NULL, -1);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }
        } else {
                ret = _sem_wait(&ctx.sem);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }
        }

        return ctx.retval;
err_ret:
        return ret;
}

void core_register_tls(int type, void *ptr)
{
        core_t *core = core_self();

        if (core == NULL)
                YASSERT(0);

        core->tls[type] = ptr;
}

void core_iterator(func1_t func, const void *opaque)
{
        int i;
        core_t *core;

        for (i = 0; i < cpuset_useable(); i++) {
                core = __core_array__[i];
                func(core, (void *)opaque);
        }
}

static void __core_dump_memory(void *_core, void *_arg)
{
        core_t *core = _core;
        uint64_t *memory = _arg;

        schedule_t *schedule = core->schedule;
        *memory += sizeof(core_t) +
                   sizeof(schedule_t) +
                   (sizeof(taskctx_t) + DEFAULT_STACK_SIZE) * schedule->size;
}

/**
 * 获取内存使用量
 *
 * @return
 */
int core_dump_memory(uint64_t *memory)
{
        *memory = 0;

        core_iterator(__core_dump_memory, memory);

        return 0;
}


static int __core_register(struct list_head *list, const char *name, func2_t func, void *ctx)
{
        int ret;
        routine_t *routine;

        ret = huge_malloc((void **)&routine, sizeof(*routine));
        if(ret)
                GOTO(err_ret, ret);

        strncpy(routine->name, name, 64);
        routine->func = func;
        routine->ctx = ctx;
        list_add_tail(&routine->hook, list);

        return 0;
err_ret:
        return ret;
}

int core_register_poller(const char *name, func2_t func, void *ctx)
{
        int ret;
        core_t *core = core_self();

        ret = __core_register(&core->poller_list, name, func, ctx);
        if(ret)
                GOTO(err_ret, ret);

        DINFO("register poller[%d], name: %s\r\n",
              core->hash, name);
        
        return 0;
err_ret:
        return ret;
}

int core_register_routine(const char *name, func2_t func, void *ctx)
{
        int ret;
        core_t *core = core_self();

        ret = __core_register(&core->routine_list, name, func, ctx);
        if(ret)
                GOTO(err_ret, ret);

        DINFO("register routine[%d], name: %s\r\n",
              core->hash, name);
        
        return 0;
err_ret:
        return ret;
}

int core_register_destroy(const char *name, func2_t func, void *ctx)
{
        int ret;
        core_t *core = core_self();

        ret = __core_register(&core->destroy_list, name, func, ctx);
        if(ret)
                GOTO(err_ret, ret);

        DINFO("register destroy[%d], name: %s\r\n",
              core->hash, name);
        
        return 0;
err_ret:
        return ret;
}

int core_request_async(int hash, int priority, const char *name, func_t exec, void *arg)
{
        int ret;
        core_t *core;
        schedule_t *schedule;

        if (unlikely(__core_array__ == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }
        
        core = __core_array__[hash % cpuset_useable()];
        schedule = core->schedule;
        if (unlikely(schedule == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }

        ret = schedule_request(schedule, priority, exec, arg, name);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int core_worker_exit(core_t *core)
{
        DINFO("%s[%u] destroy begin\n", core->name, core->hash);

        struct list_head *pos;
        routine_t *routine;
        void *ctx = variable_get_ctx();
        YASSERT(ctx);
        
        list_for_each(pos, &core->destroy_list) {
                routine = (void *)pos;
                routine->func(core, ctx, routine->ctx);
        }
        
        gettime_private_destroy();

        if (core->main_core) {
                cpuset_unset(core->main_core->cpu_id);
        }

        variable_unset(VARIABLE_CORE);

        timer_destroy();

        if (core->flag & CORE_FLAG_PRIVATE) {
                analysis_private_destroy();
                mem_cache_private_destroy();
                mem_hugepage_private_destoy();
        }

        schedule_destroy(core->schedule);

        return 0;
}

int core_islocal(const coreid_t *coreid)
{
        core_t *core;

        if (!net_islocal(&coreid->nid)) {
                DBUG("nid %u\n", coreid->nid.id);
                return 0;
        }

        core = core_self();
        
        if (unlikely(core == NULL))
                return 0;

        if (core->hash != (int)coreid->idx) {
                DBUG("idx %u %u\n", core->hash, coreid->idx);
                return 0;
        }

        return 1;
}

int core_getid(coreid_t *coreid)
{
        int ret;
        core_t *core = core_self();
        
        if (unlikely(core == NULL)) {
                ret = ENOSYS;
                GOTO(err_ret, ret);
        }

        coreid->nid = *net_getnid();
        coreid->idx = core->hash;

        return 0;
err_ret:
        return ret;
}

int core_init_modules(const char *name, func_va_t exec, ...)
{
        int ret;
        va_list ap;

        va_start(ap, exec);

        for (int i = 0; i < cpuset_useable(); i++) {
                ret = core_request_va(i, -1, name, exec, ap);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}
