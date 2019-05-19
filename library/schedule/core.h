#ifndef __CORE_H__
#define __CORE_H__

#include <sys/epoll.h>
#include <semaphore.h>
#include <linux/aio_abi.h>         /* Defines needed types */
#include <pthread.h>

#if ENABLE_RDMA
#include <rdma/rdma_cma.h>
#endif

#include "net_proto.h"
#include "../sock/ynet_sock.h"
#include "cache.h"
#include "ylock.h"
#include "schedule.h"
#include "variable.h"
#include "cpuset.h"

typedef int (*core_exec)(void *ctx, void *buf, int *count);
typedef int (*core_exec1)(void *ctx, void *data_buf, void *msg_buf);
typedef int (*core_reconnect)(int *fd, void *ctx);
typedef int (*core_func)();
typedef void (*core_exit)();

#define CORE_FILE_MAX 64

#if ENABLE_RDMA
typedef struct {
        struct list_head list;

        struct ibv_cq *cq;
        struct ibv_pd *pd;
        struct ibv_mr *mr;

        struct ibv_context *ibv_verbs;
        struct ibv_device_attr device_attr;
        // int ref;
} rdma_info_t;

#endif

typedef struct __routine {
        struct list_head hook;
        char name[64];
        func2_t func;
        void *ctx;
} routine_t;

typedef struct __core {
        char name[MAX_NAME_LEN];
        int interrupt_eventfd;   // === schedule->eventfd, 通知机制

        int idx;
        int hash;
        int flag;
        coreinfo_t *main_core;
        int aio_core;

        void *maping;
        void *rpc_table;
        void *corenet;

        schedule_t *schedule;

        void *tls[VARIABLE_MAX];

        sy_spinlock_t keepalive_lock; // for keepalive
        time_t last_check;
        time_t keepalive;

        sem_t sem;
        struct list_head poller_list;
        struct list_head routine_list;
        struct list_head destroy_list;
} core_t;

#define CORE_FLAG_PASSIVE 0x0002
#define CORE_FLAG_AIO     0x0004
#define CORE_FLAG_PRIVATE 0x0010
#define CORE_FLAG_POLLING 0x0020

int core_init(int polling_core, int flag);

void core_check_register(core_t *core, const char *name, void *opaque, func1_t func);

int core_hash(const fileid_t *fileid);
int core_attach(int hash, const sockid_t *sockid, const char *name, void *ctx,
                core_exec func, func_t reset, func_t check);
core_t *core_get(int hash);
core_t *core_self();

int core_worker_exit(core_t *core);
int core_request(int hash, int priority, const char *name, func_va_t exec, ...);
void core_register_tls(int type, void *ptr);
int core_islocal(const coreid_t *coreid);
int core_getid(coreid_t *coreid);
int core_init_modules(const char *name, func_va_t exec, ...);

void core_iterator(func1_t func, const void *opaque);

void core_latency_update(uint64_t used);
int core_dump_memory(uint64_t *memory);
int core_latency_init();

int core_register_destroy(const char *name, func2_t func, void *ctx);
int core_register_poller(const char *name, func2_t func, void *ctx);
int core_register_routine(const char *name, func2_t func, void *ctx);

#define CORE_ANALYSIS_BEGIN(mark)               \
        struct timeval t1##mark, t2##mark;      \
        int used##mark;                         \
                                                \
        _gettimeofday(&t1##mark, NULL);         \


#define CORE_ANALYSIS_UPDATE(mark, __usec, __str)                       \
        _gettimeofday(&t2##mark, NULL);                                 \
        used##mark = _time_used(&t1##mark, &t2##mark);                  \
        core_latency_update(used##mark);                                \
        if (used##mark > (__usec)) {                                    \
                if (used##mark > 1000 * 1000 * gloconf.rpc_timeout) {   \
                        DWARN_PERF("analysis used %f s %s, timeout\n", (double)(used##mark) / 1000 / 1000, (__str) ? (__str) : ""); \
                } else {                                                \
                        DINFO_PERF("analysis used %f s %s\n", (double)(used##mark) / 1000 / 1000, (__str) ? (__str) : ""); \
                }                                                       \
        }                                                               \

uint64_t core_latency_get();

#endif
