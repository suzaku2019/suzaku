#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <hiredis/hiredis.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSCDS

#include "network.h"
#include "cds.h"
#include "disk.h"
#include "md_proto.h"
#include "ylib.h"
#include "ynet_rpc.h"
#include "sdfs_lib.h"
#include "aio.h"
#include "diskid.h"
#include "md_lib.h"
#include "bh.h"
#include "net_global.h"
#include "nodeid.h"
#include "mds_rpc.h"
#include "mem_cache.h"
#include "adt.h"
#include "schedule.h"
#include "dbg.h"

#define REQUEST_SEM 1
#define REQUEST_TASK 2


typedef struct redis_co_ctx {
        struct list_head hook;
        const char *format;
        va_list ap;
        redisReply *reply;
        sem_t sem;
        int type;
        int retval;
        task_t task;
} disk_redis_ctx_t;


static void __disk_redis_run__(disk_redis_t *co);

static void *__disk_redis_worker(void *args)
{
        disk_redis_t *disk_redis = args;

        while (disk_redis->running) {
                eventfd_poll(disk_redis->eventfd, 1, NULL);

                __disk_redis_run__(disk_redis);
        }

        close(disk_redis->eventfd);
        redisFree(disk_redis->conn);
        yfree((void **)&disk_redis);
        
        pthread_exit(NULL);
}

static int __disk_redis_connect(const char *path, redisContext **ctx)
{
        int ret;
        redisContext *c = NULL;

        c = redisConnectUnix(path);
        if (!c || c->err) {
                if (c) {
                        DERROR("Connection error: %s\n", c->errstr);
                } else {
                        DERROR("Connection error: can't allocate redis context\n");
                }
                ret = ENONET;
                GOTO(err_ret, ret);
        }

        *ctx = c;
        DBUG("redis connected unix %s\n", path);

        return 0;
err_ret:
        redisFree(c);
        return ret;
}

int disk_redis_connect(const char *path, disk_redis_t **_disk_redis)
{
        int ret;
        disk_redis_t *disk_redis;

        ret = ymalloc((void **)&disk_redis, sizeof(*disk_redis));
        if (ret)
                GOTO(err_ret, ret);

        memset(disk_redis, 0x0, sizeof(*disk_redis));
        ret = sy_spin_init(&disk_redis->spin);
        if (ret)
                GOTO(err_free, ret);
        
        ret = sem_init(&disk_redis->sem, 0, 0);
        if (ret)
                GOTO(err_free, ret);

        int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (fd < 0) {
                ret = errno;
                GOTO(err_free, ret);
        }

        disk_redis->eventfd = fd;
        disk_redis->running = 1;
        INIT_LIST_HEAD(&disk_redis->queue);

        ret = __disk_redis_connect(path, &disk_redis->conn);
        if (ret)
                GOTO(err_close, ret);
        
        ret = sy_thread_create2(__disk_redis_worker, disk_redis, "disk_redis");
        if (ret)
                UNIMPLEMENTED(__DUMP__);
        
        *_disk_redis = disk_redis;
        
        return 0;
err_close:
        close(fd);
err_free:
        yfree((void **)&disk_redis);
err_ret:
        return ret;
}

void disk_redis_close(disk_redis_t *disk_redis)
{
        (void) disk_redis;
        UNIMPLEMENTED(__DUMP__);
}


static int __disk_redis_run(disk_redis_t *co, struct list_head *list)
{
        int ret;
        struct list_head *pos, *n;
        disk_redis_ctx_t *ctx;
        
        ANALYSIS_BEGIN(0);
        
        list_for_each(pos, list) {
                ctx = (disk_redis_ctx_t *)pos;
 
                ret = redisvAppendCommand(co->conn, ctx->format, ctx->ap);
                if ((unlikely(ret)))
                        UNIMPLEMENTED(__DUMP__);
        }

        ANALYSIS_QUEUE(0, IO_WARN, NULL);

#if 0        
        int done;
        ret = redisBufferWrite(co->conn, &done);
        DBUG("ret %d %d\n", ret, done);

        ret = redisBufferRead(co->conn);
        if (ret) {
                DBUG("-----ret %u--\n", ret, retry);
                UNIMPLEMENTED(__DUMP__);
        }
#endif

        list_for_each_safe(pos, n, list) {
                ctx = (disk_redis_ctx_t *)pos;

                ret = redisGetReply(co->conn, (void **)&ctx->reply);
                YASSERT(ret == 0);
                YASSERT(ctx->reply);

                list_del(pos);

                if (ctx->type == REQUEST_SEM) {
                        ctx->retval = ret;
                        sem_post(&ctx->sem);
                } else {
                        schedule_resume(&ctx->task, ret, NULL);
                }
        }

        return 0;
}

static void __disk_redis_run__(disk_redis_t *co)
{
        struct list_head list;

        if (list_empty(&co->queue)) {
                return;
        }

        INIT_LIST_HEAD(&list);

        list_splice_init(&co->queue, &list);
        
        __disk_redis_run(co, &list);
}



static int __disk_redis(disk_redis_t *disk_redis, redisReply **reply,
             const char *format, ...)
{
        int ret;
        disk_redis_ctx_t ctx;
        uint64_t e = 1;

        ANALYSIS_BEGIN(0);
        
        ctx.format = format;
        va_start(ctx.ap, format);

        if (schedule_running()) {
                ctx.type = REQUEST_TASK;
                ctx.task = schedule_task_get();
        } else {
                ctx.type = REQUEST_SEM;
                ret = sem_init(&ctx.sem, 0, 0);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
        }
        
        list_add_tail(&ctx.hook, &disk_redis->queue);

        DBUG("%s\n", format);

        ret = write(disk_redis->eventfd, &e, sizeof(e));
        if (unlikely(ret < 0)) {
                ret = errno;
                UNIMPLEMENTED(__DUMP__);
        }
        
        if (schedule_running()) {
                ret = schedule_yield1("disk_redis", NULL, NULL, NULL, -1);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = _sem_wait(&ctx.sem);
                if (unlikely(ret)) {
                        GOTO(err_ret, ret);
                }

                ret = ctx.retval;
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        *reply = ctx.reply;

        ANALYSIS_QUEUE(0, 10 * 1000, NULL);
        
        return 0;
err_ret:
        return ret;
}

int redis_error(const char *func, redisReply *reply)
{
        int ret;

        DWARN("%s reply->type %u, reply->str %s\n", func, reply->type, reply->str);
        
        if (strcmp(reply->str, "LOADING Redis is loading the dataset in memory") == 0) {
                ret = EAGAIN;
        } else if (strncmp(reply->str, "READONLY", strlen("READONLY")) == 0) {
                ret = ECONNRESET;
        } else {
                ret = EIO;
                UNIMPLEMENTED(__DUMP__);
        }

        return ret;
        
}

int disk_redis_hget(disk_redis_t *disk_redis, const char *hash, const char *key,
                    void *buf, size_t *len)
{
        int ret;
        redisReply *reply;

        ANALYSIS_BEGIN(0);

        DBUG("%s %s\n", hash, key);
        
        ret = __disk_redis(disk_redis, &reply, "HGET %s %s", hash, key);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (reply == NULL) {
                ret = ECONNRESET;
                DWARN("redis reset, hash %s, key %s\n", hash, key);
                GOTO(err_ret, ret);
        }
        
        if (reply->type == REDIS_REPLY_NIL) {
                ret = ENOENT;
                GOTO(err_free, ret);
        }
                
        if (reply->type != REDIS_REPLY_STRING) {
                DWARN("redis reply->type: %d\n", reply->type);
                ret = redis_error(__FUNCTION__, reply);
                GOTO(err_free, ret);
        }

        if (*len < (size_t)reply->len) {
                ret = EINVAL;
                GOTO(err_free, ret);
        }

        *len = reply->len;
        memcpy(buf, reply->str, reply->len);

        freeReplyObject(reply);
        
        ANALYSIS_QUEUE(0, IO_WARN, NULL);
        return 0;

err_free:
        freeReplyObject(reply);
err_ret:
        return ret;
}

int disk_redis_hset(disk_redis_t *disk_redis, const char *hash, const char *key,
                    const void *value, size_t size, int flag)
{
        int ret;
        redisReply *reply;

        ANALYSIS_BEGIN(0);
        
        DBUG("%s %s, flag 0x%o\n", hash, key, flag);
        
        if (flag & O_EXCL) {
                ret = __disk_redis(disk_redis, &reply, "HSETNX %s %s %b",
                                   hash, key, value, size);
        } else {
                ret = __disk_redis(disk_redis, &reply, "HSET %s %s %b",
                                   hash, key, value, size);
        }
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (reply == NULL) {
                ret = ECONNRESET;
                DWARN("redis reset\n");
                GOTO(err_ret, ret);
        }

        if (reply->type != REDIS_REPLY_INTEGER) {
                ret = redis_error(__FUNCTION__, reply);
                GOTO(err_free, ret);
        }

        //DINFO("reply->integer  %u\n", reply->integer);
        if (flag & O_EXCL && reply->integer == 0) {
                ret = EEXIST;
                GOTO(err_free, ret);
        }
        
        freeReplyObject(reply);

        ANALYSIS_QUEUE(0, IO_WARN, NULL);
        
        return 0;
err_free:
        freeReplyObject(reply);
err_ret:
        return ret;
}

int disk_redis_hdel(disk_redis_t *disk_redis, const char *hash, const char *key)
{
        int ret;
        redisReply *reply;

        ANALYSIS_BEGIN(0);

        DBUG("%s %s\n", hash, key);
        
        ret = __disk_redis(disk_redis, &reply, "HDEL %s %s", hash, key);
        if (unlikely(ret))
                GOTO(err_ret, ret);        

        if (reply == NULL) {
                ret = ECONNRESET;
                DWARN("redis reset\n");
                GOTO(err_ret, ret);
        }
        
        if (reply->type != REDIS_REPLY_INTEGER) {
                ret = redis_error(__FUNCTION__, reply);
                GOTO(err_free, ret);
        }

        if (reply->integer == 0) {
                ret = ENOENT;
                GOTO(err_free, ret);
        }
        
        freeReplyObject(reply);
        ANALYSIS_QUEUE(0, IO_WARN, NULL);

        return 0;
err_free:
        freeReplyObject(reply);
err_ret:
        return ret;
}

static int __disk_redis_hitor(disk_redis_t *disk_redis, const char *hash,
                              size_t *_cur, const char *match, func3_t func,
                              void *arg)
{
        int ret;
        redisReply *reply, *e1, *e2;
        size_t i, cur = *_cur;

        //DINFO("HSCAN cur %u\n", cur);

        char cmd[MAX_BUF_LEN];
        if (match)
                snprintf(cmd, MAX_BUF_LEN, "HSCAN %s %ju MATCH %s count 100",
                         hash, cur, match);
        else
                snprintf(cmd, MAX_BUF_LEN, "HSCAN %s %ju count 100",
                         hash, cur);
        
        ret = __disk_redis(disk_redis, &reply, cmd);
        if (ret)
                GOTO(err_ret, ret);
        
        if (reply->type != REDIS_REPLY_ARRAY) {
                DWARN("redis reply->type: %d\n", reply->type);
                ret = redis_error(__FUNCTION__, reply);
                GOTO(err_free, ret);
        }

        
        YASSERT(reply->elements == 2);
        YASSERT(reply->element[0]->type == REDIS_REPLY_STRING);
        YASSERT(reply->element[1]->type == REDIS_REPLY_ARRAY);
        *_cur = atol(reply->element[0]->str);

        DBUG("scan %s count %ju\n", hash, reply->element[1]->elements);
        for (i = 0; i < reply->element[1]->elements; i += 2) {
                e1 = reply->element[1]->element[i];
                e2 = reply->element[1]->element[i + 1];
                YASSERT(e1->type == REDIS_REPLY_STRING);
                YASSERT(e2->type == REDIS_REPLY_STRING);

                DBUG("key %s, value %s\n", e1->str, e2->str);
                func(e1->str, e2->str, &e2->len, arg);
        }

        freeReplyObject(reply);
        return 0;

err_free:
        freeReplyObject(reply);
err_ret:
        return ret;
}

int disk_redis_hitor(disk_redis_t *disk_redis, const char *hash,
                     const char *match, func3_t func, void *arg)
{
        int ret;//, i = 0;
        size_t cur = 0;

        while (1) {
                ret = __disk_redis_hitor(disk_redis, hash, &cur, match, func, arg);
                if ((unlikely(ret))) {
                        GOTO(err_ret, ret);
                }

                if (cur == 0)
                        break;
        }

        return 0;
err_ret:
        return ret;
}

static int __disk_redis_itor(disk_redis_t *disk_redis, size_t *_cur,
                             const char *match, func3_t func, void *arg)
{
        int ret;
        redisReply *reply, *e1, *e2;
        size_t i, cur = *_cur;

        //DINFO("HSCAN cur %u\n", cur);

        char cmd[MAX_BUF_LEN];
        snprintf(cmd, MAX_BUF_LEN, "SCAN %ju count 100",
                 cur);
        
        ret = __disk_redis(disk_redis, &reply, cmd);
        if (ret)
                GOTO(err_ret, ret);
        
        if (reply->type != REDIS_REPLY_ARRAY) {
                DWARN("redis reply->type: %d\n", reply->type);
                ret = redis_error(__FUNCTION__, reply);
                GOTO(err_free, ret);
        }

        
        YASSERT(reply->elements == 2);
        YASSERT(reply->element[0]->type == REDIS_REPLY_STRING);
        YASSERT(reply->element[1]->type == REDIS_REPLY_ARRAY);
        *_cur = atol(reply->element[0]->str);

        //DBUG("scan %s count %ju\n", hash, reply->element[1]->elements);
        for (i = 0; i < reply->element[1]->elements; i += 2) {
                e1 = reply->element[1]->element[i];
                e2 = reply->element[1]->element[i + 1];
                YASSERT(e1->type == REDIS_REPLY_STRING);
                YASSERT(e2->type == REDIS_REPLY_STRING);

                DBUG("key %s, value %s\n", e1->str, e2->str);

                ret = disk_redis_hitor(disk_redis, e1->str, match, func, arg);
                if (ret)
                        GOTO(err_free, ret);
        }

        freeReplyObject(reply);
        return 0;

err_free:
        freeReplyObject(reply);
err_ret:
        return ret;
}

int disk_redis_itor(disk_redis_t *disk_redis, const char *match, func3_t func,
                    void *arg)
{
        int ret;//, i = 0;
        size_t cur = 0;

        while (1) {
                ret = __disk_redis_itor(disk_redis, &cur, match, func, arg);
                if ((unlikely(ret))) {
                        GOTO(err_ret, ret);
                }

                if (cur == 0)
                        break;
        }

        return 0;
err_ret:
        return ret;
}
