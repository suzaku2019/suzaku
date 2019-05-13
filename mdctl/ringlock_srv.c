#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "limits.h"
#include "adt.h"
#include "ynet_rpc.h"
#include "ylib.h"
#include "net_table.h"
#include "configure.h"
#include "net_global.h"
#include "ringlock.h"
#include "network.h"
#include "dbg.h"

typedef struct {
        struct list_head hook;
        sy_spinlock_t lock;
        coreid_t coreid;
        time_t time;
        uint64_t seq;
        range_t range;
} ringlock_entry_t;

typedef struct {
        char name[MAX_NAME_LEN];
        struct list_head list;
        time_t uptime;
        uint32_t magic;
        uint64_t seq;
        sy_rwlock_t lock;
} ringlock_srv_t;

static ringlock_srv_t *__ringlock_mds__ = NULL;
static ringlock_srv_t *__ringlock_frctl__ = NULL;
static time_t __uptime__;

static int __ringlock_srv_init(ringlock_srv_t **_ringlock, const char *name)
{
        int ret;
        ringlock_srv_t *ringlock;

        ret = ymalloc((void **)&ringlock, sizeof(*ringlock));
        if (ret)
                GOTO(err_ret, ret);
        
        INIT_LIST_HEAD(&ringlock->list);
        ret = sy_rwlock_init(&ringlock->lock, name);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ringlock->uptime = gettime();
        ringlock->magic = ng.master_magic;
        ringlock->seq = 0;
        strcpy(ringlock->name, name);

        *_ringlock = ringlock;

        return 0;
err_ret:
        return ret;
}

int ringlock_srv_init()
{
        int ret;

        YASSERT(__ringlock_mds__ == NULL);
        YASSERT(__ringlock_frctl__ == NULL);

        ret = __ringlock_srv_init(&__ringlock_mds__, ROLE_MDCTL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __ringlock_srv_init(&__ringlock_frctl__, ROLE_FRCTL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __ringlock_uptime_check()
{
        int ret;
        time_t now;
        int timeout = gloconf.lease_timeout + gloconf.lease_timeout / 2
                - mdsconf.master_timeout;

        now = gettime();
        if ((int)now - (int)__uptime__ < timeout) {
                if (now < __uptime__) {
                        DERROR("time maybe changed, uptime %ds, now %ds\n",
                               (int)__uptime__, (int)now);
                        __uptime__ = now;
                } else {
                        DBUG("lease_srv will be available int %ds\n",
                             timeout - ((int)(now -  __uptime__)));
                }

                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __ringlock_timeout(ringlock_entry_t *ent)
{
        int tmo;
        time_t now;

        now = gettime();
        tmo = gloconf.lease_timeout + gloconf.lease_timeout / 2;
        if (now < ent->time) {
                DERROR("time maybe changed, time %ds, now %d, restart for safe\n",
                       (int)ent->time, (int)now);

                EXIT(EAGAIN);
        } else if (now - ent->time >= tmo) {
                DBUG(""RANGE_FORMAT" @ %s timeout %ds\n",
                      RANGE_ARG(&ent->range), network_rname(&ent->coreid.nid),
                      (int)(now - ent->time) - tmo);

                return 1;
        } else {
                DBUG(""RANGE_FORMAT" @ %s still in used, will timeout in %ds\n",
                      RANGE_ARG(&ent->range), network_rname(&ent->coreid.nid),
                      (int)(tmo - (now - ent->time)));
        }

        return 0;
}

static ringlock_entry_t *__ringlock_find(ringlock_srv_t *ringlock, const range_t *range)
{
        struct list_head *pos;
        ringlock_entry_t *ent;

        list_for_each(pos, &ringlock->list) {
                ent = (void *)pos;

                if (range->end <= ent->range.begin
                    || range->begin >= ent->range.end)
                        continue;

                return ent;
        }

        return NULL;
}

static void __ringlock_cleanup(ringlock_srv_t *ringlock)
{
        struct list_head *pos, *n;
        ringlock_entry_t *ent;

        list_for_each_safe(pos, n, &ringlock->list) {
                ent = (void *)pos;

                if (__ringlock_timeout(ent)) {
                        list_del(pos);
                        yfree((void **)&pos);
                }
        }
}

static int __ringlock_update(ringlock_srv_t *ringlock, ringlock_entry_t *ent,
                             const range_t *range, const coreid_t *coreid,
                             ltoken_t *token)
{
        int ret;

        ret = sy_spin_lock(&ent->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (coreid_cmp(&ent->coreid, coreid) == 0
            && range->begin == ent->range.begin
            && range->end == ent->range.end) {
                DBUG(RANGE_FORMAT" reuse ringlock, owner %s, "
                     "token (0x%x, %ju), update %ds\n",
                     RANGE_ARG(&ent->range), network_rname(&ent->coreid.nid),
                     ringlock->magic, ent->seq, gettime() - ent->time);

                ent->time = gettime();
                token->seq = ent->seq;
                token->master = ringlock->magic;
        } else {
                int wait = (int)((ent->time + gloconf.lease_timeout
                                  + gloconf.lease_timeout / 2) - gettime());
                if (wait % 10 == 0 || 1) {
                        DINFO(RANGE_FORMAT" ringlock %s/%d -> %s/%d fail, need wait %ds\n",
                              RANGE_ARG(&ent->range),
                              network_rname(&ent->coreid.nid), ent->coreid.idx,
                              network_rname(&coreid->nid), coreid->idx, wait);
                }

                ret = ESTALE;
                GOTO(err_lock, ret);
        }

        sy_spin_unlock(&ent->lock);

        return 0;
err_lock:
        sy_spin_unlock(&ent->lock);
err_ret:
        return ret;
}

static int __ringlock_get(ringlock_srv_t *ringlock, ringlock_entry_t *ent,
                          coreid_t *_coreid, ltoken_t *token)
{
        int ret;
        time_t now;

        ret = sy_spin_lock(&ent->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (__ringlock_timeout(ent)) {
                ret = ETIME;
                GOTO(err_lock, ret);
        }

        now = gettime();
        DBUG(RANGE_FORMAT" owner %s, left %ds\n",
              RANGE_ARG(&ent->range), network_rname(&ent->coreid.nid),
              (int)((ent->time + gloconf.lease_timeout
                     + gloconf.lease_timeout / 2) - now));
        *_coreid = ent->coreid;
        token->seq = ent->seq;
        token->master = ringlock->magic;

        sy_spin_unlock(&ent->lock);

        return 0;
err_lock:
        sy_spin_unlock(&ent->lock);
err_ret:
        return ret;
}

static int __ringlock_new__(ringlock_srv_t *ringlock, ringlock_entry_t **_ent,
                            const range_t *range, const coreid_t *coreid, ltoken_t *token)
{
        int ret;
        ringlock_entry_t *ent;

        ret = ymalloc((void **)&ent, sizeof(*ent));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent->coreid = *coreid;
        ent->range = *range;
        ent->time = gettime();
        ent->seq = ++ringlock->seq;

        token->seq = ent->seq;
        token->master = ringlock->magic;
        
        ret = sy_spin_init(&ent->lock);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        DBUG("new ringlock "RANGE_FORMAT" @ %s, token (0x%x, %ju)\n",
             RANGE_ARG(&ent->range), network_rname(&coreid->nid),
             token->master, token->seq);

        *_ent = ent;
        
        return 0;
err_ret:
        return ret;
}

static int __ringlock_new(ringlock_srv_t *ringlock, const range_t *range,
                           const coreid_t *coreid, ltoken_t *token)
{
        int ret;
        ringlock_entry_t *ent;

        ret = sy_rwlock_wrlock(&ringlock->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = __ringlock_find(ringlock, range);
        if (unlikely(ent)) {
                ret = EEXIST;
                GOTO(err_lock, ret);
        }

        ret = __ringlock_new__(ringlock, &ent, range, coreid, token);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        list_add_tail(&ent->hook, &ringlock->list);

        sy_rwlock_unlock(&ringlock->lock);

        return 0;
err_lock:
        sy_rwlock_unlock(&ringlock->lock);
err_ret:
        return ret;
}

static int __ringlock_check_range(uint32_t type, const coreid_t *coreid, const range_t *range)
{
        int ret;
        range_t range1;

        ret = part_range(type, coreid, &range1);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (range1.begin != range->begin
            || range1.end != range->end) {
                ret = ESTALE;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __ringlock_check(int type, const coreid_t *coreid, const range_t *range)
{
        int ret;
        ringlock_srv_t *ringlock = (type == RINGLOCK_MDS)
                ? __ringlock_mds__ : __ringlock_frctl__;

        if (coreid && range) {
                ret = __ringlock_check_range(type, coreid, range);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        ret = __ringlock_uptime_check();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = sy_rwlock_wrlock(&ringlock->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        __ringlock_cleanup(ringlock);
        
        sy_rwlock_unlock(&ringlock->lock);

        return 0;
err_ret:
        return ret;
}


int ringlock_srv_lock(const range_t *range, uint32_t type, const coreid_t *coreid,
                      ltoken_t *token)
{
        int ret;
        ringlock_entry_t *ent;
        ringlock_srv_t *ringlock = (type == RINGLOCK_MDS)
                ? __ringlock_mds__ : __ringlock_frctl__;

        DINFO("%s "RANGE_FORMAT" lock @ %s\n", ringlock->name, RANGE_ARG(range),
              network_rname(&coreid->nid));

        if (ringlock == NULL) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        ret = __ringlock_check(type, coreid, range);
        if (unlikely(ret))
                GOTO(err_ret, ret);

retry:
        ret = sy_rwlock_rdlock(&ringlock->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = __ringlock_find(ringlock, range);
        if (ent) {
                ret = __ringlock_update(ringlock, ent, range, coreid, token);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        } else {
                sy_rwlock_unlock(&ringlock->lock);
                
                ret = __ringlock_new(ringlock, range, coreid, token);
                if (unlikely(ret)) {
                        if (ret == EEXIST) { 
                                DWARN(""RANGE_FORMAT" new @ %s, exist\n",
                                      RANGE_ARG(range), network_rname(&coreid->nid));
                                goto retry;
                        } else {
                                GOTO(err_ret, ret);
                        }
                }

                goto out;
        }

        sy_rwlock_unlock(&ringlock->lock);
out:
        return 0;
err_lock:
        sy_rwlock_unlock(&ringlock->lock);
err_ret:
        return ret;
}

int ringlock_srv_get(const range_t *range, uint32_t type, coreid_t *coreid, ltoken_t *token)
{
        int ret;
        ringlock_entry_t *ent;
        ringlock_srv_t *ringlock = (type == RINGLOCK_MDS)
                ? __ringlock_mds__ : __ringlock_frctl__;

        DBUG(""RANGE_FORMAT" get\n", RANGE_ARG(range));

        if (ringlock == 0) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        ret = __ringlock_check(type, NULL, NULL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = sy_rwlock_rdlock(&ringlock->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ent = __ringlock_find(ringlock, range);
        if (ent) {
                ret = __ringlock_get(ringlock, ent, coreid, token);
                if (unlikely(ret)) {
                        GOTO(err_lock, ret);
                }
        } else {
                ret = ENOKEY;
                GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&ringlock->lock);

        return 0;
err_lock:
        sy_rwlock_unlock(&ringlock->lock);
err_ret:
        return ret;
}

int ringlock_srv_unlock(const range_t *range, uint32_t type, const coreid_t *coreid)
{
        int ret;
        ringlock_srv_t *ringlock = (type == RINGLOCK_MDS)
                ? __ringlock_mds__ : __ringlock_frctl__;
        
        DBUG(""RANGE_FORMAT" free @ %s\n", RANGE_ARG(range),
             network_rname(&coreid->nid));

        if (ringlock == 0) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }
        
        ret = __ringlock_check(type, coreid, range);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;        
err_ret:
        return ret;
}


static int __ringlock_destroy(ringlock_srv_t *ringlock)
{
        int ret;

        YASSERT(ringlock);
        
        ret = sy_rwlock_wrlock(&ringlock->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        YASSERT(list_empty(&ringlock->list));
        
        sy_rwlock_unlock(&ringlock->lock);

        yfree((void **)&ringlock);
        
        return 0;
err_ret:
        UNIMPLEMENTED(__DUMP__);
        return ret;
}

int ringlock_srv_destroy()
{
        __ringlock_destroy(__ringlock_mds__);
        __ringlock_destroy(__ringlock_frctl__);
        
        __ringlock_mds__ = NULL;
        __ringlock_frctl__ = NULL;

        return 0;
}
