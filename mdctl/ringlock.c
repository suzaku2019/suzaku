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
#include "rpc_proto.h"
#include "network.h"
#include "ylog.h"
#include "schedule.h"
#include "timer.h"
#include "ringlock_rpc.h"
#include "ringlock.h"
#include "core.h"
#include "dbg.h"

typedef struct {
        uint32_t type;
        range_t range;
        time_t time;
        ltoken_t token;
        plock_t plock;
        coreid_t coreid;
} ringlock_t;

static int __ringlock_update(ringlock_t *ringlock);

static int __ringlock_wrlock(ringlock_t *ringlock)
{
        int ret;

        ret = plock_wrlock(&ringlock->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

inline static int __ringlock_rdlock(ringlock_t *ringlock)
{
        int ret;

        ret = plock_rdlock(&ringlock->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static void  __ringlock_unlock(ringlock_t *ringlock)
{
        plock_unlock(&ringlock->plock);

        return;
}

static void __ringlock_worker(void *arg)
{
        int ret, tmo;
        ringlock_t *ringlock = arg;
        uint64_t i = 0;
        core_t *core = core_self();

        tmo = gloconf.lease_timeout / 4;
        tmo = tmo < 1 ? 1 : tmo;
        
        while (1) {
                schedule_sleep("ringlock_check", 1000 * 1000 * tmo);

                ret = __ringlock_update(ringlock);

                DINFO("core[%u] "RANGE_FORMAT" check %ju, retval %u, token (%u, %ju)\n",
                      core->hash,  RANGE_ARG(&ringlock->range), i, ret,
                      ringlock->token.master, ringlock->token.seq);
                
                i++;
        }
}

static int __ringlock_init(va_list ap)
{
        int ret;
        ringlock_t *ringlock;
        range_t range = {-1, -1};
        uint32_t type = va_arg(ap, uint32_t);

        va_end(ap);
        
        ret = ymalloc((void **)&ringlock, sizeof(*ringlock));
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);
                
        ret = plock_init(&ringlock->plock, "ringlock");
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        ringlock->type = type;
        ringlock->range = range;
        ringlock->time = 0;

        ret = core_getid(&ringlock->coreid);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);
        
        variable_set(VARIABLE_RINGLOCK, ringlock);

        schedule_task_new("ringlock_worker", __ringlock_worker, ringlock, -1);
        
        return 0;
}

int ringlock_init(uint32_t type)
{
        int ret;

        ret = core_init_modules("ringlock_init", __ringlock_init, type);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}


static int __ringlock_locked(const ringlock_t *ringlock, const range_t *range)
{
        time_t now = gettime();
        
        if (unlikely(now - ringlock->time > gloconf.lease_timeout / 2)) {
                return 0;
        }

        if (unlikely(now < ringlock->time)) {
                return 0;
        }

        if (unlikely(ringlock->token.master != ng.master_magic)) {
                return 0;
        }

        if (unlikely(ringlock->range.begin != range->begin
                    || ringlock->range.end != range->end)) {
                return 0;
        }
        
        return 1;
}

static int __ringlock_update__(ringlock_t *ringlock, const range_t *range)
{
        int ret;
        ltoken_t token;

        ret = __ringlock_wrlock(ringlock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (__ringlock_locked(ringlock, range)) {
                goto out;
        }
        
        time_t now = gettime();
        if (now < ringlock->time) {
                DERROR("system time maybe changed, time %u, now %u\n",
                       (int)ringlock->time, (int)now);
                ringlock->time = now - gloconf.lease_timeout * 2;
        }

        ret = ringlock_rpc_lock(net_getadmin(), range, ringlock->type,
                                &ringlock->coreid, &token);
        if (unlikely(ret)) {
                GOTO(err_lock, ret);
        }

        if (token.master != ng.master_magic) {
                ret = EAGAIN;
                DWARN(RANGE_FORMAT" wrong master 0x%x -> 0x%x\n",
                      RANGE_ARG(&ringlock->range),
                      ng.master_magic, token.master);
                GOTO(err_lock, ret);
        }

        ringlock->time = now;
        ringlock->range = *range;
        ringlock->token = token;

out:
        __ringlock_unlock(ringlock);

        
        return 0;
err_lock:
        __ringlock_unlock(ringlock);
err_ret:
        return ret;
}

static int __ringlock_update(ringlock_t *ringlock)
{
        int ret;
        range_t range;

        YASSERT(ng.daemon);

        int t = (ringlock->type == TYPE_MDCTL) ? TYPE_MDCTL : TYPE_FRCTL;
        ret = part_range(t, &ringlock->coreid, &range);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        DINFO("core[%u] "RANGE_FORMAT"\n", ringlock->coreid.idx,
              RANGE_ARG(&range));
        
        if (__ringlock_locked(ringlock, &range)) {
                DINFO(RANGE_FORMAT" locked\n", RANGE_ARG(&range));
                goto out;
        }

        ret = __ringlock_update__(ringlock, &range);
        if (unlikely(ret))
                GOTO(err_ret, ret);

out:
        return 0;
err_ret:
        return ret;
}

int ringlock_locked(uint32_t type, ltoken_t *_token, int flag)
{
        int ret;
        ringlock_t *ringlock = variable_get(VARIABLE_RINGLOCK);

        YASSERT(ng.daemon);
        YASSERT(ringlock->type == type);

        ret = __ringlock_update(ringlock);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        if (flag & O_CREAT) {
                *_token = ringlock->token;
        } else {
                if (ringlock->token.master != _token->master
                    || ringlock->token.seq != _token->seq) {
                        ret = ESTALE;
                        UNIMPLEMENTED(__DUMP__);
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        return ret;
}


int ringlock_check(const chkid_t *chkid, int rtype, int flag, ltoken_t *token)
{
        int ret;
        coreid_t coreid;
        int ptype = (rtype == TYPE_MDCTL) ? TYPE_MDCTL : TYPE_FRCTL;
        
        ret = part_location(chkid, ptype, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(!core_islocal(&coreid))) {
                ret = EREMCHG;
                GOTO(err_ret, ret);
        }

        ret = ringlock_locked(rtype, token, flag);
        if (unlikely(ret)) {
                DWARN(CHKID_FORMAT" @ core %s/%d fail\n", CHKID_ARG(chkid),
                      network_rname(&coreid.nid), coreid.idx);
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}
