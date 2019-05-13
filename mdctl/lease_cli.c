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
#include "lease_cli.h"
#include "dbg.h"

static int __lease_wrlock(lease_t *lease)
{
        int ret;

        ret = plock_wrlock(&lease->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

inline static int __lease_rdlock(lease_t *lease)
{
        int ret;

        ret = plock_rdlock(&lease->plock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static void  __lease_unlock(lease_t *lease)
{
        plock_unlock(&lease->plock);

        return;
}

int lease_set(lease_t *lease)
{
        int ret;
        time_t now;
        const chkid_t *chkid = &lease->chkid;
        ltoken_t token;

        YASSERT(ng.daemon);
        YASSERT(chkid->type == ftype_file
                || chkid->type == ftype_dir);
        
        now = gettime();
        if (unlikely(now - lease->time > gloconf.lease_timeout / 2
                     || now < lease->time
                     || lease->token.master != ng.master_magic)) {
                ret = __lease_wrlock(lease);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                if (now < lease->time) {
                        DERROR("time maybe changed, time %u, now %u\n",
                               (int)lease->time, (int)now);

                        lease->time = now - gloconf.lease_timeout * 2;
                }
                
                if (now - lease->time >= gloconf.lease_timeout / 2
                    || lease->token.master != ng.master_magic) {
                        ret = lease_rpc_set(net_getadmin(), chkid, net_getnid(), &token);
                        if (unlikely(ret)) {
                                GOTO(err_lock, ret);
                        }

                        if (token.master != ng.master_magic) {
                                ret = EAGAIN;
                                DWARN(CHKID_FORMAT" wrong master 0x%x -> 0x%x\n",
                                       CHKID_ARG(&lease->chkid), ng.master_magic, token.master);
                                GOTO(err_lock, ret);
                        }
                        
                        lease->time = now;
                        lease->token = token;
                }

                __lease_unlock(lease);
        }

        SCHEDULE_LEASE_SET();
        
        return 0;
err_lock:
        __lease_unlock(lease);
err_ret:
        return ret;
}

int lease_cli_timeout(const lease_t *lease)
{
        time_t now;
 
        now = gettime();
        if (now - lease->time > gloconf.lease_timeout || now < lease->time) {
                return 1;
        } else {
                return 0;
        }
}

int lease_cli_free(lease_t *lease)
{
        int ret;
        const chkid_t *chkid = &lease->chkid;

        ret = __lease_wrlock(lease);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (lease->time) {
                ret = lease_rpc_free(net_getadmin(), chkid, net_getnid());
                if (unlikely(ret))
                        GOTO(err_lock, ret);
                
                lease->time = 0;
        }

        __lease_unlock(lease);

        return 0;
err_lock:
        __lease_unlock(lease);
err_ret:
        return ret;
}

int lease_cli_create(lease_t *lease, const chkid_t *chkid)
{
        int ret;

        ret = plock_init(&lease->plock, "lease");
        if (unlikely(ret))
                GOTO(err_ret, ret);

        lease->chkid = *chkid;
        lease->time = 0;

        return 0;
err_ret:
        return ret;
}

int lease_cli_get(const chkid_t *chkid, nid_t *nid, ltoken_t *_token)
{
        int ret;
        ltoken_t token;

        ret = lease_rpc_get(net_getadmin(), chkid, nid, &token);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (_token)
                *_token = token;
        
        return 0;
err_ret:
        return ret;
}
