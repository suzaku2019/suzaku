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
#include "network.h"
#include "dbg.h"

typedef struct {
        chkid_t chkid;
        nid_t nid;
        time_t time;
        uint64_t seq;
        sy_spinlock_t lock;
} lease_entry_t;

#define MDS_LEASE_HASH 32

typedef struct {
        htab_t tab;
        sy_rwlock_t lock;
} mds_lease_t;

static mds_lease_t *__mds_lease__ = NULL;
static uint64_t __lease_seq__ = 0;
static uint32_t __master_magic__ = 0;

static time_t __uptime__;
static int __inited__ = 0;

static int __lease_cmp(const void *v1, const void *v2)
{
        const lease_entry_t *ent = v1;
        const chkid_t *chkid = v2;

        return chkid_cmp(&ent->chkid, chkid);
}

static uint32_t __lease_key(const void *args)
{
        const chkid_t *id = args;

        return id->id * (1 + id->idx);
}

int mds_lease_init()
{
        int ret, i;
        char name[MAX_NAME_LEN];

        YASSERT(__mds_lease__ == NULL);
        YASSERT(__inited__ == 0);
        
        ret = ymalloc((void **)&__mds_lease__, sizeof(*__mds_lease__) * MDS_LEASE_HASH);
        if (ret)
                GOTO(err_ret, ret);
        
        for (i = 0; i < MDS_LEASE_HASH; i++) {
                snprintf(name, MAX_NAME_LEN, "lease[%u]",  i);
                __mds_lease__[i].tab = htab_create(__lease_cmp, __lease_key, name);
                if (__mds_lease__[i].tab == NULL) {
                        ret = ENOMEM;
                        GOTO(err_ret, ret);
                }

                ret = sy_rwlock_init(&__mds_lease__[i].lock, name);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }

        __uptime__ = gettime();
        __master_magic__ = ng.master_magic;

        __inited__ = 1;

        return 0;
err_ret:
        return ret;
}

static int __lease_uptime_check()
{
        int ret;
        time_t now;
        int lease_timeout = gloconf.lease_timeout + gloconf.lease_timeout / 2 - mdsconf.master_timeout;

        now = gettime();
        if ((int)now - (int)__uptime__ < lease_timeout) {
                if (now < __uptime__) {
                        DERROR("time maybe changed, uptime %ds, now %ds\n", (int)__uptime__, (int)now);
                        __uptime__ = now;
                } else {
                        DBUG("lease_srv will be available int %ds\n",
                             lease_timeout - ((int)(now -  __uptime__)));
                }

                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int __mds_lease_timeout(lease_entry_t *ent)
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
                DBUG(""CHKID_FORMAT" @ %s timeout %ds\n",
                      CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
                      (int)(now - ent->time) - tmo);

                return 1;
        } else {
                DBUG(""CHKID_FORMAT" @ %s still in used, will timeout in %ds\n",
                      CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
                      (int)(tmo - (now - ent->time)));
        }

        return 0;
}

static int __mds_lease_set(lease_entry_t *ent, const nid_t *nid, ltoken_t *token)
{
        int ret;

        ret = sy_spin_lock(&ent->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (nid_cmp(&ent->nid, nid) == 0) {
                DBUG(CHKID_FORMAT" reuse lease, owner %s, token (0x%x, %ju), update %ds\n",
                      CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
                      __master_magic__, ent->seq, gettime() - ent->time);

                ent->time = gettime();
                
                token->seq = ent->seq;
                token->master = __master_magic__;
        } else {
                if (!__mds_lease_timeout(ent)) {
                        ret = EREMCHG;
                        int wait = (int)((ent->time + gloconf.lease_timeout
                                          + gloconf.lease_timeout / 2) - gettime());
                        if (wait % 10 == 0 || 1) {
                                DINFO(CHKID_FORMAT" lease %s -> %s fail, need wait %ds\n",
                                      CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
                                      network_rname(nid), wait);
                        }

                        GOTO(err_lock, ret);
                } else {
                        uint64_t seq = ++__lease_seq__;

                        DBUG(CHKID_FORMAT" update lease, owner %s -> %s "
                             "token (0x%x, %ju) -> (0x%x, %ju)\n",
                             CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
                             network_rname(nid), __master_magic__, ent->seq,
                             __master_magic__, seq);

                        ent->nid = *nid;
                        ent->seq = seq;
                        ent->time = gettime();

                        token->seq = ent->seq;
                        token->master = __master_magic__;
                }
        }

        sy_spin_unlock(&ent->lock);

        return 0;
err_lock:
        sy_spin_unlock(&ent->lock);
err_ret:
        return ret;
}

static int __mds_lease_get(lease_entry_t *ent, nid_t *_nid, ltoken_t *token)
{
        int ret;
        time_t now;

        ret = sy_spin_lock(&ent->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (__mds_lease_timeout(ent)) {
                ret = ETIME;
                GOTO(err_lock, ret);
        }

        now = gettime();
        DBUG(CHKID_FORMAT" owner %s, left %ds\n",
              CHKID_ARG(&ent->chkid), network_rname(&ent->nid),
              (int)((ent->time + gloconf.lease_timeout + gloconf.lease_timeout / 2) - now));
        *_nid = ent->nid;
        token->seq = ent->seq;
        token->master = __master_magic__;

        sy_spin_unlock(&ent->lock);

        return 0;
err_lock:
        sy_spin_unlock(&ent->lock);
err_ret:
        return ret;
}

static int __mds_lease_new__(lease_entry_t **_ent, const chkid_t *chkid,
                             const nid_t *nid, ltoken_t *token)
{
        int ret;
        lease_entry_t *ent;

        ret = ymalloc((void **)&ent, sizeof(*ent));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent->nid = *nid;
        ent->chkid = *chkid;
        ent->time = gettime();
        ent->seq = ++__lease_seq__;

        token->seq = ent->seq;
        token->master = __master_magic__;
        
        ret = sy_spin_init(&ent->lock);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        DBUG("new lease "CHKID_FORMAT" @ %s, token (0x%x, %ju)\n",
              CHKID_ARG(&ent->chkid), network_rname(nid), token->master, token->seq);

        *_ent = ent;
        
        return 0;
err_ret:
        return ret;
}

static int __mds_lease_new(mds_lease_t *mds_lease, const chkid_t *chkid,
                           const nid_t *nid, ltoken_t *token)
{
        int ret;
        lease_entry_t *ent;

        ret = sy_rwlock_wrlock(&mds_lease->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(mds_lease->tab, (void *)chkid);
        if (unlikely(ent)) {
                ret = EEXIST;
                GOTO(err_lock, ret);
        }

        ret = __mds_lease_new__(&ent, chkid, nid, token);
        if (unlikely(ret))
                GOTO(err_lock, ret);
        
        ret = htab_insert(mds_lease->tab, (void *)ent, &ent->chkid, 0);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        sy_rwlock_unlock(&mds_lease->lock);

        return 0;
err_lock:
        sy_rwlock_unlock(&mds_lease->lock);
err_ret:
        return ret;
}

int mds_lease_set(const chkid_t *chkid, const nid_t *nid, ltoken_t *token)
{
        int ret;
        lease_entry_t *ent;
        mds_lease_t *mds_lease;

        DBUG(""CHKID_FORMAT" new @ %s\n", CHKID_ARG(chkid), network_rname(nid));

        if (__inited__ == 0) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        ret = __lease_uptime_check();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mds_lease = &__mds_lease__[chkid->id % MDS_LEASE_HASH];
retry:
        ret = sy_rwlock_rdlock(&mds_lease->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(mds_lease->tab, (void *)chkid);
        if (ent) {
                ret = __mds_lease_set(ent, nid, token);
                if (unlikely(ret))
                        GOTO(err_lock, ret);
        } else {
                sy_rwlock_unlock(&mds_lease->lock);
                
                ret = __mds_lease_new(mds_lease, chkid, nid, token);
                if (unlikely(ret)) {
                        if (ret == EEXIST) { 
                                DWARN(""CHKID_FORMAT" new @ %s, exist\n",
                                      CHKID_ARG(chkid), network_rname(nid));
                                goto retry;
                        } else {
                                GOTO(err_ret, ret);
                        }
                }

                goto out;
        }

        sy_rwlock_unlock(&mds_lease->lock);
out:
        return 0;
err_lock:
        sy_rwlock_unlock(&mds_lease->lock);
err_ret:
        return ret;
}

int mds_lease_get(const chkid_t *chkid, nid_t *nid, ltoken_t *token)
{
        int ret;
        lease_entry_t *ent;
        mds_lease_t *mds_lease;

        DBUG(""CHKID_FORMAT" get\n", CHKID_ARG(chkid));

        if (__inited__ == 0) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }

        ret = __lease_uptime_check();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        mds_lease = &__mds_lease__[chkid->id % MDS_LEASE_HASH];
        ret = sy_rwlock_rdlock(&mds_lease->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent = htab_find(mds_lease->tab, (void *)chkid);
        if (ent) {
                ret = __mds_lease_get(ent, nid, token);
                if (unlikely(ret)) {
                        GOTO(err_lock, ret);
                }
        } else {
                ret = ENOKEY;
                GOTO(err_lock, ret);
        }
        
        sy_rwlock_unlock(&mds_lease->lock);

        return 0;
err_lock:
        sy_rwlock_unlock(&mds_lease->lock);
err_ret:
        return ret;
}

int mds_lease_free(const chkid_t *chkid, const nid_t *nid)
{
        int ret;

        DBUG(""CHKID_FORMAT" free @ %s\n", CHKID_ARG(chkid),
             network_rname(nid));

        if (__inited__ == 0) {
                ret = EAGAIN;
                GOTO(err_ret, ret);
        }
        
        ret = __lease_uptime_check();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;        
err_ret:
        return ret;
}


static int __mds_lease_destroy(mds_lease_t *mds_lease)
{
        int ret;

        ret = sy_rwlock_wrlock(&mds_lease->lock);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        htab_destroy(mds_lease->tab, NULL, NULL);
        mds_lease->tab = NULL;
        
        sy_rwlock_unlock(&mds_lease->lock);

        return 0;
err_ret:
        UNIMPLEMENTED(__DUMP__);
        return ret;
}

int mds_lease_destroy()
{
        int i;
        mds_lease_t *mds_lease = __mds_lease__;

        YASSERT(__inited__);
        __mds_lease__ = NULL;
        __inited__ = 0;


        for (i = 0; i < MDS_LEASE_HASH; i++) {
                __mds_lease_destroy(&mds_lease[i]);
        }

        yfree((void **)&mds_lease);
        
        return 0;
}
