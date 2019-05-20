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
#include "variable.h"
#include "core.h"
#include "dbg.h"

typedef disk_entry_t entry_t;

static int IO_FUNC __disk_io_create(const diskid_t *diskid, const chkid_t *chkid,
                                    uint32_t size, int initzero)
{
        int ret, idx;
        disk_t *disk;

        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = disk->create(disk, chkid, size, initzero);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}

int IO_FUNC __disk_io_create_va(va_list ap)
{
        const diskid_t *diskid = va_arg(ap, const diskid_t *);
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        uint32_t size = va_arg(ap, uint32_t);
        int initzero = va_arg(ap, int);

        va_end(ap);
        
        return __disk_io_create(diskid, chkid, size, initzero);
}


int disk_io_create(const diskid_t *diskid, const chkid_t *chkid, uint32_t size,
                   int initzero)
{
        int ret;

        if (likely(core_self())) {
                ret = __disk_io_create(diskid, chkid, size, initzero);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = core_request(core_hash(chkid), -1, "disk_io_create",
                                   __disk_io_create_va, diskid, chkid, size, initzero);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int IO_FUNC __disk_io_connect__(disk_t *disk, const nid_t *nid, const chkid_t *chkid,
                                       const ltoken_t *ltoken, uint32_t sessid,
                                       clockstat_t *clockstat, int resuse)
{
        int ret;
        entry_t *ent;

        (void) ltoken;

        memset(clockstat, 0x0, sizeof(*clockstat));

        ret = disk_ref(disk, chkid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        if (ent->writing) {
                ret = EBUSY;
                GOTO(err_lock, ret);
        }

        if (resuse) {
                if (ent->sessid != sessid) {
                        ret = EPERM;
                        GOTO(err_lock, ret);
                }
        } else {
                ent->sessid = sessid;
        }

        ent->owner = *nid;
        clockstat->vclock = ent->vclock;

        plock_unlock(&ent->plock);
        disk_deref(disk, ent);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ref:
        disk_deref(disk, ent);
err_ret:
        return ret;
}

static int IO_FUNC __disk_io_connect(const nid_t *nid, const diskid_t *diskid,
                                     const chkid_t *chkid,
                                     const ltoken_t *ltoken, uint32_t sessid,
                                     clockstat_t *clockstat, int resuse)
{
        int ret, idx;
        disk_t *disk;
        
        (void) chkid;
        (void) diskid;
        
        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = __disk_io_connect__(disk, nid, chkid, ltoken, sessid, clockstat, resuse);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        DINFO("connect "CHKID_FORMAT" @ %d sessid %o, clock (%ju, %ju), resuse %d\n",
              CHKID_ARG(chkid), idx, sessid, clockstat->vclock.vfm,
              clockstat->vclock.clock, resuse);
        
        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}

int IO_FUNC __disk_io_connect_va(va_list ap)
{
        const nid_t *nid = va_arg(ap, const nid_t *);
        const diskid_t *diskid = va_arg(ap, const diskid_t *);
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        const ltoken_t *ltoken = va_arg(ap, const ltoken_t *);
        uint32_t sessid = va_arg(ap, uint32_t);
        clockstat_t *clockstat = va_arg(ap, clockstat_t *);
        int resuse = va_arg(ap, int);

        va_end(ap);
        
        return __disk_io_connect(nid, diskid, chkid, ltoken, sessid,
                                 clockstat, resuse);
}


int disk_io_connect(const nid_t *nid, const diskid_t *diskid, const chkid_t *chkid,
                    const ltoken_t *ltoken, uint32_t sessid,
                    clockstat_t *clockstat, int resuse)
{
        int ret;

        if (likely(core_self())) {
                ret = __disk_io_connect(nid, diskid, chkid, ltoken, sessid,
                                        clockstat, resuse);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = core_request(core_hash(chkid), -1, "disk_io_connect",
                                   __disk_io_connect_va, nid, diskid, chkid,
                                   ltoken, sessid, clockstat, resuse);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

static int IO_FUNC __disk_io_getclock__(disk_t *disk, const chkid_t *chkid,
                                       clockstat_t *clockstat)
{
        int ret;
        entry_t *ent;

        memset(clockstat, 0x0, sizeof(*clockstat));

        ret = disk_ref(disk, chkid, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_wrlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        if (ent->writing) {
                ret = EBUSY;
                GOTO(err_lock, ret);
        }

        clockstat->vclock = ent->vclock;

        plock_unlock(&ent->plock);
        disk_deref(disk, ent);
        
        return 0;
err_lock:
        plock_unlock(&ent->plock);
err_ref:
        disk_deref(disk, ent);
err_ret:
        return ret;
}

int IO_FUNC disk_io_getclock(const diskid_t *diskid, const chkid_t *chkid,
                             clockstat_t *clockstat)
{
        int ret, idx;
        disk_t *disk;
        
        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = __disk_io_getclock__(disk, chkid, clockstat);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        DINFO("getclock "CHKID_FORMAT" @ %d clock (%ju, %ju), resuse %d\n",
              CHKID_ARG(chkid), idx, clockstat->vclock.vfm,
              clockstat->vclock.clock);
        
        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}
