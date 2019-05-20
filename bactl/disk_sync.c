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
#include "schedule.h"
#include "core.h"
#include "adt.h"
#include "dbg.h"

typedef struct {
        task_t task;
        vclock_t vclock;
        uint32_t sessid;
        chkid_t chkid;
        void *entry;
} arg_t;

typedef disk_entry_t entry_t;

static void  __disk_clock(const chkid_t *chkid, const vclock_t *vclock, int dirty)
{
        (void) chkid;
        (void) vclock;
        (void) dirty;

        UNIMPLEMENTED(__WARN__);
}

static int IO_FUNC __disk_pre_sync(entry_t *ent, const io_t *io)
{
        int ret;

#if 0
        if (unlikely(ent->sessid != io->sessid)) {
                DWARN("chunk "CHKID_FORMAT", sessid %x:%x\n",
                      CHKID_ARG(&ent->chkid), ent->sessid, io->sessid);
                ret = ESTALE;
                GOTO(err_ret, ret);
        }
#endif

        if (ent->writing) {
                ret = EBUSY;
                GOTO(err_ret, ret);
        }
        
        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent->vclock = io->vclock;
        ent->writing++;
        YASSERT(ent->writing < 1024);

        __disk_clock(&ent->chkid, &io->vclock, 1);

        sy_spin_unlock(&ent->spin);

        return 0;
err_ret:
        return ret;
}

static int IO_FUNC __disk_post_sync(entry_t *ent, const io_t *io)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent->writing--;

        __disk_clock(&ent->chkid, &io->vclock, 0);

        if (ent->sessid != io->sessid) {
                ret = ESTALE;
                GOTO(err_lock, ret);
        }
        
        sy_spin_unlock(&ent->spin);

        return 0;
err_lock:
        sy_spin_unlock(&ent->spin);
err_ret:
        return ret;
}

static int IO_FUNC __disk_sync__(disk_t *disk, const io_t *io, const buffer_t *buf)
{
        int ret;
        entry_t *ent;

        ret = disk_ref(disk, &io->id, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = __disk_pre_sync(ent, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = disk->write(disk, ent, io, buf);
        if (unlikely(ret))
                GOTO(err_reset, ret);
        
        ret = __disk_post_sync(ent, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        plock_unlock(&ent->plock);
        disk_deref(disk, ent);
        
        return 0;
err_reset:
        UNIMPLEMENTED(__DUMP__);
err_lock:
        plock_unlock(&ent->plock);
err_ref:
        disk_deref(disk, ent);
err_ret:
        return ret;
}

int IO_FUNC disk_io_sync(const diskid_t *diskid, const io_t *io, const buffer_t *buf)
{
        int ret, idx;
        disk_t *disk;

        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __disk_sync__(disk, io, buf);
        if (unlikely(ret))
                GOTO(err_ref, ret);
        
        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}
