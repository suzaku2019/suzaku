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

#include "yfs_conf.h"
#include "yfscds_conf.h"
#include "chk_meta.h"
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
#include "cds_hb.h"
#include "net_global.h"
#include "nodeid.h"
#include "mds_rpc.h"
#include "mem_cache.h"
#include "adt.h"
#include "core.h"
#include "schedule.h"
#include "dbg.h"

typedef disk_entry_t entry_t;

static int __disk_read_wait(entry_t *ent, const io_t *io)
{
        (void) ent;
        (void) io;

        UNIMPLEMENTED(__DUMP__);

        return 0;
}


static int IO_FUNC __disk_pre_read(entry_t *ent, const io_t *io)
{
        int ret;

        if (unlikely(ent->sessid != io->sessid)) {
                DWARN("chunk "CHKID_FORMAT", sessid %x:%x\n",
                      CHKID_ARG(&ent->chkid), ent->sessid, io->sessid);
                ret = ESTALE;
                GOTO(err_ret, ret);
        }

retry:
        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(io->vclock.clock > ent->vclock.clock)) {
                DWARN("chunk "CHKID_FORMAT", clock %ju:%ju\n",
                      CHKID_ARG(&ent->chkid), ent->vclock.clock, io->vclock.clock);
                sy_spin_unlock(&ent->spin);
                ret = __disk_read_wait(ent, io);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                goto retry;
        }
        
        sy_spin_unlock(&ent->spin);

        return 0;
err_ret:
        return ret;
}

static int IO_FUNC __disk_post_read(entry_t *ent, const io_t *io)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

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

static int IO_FUNC __disk_read__(disk_t *disk, const io_t *io, buffer_t *buf)
{
        int ret;
        entry_t *ent;

        ret = disk_ref(disk, &io->id, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = __disk_pre_read(ent, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = disk->read(disk, ent, io, buf);
        if (unlikely(ret))
                GOTO(err_reset, ret);
        
        ret = __disk_post_read(ent, io);
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

static int IO_FUNC __disk_read(const diskid_t *diskid, const io_t *io, buffer_t *buf)
{
        int ret, idx;
        disk_t *disk;

        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __disk_read__(disk, io, buf);
        if (unlikely(ret))
                GOTO(err_ref, ret);
        
        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}

int IO_FUNC __disk_read_va(va_list ap)
{
        const diskid_t *diskid = va_arg(ap, const diskid_t *);
        const io_t *io = va_arg(ap, const io_t *);
        buffer_t*buf = va_arg(ap, buffer_t *);

        va_end(ap);
        
        return __disk_read(diskid, io, buf);
}


int IO_FUNC disk_io_read(const diskid_t *diskid, const io_t *io, buffer_t *buf)
{
        int ret;

        if (likely(core_self())) {
                ret = __disk_read(diskid, io, buf);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = core_request(core_hash(&io->id), -1, "disk_write",
                                   __disk_read_va, diskid, io, buf);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

