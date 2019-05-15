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

STATIC void __disk_wait_check__(void *_arg)
{
        int ret;
        arg_t *arg = _arg;
        chkid_t *chkid = &arg->chkid;
        wlist_t *wlist;
        struct list_head *pos, *n;
        entry_t *ent = arg->entry;

        DINFO("core[%d][%d] write "CHKID_FORMAT" clock %ju check\n",
              arg->task.scheduleid, arg->task.taskid,
              CHKID_ARG(chkid), arg->vclock.clock);

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                UNIMPLEMENTED(__DUMP__);

        list_for_each_safe(pos, n, &ent->wlist) {
                wlist = (void *)pos;
                if (arg->vclock.clock == wlist->vclock.clock
                    && arg->sessid == wlist->sessid) {
                        if ((int)(gettime() - wlist->begin) > gloconf.rpc_timeout) {
                                DERROR("core[%d][%d] write "CHKID_FORMAT" clock %ju reset\n",
                                       wlist->task.scheduleid, wlist->task.taskid,
                                       CHKID_ARG(chkid), arg->vclock.clock);
                                list_del_init(&wlist->hook);
                                schedule_resume(&wlist->task, ETIME, NULL);
                                break;
                        }
                }
        }

        sy_spin_unlock(&ent->spin);

        mem_cache_free(MEM_CACHE_4K, _arg);

        return;
}
                       
                        
STATIC void __disk_wait_check(void *_args)
{
        wlist_t *wlist = _args;
        arg_t *arg = mem_cache_calloc1(MEM_CACHE_4K, 0);

        arg->task = wlist->task;
        arg->chkid = wlist->chkid;
        arg->sessid = wlist->sessid;
        arg->vclock.clock = wlist->vclock.clock;
        arg->entry = wlist->entry;

        schedule_task_new("disk_wait_check", __disk_wait_check__, arg, -1);
}

static int __disk_write_wait(entry_t *ent, const io_t *io)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (unlikely(io->vclock.clock <= ent->vclock.clock)) {
                ret = EINVAL;
                GOTO(err_lock, ret);
        } else if (io->vclock.clock == ent->vclock.clock + 1) {
                sy_spin_unlock(&ent->spin);
                goto out;
        }

        wlist_t wlist;
        wlist.vclock = io->vclock;
        wlist.chkid = io->id;
        wlist.sessid = io->sessid;
        wlist.begin = gettime();
        wlist.task = schedule_task_get();
        wlist.entry = ent;
        list_add_tail(&wlist.hook, &ent->wlist);

        sy_spin_unlock(&ent->spin);

        DINFO("write "CHKID_FORMAT" clock %ju wait\n",
             CHKID_ARG(&io->id), io->vclock.clock);

        ret = schedule_yield1("write_wait_clock", NULL, &wlist,
                              __disk_wait_check, 2);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        DINFO("write "CHKID_FORMAT" clock %ju resume\n",
             CHKID_ARG(&io->id), io->vclock.clock);
        
out:
        return 0;
err_lock:
        sy_spin_unlock(&ent->spin);
err_ret:
        return ret;
}

static void  __disk_clock(const chkid_t *chkid, const vclock_t *vclock, int dirty)
{
        (void) chkid;
        (void) vclock;
        (void) dirty;

        UNIMPLEMENTED(__WARN__);
}

static int IO_FUNC __disk_pre_write(entry_t *ent, const io_t *io)
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

        if (unlikely(io->vclock.clock <= ent->vclock.clock)) {
                DWARN("chunk "CHKID_FORMAT", clock %ju:%ju\n",
                      CHKID_ARG(&ent->chkid), ent->vclock.clock, io->vclock.clock);
                ret = EINVAL;
                GOTO(err_lock, ret);
        } else if (unlikely(io->vclock.clock > ent->vclock.clock + 1)) {
                sy_spin_unlock(&ent->spin);
                ret = __disk_write_wait(ent, io);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

                goto retry;
        }
        
        YASSERT(io->vclock.clock == ent->vclock.clock + 1);
        ent->vclock = io->vclock;
        ent->writing++;
        YASSERT(ent->writing < 1024);

        __disk_clock(&ent->chkid, &io->vclock, 1);

        sy_spin_unlock(&ent->spin);

        return 0;
err_lock:
        sy_spin_unlock(&ent->spin);
err_ret:
        return ret;
}

static void IO_FUNC __disk_post_clock(entry_t *ent)
{
        struct list_head *pos, *n;
        wlist_t *wlist;

        list_for_each_safe(pos, n, &ent->wlist) {
                wlist = (void *)pos;
                DINFO("chunk "CHKID_FORMAT", clock %ju:%ju\n",
                      CHKID_ARG(&ent->chkid), ent->vclock.clock, wlist->vclock.clock);
                if (wlist->vclock.clock < ent->vclock.clock) {
                        list_del(pos);
                        DWARN("chunk "CHKID_FORMAT", clock %ju:%ju\n",
                              CHKID_ARG(&ent->chkid), ent->vclock.clock, wlist->vclock.clock);
                        schedule_resume(&wlist->task, ESTALE, NULL);
                } else if (wlist->vclock.clock == ent->vclock.clock + 1) {
                        list_del(pos);
                        schedule_resume(&wlist->task, 0, NULL);
                }
        }
}

static int IO_FUNC __disk_post_write(entry_t *ent, const io_t *io)
{
        int ret;

        ret = sy_spin_lock(&ent->spin);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ent->writing--;

        __disk_clock(&ent->chkid, &io->vclock, 0);
        __disk_post_clock(ent);

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

static int IO_FUNC __disk_write__(disk_t *disk, const io_t *io, const buffer_t *buf)
{
        int ret;
        entry_t *ent;

        ret = disk_ref(disk, &io->id, &ent);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = plock_rdlock(&ent->plock);
        if (unlikely(ret))
                GOTO(err_ref, ret);

        ret = __disk_pre_write(ent, io);
        if (unlikely(ret))
                GOTO(err_lock, ret);

        ret = disk->write(disk, ent, io, buf);
        if (unlikely(ret))
                GOTO(err_reset, ret);
        
        ret = __disk_post_write(ent, io);
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

int IO_FUNC disk_io_write(const diskid_t *diskid, const io_t *io, const buffer_t *buf)
{
        int ret, idx;
        disk_t *disk;

        ret = disk2idx(diskid, &idx);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = disk_slot_private_ref(idx, &disk);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __disk_write__(disk, io, buf);
        if (unlikely(ret))
                GOTO(err_ref, ret);
        
        disk_slot_private_deref(idx);

        return 0;
err_ref:
        disk_slot_private_deref(idx);
err_ret:
        return ret;
}
