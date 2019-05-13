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
#include "schedule.h"
#include "variable.h"
#include "core.h"
#include "dbg.h"

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

static int IO_FUNC __disk_io_connect(const diskid_t *diskid, const chkid_t *chkid,
                                     const ltoken_t *ltoken, uint32_t sessid,
                                     clockstat_t *clockstat, int force)
{
        (void) chkid;
        (void) ltoken;
        (void) sessid;
        (void) force;
        (void) diskid;

        UNIMPLEMENTED(__WARN__);
        
        memset(clockstat, 0x0, sizeof(*clockstat));
        
        return 0;
}

int IO_FUNC __disk_io_connect_va(va_list ap)
{
        const diskid_t *diskid = va_arg(ap, const diskid_t *);
        const chkid_t *chkid = va_arg(ap, const chkid_t *);
        const ltoken_t *ltoken = va_arg(ap, const ltoken_t *);
        uint32_t sessid = va_arg(ap, uint32_t);
        clockstat_t *clockstat = va_arg(ap, clockstat_t *);
        int force = va_arg(ap, int);

        va_end(ap);
        
        return __disk_io_connect(diskid, chkid, ltoken, sessid,
                                 clockstat, force);
}


int disk_io_connect(const diskid_t *diskid, const chkid_t *chkid,
                    const ltoken_t *ltoken, uint32_t sessid,
                    clockstat_t *clockstat, int force)
{
        int ret;

        if (likely(core_self())) {
                ret = __disk_io_connect(diskid, chkid, ltoken, sessid,
                                        clockstat, force);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                ret = core_request(core_hash(chkid), -1, "disk_io_connect",
                                   __disk_io_connect_va, diskid, chkid,
                                   ltoken, sessid, clockstat, force);
                if (ret)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}
