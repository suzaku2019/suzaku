/*Range*/

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>

#define DBG_SUBSYS S_YFSMDS

#include "ylib.h"
#include "net_table.h"
#include "configure.h"
#include "net_global.h"
#include "mem_cache.h"
#include "yfs_md.h"
#include "pa_srv.h"
#include "plock.h"
#include "variable.h"
#include "cds_rpc.h"
#include "chunk.h"
#include "md_lib.h"
#include "partition.h"
#include "ringlock.h"
#include "range.h"
#include "chunk.h"
#include "core.h"
#include "dbg.h"

#if 1

int range_chunk_location(const chkid_t *chkid, coreid_t *coreid)
{
        return part_location(chkid, PART_FRCTL, coreid);
}

int range_init()
{
        int ret;

        ret = range_ctl_create();
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        ret = range_rpc_init();
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int range_chunk_recovery(const chkid_t *chkid)
{
        int ret;
        coreid_t coreid;

        ret = range_chunk_location(chkid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (core_islocal(&coreid)) {
                ret = range_ctl_chunk_recovery(chkid);
        } else {
                ret = range_rpc_chunk_recovery(&coreid, chkid);
        }
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

#if 0
int range_chunk_getinfo(const chkid_t *chkid, chkinfo_t *chkinfo)
{
        int ret;
        coreid_t coreid;

        ret = range_chunk_location(chkid, &coreid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (core_islocal(&coreid)) {
                ret = range_ctl_chunk_getinfo(chkid, chkinfo);
        } else {
                ret = range_rpc_chunk_getinfo(&coreid, chkid, chkinfo);
        }
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

#endif
#endif
