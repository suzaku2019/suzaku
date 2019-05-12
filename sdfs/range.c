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

int range_location(const chkid_t *chkid, coreid_t *coreid)
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

#if 0
int range_get_token(const chkid_t *chkid, int op, io_token_t *token)
{
        int ret;
        nid_t nid;

        ret = range_location(chkid, &nid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        if (net_islocal(&nid)) {
                ret = range_ctl_get_token(chkid, op, token);
        } else {
                ret = range_rpc_get_token(&nid, chkid, op, token);
        }
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
#endif

#endif
