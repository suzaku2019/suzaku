#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define DBG_SUBSYS S_YFSLIB

#include "sdfs_id.h"
#include "md_lib.h"
#include "chk_proto.h"
#include "network.h"
#include "net_global.h"
#include "chk_proto.h"
#include "job_dock.h"
#include "ylib.h"
#include "net_global.h"
#include "redis.h"
#include "sdfs_lib.h"
#include "sdfs_chunk.h"
#include "network.h"
#include "cds_rpc.h"
#include "main_loop.h"
#include "md_proto.h"
#include "dbg.h"

int sdfs_chunk_recovery(const chkid_t *chkid)
{
        (void) chkid;
        UNIMPLEMENTED(__DUMP__);

        return 0;
}

int sdfs_chunk_check(const chkid_t *chkid)
{
        int ret, i;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_SIZE(YFS_CHK_REP_MAX)];
        reploc_t *reploc;

        chkinfo = (void *)_chkinfo;
        ret = md_chunk_load(chkid, chkinfo, NULL);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        for (i = 0; i < (int)chkinfo->repnum; i++) {
                reploc = &chkinfo->diskid[i];

                if (reploc->status & __S_DIRTY) {
                        ret = EAGAIN;
                        GOTO(err_ret, ret);
                }

                ret = network_connect(&reploc->id, NULL, 1, 0);
                if (unlikely(ret))
                        GOTO(err_ret, ret);
        }
        
        return 0;
err_ret:
        return ret;
}
