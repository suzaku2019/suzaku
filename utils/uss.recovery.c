

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "configure.h"
#include "sdfs_lib.h"
#include "volume.h"
#include "disk.h"
#include "range.h"
#include "diskmap.h"
#include "mds_rpc.h"
#include "md_lib.h"

void show_help(char *prog)
{
        fprintf(stderr, "%s [-v] path\n", prog);
        fprintf(stderr, "%s (id)_v(version) -s idx:available\n", prog);
}

static int __chunk_recovery__(const chkid_t *chkid)
{
        if (chkid->type == ftype_raw) {
                return range_chunk_recovery(chkid);
        } else {
                return mds_rpc_recovery(chkid);
        }
}

static void __chunk_recovery(const chkinfo_t *chkinfo)
{
#if 0
        __chunk_recovery__(&chkinfo->chkid);
        return;
#endif
        
        for (int i = 0; i < (int)chkinfo->repnum; i++) {
                const reploc_t *reploc = &chkinfo->diskid[i];

                if (reploc->status) {
                        __chunk_recovery__(&chkinfo->chkid);
                        break;
                }

                if (unlikely(!disktab_online(&reploc->id))) {
                        __chunk_recovery__(&chkinfo->chkid);
                        break;
                }
        }
}

static void __chkstat_sub(void *_volume, void *_chkinfo)
{
        (void) _volume;

        __chunk_recovery(_chkinfo);
}
        

static void __chkstat_file__(void *_volume, void *_chkinfo)
{
        volume_t *volume = _volume;
        chkinfo_t *chkinfo = _chkinfo;

        __chunk_recovery(_chkinfo);
        
        volume_chunk_iterator(volume, &chkinfo->chkid, __chkstat_sub, volume);
}

static int __chkstat_file(const fileid_t *fileid)
{
        int ret;
        volume_t *volume;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];

        chkinfo = (void *)_chkinfo;
        ret = md_chunk_load(fileid, chkinfo, NULL);
        if (ret)
                GOTO(err_ret, ret);

        __chunk_recovery(chkinfo);
        
        ret = volume_open(&volume, fileid);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = volume_chunk_iterator(volume, fileid, __chkstat_file__, volume);
        if (ret)
                GOTO(err_free, ret);

        volume_close(&volume);
        
        return 0;
err_free:
        volume_close(&volume);
err_ret:
        return ret;
}

int main(int argc, char *argv[])
{
        int ret, args, verbose = 0;
        fileid_t chkid;
        char c_opt, *prog, *arg;

        (void) verbose;
        
        //dbg_info(0);

        prog = strrchr(argv[0], '/');
        if (prog)
                prog++;
        else
                prog = argv[0];

        args = 1;

        if (argc < 2) {
                show_help(prog);
                exit(1);
        }

        while ((c_opt = getopt(argc, argv, "vfs:")) > 0)
                switch (c_opt) {
                case 'v':
                        verbose = 1;
                        args++;
                        break;
                case 's':
                        UNIMPLEMENTED(__DUMP__);
                        args++;
                        break;
                default:
                        show_help(prog);
                        exit(1);
                }

        arg = argv[argc - 1];

        ret = conf_init(YFS_CONFIGURE_FILE);
        if (ret) {
                fprintf(stderr, "conf_init() %s\n", strerror(ret));
                exit(1);
        }

        ret = sdfs_init("chunk stat");
        if (ret)
                GOTO(err_ret, ret);

        if (arg[0] == '/') {
                ret = sdfs_lookup_recurive(arg, &chkid);
                if (ret)
                        GOTO(err_ret, ret);
        } else {
                UNIMPLEMENTED(__NULL__);
#if 0
                ret = sscanf(arg, "%ju_v%ju[%u]", &chkid.id, &chkid.volid, &chkid.idx);
                if (ret != 3) {
                        ret = EINVAL;
                        GOTO(err_ret, ret);
                }
#endif
        }

        if (chkid.type == ftype_file) {
                ret = __chkstat_file(&chkid);
                if (ret)
                        GOTO(err_ret, ret);
        } else if (chkid.type == ftype_sub) {
                UNIMPLEMENTED(__DUMP__);
        } else if (chkid.type == ftype_raw) {
                UNIMPLEMENTED(__DUMP__);
        } else {
                UNIMPLEMENTED(__DUMP__);
        }

        return 0;
err_ret:
        return ret;
}
