

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
#include "md_lib.h"

void show_help(char *prog)
{
        fprintf(stderr, "%s [-v] path\n", prog);
        fprintf(stderr, "%s (id)_v(version) -s idx:available\n", prog);
}

void chkinfo2str(const chkinfo_t *chkinfo, char *buf)
{
        int ret, i, tmo;
        const char *stat;
        const reploc_t *diskid;

        snprintf(buf, MAX_BUF_LEN, "chunk "CHKID_FORMAT" info_version %llu @ ",
                 CHKID_ARG(&chkinfo->chkid), (LLU)chkinfo->md_version);

        for (i = 0; i < (int)chkinfo->repnum; ++i) {
                diskid = &chkinfo->diskid[i];

                tmo = ng.daemon ? 0 : 1;
                ret = disk_connect(&diskid->id, NULL, tmo, 0);
                if (ret) {
                        stat = "offline";
                } else if (diskid->status == __S_DIRTY) {
                        stat = "dirty";
                } else {
                        stat = "clean";
                }

                snprintf(buf + strlen(buf), MAX_NAME_LEN, "%s:%s ",
                         disk_rname(&diskid->id), stat);
        }
}



static void __chkstat_sub(void *_volume, void *_chkinfo)
{
        (void) _volume;
        const chkinfo_t *chkinfo = _chkinfo;
        char buf[MAX_BUF_LEN];

        chkinfo2str(chkinfo, buf);
        printf("    %s\n", buf);
}


static void __chkstat_file__(void *_volume, void *_chkinfo)
{
        volume_t *volume = _volume;
        const chkinfo_t *chkinfo = _chkinfo;
        char buf[MAX_BUF_LEN];

        chkinfo2str(chkinfo, buf);
        printf("  %s\n", buf);
        
        volume_chunk_iterator(volume, &chkinfo->chkid, __chkstat_sub, volume);
}

static int __chkstat_file(const fileid_t *fileid)
{
        int ret;
        volume_t *volume;
        chkinfo_t *chkinfo;
        char _chkinfo[CHKINFO_MAX];
        char buf[MAX_BUF_LEN];

        chkinfo = (void *)_chkinfo;
        ret = md_chunk_load(fileid, chkinfo);
        if (ret)
                GOTO(err_ret, ret);

        chkinfo2str(chkinfo, buf);
        printf("%s\n", buf);
        
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
        
        dbg_info(0);

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

#if 0
	cid2fid(&fileid, &chkid);
        md = (void *)buf;
        ret = md_getattr(&fileid, (void *)md);
        if (ret)
                GOTO(err_ret, ret);

        MD2STAT(md, &stbuf);

#if 0
        if (S_ISREG((stbuf).st_mode)) {
                ret = sdfs_getattr(NULL, &fileid, &stbuf);
                if (ret) {
                        size = 0;
                } else {
                        size = stbuf.st_size;
                }
        }
#endif

        if (S_ISDIR((stbuf).st_mode)) {
                printf("fileid "FID_FORMAT"\n", FID_ARG(&fileid));
                goto out;       /* not file */
        }

	if (set) {
		ret = sscanf(set, "%d:%d", &idx, &available);
		if (ret != 2) {
                        ret = EINVAL;
                        GOTO(err_ret, ret);
                }

                chkinfo = (void *)buf1;
                ret = md_chkload(chkinfo, &chkid, NULL);
                if (ret)
                        GOTO(err_ret, ret);

                ret = md_chkavailable(NULL, &chkid, &chkinfo->diskid[idx], available);
                if (ret)
                        GOTO(err_ret, ret);

		ret = raw_printfile(&fileid, chkid.idx);
		if (ret)
			GOTO(err_ret, ret);
	} else {
		ret = raw_printfile(&fileid, chkid.idx);
		if (ret)
			GOTO(err_ret, ret);
	}
#endif

        return 0;
err_ret:
        return ret;
}
