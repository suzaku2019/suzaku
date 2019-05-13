
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
#include "sdfs_lib.h"
#include "network.h"
#include "net_table.h"
#include "mds_rpc.h"
#include "main_loop.h"
#include "dbg.h"

int normalize_path(const char *path, char *path2)
{
        int i, len, begin, off;

        len = strlen(path);

        off = 0;
        begin = -1;
        path2[off++] = '/';
        for(i = 0; i < len; ++i) {
                if (path[i] == '/') {
                        if (begin == -1) {
                                continue;
                        }

                        strncpy(path2 + off, path + begin, i - begin);
                        off += i - begin;
                        // stop a segment
                        begin = -1;
                        path2[off++] = '/';
                } else {
                        if (begin == -1) {
                                // start a new segment
                                begin = i;
                        }
                }
        }

        if (begin != -1 && begin < i) {
                strncpy(path2 + off, path + begin, i - begin);
                off += i - begin;
        }

        path2[off] = '\0';
        return 0;
}

int __chk_locate(char *loc, const chkid_t *chkid, const diskid_t *nid)
{
        int ret, seq;
        char cpath[MAX_PATH_LEN], ip[MAX_NAME_LEN];
        const char *rname = NULL;

        rname = netable_rname_nid(nid);
        if (rname == NULL  || strlen(rname) == 0)
                return ENOENT;

        ret = sscanf(rname, "%[^:]:cds/%d", ip, &seq);
        YASSERT(ret == 2);

        (void) cascade_id2path(cpath, MAX_PATH_LEN, chkid->id);

        snprintf(loc, MAX_PATH_LEN, "%s: %s/cds/%u/disk/*%s_v%llu/%u", ip, SDFS_HOME,
                 seq, cpath, (LLU)chkid->poolid, chkid->idx);

        return 0;
}

int raw_printfile(fileid_t *fileid, uint32_t _chkno)
{
        int ret;
        uint32_t i, chkno, chknum;
        fileinfo_t *md;
        chkid_t chkid;
        chkinfo_t *chkinfo;
        char buf[MAX_BUF_LEN], buf1[MAX_BUF_LEN], loc[MAX_BUF_LEN];
        char value[MAX_BUF_LEN], key[MAX_BUF_LEN];
        fileid_t volume_dir_id;
        size_t size;

        md = (void *)buf;
        chkinfo = (void *)buf1;

        ret = md_getattr(NULL, fileid, (void *)md);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(key, MAX_BUF_LEN, USS_SYSTEM_ATTR_ENGINE);
        id2vid(fileid->poolid, &volume_dir_id);
        size = sizeof(value);
        ret = sdfs_getxattr(NULL, &volume_dir_id, key, value, &size);
        if (0 == ret) {
        }

        if (_chkno == (uint32_t)-1) {
                printf("file "FID_FORMAT" mdsize %llu chklen %u"
                       " chkrep %u \n", FID_ARG(fileid),
                       (LLU)md->md_size,
                       md->split, md->repnum);

                chknum = md->chknum;

                for (chkno = 0; chkno < chknum; chkno++) {
                        fid2cid(&chkid, &md->fileid, chkno);

                        ret = md_chkload(chkinfo, &chkid, NULL);
                        if (ret) {
                                continue;
                        }

                        printf("    chk[%u] rep %u\n",
                               chkid.idx, chkinfo->repnum);

                        for (i = 0; i < chkinfo->repnum; i++) {
                                if (__chk_locate(loc, &chkid, &chkinfo->diskid[i].id) != 0) {
                                        printf("        net[%u] nid("DISKID_FORMAT"): offline\n",
                                               i, DISKID_ARG(&chkinfo->diskid[i].id));
                                        continue;
                                } else {
                                        printf("        net[%u] nid("DISKID_FORMAT"): %s %s\n",
                                               i,
                                               DISKID_ARG(&chkinfo->diskid[i].id),
                                               loc,
                                               (chkinfo->diskid[i].status & __S_DIRTY) ?
                                               "dirty" : "available");
                                }

                        }
                }
        } else {
                fid2cid(&chkid, &md->fileid, _chkno);

                ret = md_chkload(chkinfo, &chkid, NULL);
                if (ret) {
                        DWARN("chk[%d] not exist\n", _chkno);
                        GOTO(err_ret, ret);
                }

                printf("    chk[%u] rep %u\n",
                       chkid.idx, chkinfo->repnum);

                for (i = 0; i < chkinfo->repnum; i++) {
                        if (__chk_locate(loc, &chkid, &chkinfo->diskid[i].id) != 0) {
                                printf("        net[%u] nid("DISKID_FORMAT"): offline\n", i,
                                       DISKID_ARG(&chkinfo->diskid[i].id));
                                continue;
                        } else {
                                printf("        net[%u] nid("DISKID_FORMAT"): %s, %s\n",
                                       i,
                                       DISKID_ARG(&chkinfo->diskid[i].id),
                                       loc,
                                       (chkinfo->diskid[i].status & __S_DIRTY) ? "dirty" : "available" );
                        }
                }
        }

        return 0;
err_ret:
        return ret;
}

/*
*Date   : 2017.08.14
*Author : JiangYang
*raw_realpath : only string operation, not expands symbolic link, not getwd
*    and not stat the directory, resolves references to /./, /../ and extra '/'
*    characters in the null-terminated string named by path to produce a
*    canonicalized absolute pathname. The resulting pathname  is stored as
*    a null-terminated string, up to a maximum of MAX_PATH_LEN  bytes,
*    in the buffer pointed to by resolved_path.
*    The resulting path will have no symbolic link, /./ or /../ components.
*/
char *sdfs_realpath(const char *path, char *resolved_path)
{

        char copy_path[MAX_PATH_LEN];
        char *new_path = resolved_path;
        char *max_path;

        YASSERT(NULL != path);
        YASSERT(NULL != resolved_path);

        /* Make a copy of the source path since we may need to modify it. */
        if (strlen(path) >= MAX_PATH_LEN) {
                errno = ENAMETOOLONG;
                return NULL;
        }

        strcpy(copy_path, path);
        path = copy_path;
        max_path = copy_path + MAX_PATH_LEN - 2;

        /* If it's a relative pathname use '/' for starters. */
        if (*path != '/')
                *new_path++ = '/';
        else{
                *new_path++ = '/';
                path++;
        }

        /* Expand each slash-separated pathname component. */
        while (*path != '\0') {

                /* Ignore stray "/". */
                if (*path == '/') {
                        path++;
                        continue;
                }
                if (*path == '.') {
                        /* Ignore ".". */
                        if (path[1] == '\0' || path[1] == '/') {
                                path++;
                                continue;
                        }

                        if (path[1] == '.') {
                                if (path[2] == '\0' || path[2] == '/') {
                                        path += 2;
                                        /* Ignore ".." at root. */
                                        if (new_path == resolved_path + 1)
                                                continue;
                                        /* Handle ".." by backing up. */
                                        while ((--new_path)[-1] != '/')
                                                ;
                                                continue;
                                }

                        }

                }

                /* Safely copy the next pathname component. */
                while (*path != '\0' && *path != '/') {
                        if (path > max_path) {
                                errno = ENAMETOOLONG;
                                return NULL;
                        }
                        *new_path++ = *path++;
                }
                *new_path++ = '/';
        }

        /* Delete trailing slash but don't whomp a lone slash. */
        if (new_path != resolved_path + 1 && new_path[-1] == '/')
                new_path--;

        /* Make sure it's null terminated. */
        *new_path = '\0';

        return resolved_path;
}
