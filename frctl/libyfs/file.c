#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSLIB

#include "md_lib.h"
#include "chk_proto.h"
#include "chk_proto.h"
#include "job_dock.h"
#include "ylib.h"
#include "net_global.h"
#include "sdfs_lib.h"
#include "dbg.h"

#define YFS_FILE_ALLOC_INC 8

#ifdef YFS_DEBUG
#define yfs_node_dump(__yn__) \
{                                                               \
        DBUG("==node info==\n");                                \
        DBUG("path_len %u\n", __yn__->path_len);                \
        DBUG("md::md_size %u\n", __yn__->md->md_size);          \
        DBUG("md::file_len %llu\n", (LLU)__yn__->md->file_len); \
        DBUG("md::chk_len %u\n", __yn__->md->chk_len);          \
        DBUG("md::chk_rep %u\n", __yn__->md->chkrep);          \
        DBUG("md::chk_num %u\n", __yn__->md->chknum);           \
}

#define yfs_chunk_dump(__chk__) \
{                                                               \
        DBUG("==chunk info==\n");                               \
        DBUG("chkid (%llu %u)\n", (LLU)__chk__->chkid.id, __chk__->chkid.version); \
        DBUG("chkno %u chkrep %u\n", __chk__->no, __chk__->rep);        \
        DBUG("chklen %u\n", __chk__->chklen);                       \
        DBUG("loaded %d\n", __chk__->loaded);                       \
}

#define yfs_file_dump(__yf__) \
{                                  \
        yfs_node_dump(__yf->node__);   \
}

#else
#define yfs_node_dump(yn) {}
#define yfs_chunk_dump(chk) {}
#define yfs_file_dump(yf) {}
#endif

#if 1
extern jobtracker_t *jobtracker;

int ly_open(const char *path)
{
        int ret;
        fileid_t fileid;

        ret = sdfs_lookup_recurive(path, &fileid);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int ly_read(const char *path, char *buf, size_t size, yfs_off_t offset)
{
        int ret;
        fileid_t fileid;
        buffer_t pack;

        ret = sdfs_lookup_recurive(path, &fileid);
        if (ret) {
                ret = -ret;
                GOTO(err_ret, ret);
        }

        mbuffer_init(&pack, 0);

        ret = sdfs_read_sync(NULL, &fileid, &pack, size, offset);
        if (ret < 0) {
                ret = -ret;
                GOTO(err_free, ret);
        }

        mbuffer_get(&pack, buf, ret);

        mbuffer_free(&pack);
        return ret;
err_free:
        mbuffer_free(&pack);
err_ret:
        return -ret;
}

int ly_create(const char *path, mode_t mode)
{
        int ret;
        fileid_t parent;
        char name[MAX_NAME_LEN];
        fileid_t fileid;
        uid_t uid;
        gid_t gid;

        ret = sdfs_splitpath(path, &parent, name);
        if (ret)
                GOTO(err_ret, ret);


        uid = geteuid();
        gid = getegid();

        DBUG("parent "FID_FORMAT" name %s\n", FID_ARG(&parent), name);
        ret = sdfs_create(NULL, &parent, name, &fileid, mode, uid , gid);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int ly_write(const char *path, const char *buf, size_t size, yfs_off_t offset)
{
        int ret;
        fileid_t fileid;
        buffer_t pack;

        ret = sdfs_lookup_recurive(path, &fileid);
        if (ret) {
                ret = -ret;
                GOTO(err_ret, ret);
        }

        mbuffer_init(&pack, 0);

        ret = mbuffer_copy(&pack, buf, size);
        if (ret) {
                ret = -ret;
                GOTO(err_free, ret);
        }

        ret = sdfs_write_sync(NULL, &fileid, &pack, size, offset);
        if (ret < 0) {
                GOTO(err_free, -ret);
        }

        mbuffer_free(&pack);
        return ret;
err_free:
        mbuffer_free(&pack);
err_ret:
        return ret;
}

int ly_truncate(const char *path, off_t length)
{
        int ret;
        fileid_t fileid;

        ret = sdfs_lookup_recurive(path, &fileid);
        if (ret)
                GOTO(err_ret, ret);

        ret = sdfs_truncate(NULL, &fileid, length);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

#endif
