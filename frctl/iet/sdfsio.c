#define DBG_SUBSYS S_YISCSI

#include "iscsi.h"
#include "volume.h"
#include "net_global.h"
#include "schedule.h"
#include "dbg.h"

struct sdfsio_data {
        fileid_t fileid;
};

STATIC int __sdfsio_connect(struct iscsi_volume *volume, struct sdfs_lun_entry *lu)
{
        int ret;
        lichbd_ioctx_t *ioctx;

        ret = ymalloc((void **)&ioctx, sizeof(*ioctx));
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ioctx->fileid = lu->fileid;
        volume->private = ioctx;

        return 0;
err_ret:
        return ret;
}

STATIC void __sdfsio_disconnect(struct iscsi_volume *volume)
{

        struct sdfsio_data *priv = volume->private;
        fileid_t *fileid;

        (void) fileid;

        fileid = &priv->fileid;

        DINFO("detach %s/%u\n", volume->tname, volume->lun);

        free(priv);
        volume->private = NULL;

        return;
}

STATIC int __sdfsio_attach(struct iscsi_volume *volume, void *entry)
{
        int ret;
        struct sdfs_lun_entry *lu;

        if (unlikely(volume->private)) {
                ret = EBUSY;
                GOTO(err_ret, ret);
        }

        ret = __sdfsio_connect(volume, entry);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        struct iscsi_target *target = volume->target;
        ret = volume_open(&target->volume, &target->fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
        
        /**
         * Block size shift
         *       9 -> 512
         *      12 -> 4096
         */
        lu = entry;
        if (unlikely(lu->blk_shift != 9 && lu->blk_shift != 12)) {
                DWARN("invalid block shift %d\n", lu->blk_shift);
                YASSERT(0);
        }

        volume->blk_shift = lu->blk_shift;
        volume->blk_cnt   = (u64)(lu->blk_size >> volume->blk_shift);
        volume->blk_size  = lu->blk_size;

        /*
         * Set Logic Unit Attribute Feature
         */
#if 0
        SetLURCache(volume);
        SetLUWCache(volume);
        SetLUReadonly(volume);
#endif

        DINFO("attach %s/%u (size: %llu bytes)(block: %u bytes)\n",
              volume->tname, volume->lun,
              (LLU)(lu->blk_size), (1 << volume->blk_shift));

        return 0;
err_ret:
        return ret;
}

STATIC int __sdfsio_update(struct iscsi_volume *volume, void *entry)
{
        struct sdfs_lun_entry *lu;

        lu = entry;

        /**
         * Block size shift
         *       9 -> 512
         *      12 -> 4096
         */
        if (lu->blk_shift != 9 && lu->blk_shift != 12) {
                DWARN("invalid block shift %d\n", lu->blk_shift);
                YASSERT(0);
        }

        volume->blk_shift = lu->blk_shift;
        volume->blk_cnt   = (u64)(lu->blk_size >> volume->blk_shift);
        volume->blk_size  = lu->blk_size;

        /*
         * Set Logic Unit Attribute Feature
         */
#if 0
        SetLURCache(volume);
        SetLUWCache(volume);
        SetLUReadonly(volume);
#endif

        DINFO("update %s/%u (size: %llu bytes)(block: %u bytes)\n",
              volume->tname, volume->lun,
              (LLU)(lu->blk_size), (1 << volume->blk_shift));

        return 0;
}

STATIC int __sdfsio_io_read__(struct iscsi_cmd *cmd)
{
        int ret;
        

        if (unlikely(cmd->conn->state == STATE_CLOSE)) {
                DINFO("conn close, read "CHKID_FORMAT" (%llu, %llu)\n",
                      CHKID_ARG(&cmd->ioctx->fileid),
                      (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        struct iscsi_target *target = cmd->lun->target;
        volume_t *volume = target->volume;
        ret = volume_read(volume, &cmd->tio->buffer,
                          cmd->tio->io_len, cmd->tio->io_off);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

STATIC int __sdfsio_io_read(struct iscsi_cmd *cmd)
{
        int ret, retry = 0;
        time_t begin = gettime();

        ANALYSIS_BEGIN(0);
        
        schedule_task_setname("iscsi_read");

        YASSERT(cmd->tio->buffer.len == 0);
        //	YASSERT(cmd->tio->buffer.list.next == &cmd->tio->buffer.list);
        DBUG("iscsi_lsv read %llu %llu\n", (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);

        if (unlikely(cmd->tio->io_off + cmd->tio->io_len > cmd->lun->blk_size)) {
                ret = EIO;
                GOTO(err_ret, ret);
        }

        cmd->ioctx = cmd->lun->private;

#if ISCSI_IO_RECORD
        DINFO("begin read, iscsi io record read "CHKID_FORMAT" (%llu, %llu)\n",
                        CHKID_ARG(&cmd->ioctx->fileid),
                        (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
#endif

retry:
        if (unlikely(cmd->conn->state == STATE_CLOSE || cmd->conn->state == STATE_CLOSED)) {
                DINFO("conn close, read "CHKID_FORMAT" (%llu, %llu)\n",
                                CHKID_ARG(&cmd->ioctx->fileid),
                                (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        ret = __sdfsio_io_read__(cmd);
        if (unlikely(ret)) {
                ret = _errno(ret);
                if (retry < 1000 && (ret == EAGAIN || ret == ENOSPC)
                                && ((gettime() - begin) < gloconf.rpc_timeout + 20)) {
                        if (retry > 100) {
                                DINFO("read "CHKID_FORMAT" (%llu, %llu),"
                                      " ret (%d) %s, need retry %u\n",
                                      CHKID_ARG(&cmd->ioctx->fileid),
                                      (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len,
                                      ret, strerror(ret), retry);
                        }

                        retry++;
                        schedule_sleep("iscsi_read", 1000 * 100);
                        goto retry;
                } else if (ret == EPERM || ret == ESHUTDOWN) {
                        if (cmd->conn->state != STATE_CLOSE && cmd->conn->state != STATE_CLOSED)
                                cmd->conn->state = STATE_CLOSE;
                        DERROR("conn close, read "CHKID_FORMAT" (%llu, %llu)\n",
                                        CHKID_ARG(&cmd->ioctx->fileid),
                                        (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                        if (ret == ESHUTDOWN) {
                                return 0;
                        } else {
                                ret = EIO;
                                GOTO(err_ret, ret);
                        }
                } else {
                        if (cmd->conn->state == STATE_CLOSE || cmd->conn->state == STATE_CLOSED) {
                                DWARN("conn close, read "CHKID_FORMAT" (%llu, %llu)\n",
                                                CHKID_ARG(&cmd->ioctx->fileid),
                                                (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                                ret = EIO;
                                GOTO(err_ret, ret);
                        } else {
                                DERROR("read "CHKID_FORMAT" cmd(%llu, %llu), ret (%d) %s\n",
                                                CHKID_ARG(&cmd->ioctx->fileid), (LLU)cmd->tio->io_off,
                                                (LLU)cmd->tio->io_len, ret, strerror(ret));
                                GOTO(err_ret, ret);
                        }
                }
        }

#if ISCSI_IO_RECORD
        char tmp[MAX_INFO_LEN];

        sprintf(tmp, "iscsi read ok, iscsi io record read "CHKID_FORMAT" (%llu, %llu), ",
                        CHKID_ARG(&cmd->ioctx->fileid),
                        (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);

        mbuffer_dump(&cmd->tio->buffer, 8, tmp);
#endif

        ANALYSIS_QUEUE(0, IO_WARN, "lich_io_read");
        
        return 0;
err_ret:
        /* @---------- */
        //cops->scan_async();
        /* @---------- */

        return ret;
}

STATIC int __sdfsio_io_write__(struct iscsi_cmd *cmd)
{
        int ret;

        if (unlikely(cmd->conn->state == STATE_CLOSE)) {
                DINFO("conn close, write "CHKID_FORMAT" (%llu, %llu)\n",
                      CHKID_ARG(&cmd->ioctx->fileid), (LLU)cmd->tio->io_off,
                      (LLU)cmd->tio->io_len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        struct iscsi_target *target = cmd->lun->target;
        volume_t *volume = target->volume;
        ret = volume_write(volume, &cmd->tio->buffer,
                           cmd->tio->io_len, cmd->tio->io_off);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}


STATIC int __sdfsio_io_write(struct iscsi_cmd *cmd)
{
        int ret, retry = 0;
        time_t begin = gettime();

        schedule_task_setname("iscsi_write");

        YASSERT(cmd->tio->buffer.len == cmd->tio->io_len);

        DBUG("iscsi_lsv write %llu %llu\n", (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);

        ANALYSIS_BEGIN(0);
        
        if (unlikely(cmd->tio->io_off + cmd->tio->io_len > cmd->lun->blk_size)) {
                ret = EIO;
                GOTO(err_ret, ret);
        }

        YASSERT(cmd->tio->buffer.len == cmd->tio->io_len);

        if (likely(cmd->lun->private != NULL)) {
                cmd->ioctx = cmd->lun->private;
        } else {
                ret = EIO;
                GOTO(err_ret, ret);
        }

#if ISCSI_IO_RECORD
        DINFO("iscsi io record write "CHKID_FORMAT" (%llu, %llu)\n",
                        CHKID_ARG(&cmd->ioctx->fileid), (LLU)cmd->tio->io_off,
                        (LLU)cmd->tio->io_len);
#endif

retry:
        if (unlikely(cmd->conn->state == STATE_CLOSED || cmd->conn->state == STATE_CLOSE)) {
                DINFO("conn close, write "CHKID_FORMAT" (%llu, %llu)\n",
                                CHKID_ARG(&cmd->ioctx->fileid), (LLU)cmd->tio->io_off,
                                (LLU)cmd->tio->io_len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        /**
         * @note 有选择地屏蔽底层的EIO，如拔盘等场景
         */
        ret = __sdfsio_io_write__(cmd);
        if (unlikely(ret)) {
                ret = _errno(ret);
                if (retry < 1000 && (ret == EAGAIN || ret == ENOSPC)
                                && ((gettime() - begin) < gloconf.rpc_timeout + 20)) {
                        if (retry > 100) {
                                DINFO("write "CHKID_FORMAT" (%llu, %llu),"
                                      " ret (%d) %s, need retry %u\n",
                                      CHKID_ARG(&cmd->ioctx->fileid),
                                      (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len,
                                      ret, strerror(ret), retry);
                        }

                        retry++;
                        schedule_sleep("iscsi_write", 1000 * 100);
                        goto retry;
                } else if (ret == EPERM || ret == ESHUTDOWN) {
                        if (cmd->conn->state != STATE_CLOSE && cmd->conn->state != STATE_CLOSED)
                                cmd->conn->state = STATE_CLOSE;
                        DERROR("conn close, write "CHKID_FORMAT" (%llu, %llu)\n",
                                        CHKID_ARG(&cmd->ioctx->fileid),
                                        (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                        if (ret == ESHUTDOWN) {
                                return 0;
                        } else {
                                ret = EIO;
                                GOTO(err_ret, ret);
                        }
                } else {
                        if (cmd->conn->state == STATE_CLOSE || cmd->conn->state == STATE_CLOSED) {
                                DWARN("conn close, write "CHKID_FORMAT" (%llu, %llu)\n",
                                        CHKID_ARG(&cmd->ioctx->fileid),
                                      (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);
                                ret = EIO;
                                GOTO(err_ret, ret);
                        } else {
                                DERROR("write "CHKID_FORMAT" cmd(%llu, %llu), begin %ld ret (%d) %s\n",
                                      CHKID_ARG(&cmd->ioctx->fileid), (LLU)cmd->tio->io_off,
                                       (LLU)cmd->tio->io_len, begin, ret, strerror(ret));
                                GOTO(err_ret, ret);
                        }
                }
        }

#if ISCSI_IO_RECORD
        char tmp[MAX_INFO_LEN];
        sprintf(tmp, "lich_io write ok, iscsi io record read "CHKID_FORMAT" (%llu, %llu), ",
                        CHKID_ARG(&cmd->ioctx->fileid),
                        (LLU)cmd->tio->io_off, (LLU)cmd->tio->io_len);

        mbuffer_dump(&cmd->tio->buffer, 8, tmp);
#endif
        ANALYSIS_QUEUE(0, IO_WARN, "lich_io_write");
        
        return 0;
err_ret:
        /* @---------- */
        //cops->scan_async();
        /* @---------- */

        return ret;
}

#if ENABLE_VAAI
STATIC int __sdfsio_io_unmap__(struct iscsi_cmd *cmd, uint64_t offset, uint32_t length)
{
        struct iscsi_target *target = cmd->lun->target;

        DINFO("__sdfsio_io_unmap__ %ju, %d\r\n", offset, length);

        return stor_unmap(target->pool, &cmd->ioctx->fileid,
                length, offset);
}

STATIC int __sdfsio_io_unmap(struct iscsi_cmd *cmd, uint64_t lba, uint32_t count)
{
        int ret;
        uint64_t off;
        uint32_t len;

        schedule_task_setname("iscsi_unmap");

        off = lba * (1U << cmd->lun->blk_shift);
        len = count * (1U << cmd->lun->blk_shift);

        off -= off % LICH_CHUNK_SPLIT;          //align to chunk.
        
        off = off / LICH_CHUNK_SPLIT * LICH_CHUNK_SPLIT;
        len = len / LICH_CHUNK_SPLIT * LICH_CHUNK_SPLIT;

        if(len == 0)
                return 0;
        
        DINFO("iscsi_lsv unmap %llu %llu\n", (LLU)off, (LLU)len);

        if (unlikely(lba + count > cmd->lun->blk_size)) {
                ret = EIO;
                GOTO(err_ret, ret);
        }

        if (likely(cmd->lun->private != NULL)) {
                cmd->ioctx = cmd->lun->private;
        } else {
                ret = EIO;
                GOTO(err_ret, ret);
        }

#if ISCSI_IO_RECORD
        DINFO("iscsi io record unmap "CHKID_FORMAT" (%llu, %llu)\n",
                        CHKID_ARG(&cmd->ioctx->fileid), (LLU)off, (LLU)len);
#endif

        if (unlikely(cmd->conn->state == STATE_CLOSE)) {
                DINFO("conn close, unmap "CHKID_FORMAT" (%llu, %llu)\n",
                      CHKID_ARG(&cmd->ioctx->fileid), (LLU)off, (LLU)len);
                ret = EIO;
                GOTO(err_ret, ret);
        }

        ret = __sdfsio_io_unmap__(cmd, off, len);
        if (unlikely(ret)) {
                ret = _errno(ret);
                GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        /* @---------- */
        //cops->scan_async();
        /* @---------- */

        return ret;
}
#endif

STATIC int __sdfsio_sync(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

STATIC int __sdfsio_detach(struct iscsi_volume *lu)
{
        __sdfsio_disconnect(lu);

        struct iscsi_target *target = lu->target;
        volume_close(&target->volume);

        return 0;
}

struct iotype lich_io = {
        .attach = __sdfsio_attach,
        .detach = __sdfsio_detach,

        .aio_read = __sdfsio_io_read,
        .aio_write = __sdfsio_io_write,

        .update = __sdfsio_update,
        //.unmap = __sdfsio_io_unmap,
        .unmap = NULL,
        .sync = __sdfsio_sync,
};
