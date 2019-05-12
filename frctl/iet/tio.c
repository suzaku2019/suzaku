/*
 * Target I/O.
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

#define MAX_TIO 1024


struct iscsi_tio *tio_alloc(struct iscsi_conn *conn, int size)
{
        struct iscsi_tio *tio;
        
        (void) conn;

       // if (conn->rdma) {
              tio = mem_cache_calloc(MEM_CACHE_64, 1);
              if (tio == NULL) 
                      YASSERT(0);
        /*} else {
                tio = iscsi_mem_mcache_calloc(conn->mem_cache[ISCSI_MEM_CACHE_TIO], MC_FLAG_NOFAIL);
        }*/

        tio->count++;
        mbuffer_init(&tio->buffer, size);

        tio->io_off = 0;
        tio->io_len = 0;

        return tio;
}

void tio_free(struct iscsi_conn *conn, struct iscsi_tio *tio)
{
        (void )conn;

        if (likely(tio)) {
                mbuffer_free(&tio->buffer);
                //if (conn->rdma) {
                        mem_cache_free(MEM_CACHE_64, tio);
               /* } else {
                        iscsi_mem_mcache_free(conn->mem_cache[ISCSI_MEM_CACHE_TIO], tio);
                }*/
        }
}

void tio_put(struct iscsi_conn* conn, struct iscsi_cmd *cmd)
{
        cmd->tio->count--;
        if (likely(cmd->tio->count == 0)) {
                tio_free(conn, cmd->tio);
                cmd->tio = NULL;
        }
}

void tio_get(struct iscsi_tio *tio)
{
        tio->count++;
}

void tio_set_diskseek(struct iscsi_tio *tio, u64 off, u64 len)
{
        tio->io_off = off;
        tio->io_len = len;
}

inline int tio_read(struct iscsi_cmd *cmd)
{
        if (likely(cmd->tio->io_len))
                return cmd->lun->iotype->aio_read(cmd);
        else
                return 0;
}

inline int tio_write(struct iscsi_cmd *cmd)
{
        if (likely(cmd->tio->io_len))
                return cmd->lun->iotype->aio_write(cmd);
        else
                return 0;
}

int tio_unmap(struct iscsi_cmd *cmd, uint64_t lba, uint32_t len)
{
        DINFO("tio_unmap %ju, %d\r\n", lba, len);

        return cmd->lun->iotype->unmap(cmd, lba, len);
}

inline int tio_sync(struct iscsi_cmd *cmd)
{
        return cmd->lun->iotype->sync(cmd);
}

void tio_add_param(struct iscsi_cmd *cmd, char *key, char *val)
{
        u32 len;
        char buf[MAX_BUF_LEN];

        len = snprintf(buf, sizeof(buf), "%s=%s", key, val);
        len++;

        if (!cmd->tio) {
                cmd->tio = tio_alloc(cmd->conn, 0);
        }

        mbuffer_appendmem(&cmd->tio->buffer, buf, len);

        cmd->pdu.datasize += len;

        return;
}
