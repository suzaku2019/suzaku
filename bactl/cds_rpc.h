#ifndef __CDS_RPC_H__
#define __CDS_RPC_H__

#include "ylib.h"
#include "disk.h"
#include "mds.h"

int cds_rpc_init();
int cds_rpc_read(const diskid_t *diskid, const io_t *io, buffer_t *_buf);
int cds_rpc_write(const diskid_t *diskid, const io_t *io, const buffer_t *_buf);
int cds_rpc_sync(const diskid_t *diskid, const io_t *io, const buffer_t *_buf);
int cds_rpc_connect(const diskid_t *diskid, const chkid_t *chkid,
                    const ltoken_t *token, uint32_t magic,
                    clockstat_t *clockstat, int resuse);
int cds_rpc_create(const diskid_t *diskid, const chkid_t *chkid, uint32_t size,
                   int initzero);
int cds_rpc_diskstat(const diskid_t *diskid, disk_info_t *stat);
int cds_rpc_getclock(const diskid_t *diskid, const chkid_t *chkid, clockstat_t *clockstat);
int cds_rpc_reset(const diskid_t *diskid, const chkid_t *chkid);

#endif
