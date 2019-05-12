#ifndef __PA_SRV_H__
#define __PA_SRV_H__

#include "ylib.h"
#include "chk_proto.h"
#include "net_proto.h"
#include "dbg.h"

#define PA_INFO_COUNT (32)
#define PA_INFO_SIZE (512)
#define PA_ITEM_SIZE (128)
#define PA_INFO_AREA (PA_INFO_COUNT * PA_INFO_SIZE)
#define PA_ITEM_COUNT ((SDFS_CHUNK_SPLIT - PA_INFO_AREA) / PA_ITEM_SIZE)
#define PA_HASH (32)

int pa_srv_get(const chkid_t *chkid, chkinfo_t *chkinfo);
int pa_srv_set(const chkinfo_t *chkinfo, uint64_t prev_version);
int pa_srv_create();

#endif
