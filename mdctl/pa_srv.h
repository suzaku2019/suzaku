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

inline static void IO_FUNC cid2tid(const chkid_t *chkid, chkid_t *tid)
{
        *tid = *chkid;

        tid->idx = chkid->idx / PA_ITEM_COUNT;

        if (chkid->type == ftype_raw) 
                tid->type = ftype_sub;
        else if (chkid->type == ftype_sub)
                tid->type = ftype_file;
        else {
                UNIMPLEMENTED(__DUMP__);
        }
}


int pa_srv_recovery(const chkid_t *chkid);
int pa_srv_get(const chkid_t *chkid, chkinfo_t *chkinfo, uint64_t *version);
int pa_srv_set(const chkid_t *chkid, const chkinfo_t *chkinfo, uint64_t *version);
int pa_srv_getinfo(const chkid_t *tid, int idx, char *buf, 
                   int *buflen, uint64_t *version);
int pa_srv_setinfo(const chkid_t *tid, int idx, const char *buf,
                   int buflen, uint64_t prev_version);
int pa_srv_create();

#endif
