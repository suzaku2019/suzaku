#ifndef __RANGE_H__
#define __RANGE_H__

#include "chunk.h"
#include "pa_srv.h"

#define RANGE_CHUNK_COUNT (4)
#define RANGE_ITEM_COUNT ((uint64_t)PA_ITEM_COUNT * RANGE_CHUNK_COUNT)

typedef chkid_t rid_t;

static inline void cid2rid(const chkid_t *chkid, rid_t *rid)
{
        *rid = *chkid;
        if (chkid->type == ftype_raw) {
                rid->type = ftype_sub;
        } else if (chkid->type == ftype_sub) {
                rid->type = ftype_file;
        } else {
                YASSERT(0);
        }

        rid->idx = chkid->idx / RANGE_ITEM_COUNT;
}

int range_ctl_create();
int range_ctl_get_token(const chkid_t *chkid, int op, io_token_t *token);
int range_ctl_chunk_recovery(const chkid_t *chkid);
int range_ctl_chunk_getinfo(const chkid_t *chkid, chkinfo_t *chkinfo);
int range_rpc_get_token(const coreid_t *, const chkid_t *chkid, uint32_t op,
                        io_token_t *token);
int range_rpc_chunk_recovery(const coreid_t *coreid, const chkid_t *chkid);
int range_rpc_chunk_getinfo(const coreid_t *coreid, const chkid_t *chkid, chkinfo_t *chkinfo);
int range_rpc_init();
int range_init();

int range_chunk_location(const chkid_t *chkid, coreid_t *coreid);
int range_chunk_getinfo(const chkid_t *chkid, chkinfo_t *chkinfo);
int range_chunk_recovery(const chkid_t *chkid);

#endif
