#ifndef __VSS_H__
#define __VSS_H__

#include "vs_chunk.h"

#define VSS_ITEM_COUNT (RANGE_ITEM_COUNT * 4)

typedef struct {
        fileid_t id;
        plock_t plock;
        ec_t ec;
        uint32_t chunk_split;
        uint32_t real_split;
        uint32_t range_count;
        vs_range_t *array;
} vss_t;

int vss_write(vss_t *vss, const buffer_t *_buf, uint32_t size, uint64_t offset);
int vss_read(vss_t *vss, buffer_t *_buf, uint32_t size, uint64_t offset);
int vss_create(const fileid_t *fileid, const ec_t *ec, uint32_t chunk_split,
               uint32_t real_split, vss_t **_vss);
void vss_close(vss_t **_vss);


#endif
