#ifndef __VS_CHUNK_H__
#define __VS_CHUNK_H__

#include "chunk.h"

typedef struct {
        coreid_t coreid;
        ec_t ec;
        uint32_t magic;
        int (*read)(const io_token_t *, io_t *);
        int (*write)(const io_token_t *, io_t *);
} vs_range_t;

int vs_chunk_write(vs_range_t *range, const chkid_t *chkid, const buffer_t *buf,
                   int count, uint64_t offset);
int vs_chunk_read(vs_range_t *range, const chkid_t *chkid, buffer_t *buf,
                  int count, uint64_t offset);

#endif
