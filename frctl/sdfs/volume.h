#ifndef __VOLUME_H__
#define __VOLUME_H__

#include "ylib.h"
#include "vss.h"

typedef struct {
        fileid_t id;
        plock_t plock;
        ec_t ec;
        uint64_t size;
        uint64_t vss_split;
        uint32_t chunk_split;
        uint32_t real_split;
        uint32_t vss_count;
        vss_t **array;
} volume_t;

int volume_write(volume_t *volume, const buffer_t *_buf, uint32_t size, uint64_t offset);
int volume_read(volume_t *volume, buffer_t *_buf, uint32_t size, uint64_t offset);
int volume_open(volume_t **_volume, const fileid_t *fileid);
void volume_close(volume_t **_volume);

int volume_write1(volume_t *volume, const buffer_t *_buf, uint32_t size, uint64_t offset);
int volume_read1(volume_t *volume, buffer_t *_buf, uint32_t size, uint64_t offset);
int volume_open1(volume_t **_volume, const fileid_t *fileid);
void volume_close1(volume_t **_volume);

#endif
