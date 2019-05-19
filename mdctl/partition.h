#ifndef __PARTITION_H__
#define __PARTITION_H__

typedef struct {
        int64_t begin;
        int64_t end;
} range_t;

#if 0
#define TYPE_MDCTL     0x01
#define TYPE_FRCTL   0x02
#endif

int part_hash(uint64_t id, int type, coreid_t *coreid);
int part_dump(int type);
int part_register(int type);
int part_init();
int part_range(int type, const coreid_t *coreid, range_t *range);
int part_location(const chkid_t *chkid, int type, coreid_t *coreid);

void int2coreid(const uint32_t coreid32, coreid_t *coreid);
void coreid2int(const coreid_t *, uint32_t *coreid32);

#endif
