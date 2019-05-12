#ifndef __ALLOCATOR__
#define __ALLOCATOR__

#include <stdint.h>

#include "ylib.h"
#include "dbg.h"

#define ENABLE_ALLOCATE_BALANCE 1

int allocator_init();
int allocator_new(uint64_t poolid, int repnum, nid_t *disks);
int allocator_dump();
int allocator_disk_register(uint64_t poolid, const nid_t *nid, diskid_t *diskid,
                            const char *faultdomain);
int allocator_disk_unregister(uint64_t poolid, const nid_t *nid, const diskid_t *diskid);

#endif
