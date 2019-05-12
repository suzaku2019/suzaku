#ifndef __RINGLOCK__
#define __RINGLOCK__

#include "mds.h"
#include "partition.h"

#define RANGE_FORMAT "(%ld, %ld]"
#define RANGE_ARG(_id) (_id)->begin, (_id)->end

#define RINGLOCK_MDS 1
#define RINGLOCK_FRCTL 2

int ringlock_srv_lock(const range_t *range, uint32_t type, const coreid_t *coreid,
                      ltoken_t *token);
int ringlock_srv_unlock(const range_t *range, uint32_t type, const coreid_t *coreid);
int ringlock_srv_get(const range_t *range, uint32_t type, coreid_t *coreid,
                     ltoken_t *token);
int ringlock_srv_init();
int ringlock_srv_destroy();

#endif

