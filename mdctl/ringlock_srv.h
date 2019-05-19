#ifndef __RINGLOCK__
#define __RINGLOCK__

#include "mds.h"
#include "partition.h"

#define RANGE_FORMAT "(%ld, %ld]"
#define RANGE_ARG(_id) (_id)->begin, (_id)->end

#if 0
#define TYPE_MDCTL 1
#define TYPE_FRCTL 2
#endif

int ringlock_srv_lock(const range_t *range, uint32_t type, const coreid_t *coreid,
                      ltoken_t *token);
int ringlock_srv_unlock(const range_t *range, uint32_t type, const coreid_t *coreid);
int ringlock_srv_get(const range_t *range, uint32_t type, coreid_t *coreid,
                     ltoken_t *token);
int ringlock_srv_init();
int ringlock_srv_destroy();

#endif

