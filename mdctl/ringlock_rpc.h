#ifndef __RINGLOCK_RPC__
#define __RINGLOCK_RPC__

#include "ringlock_srv.h"

int ringlock_rpc_destroy();
int ringlock_rpc_init();
int ringlock_rpc_lock(const nid_t *srv, const range_t *range, uint32_t type, 
                      const coreid_t *coreid, ltoken_t *token);
int ringlock_rpc_get(const nid_t *srv, const range_t *range, uint32_t type,
                     coreid_t *coreid, ltoken_t *token);
int ringlock_rpc_unlock(const nid_t *srv, const range_t *range, uint32_t type,
                        const coreid_t *coreid);

#endif
