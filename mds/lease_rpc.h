#ifndef __LEASE_RPC__
#define __LEASE_RPC__

#include "mds_lease.h"

int lease_rpc_destroy();
int lease_rpc_init();
int lease_rpc_set(const nid_t *srv, const chkid_t *chkid,
                  const nid_t *nid, ltoken_t *token);
int lease_rpc_get(const nid_t *srv, const chkid_t *chkid,
                  nid_t *nid, ltoken_t *token);
int lease_rpc_free(const nid_t *srv, const chkid_t *chkid, const nid_t *nid);

#endif
