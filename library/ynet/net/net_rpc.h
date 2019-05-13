#ifndef __NET_RPC_H__
#define __NET_RPC_H__

#include "job_dock.h"
#include "net_global.h"

#include "corenet_connect.h"

int net_rpc_heartbeat(const sockid_t *sockid, uint64_t seq);
int net_rpc_coreinfo(const coreid_t *coreid, corenet_addr_t *addr);
int net_rpc_cores(const nid_t *nid, int *cores);
int net_rpc_init(void);

#endif
