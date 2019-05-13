#ifndef __LEASE_CLI__
#define __LEASE_CLI__

#include "lease_rpc.h"

typedef struct {
        chkid_t chkid;
        time_t time;
        ltoken_t token;
        plock_t plock;
} lease_t;

int lease_cli_set(lease_t *lease);
int lease_cli_free(lease_t *lease);
int lease_cli_get(const chkid_t *chkid, nid_t *nid, ltoken_t *_token);
int lease_cli_timeout(const lease_t *lease);

#endif
