#ifndef __MDS_LEASE__
#define __MDS_LEASE__

#include "mds.h"

int mds_lease_set(const chkid_t *chkid, const nid_t *nid, ltoken_t *token);
int mds_lease_free(const chkid_t *chkid, const nid_t *nid);
int mds_lease_get(const chkid_t *chkid, nid_t *nid, ltoken_t *token);
int mds_lease_init();
int mds_lease_destroy();

#endif

