#ifndef __MOND_RPC_H__
#define __MOND_RPC_H__

#include <sys/statvfs.h>

#include "md_proto.h"
#include "yfs_md.h"

typedef struct {
        nid_t nid;
        int online;
} instat_t;  

typedef struct {
        int klen;
        int vlen;
        unsigned char type;
        unsigned char eof;
        uint64_t offset;
        char buf[0];
} mon_entry_t;


#define MON_ENTRY_MAX (64 * 1024)

int mds_rpc_init();
int mds_rpc_getstat(const nid_t *nid, instat_t *instat);

int mds_rpc_null(const nid_t *mds);
int mds_rpc_set(const char *path, const char *value, uint32_t valuelen);
int mds_rpc_get(const char *path, uint64_t offset, void *value, int *valuelen);
int mds_rpc_paset(const chkid_t *chkid, const chkinfo_t *chkinfo, uint64_t *version);
int mds_rpc_paget(const chkid_t *chkid, chkinfo_t *chkinfo, uint64_t *_version);
int mds_rpc_recovery(const chkid_t *chkid);

#endif
