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

#if 0
int mds_rpc_diskhb(const nid_t *nid, int tier, const uuid_t *uuid,
                   const diskinfo_stat_diff_t *diff);
int mds_rpc_statvfs(const nid_t *nid, const fileid_t *fileid, struct statvfs *stbuf);
int mds_rpc_diskjoin(const nid_t *nid, uint32_t tier, const uuid_t *uuid,
                      const diskinfo_stat_t *stat);
int mds_rpc_newdisk(const nid_t *nid, uint32_t tier, uint32_t repnum,
                     uint32_t hardend, diskid_t *disks);
#endif
int mds_rpc_null(const nid_t *mds);
int mds_rpc_set(const nid_t *nid, const char *path, const char *value, uint32_t valuelen);
int mds_rpc_get(const nid_t *nid, const char *path, uint64_t offset, void *value, int *valuelen);
int mds_rpc_paset(const nid_t *nid, const chkinfo_t *chkinfo, uint64_t prev_version);
int mds_rpc_paget(const nid_t *nid, const chkid_t *chkid, chkinfo_t *chkinfo);

#endif
