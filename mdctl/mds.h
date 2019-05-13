#ifndef __MDS_H__
#define __MDS_H__

#include <semaphore.h>
#include <pthread.h>

#include "sdfs_list.h"
#include "ylock.h"
#include "ynet_rpc.h"
#include "yatomic.h"
#include "file_proto.h"
#include "yfs_conf.h"

enum {
        MDS_NULL,
        MDS_PRIMARY,        /* primary mds */
        MDS_SHADOW,         /* shadow mds, rd only, no cds info */
        MDS_SHADOW_FORCE,
};

typedef struct {
        int mds_type;
        time_t uptime;
} mds_info_t;

extern mds_info_t mds_info;

#endif
