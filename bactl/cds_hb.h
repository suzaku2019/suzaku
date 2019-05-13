#ifndef __CDS_HB_H__
#define __CDS_HB_H__

#include "file_proto.h"
#include "chk_proto.h"

#if 0
typedef struct {
        sem_t             sem;
        int               stop;
        int               running;
        int               inited;
        diskid_t          diskid;
        struct statvfs    fsbuf;
        char home[MAX_PATH_LEN];
} hb_service_t;

int hb_service_init(hb_service_t *hbs, const diskid_t *diskid, const char *path);
int hb_service_destroy(hb_service_t *);
#endif
#endif
