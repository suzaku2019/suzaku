#ifndef __CDS_H__
#define __CDS_H__

#include <dirent.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "sdfs_list.h"
#include "md_proto.h"
#include "ylock.h"
#include "ynet_rpc.h"

/**
 * global cds info
 */
typedef struct {
	enum {
		CDS_TYPE_NODE,
		CDS_TYPE_CACHE,
	} type;
	
        uint32_t         tier; /*0:ssd, 1:hdd*/
        int readonly;
        int running;
} cds_info_t;

extern cds_info_t cds_info;
extern int cds_run(void *);

void cds_exit_handler(int sig);
void cds_signal_handler(int sig);
void cds_monitor_handler(int sig);

typedef struct {
        int daemon;
        char home[MAX_PATH_LEN];
} cds_args_t;

#endif
