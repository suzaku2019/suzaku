#ifndef MDS_MAIN_H 
#define MDS_MAIN_H


#include "configure.h"
#include "net_global.h"
#include "job_dock.h"
#include "get_version.h"
#include "ylib.h"
#include "sdfs_lib.h"
#include "ylog.h"
#include "mds.h"
#include "md_lib.h"
#include "dbg.h"
#include "fnotify.h"

typedef enum {
        ELECTION_NORMAL,
        ELECTION_INIT,
        ELECTION_SYNC,
        ELECTION_MASTER,
} election_type_t;

typedef struct {
        int daemon;
        const char *home;
} mds_args_t;

void mds_monitor_handler(int sig);
void mds_signal_handler(int sig);
int mds_primary();
int mds_init(const char *home);
int mds_run(void *args);

#endif
