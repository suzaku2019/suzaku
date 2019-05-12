#include <sys/types.h>
#include <sys/wait.h>
#include <rpc/pmap_clnt.h>
#include <errno.h>
#include <getopt.h>

#define DBG_SUBSYS S_YNFS

#include "get_version.h"
#include "ylib.h"
#include "sdfs_lib.h"
#include "ynet_rpc.h"
#include "configure.h"
#include "net_table.h"
#include "network.h"
#include "sdfs_quota.h"
#include "core.h"
#if 0
#include "iscsid.h"
#endif
#include "io_analysis.h"
#include "ringlock.h"
#include "partition.h"
#include "allocator.h"
#include "dbg.h"

static int frctl_srv_running;
extern int use_memcache;

typedef struct {
        int daemon;
        char home[MAX_PATH_LEN];
} frctl_args_t;

static void frctl_signal_handler(int sig)
{
        (void) sig;
        //DINFO("got signal %d, load %llu\n", sig, (LLU)jobdock_load());

        if (frctl_srv_running == 0)
                return;
        
        DINFO("got signal %d\n", sig);
        //inode_proto_dump();
        netable_iterate();
        analysis_dumpall();
}

static void frctl_exit_handler(int sig)
{
        DINFO("got signal %d, exiting\n", sig);

        frctl_srv_running = 0;
        srv_running = 0;
}

int frctl_reset_handler(net_handle_t *nh, uuid_t *nodeid)
{
        (void) nodeid;
        net_handle_t *mds_nid;

        mds_nid = &ng.mds_nh;

        if (nid_cmp(&nh->u.nid, &mds_nid->u.nid) == 0) {
                DWARN("mds off\n");
        } else
                DWARN("peer off\n");

        return 0;
}

int frctl_srv(void *args)
{
        int ret;
        frctl_args_t *frctl_args;
        char path[MAX_PATH_LEN];

        frctl_args = args;

        snprintf(path, MAX_NAME_LEN, "%s/status/status.pid", frctl_args->home);
        ret = daemon_pid(path);
        if (ret)
                GOTO(err_ret, ret);

#if ENABLE_MEM_CACHE1
        use_memcache = 1;
#endif
        ret = sdfs_init_verbose(ROLE_FRCTL, gloconf.polling_core);
        if (ret)
                GOTO(err_ret, ret);

        ret = part_register(PART_FRCTL);
        if (ret)
                GOTO(err_ret, ret);

        ret = ringlock_init(RINGLOCK_FRCTL);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = io_analysis_init(ROLE_FRCTL, 0);
        if (ret)
                GOTO(err_ret, ret);

        ret = allocator_init();
        if (ret)
                GOTO(err_ret, ret);
        
retry:
        ret = network_connect_mds(0);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        sleep(5);
                        goto retry;
                } else
                        GOTO(err_ret, ret);
        }

        DINFO("frctl started...\n");

#if 0
        int driver = 0;
        //driver |= ISCSID_DRIVER_ISER;
        driver |= ISCSID_DRIVER_TCP;
        
        ret = iscsid_srv(driver);
        if (unlikely(ret))
                GOTO(err_ret, ret);
#endif
        
        ret = rpc_start(); /*begin serivce*/
        if (ret)
                GOTO(err_ret, ret);
        
        ret = ly_update_status("running", -1);
        if (ret)
                GOTO(err_ret, ret);

        frctl_srv_running = 1;

        DINFO("begin running\n");
        
        while (frctl_srv_running) { //we got nothing to do here
                //ret = register_nlm_service();
                sleep(1);
        }

        ret = ly_update_status("stopping", -1);
        if (ret)
                GOTO(err_ret, ret);

#if 0
        if (strcmp(gloconf.nfs_srv, "native")) {
                nfs_srv_stop();
        }
#endif
        
        DINFO("exiting...\n");

        ret = ly_update_status("stopped", -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int main(int argc, char *argv[])
{
        int ret, daemon = 1, maxcore;
        int c_opt;
        frctl_args_t frctl_args;
        const char *home = NULL;

        (void) maxcore;

        while (srv_running) {
                int option_index = 0;
#if 1
                static struct option long_options[] = {
                        { "home", required_argument, 0, 'h'},
                };
#endif

                c_opt = getopt_long(argc, argv, "cfm:h:v",
                                    long_options, &option_index);
                if (c_opt == -1)
                        break;

                switch (c_opt) {
#if 1
                case 0:
                        switch (option_index) {
                        case 0:
                                break;
                        case 1:
                                break;
                        default:
                                fprintf(stderr, "Hoops, wrong op got!\n");
                        }

                        break;
#endif
                case 'c':
                        maxcore = 1;
                        break;
                case 'f':
                        daemon = 2;
                        break;
                case 'v':
                        get_version();
                        exit(0);
                case 'h':
                        home = optarg;
                        break;
                default:
                        fprintf(stderr, "Hoops, wrong op (%c) got!\n", c_opt);
                        exit(1);
                }
        }

        if (home == NULL) {
                fprintf(stderr, "set --home <dir> please\n");
                exit(1);
        }

        ret = ly_prep(daemon, home, ROLE_FRCTL, -1);
        if (ret)
                GOTO(err_ret, ret);

        strcpy(frctl_args.home, home);
        frctl_args.daemon = daemon;

        signal(SIGUSR1, frctl_signal_handler);
        signal(SIGUSR2, frctl_exit_handler);
        signal(SIGTERM, frctl_exit_handler);
        signal(SIGHUP, frctl_exit_handler);
        signal(SIGKILL, frctl_exit_handler);
        signal(SIGINT, frctl_exit_handler);

        ret = ly_run(home, frctl_srv, &frctl_args);
        if (ret)
                GOTO(err_ret, ret);

        (void) ylog_destroy();

        return 0;
err_ret:
        return ret;
}
