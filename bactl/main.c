#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <sys/vfs.h>

#define DBG_SUBSYS S_YFSCDS

#include "ylib.h"
#include "get_version.h"
#include "configure.h"
#include "ylog.h"
#include "dbg.h"
//#include "../../ynet/sock/sock_buffer.h"
#include "cds.h"
#include "sdfs_lib.h"

int main(int argc, char *argv[])
{
        int ret, daemon = 1, maxcore, c_opt;
        const char *home;
        cds_args_t cds_args;

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

        ret = conf_init(YFS_CONFIGURE_FILE);
        if (ret)
                GOTO(err_ret, ret);

        ret = path_validate(home, YLIB_ISDIR, YLIB_DIRCREATE);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = ly_prep(daemon, home, ROLE_BACTL, 524288 * 10);
        if (ret)
                GOTO(err_ret, ret);

        cds_args.daemon = daemon;
        strcpy(cds_args.home, home);

        signal(SIGUSR1, cds_monitor_handler);
        signal(SIGUSR2, cds_monitor_handler);
        signal(SIGTERM, cds_monitor_handler);
        signal(SIGHUP, cds_monitor_handler);
        signal(SIGKILL, cds_monitor_handler);
        signal(SIGINT, cds_monitor_handler);

        ret = ly_run(home, cds_run, &cds_args);
        if (ret)
                GOTO(err_ret, ret);

        (void) ylog_destroy();

        return 0;
err_ret:
        return ret;
}
