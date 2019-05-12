#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/statfs.h>

#define DBG_SUBSYS S_YFSCDS

#include "configure.h"
#include "md_lib.h"
#include "rpc_proto.h"
#include "cds.h"
#include "cds_lib.h"
#include "ylib.h"
#include "yfscds_conf.h"
#include "conn.h"
#include "ylock.h"
#include "nodeid.h"
#include "ynet.h"
#include "yfscli_conf.h"
#include "sdfs_lib.h"
#include "disk.h"
#include "diskid.h"
#include "schedule.h"
#include "redis.h"
#include "core.h"
#include "io_analysis.h"
#include "net_global.h"
#include "../../cds/diskio.h"
#include "bh.h"
#include "dbg.h"

extern int use_memcache;
cds_info_t cds_info;
uint32_t num_cds_read;
uint32_t num_cds_read_done;
uint32_t num_cds_write;
uint32_t num_cds_write_done;

extern int __fence_test_need__;

static int inited;

extern uint32_t zero_crc;
extern struct sockstate sock_state;

#define LEN_MOUNT_PATH (sizeof (YFS_CDS_DIR_DISK_PRE) + 10)
#define LOG_TYPE_CDS "cds"
#define SLEEP_INTERVAL 5
#define LENSTATE 20
#define STATENUM 5
#define FILE_PATH_LEN 64
#define CDS_LEVELDB_THREAD_NUM 4

extern int __is_cds_cache;

#undef LEN_MOUNT_PATH
#undef LOG_TYPE_CDS
#undef SLEEP_INTERVAL

void cds_monitor_handler(int sig)
{
        DINFO("got signal %d\n", sig);
}

void cds_signal_handler(int sig)
{
        (void) sig;

        jobdock_iterator();

        analysis_dumpall();
}

int cds_destroy(int cds_sd, int servicenum)
{
        (void) cds_sd;
        (void) servicenum;

        return 0;
}

int disk_unlink1(const chkid_t *chkid, uint64_t snapvers)
{
        int ret;
        char dpath[MAX_PATH_LEN] = {0}, dir[MAX_PATH_LEN];

        (void) snapvers;
        (void) chkid;
        
        UNIMPLEMENTED(__DUMP__);
#if 0
        chkid2path(-1, chkid, dpath);
#endif

        ret = unlink(dpath);
        if (ret == -1) {
                ret = errno;
                GOTO(err_ret, ret);
        }

        ret = _path_split2(dpath, dir, NULL);
        if (ret)
                GOTO(err_ret, ret);

        rmdir(dir);
        
        return 0;
err_ret:
        return ret;
}

inline static int __chunk_unlink(const chkid_t *chkid, uint64_t snapvers)
{
        int i;
        int ret;
        char buf[MAX_BUF_LEN];
        chkinfo_t *chkinfo;

        chkinfo = (void *)buf;
        ret = md_chunk_load(chkid, chkinfo);
        if (ret) {
                if (ret == ENOENT) {
                        /*no op*/
                } else
                        GOTO(err_ret, ret);
        } else {
                for (i = 0; i < (int)chkinfo->repnum; i++) {
                        if (ynet_nid_cmp(&chkinfo->diskid[i].id, &ng.local_nid) == 0) {
                                DINFO("chk "OBJID_FORMAT" still in use\n", OBJID_ARG(chkid));
                                ret = EPERM;
                                goto err_ret;
                        }
                }
        }

        ret = disk_unlink1(chkid, snapvers);
        if (ret)
                GOTO(err_ret, ret);

        DINFO("remove chunk "OBJID_FORMAT"\n", OBJID_ARG(chkid));

        return 0;

err_ret:
        return ret;
}

#if 1
int chunk_cleanup(void *arg)
{
        (void) arg;
        UNIMPLEMENTED(__WARN__);

        return 0;
}
#else

int chunk_cleanup(void *arg)
{
        int ret, i, count;
        chkid_t array[100], *chkid;

        (void) arg;

        DBUG("get cleanup msg\n");

        while (1) {
                count = 100;
                
                ret = rm_pop(net_getnid(), -1, array, &count);
                if (ret) {
                        ret = ENOENT;
                        goto err_ret;
                }

                if (count == 0)
                        goto out;

                for (i = 0; i < (int)count; i++) {
                        chkid = &array[i];
                        YASSERT(chkid_null(chkid) == 0);

                        UNIMPLEMENTED(__WARN__);
                        ret = __chunk_unlink(chkid, 0);
                        if (ret) {
                                if (ret == ENOENT || ret == EPERM)
                                        continue;
                                else
                                        GOTO(err_ret, ret);
                        }
                }
        }

out:
        return 0;
err_ret:
        return ret;
}
#endif

int cds_init(const char *home)
{
        int ret;

        ret = disk2idx_init();
        if (ret)
                GOTO(err_ret, ret);
        
        int flag = CORE_FLAG_PASSIVE | CORE_FLAG_AIO;
#if 1
        if (cdsconf.cds_polling && gloconf.polling_timeout == 0) {
                flag |= CORE_FLAG_POLLING;
        }
#endif

        ret = core_init(gloconf.polling_core, flag);
        if (ret)
                GOTO(err_ret, ret);

        ret = disk_init(home);
        if (ret)
                GOTO(err_ret, ret);
        
retry:
        ret = network_connect_mds(1);
        if (ret) {
                ret = _errno(ret);
                if (ret == EAGAIN) {
                        sleep(5);
                        goto retry;
                } else
                        GOTO(err_ret, ret);
        }

        ret = bh_register("chunk_recycle", chunk_cleanup, NULL, (60));
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

inline void cds_exit_handler(int sig)
{
        if (inited == 0) {
                DINFO("got signal %d, force exit\n", sig);
                EXIT(0);
        } else {
                DINFO("got signal %d, prepare exit, please waiting\n", sig);
        }

        cds_info.running = 0;
        srv_running = 0;
}

int cds_run(void *args)
{
        int ret;
        int daemon;
        net_proto_t net_op;
        const char *home;
        char path[MAX_PATH_LEN];
        cds_args_t *cds_args;

        cds_args = args;
        daemon = cds_args->daemon;
        home = cds_args->home;

        snprintf(path, MAX_NAME_LEN, "%s/status/status.pid", home);
        ret = daemon_pid(path);
        if (ret)
                GOTO(err_ret, ret);
        
        signal(SIGUSR1, cds_signal_handler);
        signal(SIGUSR2, cds_exit_handler);
        signal(SIGTERM, cds_exit_handler);
        signal(SIGHUP, cds_exit_handler);
        signal(SIGKILL, cds_exit_handler);
        signal(SIGINT, cds_exit_handler);

        _memset(&net_op, 0x0, sizeof(net_proto_t));

#if ENABLE_MEM_CACHE1
        use_memcache = 1;
#endif

        ret = ly_init(daemon, ROLE_BACTL, 524288 * 10);
        if (ret)
                GOTO(err_ret, ret);

        ret = path_validate(home, 1, 1);
        if (ret)
                GOTO(err_ret, ret);

        cds_info.running = 1;
        __fence_test_need__ = 1;

        ret = io_analysis_init("cds", 0);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = cds_init(home);
        if (ret)
                GOTO(err_ret, ret);

        ret = disk_fs_thread_init();
        if (ret)
                GOTO(err_ret, ret);
        
        ret = rpc_start(); /*begin serivce*/
        if (ret)
                GOTO(err_ret, ret);

        inited = 1;

        ret = ly_update_status("running", -1);
        if (ret)
                GOTO(err_ret, ret);

        while (cds_info.running) { //we got nothing to do here
                sleep(1);

#if 0
                if (time(NULL) % 10 == 0) {
                        DINFO("latency %ju\n", core_latency_get());
                }
#endif
        }

        ret = ly_update_status("stopping", -1);
        if (ret)
                GOTO(err_ret, ret);

        DINFO("exiting...\n");

        ret = ly_update_status("stopped", -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}
