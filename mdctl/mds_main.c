#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "configure.h"
#include "net_global.h"
#include "job_dock.h"
#include "get_version.h"
#include "ylib.h"
#include "ynet.h"
#include "sdfs_lib.h"
#include "ylog.h"
#include "mds.h"
#include "md.h"
#include "md_lib.h"
#include "nodeid.h"
#include "conn.h"
#include "rpc_proto.h"
#include "schedule.h"
#include "mds_rpc.h"
#include "fnotify.h"
#include "sdfs_quota.h"
#include "partition.h"
#include "pa_srv.h"
#include "mds_main.h"
#include "ringlock.h"
#include "ringlock_rpc.h"
#include "allocator.h"
#include "core.h"
#include "dbg.h"

extern int mds_scan_init();
static int mds_exiting  = 0;
static int __mds_master__ = 0;

extern jobtracker_t *boardcast_jobtracker;

mds_info_t mds_info;

void mds_monitor_handler(int sig)
{
        DINFO("got signal %d \n", sig);
}

void mds_signal_handler(int sig)
{
        (void) sig;
        //DINFO("got signal %d load %llu\n", sig, (LLU)jobdock_load());

        jobdock_iterator();
        //nodepool_hash_print();
        analysis_dumpall();
}

static int __mds_exit__(int ret)
{
        DINFO("exit %d\n", ret);
        EXIT(ret);
}

int __mds_restart(int rebuild)
{
        (void)rebuild;

        __mds_exit__(EAGAIN);
        return 0;
}

static void *__mds_exit(void *nil)
{
        int ret;//, count;

        (void) nil;

        ret = ly_update_status("stopping", -1);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

#if 0
retry:
        ret = diskpool_count(&count);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        if (count > 0) {
                DINFO("cds count %u, sleep 1\n", count);
                sleep(1);
                goto retry;
        }
#endif

        srv_running = 0;

        if (mds_info.mds_type == MDS_PRIMARY) {
        } else {
                netable_put(&ng.mds_nh, "exit");
        }

        /*__mds_secondary();*/
        /*__redis_stop();*/

        ret = ly_update_status("stopped", -1);
        if (ret)
                UNIMPLEMENTED(__DUMP__);

        return NULL;
}


void mds_exit_handler(int sig)
{
        int ret;
        pthread_t th;
        pthread_attr_t ta;

        if (mds_exiting) {
                DWARN("exiting\n");
                return;
        }

        DINFO("got signal %d, exiting\n", sig);

        mds_exiting = 1;

        (void) pthread_attr_init(&ta);
        (void) pthread_attr_setdetachstate(&ta,PTHREAD_CREATE_DETACHED);

        ret = pthread_create(&th, &ta, __mds_exit, NULL);
        if (ret)
                UNIMPLEMENTED(__DUMP__);
}

int mds_init(const char *home)
{
        (void) home;
        
        ng.mds_nh.type = NET_HANDLE_PERSISTENT;
        ng.mds_nh.u.nid = ng.local_nid;

        //mds_info.version = time(NULL);
        mds_info.mds_type = MDS_PRIMARY;
        mds_info.uptime = time(NULL);

        __mds_master__ = 1;
        net_setadmin(net_getnid());
        
        return 0;
}

static int __mon_master(etcd_lock_t *lock, const char *home)
{
        int ret;

        ret = mds_init(home);
        if (ret)
                GOTO(err_ret, ret);

        ret = ringlock_srv_init();
        if (ret)
                GOTO(err_ret, ret);
        
        while (srv_running) {
                if (!etcd_lock_health(lock)) {
                        DWARN("lock fail\n");
                        EXIT(EAGAIN);
                        ret = EAGAIN;
                        GOTO(err_ret, ret);
                }

                sleep(gloconf.rpc_timeout / 2);

                part_dump(PART_MDS | PART_FRCTL);

                allocator_dump();
        }
        
        return 0;
err_ret:
        return ret;
}

static int __mon_slave(etcd_lock_t *lock)
{
        int ret, idx;
        char master[MAX_NAME_LEN];
        nid_t nid, newnid;
        uint32_t magic;

        __mds_master__ = 0;
        
        ret = etcd_locker(lock, master, &nid, &magic, &idx);
        if (ret) {
                DWARN("get master fail %u %s\n", ret, strerror(ret));
                GOTO(err_ret, ret);
        }
                
        while (srv_running) {
                ret = etcd_lock_watch(lock, master, &newnid, &magic, &idx);
                if (unlikely(ret))
                        GOTO(err_ret, ret);

#if 0
                if (ng.master_magic != magic) {
                        DINFO("set master magic 0x%x --> 0x%x\n", ng.master_magic, magic);
                        ng.master_magic = magic;
                }
#endif

                idx++;

                if (nid_cmp(&nid, &newnid)) {
                        DINFO("master swaped old %s new %s, nid %d %d\n", network_rname(&nid),
                              network_rname(&newnid), nid.id, newnid.id);
                        break;
                }
        }

        return 0;
err_ret:
        return ret;
}

static int __mds_loop(const char *home)
{
        int ret;
        etcd_lock_t lock;
        char buf[MAX_BUF_LEN], key[MAX_PATH_LEN];

        nid2str(buf, net_getnid());
        snprintf(key, MAX_NAME_LEN, "%s/master", ROLE_MDCTL);
        ret = etcd_lock_init(&lock, ETCD_INSTANCE, key, gloconf.rpc_timeout / 2 , -1, -1);
        if (ret)
                GOTO(err_ret, ret);

        while (srv_running) {
                ret = etcd_lock(&lock);
                if (ret) {
                        if (ret == EEXIST) {
                                __mon_slave(&lock);
                                continue;
                        } else {
                                GOTO(err_ret, ret);
                        }
                }

                break;
        }

        ret = __mon_master(&lock, home);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}


static int __mds_prep(const char *home, int daemon)
{
        int ret;
        char path[MAX_PATH_LEN];

        ret = ly_init(daemon, ROLE_MDCTL, -1);
        if (ret)
                GOTO(err_ret, ret);

        ret = path_validate(home, 1, 1);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(path, MAX_NAME_LEN, "%s/status/status.pid", home);
        ret = daemon_pid(path);
        if (ret)
                GOTO(err_ret, ret);

        /*if (gloconf.check_mountpoint && !sy_is_mountpoint(home, REISERFS_SUPER_MAGIC)*/
            /*&& !sy_is_mountpoint(home, EXT4_SUPER_MAGIC)) {*/
                /*ret = ENODEV;*/
                /*GOTO(err_ret, ret);*/
        /*}*/

        ret = ly_update_status("running", -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __mds_stop()
{
        int ret;
        char path[MAX_PATH_LEN];

        ret = ly_update_status("stopping", -1);
        if (ret)
                GOTO(err_ret, ret);

        snprintf(path, MAX_PATH_LEN, "%s/dirty", ng.home);

        DINFO("unlink %s\n", path);

        unlink(path);

        sprintf(path, "/dev/shm/uss/tmp/%s/dirty", ng.name);

        DINFO("unlink %s\n", path);

        unlink(path);

        ret = ly_update_status("stopped", -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int mds_run(void *args)
{
        int ret;
        mds_args_t *mds_args;

        mds_args = args;

        signal(SIGUSR1, mds_signal_handler);
        signal(SIGUSR2, mds_exit_handler);
        signal(SIGTERM, mds_exit_handler);
        signal(SIGHUP, mds_exit_handler);
        signal(SIGKILL, mds_exit_handler);
        signal(SIGINT, mds_exit_handler);

        ret = __mds_prep(mds_args->home, mds_args->daemon);
        if (ret)
                GOTO(err_ret, ret);

        nodeid_t id;
        ret = nodeid_load(&id);
        if (ret)
                GOTO(err_ret, ret);

        nid_t nid = {0};
        nid.id = id;
        net_setnid(&nid);

        ret = core_init(4, CORE_FLAG_PASSIVE | CORE_FLAG_ACTIVE);
        if (ret)
                GOTO(err_ret, ret);
        
        ret = part_register(PART_MDS);
        if (ret)
                GOTO(err_ret, ret);

        ret = ringlock_init(RINGLOCK_MDS);
        if (ret)
                GOTO(err_ret, ret);

        ret = ringlock_rpc_init();
        if (ret)
                GOTO(err_ret, ret);

        ret = part_init(PART_MDS | PART_FRCTL);
        if (ret)
                GOTO(err_ret, ret);

        ret = pa_srv_create();
        if (ret)
                GOTO(err_ret, ret);

        ret = allocator_init();
        if (ret)
                GOTO(err_ret, ret);

        ret = mds_rpc_init();
        if (ret)
                GOTO(err_ret, ret);

        ret = rpc_start(); /*begin serivce*/
        if (ret)
                GOTO(err_ret, ret);
        
        ret = __mds_loop(mds_args->home);
        if (ret)
                GOTO(err_ret, ret);

        ret = __mds_stop();
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int mds_ismaster()
{
        return __mds_master__;
}
