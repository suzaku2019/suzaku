#include <sys/statvfs.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#define DBG_SUBSYS S_YFSCDS

#include "configure.h"
#include "yfs_conf.h"
#include "chk_proto.h"
#include "disk.h"
#include "cds.h"
#include "md_proto.h"
#include "md_lib.h"
#include "node_proto.h"
#include "ylib.h"
#include "yfscds_conf.h"
#include "yfscli_conf.h"
#include "ynet.h"
#include "diskid.h"
#include "mds_rpc.h"
#include "net_global.h"
#include "msgqueue.h"
#include "dbg.h"

extern net_global_t ng;
//XXX
int overload = 0;
#define OVERLOAD_FLAG "overload"
//XXX

static int __cds_hb(hb_service_t *hbs, const diskid_t *diskid)
{
        int ret;
        struct statvfs fsbuf;
        diskinfo_stat_diff_t diff;

        ret = disk_statvfs(hbs->home, &fsbuf);
        if (ret) {
                GOTO(err_ret, ret);
        }
#if 0
        DUMP_VFSTAT(&fsbuf);
#endif
        //XXX
        if (overload == 1 || CDS_TYPE_CACHE == cds_info.type) {
                fsbuf.f_bfree = 0;
                fsbuf.f_bavail = 0;
                fsbuf.f_ffree = 0;
                fsbuf.f_favail = 0;
        }

        diff.ds_bfree = fsbuf.f_bfree
                - hbs->fsbuf.f_bfree;
        diff.ds_bavail = fsbuf.f_bavail
                - hbs->fsbuf.f_bavail;
        diff.ds_ffree = fsbuf.f_ffree
                - hbs->fsbuf.f_ffree;
        diff.ds_favail = fsbuf.f_favail
                - hbs->fsbuf.f_favail;

        diff.ds_bsize = hbs->fsbuf.f_bsize;

        YASSERT(diff.ds_bsize == 4096);

        DBUG("try to send heartbeat message diff %lld %lld\n",
             (long long)diff.ds_bfree, (long long)diff.ds_bavail);
        ret = mds_rpc_diskhb(diskid, cds_info.tier, (const uuid_t *)&ng.nodeid, &diff);
        if (ret)
                GOTO(err_ret, ret);

        hbs->fsbuf.f_bfree  = fsbuf.f_bfree;
        hbs->fsbuf.f_bavail = fsbuf.f_bavail;
        hbs->fsbuf.f_ffree  = fsbuf.f_ffree;
        hbs->fsbuf.f_favail = fsbuf.f_favail;
        
        return 0;
err_ret:
        return ret;
}

int hb_msger(hb_service_t *hbs, const diskid_t *diskid)
{
        int ret;
        time_t prev, now;

        ret = network_connect(net_getadmin(), &prev, 0, 0);
        if (ret)
                GOTO(err_ret, ret);

        while (srv_running) {
                sleep(10);

                ret = network_connect_mds(0);
                if (ret)
                        GOTO(err_ret, ret);

                ret = network_connect(net_getadmin(), &now, 0, 0);
                if (ret)
                        GOTO(err_ret, ret);

                if (prev != now) {
                        ret = ECONNRESET;
                        GOTO(err_ret, ret);
                }

                prev = now;
                
                ret = __cds_hb(hbs, diskid);
                if (ret) {
                        DWARN("hb fail\n");
                        GOTO(err_ret, ret);
                }
        }

        return 0;
err_ret:
        return ret;
}

static int __cds_join(const diskid_t *diskid, struct statvfs *fsbuf)
{
        diskinfo_stat_t stat;
        FSTAT2DISKSTAT(fsbuf, &stat);
        return mds_rpc_diskjoin(diskid, cds_info.tier, (const uuid_t *)&ng.nodeid, &stat);
}


static void *cds_hb(void *_hbs)
{
        int ret;
        hb_service_t *hbs = _hbs;

        while (srv_running) {
                if (hbs->stop)
                        break;

                DINFO("begin diskjoin ...\n");
                ret = __cds_join(&hbs->diskid, &hbs->fsbuf);
                if (ret) {
                        DBUG("ret (%d) %s\n", ret, strerror(ret));

                        if (ret == EAGAIN) {
                                netable_put(&ng.mds_nh, "cds rejoin busy");
                        }

                        sleep(random() % 9);
                        goto reconnect;
                }

#if 1
                int idx;
                ret = disk2idx(&hbs->diskid, &idx);
                if (ret) {
                        goto out;
                }
#endif
                
                DINFO("disk[%d] join ok...\n", idx);

                if (hbs->running == 0) {
                        hbs->running = 1;
                        
                        sem_post(&hbs->sem);
                }

                hb_msger(hbs, &hbs->diskid);

                if (hbs->running == 0) {
                        goto out;
                }

        reconnect:
                if (srv_running) {
                        ret = network_connect_mds(0);
                        if (ret) {
                                DERROR("connect fail\n");
                                sleep(10);
                                goto reconnect;
                        }
                }
        }

        hbs->running = 0;

out:
        sem_post(&hbs->sem);

        pthread_exit(NULL);
}

int hb_service_init(hb_service_t *hbs, const diskid_t *diskid, const char *path)
{
        int ret;
        struct stat stbuf;
        char dpath[MAX_PATH_LEN];
        pthread_t th;
        pthread_attr_t ta;

        YASSERT(diskid->id);
        
        (void) sem_init(&hbs->sem, 0, 0);

        hbs->stop = 0;
        hbs->running = 0;
        hbs->diskid = *diskid;
        strcpy(hbs->home, path);

        ret = disk_statvfs(hbs->home, &hbs->fsbuf);
        if (ret) {
                GOTO(err_sem, ret);
        }

        DBUG("diskfree %llu ffree %llu aval %llu\n",
              (LLU)hbs->fsbuf.f_bsize * (LLU)hbs->fsbuf.f_bavail,
             (LLU)hbs->fsbuf.f_ffree, (LLU)hbs->fsbuf.f_favail);

        // This cds overload flag is true
        // XXX
        snprintf(dpath, MAX_PATH_LEN, "%s/%s",
                 ng.home, OVERLOAD_FLAG);

        if (stat(dpath, &stbuf) == 0) {
                overload = 1;
                DWARN("%s found, set to ro mode \n", dpath);
        } else {
                overload = 0;
                DBUG("%s not found, set to rw mode\n", dpath);
        }

        YASSERT(strlen(ng.home) != 0);

        (void) pthread_attr_init(&ta);
        (void) pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);
        
        ret = pthread_create(&th, &ta, cds_hb, hbs);
        if (ret)
                GOTO(err_ret, ret);

        _sem_wait(&hbs->sem);

        if (hbs->running == 1) {
                DBUG("cds heartbeats thread started\n");
        } else {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        hbs->inited = 1;

        return 0;
err_sem:
        (void) sem_destroy(&hbs->sem);

err_ret:
        return ret;
}

int hb_service_destroy(hb_service_t *hbs)
{
        int ret;

        DINFO("wait for cds hb destroy...\n");

        hbs->running = 0;

        while (1) {
                ret = sem_wait(&hbs->sem);
                if (ret) {
                        ret = errno;
                        if (ret == EINTR)
                                continue;
                        else
                                GOTO(err_ret, ret);
                }

                break;
        }

        DINFO("cds hb destroyed\n");

        return 0;
err_ret:
        return ret;
}
