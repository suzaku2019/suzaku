/*
 * Volume manager
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

static struct iscsi_volume *
__volume_find(struct iscsi_target *target, u32 lun)
{
        struct iscsi_volume *volume;

        list_for_each_entry(volume, &target->volume_list, entry) {
                if (volume->lun == lun) {
                        return volume;
                }
        }

        return NULL;
}

static void gen_scsi_id(fileid_t *fid, struct iscsi_volume *volume)
{
        uint32_t version = 0;

        /*
         * | 8-bytes id | 4-bytes version | 4-bytes lun |
         */
        YASSERT(sizeof(fid->id) == 8);

        if(volume->target->vaai_enabled) {        //12 bytes for scsi_id and ieee.id.
                uint32_t cluster_id = 0;
                
                /*for(int i=0;i<sizeof(gloconf.uuid);i++){
                        cluster_id = (cluster_id << 1) + gloconf.uuid[i];
                }*/
#if 1
                UNIMPLEMENTED(__WARN__);
                cluster_id = 0;
#else
                cluster_id = gloconf.cluster_id;
#endif

                memset(volume->scsi_id, 0, sizeof(volume->scsi_id));

                memcpy(volume->scsi_id, &fid->id, sizeof(fid->id));     //8bytes.
                memcpy(volume->scsi_id + sizeof(fid->id), &cluster_id, sizeof(cluster_id));
        }
        else {
                memcpy(volume->scsi_id, &fid->id, sizeof(fid->id));
                memcpy(volume->scsi_id + sizeof(fid->id), &version, sizeof(version));
                memcpy(volume->scsi_id + sizeof(fid->id) + sizeof(version),&volume->lun, sizeof(volume->lun));
        }
}

static void gen_scsi_sn(struct iscsi_volume *volume)
{
        int i;

        for (i = 0; i < SCSI_ID_LEN; ++i)
                snprintf((char *)(volume->scsi_sn) + (i * 2), 3, "%02x", volume->scsi_id[i]);
}

static int __volume_create(struct iscsi_target *target, struct sdfs_lun_entry *lu)
{
        int ret;
        struct iscsi_volume *volume;

        ret = ymalloc((void **)&volume, sizeof(struct iscsi_volume));
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        /* Use the YFS iotype */
        volume->target = target;
        snprintf(volume->tname, sizeof(volume->tname), "%s", target->name);

        volume->lun = lu->lun;
        volume->fileid = lu->fileid;
        volume->iotype = &lich_io;
        volume->unavailable = 0;

        ret = volume->iotype->attach(volume, lu);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        INIT_LIST_HEAD(&volume->queue.wait_list);

        volume->stat = IDEV_RUNNING;

        atomic_set(&volume->count, 1);

        gen_scsi_id(&target->fileid, volume);
        gen_scsi_sn(volume);

        target_add_lun_nolock(target, volume);

        DINFO("target "CHKID_FORMAT" %s volume "CHKID_FORMAT" %s/%u created, rest %u\n",
              CHKID_ARG(&target->fileid), target->name,
              CHKID_ARG(&volume->fileid), volume->tname, lu->lun, (u32)atomic_read(&target->nr_volumes));

        return 0;
err_ret:
        return ret;
}

static void __volume_destroy(struct iscsi_volume *volume)
{

        DINFO("volume "CHKID_FORMAT" %s/%u removing ...\n",
              CHKID_ARG(&volume->fileid), volume->tname, volume->lun);

        target_del_lun_nolock(volume->target, volume);
        volume->iotype->detach(volume);

        yfree((void **)&volume);
}

struct iscsi_volume *volume_get(struct iscsi_target *target, u32 lun)
{
        struct iscsi_volume *volume;

        DBUG("the target id is %u and name is %s lun id is %u\n", target->tid, target->name, lun);

        volume = __volume_find(target, lun);
        if (volume) {
                if (volume->stat == IDEV_RUNNING) {
                        atomic_inc(&volume->count);
                } else
                        volume = NULL;
        }

        if (!volume){
                DBUG("the target id is NULL and name is %s lun id is %u\n", target->name, lun);
        } else {
                DBUG("the target id is not NULL and name is %s lun id is %u\n", target->name, volume->lun);
        }

        return volume;
}

static void __volume_put(struct iscsi_volume *volume)
{
        if (atomic_dec_and_test(&volume->count))
                __volume_destroy(volume);
}

void volume_put(struct iscsi_volume *volume)
{
        __volume_put(volume);
}

void volume_del(struct iscsi_volume *volume)
{
        __volume_destroy(volume);
}

void volume_apply_change(struct iscsi_target *target, struct list_head *head)
{
        int ret;
        struct iscsi_volume *volume, *tmp;
        struct sdfs_lun_entry *lu;

        list_for_each_entry_safe(volume, tmp, &target->volume_list, entry) {
                lu = sdfs_lun_find(head, volume->lun, &volume->fileid);
                if (!lu) {
                        DINFO("%s/%u is to be removed ...\n", target->name, volume->lun);

                        if (volume->stat != IDEV_DEL) {
                                volume->stat = IDEV_DEL;
                                __volume_put(volume);
                        }
                }
        }

        list_for_each_entry(lu, head, entry) {
                //if (lu->delay_check)
                //        continue;

                volume = __volume_find(target, lu->lun);
                if (likely(volume)) {
                        ret = volume->iotype->update(volume, lu);
                        if (unlikely(ret)) {
                                DWARN("%s/%u update failed (%d)\n", target->name, lu->lun, ret);
                                continue;
                        }
                } else {
                        ret = __volume_create(target, lu);
                        if (unlikely(ret)) {
                                DWARN("%s/%u add failed (%d)\n", target->name, lu->lun, ret);
                                continue;
                        }
                }
        }
}

int volume_is_reserved(struct iscsi_volume *volume, u64 sid)
{
	int err = 0;

	if (!volume)
		return -ENOENT;

	if (!volume->reserve_sid || volume->reserve_sid == sid)
		err = 0;
	else
		err = -EBUSY;

	return err;
}

int volume_reserve(struct iscsi_volume *volume, u64 sid)
{
        int err = 0;

        if (!volume) {
                err = ENOENT;
                goto out;
        }

        if (volume->reserve_sid && volume->reserve_sid != sid)
                err = EBUSY;
        else
                volume->reserve_sid = sid;

out:
        return err;
}

int volume_release(struct iscsi_volume *volume, u64 sid, int force)
{
        int err = 0;

        if (!volume) {
                err = ENOENT;
                goto out;
        }

        if (force || volume->reserve_sid == sid)
                volume->reserve_sid = 0;
        else
                err = EBUSY;

out:
        return err;
}
