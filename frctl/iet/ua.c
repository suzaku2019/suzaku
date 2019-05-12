/*
 * IET Unit Attention support
 *
 * Copyright (C) 2009 Xie Gang <xiegang112@gmail.com>
 * Copyright (C) 2009 Arne Redlich <arne.redlich@googlemail.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

#define ua_hashfn(lun) ((lun) % ISCSI_UA_HASH_LEN)

static struct ua_entry *__ua_find_hash(struct iscsi_session *sess, u32 lun,
                                     u8 asc, u8 ascq, int match)
{
        struct ua_entry *ua;
        struct list_head *head = &sess->ua_hash[ua_hashfn(lun)];

        list_for_each_entry(ua, head, entry) {
                if (ua->lun == lun) {
                        if (!match)
                                goto found;
                        if (ua->asc == asc && ua->ascq == ascq)
                                goto found;
                }
        }

        return NULL;
found:
        return ua;
}

static struct ua_entry *__ua_get_hash(struct iscsi_session *sess, u32 lun,
                                      u8 asc, u8 ascq, int match)
{
        struct ua_entry *ua;

        ua = __ua_find_hash(sess, lun, asc, ascq, match);
        if (ua)
                list_del_init(&ua->entry);

        return ua;
}

int ua_pending(struct iscsi_session *sess, u32 lun)
{
        struct ua_entry *ua;

        ua = __ua_find_hash(sess, lun, 0, 0, 0);

        iscsi_dump_ua(ua, sess, lun);

        return ua ? 1 : 0;
}

struct ua_entry *ua_get_first(struct iscsi_session *sess, u32 lun)
{
        struct ua_entry *ua;

        ua = __ua_get_hash(sess, lun, 0, 0, 0);

        iscsi_dump_ua(ua, sess, lun);

        return ua;
}

struct ua_entry *ua_get_match(struct iscsi_session *sess, u32 lun,
                              u8 asc, u8 ascq)
{
        struct ua_entry *ua;

        ua = __ua_get_hash(sess, lun, asc, ascq, 1);

        iscsi_dump_ua(ua, sess, lun);

        return ua;
}

void ua_free(struct ua_entry *ua)
{
        if (ua) {
                iscsi_dump_ua(ua, ua->session, ua->lun);
                free(ua);
        }
}
