/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 *
 * This code is licenced under the GPL.
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "dbg.h"

int param_list_build(struct list_head *head, struct iscsi_cmd *cmd)
{
        struct iscsi_tio *tio = cmd->tio;
        struct iscsi_param_node *node;
        char *data, buf[MAX_BUF_LEN];
        char *key, *value, *save;
        u32 datasize;

        if (!tio || !tio->buffer.len)
                goto out;

        datasize = tio->buffer.len;
        data = buf;
        mbuffer_popmsg(&tio->buffer, buf, datasize);

        while (1) {
                for (key = data; datasize > 0 && *data != '='; ++data, --datasize)
                        ;
                if (!datasize)
                        break;

                save = data;
                *save = 0;
                ++data;
                --datasize;

                for (value = data; datasize > 0 && *data != 0; ++data, --datasize)
                        ;
                if (!datasize)
                        break;

                ++data;
                --datasize;

                node = malloc(sizeof(*node));
                if (node) {
                        node->key = strdup(key);
                        node->val = strdup(value);
                        list_add_tail(&node->entry, head);
                }
                *save = '=';
        }

out:
        return 0;
}

void param_list_destroy(struct list_head *head)
{
        struct iscsi_param_node *node, *tmp;

        list_for_each_entry_safe(node, tmp, head, entry) {
                list_del_init(&node->entry);
                free(node->key);
                free(node->val);
                free(node);
        }
        YASSERT(list_empty(head));
}

char *param_list_find(struct list_head *head, char *key)
{
        struct iscsi_param_node *node;

        list_for_each_entry(node, head, entry) {
                if (!strcmp(node->key, key))
                        return node->val;
        }
        return NULL;
}

int param_index_by_name(char *name, struct iscsi_key *keys, int *index)
{
        int i, ret = ENOENT;

        for (i = 0; keys[i].name; ++i) {
                if (!strcasecmp(keys[i].name, name)) {
                        if (index)
                                *index = i;
                        goto find;
                }
        }

        return ret;
find:
        return 0;
}

void param_set_defaults(struct iscsi_param *params, struct iscsi_key *keys)
{
        int i;

        for (i = 0; keys[i].name; ++i)
                params[i].val = keys[i].def;
}

void param_adjust_sess(struct iscsi_param *params, struct iscsi_sess_param *sess_param)
{
#define SESS_PARAM_SET(p, sp, parameter) \
        p[key_##parameter].val = sp->parameter;

        SESS_PARAM_SET(params, sess_param, initial_r2t);
        SESS_PARAM_SET(params, sess_param, immediate_data);
        SESS_PARAM_SET(params, sess_param, max_connections);
        SESS_PARAM_SET(params, sess_param, max_recv_data_length);
        SESS_PARAM_SET(params, sess_param, max_xmit_data_length);
        SESS_PARAM_SET(params, sess_param, max_burst_length);
        SESS_PARAM_SET(params, sess_param, first_burst_length);
        SESS_PARAM_SET(params, sess_param, default_wait_time);
        SESS_PARAM_SET(params, sess_param, default_retain_time);
        SESS_PARAM_SET(params, sess_param, max_outstanding_r2t);
        SESS_PARAM_SET(params, sess_param, data_pdu_inorder);
        SESS_PARAM_SET(params, sess_param, data_sequence_inorder);
        SESS_PARAM_SET(params, sess_param, error_recovery_level);
        SESS_PARAM_SET(params, sess_param, header_digest);
        SESS_PARAM_SET(params, sess_param, data_digest);
        SESS_PARAM_SET(params, sess_param, ofmarker);
        SESS_PARAM_SET(params, sess_param, ifmarker);
        SESS_PARAM_SET(params, sess_param, ofmarkint);
        SESS_PARAM_SET(params, sess_param, ifmarkint);

        SESS_PARAM_SET(params, sess_param, rdma_extensions);
        SESS_PARAM_SET(params, sess_param, target_recv_data_length);
        SESS_PARAM_SET(params, sess_param, initiator_recv_data_length);
        SESS_PARAM_SET(params, sess_param, max_outstanding_unexpected_pdus);
}

void param_partial_set(struct iscsi_sess_param *param, int idx, u32 val)
{
#define SESS_PARAM_CASE_SET(p, value, parameter) \
        case key_##parameter: \
                p->parameter = value; \
                break;

        switch (idx) {
                SESS_PARAM_CASE_SET(param, val, initial_r2t);
                SESS_PARAM_CASE_SET(param, val, immediate_data);
                SESS_PARAM_CASE_SET(param, val, max_connections);
                SESS_PARAM_CASE_SET(param, val, max_recv_data_length);
                SESS_PARAM_CASE_SET(param, val, max_xmit_data_length);
                SESS_PARAM_CASE_SET(param, val, max_burst_length);
                SESS_PARAM_CASE_SET(param, val, first_burst_length);
                SESS_PARAM_CASE_SET(param, val, default_wait_time);
                SESS_PARAM_CASE_SET(param, val, default_retain_time);
                SESS_PARAM_CASE_SET(param, val, max_outstanding_r2t);
                SESS_PARAM_CASE_SET(param, val, data_pdu_inorder);
                SESS_PARAM_CASE_SET(param, val, data_sequence_inorder);
                SESS_PARAM_CASE_SET(param, val, error_recovery_level);
                SESS_PARAM_CASE_SET(param, val, header_digest);
                SESS_PARAM_CASE_SET(param, val, data_digest);
                SESS_PARAM_CASE_SET(param, val, ofmarker);
                SESS_PARAM_CASE_SET(param, val, ifmarker);
                SESS_PARAM_CASE_SET(param, val, ofmarkint);
                SESS_PARAM_CASE_SET(param, val, ifmarkint);
        }
}

static int range_val_to_str(u32 val, char *str)
{
        sprintf(str, "%u", val);
        return 0;
}

static int range_str_to_val(char *str, u32 *val)
{
        *val = strtol(str, NULL, 0);
        return 0;
}

static int bool_val_to_str(u32 val, char *str)
{
        int ret = 0;

        switch (val) {
        case 0:
                strcpy(str, "No");
                break;
        case 1:
                strcpy(str, "Yes");
                break;
        default:
                ret = EINVAL;
                break;
        }

        return ret;
}

static int bool_str_to_val(char *str, u32 *val)
{
        int ret = 0;

        if (!strcmp(str, "No"))
                *val = 0;
        else if (!strcmp(str, "Yes"))
                *val = 1;
        else
                ret = EINVAL;

        return ret;
}

static int or_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        *val |= param[idx].val;
        param[idx].val = *val;

        return 0;
}

static int and_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        *val &= param[idx].val;
        param[idx].val = *val;

        return 0;
}

static int minimum_check_val(struct iscsi_key *key, u32 *val)
{
        int ret = 0;

        if (*val < key->min || key->max < *val) {
                *val = key->min;
                ret = EINVAL;
        }

        return ret;
}

static int min_or_zero_check_val(struct iscsi_key *key, unsigned int *val)
{
        int err = 0;

        if (*val != 0 && (*val < key->min || key->max < *val)) {
                *val = key->min;
                err = -EINVAL;
        }

        return err;
}

static int maximum_check_val(struct iscsi_key *key, u32 *val)
{
        int ret = 0;

        if (*val < key->min || key->max < *val) {
                *val = key->max;
                ret = EINVAL;
        }

        return ret;
}

static int minimum_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        if (*val > param[idx].val)
                *val = param[idx].val;
        else
                param[idx].val = *val;

        return 0;
}

static int maximum_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        if (param[idx].val > *val)
                *val = param[idx].val;
        else
                param[idx].val = *val;

        return 0;
}

static int min_or_zero_set_val(struct iscsi_param *param, int idx, unsigned int *val)
{
        if (*val > param[idx].val || *val == 0)
                *val = param[idx].val;
        else
                param[idx].val = *val;

        return 0;
}

static int digest_val_to_str(u32 val, char *str)
{
        int ret = 0;

        if (val & DIGEST_NONE)
                strcpy(str, "None");
        if (val & DIGEST_CRC32C) {
                if (strlen(str))
                        strcat(str, ",CRC32C");
                else
                        strcpy(str, "CRC32C");
        }
        if (!strlen(str))
                ret = EINVAL;

        return ret;
}

static int digest_str_to_val(char *str, u32 *val)
{
        int ret = 0;
        char *p, *q;
        p = str;

        *val = 0;
        do {
                q = strsep(&p, ",");
                if (!strcmp(q, "None"))
                        *val |= DIGEST_NONE;
                else if (!strcmp(q, "CRC32C"))
                        *val |= DIGEST_CRC32C;
                else {
                        ret = EINVAL;
                        break;
                }
        } while (p);

        return ret;
}

static int digest_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        if (*val & DIGEST_CRC32C && param[idx].val & DIGEST_CRC32C)
                *val = DIGEST_CRC32C;
        else
                *val = DIGEST_NONE;

        param[idx].val = *val;

        return 0;
}

static int marker_val_to_str(u32 val, char *str)
{
        if (val == 0)
                strcpy(str, "Irrelevant");
        else
                strcpy(str, "Reject");

        return 0;
}

static int marker_set_val(struct iscsi_param *param, int idx, u32 *val)
{
        if ((idx == key_ofmarkint && param[key_ofmarker].state == KEY_STATE_DONE)
            || (idx == key_ifmarkint && param[key_ifmarker].state == KEY_STATE_DONE))
                *val = 0;
        else
                *val = 1;

        param[idx].val = *val;

        return 0;
}

int param_val_to_str(struct iscsi_key *keys, int idx, u32 val, char *str)
{
        int ret = 0;

        if (keys[idx].ops->val_to_str)
                ret = keys[idx].ops->val_to_str(val, str);

        return ret;
}

int param_str_to_val(struct iscsi_key *keys, int idx, char *str, u32 *val)
{
        int ret = 0;

        if (keys[idx].ops->str_to_val)
                ret = keys[idx].ops->str_to_val(str, val);

        return ret;
}

int param_check_val(struct iscsi_key *keys, int idx, u32 *val)
{
        int ret = 0;

        if (keys[idx].ops->check_val)
                ret = keys[idx].ops->check_val(&keys[idx], val);

        return ret;
}

int param_set_val(struct iscsi_key *keys, struct iscsi_param *param,
                  int idx, u32 *val)
{
        int ret = 0;

        if (keys[idx].ops->set_val)
                ret = keys[idx].ops->set_val(param, idx, val);

        return ret;
}

static struct iscsi_key_ops minimum_ops = {
        .val_to_str = range_val_to_str,
        .str_to_val = range_str_to_val,
        .check_val = minimum_check_val,
        .set_val = minimum_set_val,
};

static struct iscsi_key_ops min_or_zero_ops = {
        .val_to_str = range_val_to_str,
        .str_to_val = range_str_to_val,
        .check_val = min_or_zero_check_val,
        .set_val = min_or_zero_set_val,
};

static struct iscsi_key_ops maximum_ops = {
        .val_to_str = range_val_to_str,
        .str_to_val = range_str_to_val,
        .check_val = maximum_check_val,
        .set_val = maximum_set_val,
};

static struct iscsi_key_ops or_ops = {
        .val_to_str = bool_val_to_str,
        .str_to_val = bool_str_to_val,
        .set_val = or_set_val,
};

static struct iscsi_key_ops and_ops = {
        .val_to_str = bool_val_to_str,
        .str_to_val = bool_str_to_val,
        .set_val = and_set_val,
};

static struct iscsi_key_ops digest_ops = {
        .val_to_str = digest_val_to_str,
        .str_to_val = digest_str_to_val,
        .set_val = digest_set_val,
};

static struct iscsi_key_ops marker_ops = {
        .val_to_str = marker_val_to_str,
        .set_val = marker_set_val,
};

#define SET_KEY_VALUES(x)       DEFAULT_##x, MIN_##x, MAX_##x

struct iscsi_key target_keys [] = {
        { "QueuedCommands", SET_KEY_VALUES(NR_QUEUED_CMDS),                      &minimum_ops , 0},
        { "Type",           ISCSI_TARGET_TYPE_DISK, 0, ISCSI_TARGET_TYPE_NR_MAX, &minimum_ops , 0},
        { NULL,             0,                      0, 0,                        NULL         , 0},
};

/*
 * DON'T CHANGE THIS !
 *
 * The RFC specify params, see rfc3720 for detail.
 */
struct iscsi_key session_keys [] = {
        /*   name         |          def     |    min     |    max     |      ops       */
        { "InitialR2T",               1,           0,           1,          &or_ops      , 0},
        { "ImmediateData",            1,           0,           1,          &and_ops     , 0},
        { "MaxConnections",           1,           1,           65535,      &minimum_ops , 0},
        { "MaxRecvDataSegmentLength", 8192,        512,         16777215,   &minimum_ops , 0},
        { "MaxXmitDataSegmentLength", 8192,        512,         16777215,   &minimum_ops , 0},
        { "MaxBurstLength",           262144,      512,         16777215,   &minimum_ops , 0},
        { "FirstBurstLength",         65536,       512,         16777215,   &minimum_ops , 0},
        { "DefaultTime2Wait",         2,           0,           3600,       &maximum_ops , 0},
        { "DefaultTime2Retain",       20,          0,           3600,       &minimum_ops , 0},
        { "MaxOutstandingR2T",        1,           1,           65535,      &minimum_ops , 0},
        { "DataPDUInOrder",           1,           0,           1,          &or_ops      , 0},
        { "DataSequenceInOrder",      1,           0,           1,          &or_ops      , 0},
        { "ErrorRecoveryLevel",       0,           0,           2,          &minimum_ops , 0},
        { "HeaderDigest",             DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, &digest_ops  , 0},
        { "DataDigest",               DIGEST_NONE, DIGEST_NONE, DIGEST_ALL, &digest_ops  , 0},
        { "OFMarker",                 0,           0,           1,          &and_ops     , 0},
        { "IFMarker",                 0,           0,           1,          &and_ops     , 0},
        { "OFMarkInt",                2048,        1,           65535,      &marker_ops  , 0},
        { "IFMarkInt",                2048,        1,           65535,      &marker_ops  , 0},

        /* iSER draft */
        {"RDMAExtensions",            0,           0,           1,          &and_ops     ,      1},
        {"TargetRecvDataSegmentLength", 8192,      512,         16777215,   &minimum_ops ,      1},
        {"InitiatorRecvDataSegmentLength", 8192,   512,         16777215,   &minimum_ops ,      1},
        {"MaxOutstandingUnexpectedPDUs", 0,        2,           4294967295U, &min_or_zero_ops,  1},

        { NULL,                       0,           0,           0,          NULL         , 0},
};
