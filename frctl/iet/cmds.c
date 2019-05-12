#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "schedule.h"
#include "dbg.h"
/** ,====================
 * /  ASYNC
 * `==============================
 */

/*
 * An Asynchronous Message may be sent from the target to the initiator without
 * correspondence to a particular command. The target specifies the reason for
 * the event and sense data.
 */

static int cmd_async_tx_start(struct iscsi_cmd *cmd)
{
        iscsi_cmd_set_sn(cmd, 1);
        return 0;
}

static int cmd_async_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_async = {
        .name     = "async",
        .req_op   = -1,
        .rsp_op   = ISCSI_OP_ASYNC,
        .tx_start = cmd_async_tx_start,
        .tx_end   = cmd_async_tx_end,
};

/** ,====================
 * /  LOGIN
 * `==============================
 */

static struct iscsi_key login_keys[] = {
        { "InitiatorName",  0, 0, 0, NULL , 0},
        { "InitiatorAlias", 0, 0, 0, NULL , 0},
        { "SessionType",    0, 0, 0, NULL , 0},
        { "TargetName",     0, 0, 0, NULL , 0},
        { NULL,             0, 0, 0, NULL , 0},
};

static char *initiator_strerror_map[] = {
        "Initiator error",              /* 0 */
        "Auth failed",                  /* 1 */
        "Target forbidden",             /* 2 */
        "Target not found",             /* 3 */
        "Target removed",               /* 4 */
        "No version",                   /* 5 */
        "Too many connections",         /* 6 */
        "Missing fields",               /* 7 */
        "Connection add failed",        /* 8 */
        "Invalid session type",         /* 9 */
        "Session not found",            /* 10 */
        "Invalid request type",         /* 11 */
};

static char *target_strerror_map[] = {
        "Target error",                 /* 0 */
        "Server unavailable",           /* 1 */
        "No resources",                 /* 2 */
};

static char *login_strerror(int class, int detail)
{
        if (class == ISCSI_STATUS_INITIATOR_ERR) {
                if (detail >= 0 && detail < (int)(sizeof(initiator_strerror_map) / sizeof(initiator_strerror_map[0]))) {
                        return initiator_strerror_map[detail];
                }
        } else if (class == ISCSI_STATUS_TARGET_ERR) {
                if (detail >= 0 && detail < (int)(sizeof(target_strerror_map) / sizeof(target_strerror_map[0]))) {
                        return target_strerror_map[detail];
                }
        }

        return NULL;
}

static void login_rsp_err(struct iscsi_cmd *rsp, int class, int detail)
{
        char *strerr;
        struct iscsi_conn *conn = rsp->conn;
        struct iscsi_login_rsp_hdr *rsp_hdr = (struct iscsi_login_rsp_hdr *)&rsp->pdu.bhs;

        strerr = login_strerror(class, detail);

        if (class != ISCSI_STATUS_REDIRECT) {
                DERROR("%s:%d login target %s failed: %s (0x%x, 0x%x)\n",
                        _inet_ntop((struct sockaddr *)&conn->peer),
                        ntohs(conn->peer.sin_port),
                        conn->tname,
                        strerr ? strerr : "",
                        class, detail);
                SERROR(0, "%s, %s:%d login target %s failed: %s (0x%x, 0x%x)\n",
                        M_PROTO_ISCSI_LOGIN_ERROR,
                        _inet_ntop((struct sockaddr *)&conn->peer),
                        ntohs(conn->peer.sin_port),
                        conn->tname,
                        strerr ? strerr : "",
                        class, detail);
        }

        rsp_hdr->flags = 0;
        rsp_hdr->status_class = class;
        rsp_hdr->status_detail = detail;
        conn->state = STATE_EXIT;
}

static void login_rsp_ini_err(struct iscsi_cmd *rsp, int detail)
{
        login_rsp_err(rsp, ISCSI_STATUS_INITIATOR_ERR, detail);
}

static void login_rsp_tgt_err(struct iscsi_cmd *rsp, int detail)
{
        login_rsp_err(rsp, ISCSI_STATUS_TARGET_ERR, detail);
}

static int text_check_param(struct iscsi_cmd *rsp)
{
        struct iscsi_conn *conn = rsp->conn;
        struct iscsi_param *p = conn->session_param;
        char buf[32];
        int i, cnt;

        for (i = 0, cnt = 0; session_keys[i].name && !session_keys[i].mask; ++i) {      //iscsi is not allowed to send iser extension.
                if (p[i].state == KEY_STATE_START && p[i].val != session_keys[i].def) {
                        switch (conn->state) {
                        case STATE_LOGIN_FULL:
                        case STATE_SECURITY_FULL:
                                if (i == key_max_xmit_data_length) {
                                        if (p[i].val > session_keys[i].def)
                                                p[i].val = session_keys[i].def;
                                        p[i].state = KEY_STATE_DONE;
                                        continue;
                                }
                                break;
                        case STATE_LOGIN:
                                if (i == key_max_xmit_data_length)
                                        continue;
                                memset(buf, 0x00, sizeof(buf));
                                param_val_to_str(session_keys, i, p[i].val, buf);
                                tio_add_param(rsp, session_keys[i].name, buf);
                                if (i == key_max_recv_data_length) {
                                        p[i].state = KEY_STATE_DONE;
                                        continue;
                                }
                                p[i].state = KEY_STATE_REQUEST;
                                break;
                        default:
                                if (i == key_max_xmit_data_length)
                                        continue;
                        }
                        ++cnt;
                }
        }

        return cnt;
}

int account_empty(struct iscsi_conn *conn, int dir)
{
        char pass[MAX_BUF_LEN];

        memset(pass, 0x00, sizeof(pass));
        return cops->account_query(conn, dir, pass, pass) ? 1 : 0;
}

static void text_scan_security(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        char *key, *val, *next_value;
        struct iscsi_conn *conn = req->conn;
        struct iscsi_param_node *node;

        list_for_each_entry(node, &conn->param_list, entry) {
                key = node->key;
                val = node->val;
                if (param_index_by_name(key, login_keys, NULL) == 0)
                        ;
                else if (!strcmp(key, "AuthMethod")) {
                        do {
                                next_value = strchr(val, ',');
                                if (next_value)
                                        *next_value++ = 0;

                                if (!strcmp(val, "None")) {
                                        if (conn->session_type != SESSION_DISCOVERY && !account_empty(conn, AUTH_DIR_INCOMING))
                                                continue;
                                        conn->auth_method = AUTH_NONE;
                                        tio_add_param(rsp, key, "None");
                                        break;
                                } else if (!strcmp(val, "CHAP")) {
                                        if (conn->session_type != SESSION_NORMAL && account_empty(conn, AUTH_DIR_INCOMING)) {
                                                continue;
                                        }
                                        conn->auth_method = AUTH_CHAP;
                                        tio_add_param(rsp, key, "CHAP");
                                        break;
                                }
                        } while ((val = next_value));

                        if (conn->auth_method == AUTH_UNKNOWN) {
                                tio_add_param(rsp, key, "Reject");
                        }
                } else
                        tio_add_param(rsp, key, "NotUnderStood");
        }
        if (conn->auth_method == AUTH_UNKNOWN) {
                DWARN(" auth method: AUTH_UNKNOWN !!!\n");
                login_rsp_ini_err(rsp, ISCSI_STATUS_AUTH_FAILED);
        }
}

static void login_security_done(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret, retry = 0;
        struct iscsi_login_req_hdr *req_hdr;
        struct iscsi_conn *conn = req->conn;
        struct iscsi_session *sess;

        req_hdr = (struct iscsi_login_req_hdr *)&req->pdu.bhs;

        if (conn->session_type == SESSION_DISCOVERY)
                return;

retry1:
        if ((sess= session_find_by_name(conn->initiator, req_hdr->sid, &conn->target->fileid))) {
                DWARN("session found %s:%d sid:%lx tsih:%u, sesstsih:%u cid:%d tid:"CHKID_FORMAT" "CHKID_FORMAT"\n",
                                _inet_ntop((struct sockaddr *)&conn->peer), ntohs(conn->peer.sin_port),
                                req_hdr->sid.id64, req_hdr->sid.id.tsih, sess->sid.id.tsih,
                                conn->cid, CHKID_ARG(&sess->target->fileid), CHKID_ARG(&conn->target->fileid));

                if (!req_hdr->sid.id.tsih) {
                        /* do session reinstatement */
                        DBUG("session %#" PRIx64 " reinstated",
                                                                req_hdr->sid.id64);
                        ret = session_remove(sess);
                        if (unlikely(ret)) {
                                if (ret == EAGAIN) {
                                        USLEEP_RETRY(err_ret, ret, retry1, retry, 30, (1000 * 1000));
                                } else
                                        login_rsp_tgt_err(rsp, ISCSI_STATUS_TARGET_ERROR);
                        }

                        return;
                } else if (req_hdr->sid.id.tsih != sess->sid.id.tsih) {
                        /* fail the login */
                        login_rsp_ini_err(rsp, ISCSI_STATUS_SESSION_NOT_FOUND);
                        return;
                }

                /* Currently not support session reuse */
                YASSERT(0);

                /* add connection to existing session */
                /* reinstatement handled in kernel */
                DBUG("connection %u added to session %#" PRIx64,
                                                conn->cid, req_hdr->sid.id64);
                retry = 0;
        retry2:
                ret = conn_add(sess, conn);
                if (unlikely(ret)) {
                        if (ret == EAGAIN) {
                                USLEEP_RETRY(err_ret, ret, retry2, retry, 30, (1000 * 1000));
                        } else
                                login_rsp_tgt_err(rsp, ISCSI_STATUS_TARGET_ERROR);
                }

                conn->session = sess;
        } else {
                DWARN("session not found tsih:%u\n", req_hdr->sid.id.tsih);
                if (req_hdr->sid.id.tsih) {
                        /* fail the login */
                        login_rsp_ini_err(rsp, ISCSI_STATUS_SESSION_NOT_FOUND);
                        return;
                }
                /* instantiate a new session */
        }

        return;
err_ret:
        EXIT(EAGAIN); /* ther right way is exit all task from corenet */
        login_rsp_tgt_err(rsp, ISCSI_STATUS_TARGET_ERROR);
        return;
}

static void text_scan_login(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret, idx;
        char *key, *value;
        struct iscsi_conn *conn = req->conn;
        struct iscsi_param_node *node;

        list_for_each_entry(node, &conn->param_list, entry) {
                key = node->key;
                value = node->val;
                if (param_index_by_name(key, login_keys, NULL) == 0)
                        ;
                else if (!strcmp(key, "AuthMethod"))
                        ;
                else if (param_index_by_name(key, session_keys, &idx) == 0) {
                        unsigned int val;
                        char buf[32];

                        if (idx == key_max_xmit_data_length) {
                                tio_add_param(rsp, key, "NotUnderStood");
                                continue;
                        }
                        if (idx == key_max_recv_data_length)
                                idx = key_max_xmit_data_length;

                        ret = param_str_to_val(session_keys, idx, value, &val);
                        if (unlikely(ret)) {
                                if (conn->session_param[idx].state == KEY_STATE_START) {
                                        tio_add_param(rsp, key, "Reject");
                                        continue;
                                } else
                                        goto init_err;
                        }

                        param_check_val(session_keys, idx, &val);
                        param_set_val(session_keys, conn->session_param, idx, &val);

                        switch (conn->session_param[idx].state) {
                        case KEY_STATE_START:
                                if (idx == key_max_xmit_data_length)
                                        break;
                                memset(buf, 0x00, sizeof(buf));
                                param_val_to_str(session_keys, idx, val, buf);
                                tio_add_param(rsp, key, buf);
                                break;
                        case KEY_STATE_REQUEST:
                                if (val != conn->session_param[idx].val) {
                                        DWARN("%s %u %u\n", key,
                                              val, conn->session_param[idx].val);
                                        goto init_err;
                                }
                                break;
                        case KEY_STATE_DONE:
                                break;
                        }
                        conn->session_param[idx].state = KEY_STATE_DONE;
                } else
                        tio_add_param(rsp, key, "NotUnderStood");
        }

        return;
init_err:
        login_rsp_ini_err(rsp, ISCSI_STATUS_INIT_ERR);
        return;
}

/*
 * A target receiving a Text or Login Request with the C bit set to 1 MUST
 * answer with a Text or Login Response with no data segment (DataSegmentLength
 * 0).
 */
static void login_start(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret;
        struct iscsi_login_req_hdr *req_hdr = (struct iscsi_login_req_hdr *)&req->pdu.bhs;
        struct iscsi_conn *conn = req->conn;
        char *name, *alias __attribute__((unused)), *session_type, *target_name;

        /*
         * Get the CID and ISID from the first login request message
         */
        conn->cid = be16_to_cpu(req_hdr->cid);
        conn->sid.id64 = req_hdr->sid.id64;
        if (!conn->sid.id64) {
                login_rsp_ini_err(rsp, ISCSI_STATUS_MISSING_FIELDS);
                goto out;
        }

        name = param_list_find(&conn->param_list, "InitiatorName");
        if (!name) {
                login_rsp_ini_err(rsp, ISCSI_STATUS_MISSING_FIELDS);
                goto out;
        }

        conn->initiator = strdup(name);
        alias = param_list_find(&conn->param_list, "InitiatorAlias");
        session_type = param_list_find(&conn->param_list, "SessionType");
        target_name = param_list_find(&conn->param_list, "TargetName");

        conn->auth_method = AUTH_UNKNOWN;
        conn->session_type = SESSION_NORMAL;

        /*
         * ISCSI defines two types of sessions:
         * a) Normal operational session - an unrestricted session.
         * b) Discovery-session - a session only opened for target discovery.
         *    The target Must ONLY accept text requests with the SendTargets key
         *    and a logout request with the reason "close the session". All other
         *    request MUST be reject.
         */
        if (session_type) {
                if (!strcmp(session_type, "Discovery"))
                        conn->session_type = SESSION_DISCOVERY;
                else if (strcmp(session_type, "Normal")) {
                        login_rsp_ini_err(rsp, ISCSI_STATUS_INV_SESSION_TYPE);
                        goto out;
                }
        }

        if (conn->session_type == SESSION_NORMAL) {
                struct iscsi_target *target;
                char redirect[NI_MAXHOST + NI_MAXSERV + 4];
                time_t ctime = gettime();

                (void) redirect;
                
                if (!target_name) {
                        login_rsp_ini_err(rsp, ISCSI_STATUS_MISSING_FIELDS);
                        goto out;
                }

                snprintf(conn->tname, sizeof(conn->tname), "%s", target_name);

                ret = target_alloc_by_name(target_name, &target);
                if (unlikely(ret)) {
                        if (ret == ENOENT)
                                login_rsp_ini_err(rsp, ISCSI_STATUS_TGT_NOT_FOUND);
                        else
                                login_rsp_tgt_err(rsp, ISCSI_STATUS_SVC_UNAVAILABLE);
                        goto out;
                }

#if 0
                ret = block_reload(&target->fileid);
                if (unlikely(ret)) {
                        if (ret == ENOENT) {
                                login_rsp_ini_err(rsp, ISCSI_STATUS_TGT_NOT_FOUND);
                                target_free(target);
                                goto out;
                        } else {
                                DERROR(""CHKID_FORMAT": %d:%s\n",
                                       CHKID_ARG(&target->fileid), ret, strerror(ret));
                        }
                }
#endif

                target->ctime = ctime;
                conn->target = target;

#if ENABLE_ISCSI_VIP
                int is_local = target_islocal(target);

                if (netvip_is_vip(conn->conn_fd) || (netvip_in_vipnet(conn->conn_fd) && !is_local)) {
                        ret = target_redirect(conn->conn_fd, target);
                        if (unlikely(ret)) {
                                login_rsp_ini_err(rsp, ISCSI_STATUS_MISSING_FIELDS);
                                target_free(target);
                                goto out;
                        }

                        DINFO("redirected target %s login to %s:%s\n",
                              target->name, target->redirect.addr, target->redirect.port)

                        snprintf(redirect, sizeof(redirect), "%s:%s",
                                 target->redirect.addr, target->redirect.port);
                        tio_add_param(rsp, "TargetAddress", redirect);

                        login_rsp_err(rsp, ISCSI_STATUS_REDIRECT, target->redirect.type);
                        target_free(target);
                        goto out;
                }
#endif

                /*after redirect.*/
                if(unlikely(sanconf.tcp_discovery && !conn->rdma)) {
                        login_rsp_ini_err(rsp, ISCSI_STATUS_TGT_FORBIDDEN);
                        goto out;
                }

#if ENABLE_ISCSI_VIP
#if ISCSI_CHECK_TARGET_CTIME
                time_t now = gettime();

                DINFO("target %s is_local %d used %lds\n", target->name, is_local,
                      now - target->ctime);
                if (!is_local && now - target->ctime > gloconf.lease_timeout) {
                        login_rsp_tgt_err(rsp, ISCSI_STATUS_SVC_UNAVAILABLE);
                        target_free(target);
                        goto out;
                }
#endif
#endif

#ifdef USE_ROW2
                // check local volumes
                //if (is_local) 
                {
                        ret = block_check_ready(&target->fileid);
                        DWARN("target ino %lu %s local %d ret %d\n", target->fileid.id, target->name, is_local, ret);
                        if (unlikely(ret)) {
                                //if (ret == ENOENT) {
                                        //initiator will keep trying.
                                        login_rsp_tgt_err(rsp, ISCSI_STATUS_SVC_UNAVAILABLE);
                                        goto out;
                                //} else {
                               //         DERROR(""CHKID_FORMAT": %d:%s\n",
                                //               CHKID_ARG(&target->fileid), ret, strerror(ret));
                               // }
                        }
                }
#endif

                param_adjust_sess(conn->session_param, &target->sess_param);
        }

        /* Init connection's @exp_cmd_sn */
        conn->exp_cmd_sn = be32_to_cpu(req_hdr->cmd_sn);

        tio_add_param(rsp, "TargetPortalGroupTag", "1");
out:
        return;
}

static void login_finish(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret;
        struct iscsi_conn *conn = req->conn;

        if (!conn->session) {
                ret = session_create(conn);
                if (unlikely(ret)) {
                        login_rsp_tgt_err(rsp, ISCSI_STATUS_TARGET_ERROR);
                        goto out;
                }
        } else {
                conn->sid = conn->session->sid;
        }

out:
        return;
}

/*
 * cmd_exec_auth - chap auth
 *
 * @req: request cmd
 * @rsp: response cmd
 *
 * @return: 0 on success, -1 on initiator error, -2 on auth failed,
 *          other failure on other return value.
 */
static int cmd_exec_auth(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
#if ENABLE_ISCSI_CHAP
        int ret;
        struct iscsi_conn *conn = req->conn;

        switch (conn->auth_method) {
        case AUTH_CHAP:
                ret = cmd_exec_auth_chap(req, rsp);
                break;
        case AUTH_NONE:
                ret = 0;
                break;
        default:
                DERROR("Unknow auth. method %d\n", conn->auth_method);
                ret = -3;
                break;
        }

        return ret;
#else
        (void) req;
        (void) rsp;
        return 0;
#endif
}

static void login_exec(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int stay = 0, nsg_disagree = 0;
        struct iscsi_login_req_hdr *req_hdr;
        struct iscsi_login_rsp_hdr *rsp_hdr;
        struct iscsi_conn *conn = req->conn;

        req_hdr = (struct iscsi_login_req_hdr *)&req->pdu.bhs;

        /* Version check */
        if ((req_hdr->min_version > ISCSI_VERSION)
            || !(req->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE)) {
                login_rsp_ini_err(rsp, ISCSI_STATUS_NO_VERSION);
                goto out;
        }

        rsp_hdr = (struct iscsi_login_rsp_hdr *)&rsp->pdu.bhs;
        rsp_hdr->opcode = ISCSI_OP_LOGIN_RSP;
        rsp_hdr->flags = ISCSI_FLG_FINAL;
        rsp_hdr->itt = req_hdr->itt;

        /*
         * Current Stage
         */
        switch (req_hdr->flags & ISCSI_FLG_CSG_MASK) {
        case ISCSI_FLG_CSG_SECURITY:
                rsp_hdr->flags = ISCSI_FLG_CSG_SECURITY;

                switch (conn->state) {
                case STATE_FREE:
                        conn->state = STATE_SECURITY;
                        login_start(req, rsp);
                        if (rsp_hdr->status_class)
                                goto out;
                        /* fall through */
                case STATE_SECURITY:
                        text_scan_security(req, rsp);
                        conn->auth_username[0] = '\0';
                        conn->auth_password[0] = '\0';
                        if (rsp_hdr->status_class)
                                goto out;
                        if (conn->auth_method != AUTH_NONE) {
                                conn->state = STATE_SECURITY_AUTH;
                                conn->auth_state = AUTH_STATE_START;
                        }
                        break;
                case STATE_SECURITY_AUTH:
                        switch (cmd_exec_auth(req, rsp)) {
                        case 0:
                                break;
                        default:
                        case -1:
                                goto init_err;
                        case -2:
                                goto auth_err;
                        }
                        break;
                default:
                        DERROR("conn->state: %lu\n", conn->state);
                        goto init_err;
                }
                break;
        case ISCSI_FLG_CSG_OPERATIONAL:
                rsp_hdr->flags = ISCSI_FLG_CSG_OPERATIONAL;

                switch (conn->state) {
                case STATE_FREE:
                        conn->state = STATE_LOGIN;
                        login_start(req, rsp);
                        if (rsp_hdr->status_class)
                                goto out;
                        if (conn->session_type != SESSION_DISCOVERY
                            && !account_empty(conn, AUTH_DIR_INCOMING)) {
                                DWARN("Auth failed, session type: %d \n", conn->session_type);
                                goto auth_err;
                        }
                        if (rsp_hdr->status_class)
                                goto out;
                        text_scan_login(req, rsp);
                        if (rsp_hdr->status_class)
                                goto out;
                        stay = text_check_param(rsp);
                        break;
                case STATE_LOGIN:
                        text_scan_login(req, rsp);
                        if (rsp_hdr->status_class)
                                goto out;
                        stay = text_check_param(rsp);
                        break;
                default:
                        DERROR("conn->state: %lu\n", conn->state);
                        goto init_err;
                }
                break;
        default:
                goto init_err;
        }

        /* Something wrong */
        if (rsp_hdr->status_class)
                goto out;

        if (conn->state != STATE_SECURITY_AUTH && req_hdr->flags & ISCSI_FLG_TRANSIT) {
                int nsg = req_hdr->flags & ISCSI_FLG_NSG_MASK;

                switch (nsg) {
                case ISCSI_FLG_NSG_OPERATIONAL:
                        switch (conn->state) {
                        case STATE_SECURITY:
                        case STATE_SECURITY_DONE:
                                conn->state = STATE_SECURITY_LOGIN;
                                login_security_done(req, rsp);
                                break;
                        default:
                                goto init_err;
                        }
                        break;
                case ISCSI_FLG_NSG_FULL_FEATURE:
                        switch (conn->state) {
                        case STATE_SECURITY:
                        case STATE_SECURITY_DONE:
                                nsg_disagree = text_check_param(rsp);
                                if (nsg_disagree) {
                                        conn->state = STATE_LOGIN;
                                        nsg = ISCSI_FLG_NSG_OPERATIONAL;
                                        break;
                                } else {
                                        conn->state = STATE_SECURITY_FULL;
                                        login_security_done(req, rsp);
                                }
                                break;
                        case STATE_LOGIN:
                                if (stay) {
                                        nsg = ISCSI_FLG_NSG_OPERATIONAL;
                                } else {
                                        conn->state = STATE_LOGIN_FULL;
                                        login_security_done(req, rsp);
                                }
                                break;
                        default:
                                goto init_err;
                        }
                        if (!stay && !nsg_disagree) {
                                text_check_param(rsp);
                                login_finish(req, rsp);
                        }
                        break;
                default:
                        goto init_err;
                }
                rsp_hdr->flags |= nsg | (stay ? 0 : ISCSI_FLG_TRANSIT);
        }

        rsp_hdr->sid = conn->sid;

out:
        return;
init_err:
        login_rsp_ini_err(rsp, ISCSI_STATUS_INIT_ERR);
auth_err:
        login_rsp_ini_err(rsp, ISCSI_STATUS_AUTH_FAILED);
}

static int cmd_login_rx_start(struct iscsi_cmd *cmd)
{
        int reject;
        struct iscsi_conn *conn = cmd->conn;

        conn_update_stat_sn(cmd);

        /*
         * Once the login phase has started, if the target receives any PDU
         * except a Login request, it MUST send a Login reject (with Status
         * "invalid during login") and then disconnect - RFC3720.
         */
        if (conn->state == STATE_FULL) {
                reject = ISCSI_REASON_PROTOCOL_ERROR;
                goto reject;
        }

        iscsi_cmd_alloc_data_tio(cmd);

        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;
}

static int cmd_login_rx_end(struct iscsi_cmd *req)
{
        struct iscsi_cmd *rsp;
        struct iscsi_login_rsp_hdr *rsp_hdr;
        struct iscsi_conn *conn = req->conn;

        (void) param_list_build(&conn->param_list, req);

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);
        login_exec(req, rsp);

        (void) param_list_destroy(&conn->param_list);

        rsp_hdr = (struct iscsi_login_rsp_hdr *)&rsp->pdu.bhs;
        if (rsp_hdr->status_class && rsp_hdr->status_class != ISCSI_STATUS_REDIRECT && rsp->tio) {
                tio_put(rsp->conn, rsp);
                rsp->tio = NULL;
                rsp->pdu.datasize = 0;
        }
        iscsi_cmd_init_write(rsp);

        return 0;
}

static int cmd_login_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        /* No session now, use connection's sn */
        cmd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn++);
        cmd->pdu.bhs.exp_sn = cpu_to_be32(conn->exp_cmd_sn);
        conn->max_cmd_sn = conn->exp_cmd_sn + 1;
        cmd->pdu.bhs.max_sn = cpu_to_be32(conn->max_cmd_sn);

        iscsi_cmd_send_pdu(conn, cmd);

        return 0;
}

static int cmd_login_tx_end(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        int peer_port = ntohs(conn->peer.sin_port);

        /* Enable connection's digest if session state is FULL */
        if (conn->session) {
                conn->hdigest_type = conn->session->param.header_digest;
                conn->ddigest_type = conn->session->param.data_digest;
        }

        switch (conn->state) {
        case STATE_EXIT:
                DBUG("close point 1\n");

                conn->state = STATE_CLOSE;
                break;
        case STATE_SECURITY_LOGIN:
                conn->state = STATE_LOGIN;
                break;
        case STATE_SECURITY_FULL:
        case STATE_LOGIN_FULL:
                conn->state = STATE_FULL;

                /* Register connection info to chunktable */
                if (conn->session->target) {
                        int ret;
                        struct iscsi_cmd *rsp;

                        // 连接授权
                        ret = cops->scan_lun(conn);
                        if (unlikely(ret)) {
                                rsp = iscsi_cmd_get_rsp_cmd(cmd);
                                login_rsp_ini_err(rsp, ISCSI_STATUS_TGT_NOT_FOUND);
                                conn->state = STATE_CLOSE;
                                break;
                        }

#if ENABLE_ISCSI_VIP
#if ISCSI_CHECK_TARGET_CTIME
                        struct iscsi_target *target = conn->session->target;
                        int is_local = target_islocal(target);
                        time_t now = gettime();

                        DINFO("target %s is_local %d used %lds\n", target->name, is_local, now - target->ctime);
                        if (!is_local && now - target->ctime > gloconf.lease_timeout) {
                                rsp = iscsi_cmd_get_rsp_cmd(cmd);
                                login_rsp_tgt_err(rsp, ISCSI_STATUS_SVC_UNAVAILABLE);
                                conn->state = STATE_CLOSE;
                                break;
                        }
#endif
#endif
                        ret = target_connect(conn->session->target, _inet_ntop((struct sockaddr *)&conn->peer), peer_port);
                        if (unlikely(ret)) {
                                rsp = iscsi_cmd_get_rsp_cmd(cmd);
                                login_rsp_ini_err(rsp, ISCSI_STATUS_TGT_NOT_FOUND);
                                conn->state = STATE_CLOSE;
                                break;
                        }
                }

                if (conn->session_type == SESSION_NORMAL) {
                        DINFO("connection %s:%d login\n",
                              _inet_ntop((struct sockaddr *)&conn->peer), peer_port);
                        conn->login_state = STATE_LOGIN;
                }

                break;
        }

        return 0;
}

static struct iscsi_cmd_hook cmd_hook_login = {
        .name     = "login",
        .req_op   = ISCSI_OP_LOGIN_REQ,
        .rsp_op   = ISCSI_OP_LOGIN_RSP,
        .rx_start = cmd_login_rx_start,
        .rx_end   = cmd_login_rx_end,
        .tx_start = cmd_login_tx_start,
        .tx_end   = cmd_login_tx_end,
};

/** ,====================
 * /  LOGOUT
 * `==============================
 */

static int cmd_logout_exec(struct iscsi_cmd *req)
{
        struct iscsi_logout_req_hdr *req_hdr;
        struct iscsi_cmd *rsp;
        struct iscsi_logout_rsp_hdr *rsp_hdr;
        struct iscsi_conn *conn;
        u8 reason;

        req_hdr = (struct iscsi_logout_req_hdr *)&req->pdu.bhs;

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);
        rsp_hdr = (struct iscsi_logout_rsp_hdr *)&rsp->pdu.bhs;
        rsp_hdr->opcode = ISCSI_OP_LOGOUT_RSP;
        rsp_hdr->flags |= ISCSI_FLG_FINAL;
        rsp_hdr->itt = req_hdr->itt;

        reason = req_hdr->flags & ISCSI_FUNCTION_MASK;

        if (reason == ISCSI_LOGOUT_SESSION)
                rsp->flags |= CMD_FLG_CLOSE_SESSION;
        else if (reason == ISCSI_LOGOUT_CONNECTION) {
                if (req_hdr->cid != req->conn->cid) {
                        conn = conn_find(req->conn->session, req_hdr->cid);
                        if (!conn)
                                rsp_hdr->response = 1;
                        else if (conn->state & STATE_FULL)
                                rsp_hdr->response = 3;
                        else {
                                /* End time2wait timer for connection */
                        }
                } else
                        rsp->flags |= CMD_FLG_CLOSE;
        } else if (reason == ISCSI_LOGOUT_CONNECTION_RECOVER)
                rsp_hdr->response = 2;
        else {
                /* Protocol error */
                DBUG("close point 2\n");
                req->conn->state = STATE_CLOSE;
        }

        iscsi_cmd_init_write(iscsi_cmd_get_rsp_cmd(req));
        return 0;
}

static int cmd_logout_rx_start(struct iscsi_cmd *cmd)
{
        int reject;
        struct iscsi_conn *conn = cmd->conn;

        if (conn->state != STATE_FULL || cmd->pdu.datasize ) {
                reject = ISCSI_REASON_PROTOCOL_ERROR;
                goto reject;
        }

        reject = iscsi_cmd_insert_hash(cmd);
        if (reject)
                goto reject;

        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;
}

static int cmd_logout_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static int cmd_logout_tx_start(struct iscsi_cmd *cmd)
{
        iscsi_cmd_set_sn(cmd, 1);
        return 0;
}

static int cmd_logout_tx_end(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        int peer_port = ntohs(conn->peer.sin_port);

        DINFO("target %p addr %s:%d\n",
              conn->session->target,
              _inet_ntop((struct sockaddr *)&conn->peer),
              peer_port);

        if (conn->session->target) {
                (void) target_disconnect(conn->session->target,
                                         _inet_ntop((struct sockaddr *)&conn->peer),
                                         peer_port);
        }

        return 0;
}

static struct iscsi_cmd_hook cmd_hook_logout = {
        .name     = "logout",
        .req_op   = ISCSI_OP_LOGOUT_REQ,
        .rsp_op   = ISCSI_OP_LOGOUT_RSP,
        .rx_start = cmd_logout_rx_start,
        .rx_end   = cmd_logout_rx_end,
        .cmd_exec = cmd_logout_exec,
        .tx_start = cmd_logout_tx_start,
        .tx_end   = cmd_logout_tx_end,
};

/** ,====================
 * /  NOPIN/NOPOUT
 * `==============================
 */

static int cmd_nop_exec(struct iscsi_cmd *req)
{
        struct iscsi_cmd *rsp;
        struct iscsi_hdr *hdr;

        ANALYSIS_BEGIN(0);

        if (cmd_itt(req) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
                rsp = iscsi_cmd_create_rsp_cmd(req, 1);
                hdr = (struct iscsi_hdr *)&rsp->pdu.bhs;
                hdr->opcode = ISCSI_OP_NOP_IN;
                hdr->flags = ISCSI_FLG_FINAL;
                hdr->itt = req->pdu.bhs.itt;
                hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);

                if (req->tio) {
                        tio_get(req->tio);
                        rsp->tio = req->tio;
                }
                rsp->pdu.datasize = req->pdu.datasize;
                iscsi_cmd_init_write(rsp);
        } else {
                iscsi_cmd_remove(req);
        }

        ANALYSIS_END(0, IO_WARN, NULL);

        return 0;
}

static int cmd_nop_rx_start(struct iscsi_cmd *cmd)
{
        int ret, reject;

        if (cmd_ttt(cmd) != cpu_to_be32(ISCSI_RESERVED_TAG)) {
                /* We Don't request this NOP-Out (by sending a NOP-In with @ttt
                 * no equal to 0xffffffff.
                 */
                reject = ISCSI_REASON_PROTOCOL_ERROR;
                goto reject;
        }

        if (cmd_itt(cmd) == cpu_to_be32(ISCSI_RESERVED_TAG)) {
                if (!cmd_immediate(cmd))
                        DWARN("Initiator bug !\n");
                ret = iscsi_cmd_check_sn(cmd);
                if (unlikely(ret)) {
                        reject = ret;
                        goto reject;
                }
                conn_update_stat_sn(cmd);
        } else if ((ret = iscsi_cmd_insert_hash(cmd))) {
                DWARN("Ignore this request %x\n", cmd_itt(cmd));
                goto out;
        }

        iscsi_cmd_alloc_data_tio(cmd);
out:
        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;
}

static int cmd_nop_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static int cmd_nop_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        iscsi_cmd_set_sn(cmd, 1);
        iscsi_cmd_send_pdu(conn, cmd);

        return 0;
}

static int cmd_nop_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_nop = {
        .name     = "nop",
        .req_op   = ISCSI_OP_NOP_OUT,
        .rsp_op   = ISCSI_OP_NOP_IN,
        .rx_start = cmd_nop_rx_start,
        .rx_end   = cmd_nop_rx_end,
        .cmd_exec = cmd_nop_exec,
        .tx_start = cmd_nop_tx_start,
        .tx_end   = cmd_nop_tx_end,
};

/** ,====================
 * /  R2T
 * `==============================
 */

static int cmd_r2t_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        /*
         * The StatSN field will contain the next StatSN. The StatSN for this
         * connection is not advanced after this PDU is sent.
         */
        iscsi_cmd_set_sn(cmd, 0);
        cmd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn);
        return 0;
}

static int cmd_r2t_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_r2t = {
        .name     = "r2t",
        .req_op   = -1,
        .rsp_op   = ISCSI_OP_R2T,
        .tx_start = cmd_r2t_tx_start,
        .tx_end   = cmd_r2t_tx_end,
};

/** ,====================
 * /  REJECT
 * `==============================
 */

static int cmd_reject_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;
        iscsi_cmd_set_sn(cmd, 1);
        iscsi_cmd_send_pdu(conn, cmd);
        return 0;
}

static int cmd_reject_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_reject = {
        .name     = "reject",
        .req_op   = -1,
        .rsp_op   = ISCSI_OP_REJECT,
        .tx_start = cmd_reject_tx_start,
        .tx_end   = cmd_reject_tx_end,
};

/** ,====================
 * /  SCSI
 * `==============================
 */

struct iscsi_cmd *create_sense_rsp(struct iscsi_cmd *req,
                                          u8 sense_key, u8 asc, u8 ascq)
{
        iscsi_cmd_set_sense(req, sense_key, asc, ascq);
        return create_scsi_rsp(req);
}

static u32 get_next_ttt(struct iscsi_session *sess)
{
        u32 ttt;

        if (sess->next_ttt == ISCSI_RESERVED_TAG)
                ++sess->next_ttt;
        ttt = sess->next_ttt++;

        return cpu_to_be32(ttt);
}

void set_offset_and_length(struct iscsi_volume *lu, u8 *cmd, loff_t *off, u32 *len)
{
        YASSERT(lu);

        switch (cmd[0]) {
        case READ_6:
        case WRITE_6:
                *off = ((cmd[1] & 0x1f) << 16) + (cmd[2] << 8) + cmd[3];
                *len = cmd[4];
                if (!*len)
                        *len = 256;
                break;
        case READ_10:
        case WRITE_10:
        case WRITE_SAME:
        case WRITE_VERIFY:
                *off = (u32)cmd[2] << 24 | (u32)cmd[3] << 16 |
                        (u32)cmd[4] << 8 | (u32)cmd[5];
                *len = (cmd[7] << 8) + cmd[8];
                break;
        case READ_16:
        case WRITE_16:
        case WRITE_SAME_16: //added by zsy at 2017.7.20 to support VAAI.
        case COMPARE_AND_WRITE_16:
                *off = (u64)cmd[2] << 56 | (u64)cmd[3] << 48 |
                        (u64)cmd[4] << 40 | (u64)cmd[5] << 32 |
                        (u64)cmd[6] << 24 | (u64)cmd[7] << 16 |
                        (u64)cmd[8] << 8 | (u64)cmd[9];
                *len = (u32)cmd[10] << 24 | (u32)cmd[11] << 16 |
                        (u32)cmd[12] << 8 | (u32)cmd[13];
                break;
        default:
                UNIMPLEMENTED(__DUMP__);
        }

        *off <<= lu->blk_shift;
        *len <<= lu->blk_shift;
}

void cmd_skip_data(struct iscsi_cmd *req)
{
        struct iscsi_cmd *rsp;
        struct iscsi_scsi_rsp_hdr *rsp_hdr;
        u32 size;

        rsp = iscsi_cmd_get_rsp_cmd(req);
        rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
        if (cmd_opcode(rsp) != ISCSI_OP_SCSI_RSP) {
                DERROR("unexpected response command %u\n", cmd_opcode(rsp));
                goto out;
        }

        size = iscsi_cmd_write_size(req);
        if (size) {
                if (cmd_scsi_hdr(req)->flags & ISCSI_CMD_WRITE) {
                        rsp_hdr->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
                        rsp_hdr->bi_residual_count = cpu_to_be32(size);
                } else {
                        rsp_hdr->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
                        rsp_hdr->residual_count = cpu_to_be32(size);
                }
        }

        req->pdu.bhs.opcode =
                (req->pdu.bhs.opcode & ~ISCSI_OPCODE_MASK) | ISCSI_OP_SCSI_REJECT;

        iscsi_cmd_skip_pdu(req);
out:
        return;
}

STATIC int __tio_read__(va_list ap)
{
        struct iscsi_cmd *req = va_arg(ap, struct iscsi_cmd *);

        va_end(ap);

        return tio_read(req);
}

static int scsi_cmd_start(struct iscsi_cmd *req)
{
        int ret;
        struct iscsi_conn *conn = req->conn;
        struct iscsi_scsi_cmd_hdr *req_hdr = cmd_scsi_hdr(req);
        struct iscsi_cmd *rsp;
        struct iscsi_scsi_rsp_hdr *rsp_hdr;

        req->lun = volume_get(conn->session->target, translate_lun(req_hdr->lun));
        if (!req->lun) {
                switch (req_hdr->scb[0]) {
                case INQUIRY:
                case REPORT_LUNS:
                        break;
                default:
                        DWARN("SCSI 0x%x: %s/%u not found\n",
                        req_hdr->scb[0],
                        conn->session->target->name,
                        translate_lun(req_hdr->lun));

                        /* If the initiator want to access a lun which has been
                        * removed, set sense key.
                        */
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x25, 0x00);
                        rsp = iscsi_cmd_get_rsp_cmd(req);
                        rsp_hdr = (struct iscsi_scsi_rsp_hdr *)&rsp->pdu.bhs;
                        rsp_hdr->flags = CMD_FLG_CLOSE;
                        cmd_skip_data(req);
                        goto out;
                }
        } else {
                DBUG("the lun id is %u in find lun path and cmd is 0x%x\n",
                     translate_lun(req_hdr->lun), req_hdr->scb[0]);
                /* Used for put volume when release this command */
                req->flags |= CMD_FLG_LUNIT;
        }

        switch (req_hdr->scb[0]) {
        case SERVICE_ACTION_IN:
                if ((req_hdr->scb[1] & 0x1f) != 0x10)
                        goto error;
                /* Fall through */
        case INQUIRY:
        case REPORT_LUNS:
        case TEST_UNIT_READY:
        case SYNCHRONIZE_CACHE:
        case VERIFY:
        case VERIFY_16:
        case START_STOP:
        case READ_CAPACITY:
        case MODE_SENSE:
        case REQUEST_SENSE:
        case RESERVE:
        case RELEASE:
        case PERSISTENT_RESERVE_IN:
        case PERSISTENT_RESERVE_OUT: {
                if (!(req_hdr->flags & ISCSI_CMD_FINAL) || req->pdu.datasize) {
                        /* Unexpected unsolicited data */
                        DERROR("itt: %x, scb: %x\n", cmd_itt(req), req_hdr->scb[0]);
                        create_sense_rsp(req, ABORTED_COMMAND, 0x0c, 0x0c);
                        cmd_skip_data(req);
                }
                break;
        }
        case READ_6:
        case READ_10:
        case READ_16: {
                loff_t offset;
                u32 length;

                if (!(req_hdr->flags & ISCSI_CMD_FINAL) || req->pdu.datasize) {
                        /* Unexpected unsolicited data */
                        DERROR("itt: %x, scb: %x\n", cmd_itt(req), req_hdr->scb[0]);
                        create_sense_rsp(req, ABORTED_COMMAND, 0x0c, 0x0c);
                        cmd_skip_data(req);
                        break;
                }

                set_offset_and_length(req->lun, req_hdr->scb, &offset, &length);
                req->tio = tio_alloc(conn, 0);
                /*
                 * Set the length of data want to read, and the device's offset
                 * where to read.
                 */
                tio_set_diskseek(req->tio, offset, length);
                break;
        }
#if ENABLE_VAAI
        case WRITE_SAME_16:
        case COMPARE_AND_WRITE_16:
                if(!conn->target->vaai_enabled){
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x00);
                        cmd_skip_data(req);
                        break;
                }
                //no break.
#endif
        case WRITE_6:
        case WRITE_10:
        case WRITE_16:
        case WRITE_VERIFY: {
                struct iscsi_sess_param *param = &conn->session->param;
                loff_t offset;
                u32 length;

                req->exp_offset = req->pdu.datasize;
                req->r2t_length = iscsi_cmd_write_size(req) - req->pdu.datasize;
                req->is_unsolicited_data = !(req_hdr->flags & ISCSI_CMD_FINAL);
                req->target_task_tag = get_next_ttt(conn->session);

                if (LUReadonly(req->lun)) {
                        create_sense_rsp(req, DATA_PROTECT, 0x27, 0x00);
                        cmd_skip_data(req);
                        break;
                }

                /*  +----------+-------------+------------------+--------------+
                 *  |InitialR2T|ImmediateData|    Unsolicited   |Immediate Data|
                 *  |          |             |   Data Out PDUs  |              |
                 *  +----------+-------------+------------------+--------------+
                 *  | No       | No          | Yes              | No           |
                 *  +----------+-------------+------------------+--------------+
                 *  | No       | Yes         | Yes              | Yes          |
                 *  +----------+-------------+------------------+--------------+
                 *  | Yes      | No          | No               | No           |
                 *  +----------+-------------+------------------+--------------+
                 *  | Yes      | Yes         | No               | Yes          |
                 *  +----------+-------------+------------------+--------------+
                 */
                if (!param->immediate_data && req->pdu.datasize)
                        DERROR("Session don't support Immediate Data but the first"
                               "command takes some data. (itt: %x, scb: %x)\n",
                               cmd_itt(req), req_hdr->scb[0]);

                if (param->initial_r2t && !(req_hdr->flags & ISCSI_CMD_FINAL))
                        DERROR("Session support InitialR2T but received command"
                               "with Unsolicited Data-Out PDU: (itt: %x, scb: %x)\n",
                               cmd_itt(req), req_hdr->scb[0]);

                if (req_hdr->scb[0] == WRITE_VERIFY && req_hdr->scb[1] & 0x02)
                        DWARN("Verification is ignored %x\n", cmd_itt(req));

                set_offset_and_length(req->lun, req_hdr->scb, &offset, &length);
                if (iscsi_cmd_write_size(req) != length && req_hdr->scb[0] != WRITE_SAME_16 && req_hdr->scb[0] != COMPARE_AND_WRITE_16) {
                        DERROR("itt %x cmd %x %u %u\n", cmd_itt(req), req_hdr->scb[0], iscsi_cmd_write_size(req), length);
                }

                if(req_hdr->scb[0] == WRITE_SAME_16)
                {
                        if(req_hdr->scb[1] & (1 << 3)) //UNMAP
                        {
                               break;
                        }

                        if(length > 0x200000)   //todo. hard code, should match read limit
                        {
                                create_sense_rsp(req, ILLEGAL_REQUEST, 0x24, 0x00);
                                cmd_skip_data(req);
                                break;
                        }
                        /*uint8_t *newbuff = malloc(length);
                        uint32_t data_len = req->pdu.datasize;

                        DINFO("WRITE_SAME_16: %d:%d\r\n", length, req->pdu.datasize);

                        mbuffer_get(&req->tio->buffer, newbuff, req->pdu.datasize);
                        while(data_len < length) {
                                memcpy(newbuff + data_len, newbuff, 512);
		                data_len += 512;
                        }

                        mbuffer_write(&req->tio->buffer, newbuff, 0, length);
                        free(newbuff);*/
                }

                if (req_hdr->scb[0] == COMPARE_AND_WRITE_16)
                        req->tio = tio_alloc(conn, req->pdu.datasize);
                else
                        req->tio = tio_alloc(conn, length);

                /*
                * Set the length of data want to write, and the device's offset
                * where to write.
                */
                tio_set_diskseek(req->tio, offset, length);

                if (req->pdu.datasize) 
                {
                        ret = iscsi_cmd_recv_pdu(conn, req->tio, 0, req->pdu.datasize);
                        if (unlikely(ret))
                                UNIMPLEMENTED(__DUMP__);
                }

                break;
        }

 #if ENABLE_VAAI       
        // TODO win server 2016 format error
        case UNMAP:
                DINFO("UNMAP\r\n");
                if(!conn->target->vaai_enabled)
                {
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x00);
                        cmd_skip_data(req);
                        break;
                }
                else if(req_hdr->scb[1] & 1) //anchor is invalid.
                {
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x24, 0x00);
                        cmd_skip_data(req);
                        break;
                }
                else if(!req->pdu.datasize)
                {
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x24, 0x00);
                        cmd_skip_data(req);
                        break;
                }
                else
                {
                        req->tio = tio_alloc(conn, req->pdu.datasize);
                        
                        ret = iscsi_cmd_recv_pdu(conn, req->tio, 0, req->pdu.datasize);
                        if (unlikely(ret))
                                UNIMPLEMENTED(__DUMP__);
                }
                DINFO("UNMAP..\r\n");
                break;
                

        case EXTENDED_COPY:
                DINFO("xcopy\r\n");

                if(!conn->target->vaai_enabled)
                {
                        DBUG("Unsupported %x\n", req_hdr->scb[0]);
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x00);
                        cmd_skip_data(req);
                        
                        break;
                }

                req->tio = tio_alloc(conn, req->pdu.datasize);

                if (req->pdu.datasize) {
                        ret = iscsi_cmd_recv_pdu(conn, req->tio, 0, req->pdu.datasize);
                        if (unlikely(ret))
                                UNIMPLEMENTED(__DUMP__);
                }

                break;

        case RECEIVE_COPY_RESULTS:

                if(!conn->target->vaai_enabled)
                {
                        create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x00);
                        cmd_skip_data(req);
                        break;
                }
                
                break;
        case MANAGEMENT_PROTOCOL_IN:
                break;
#endif

error:
        default:
                DBUG("Unsupported %x\n", req_hdr->scb[0]);
                create_sense_rsp(req, ILLEGAL_REQUEST, 0x20, 0x00);
                cmd_skip_data(req);
                break;
        }

out:
        return 0;
}

static void iscsi_device_queue_cmd(struct iscsi_cmd *cmd)
{
        cmd->flags |= CMD_FLG_WAITIO;
        worker_thread_queue(cmd);
}

static void iscsi_scsi_queue_cmd(struct iscsi_cmd *cmd)
{
        struct iscsi_queue *queue = &cmd->lun->queue;

        if ((cmd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) != ISCSI_CMD_UNTAGGED &&
            (cmd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) != ISCSI_CMD_SIMPLE) {
                cmd->pdu.bhs.flags &= ~ISCSI_CMD_ATTR_MASK;
                cmd->pdu.bhs.flags |= ISCSI_CMD_UNTAGGED;
        }

        cmd->flags |= CMD_FLG_QUEUED;

        switch (cmd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
        case ISCSI_CMD_UNTAGGED:
        case ISCSI_CMD_SIMPLE:
                if (!list_empty(&queue->wait_list) || queue->ordered_cmd)
                        goto pending;
                queue->active_cnt++;
                break;
        default:
                UNIMPLEMENTED(__DUMP__);
        }

        iscsi_device_queue_cmd(cmd);

        return;
pending:
        YASSERT(list_empty(&cmd->entry));
        list_add_tail(&cmd->entry, &queue->wait_list);

        return;
}

static int cmd_scsi_exec(struct iscsi_cmd *cmd)
{
        YASSERT(!(cmd->r2t_length || cmd->outstanding_r2t));

        if (cmd->lun) {
                iscsi_scsi_queue_cmd(cmd);
        } else {
                iscsi_device_queue_cmd(cmd);
        }

        return 0;
}

static int cmd_scsi_rx_start(struct iscsi_cmd *cmd)
{
        int ret, reject;

        ret = iscsi_cmd_insert_hash(cmd);
        if (!ret)
                scsi_cmd_start(cmd);
        else {
                reject = ret;
                goto reject;
        }

        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;
}

static int cmd_scsi_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static int cmd_scsi_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        iscsi_cmd_set_sn(cmd, 1);
        iscsi_cmd_send_pdu(conn, cmd);
        return 0;
}

static int cmd_scsi_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_scsi = {
        .name     = "scsi",
        .req_op   = ISCSI_OP_SCSI_REQ,
        .rsp_op   = ISCSI_OP_SCSI_RSP,
        .rx_start = cmd_scsi_rx_start,
        .rx_end   = cmd_scsi_rx_end,
        .cmd_exec = cmd_scsi_exec,
        .tx_start = cmd_scsi_tx_start,
        .tx_end   = cmd_scsi_tx_end,
};

/** ,====================
 * /  DATAIN/DATAOUT
 * `==============================
 */

static int cmd_data_rx_start(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_conn *conn = cmd->conn;
        struct iscsi_sess_param *param = &conn->session->param;
        struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmd->pdu.bhs;
        struct iscsi_cmd *scsi_cmd = NULL;
        u32 offset = be32_to_cpu(req->buffer_offset);

        ANALYSIS_BEGIN(0);

        /*
         * Data-Out command not insert hash, so update StatSN here.
         */
        conn_update_stat_sn(cmd);

        cmd->req = scsi_cmd = iscsi_cmd_find_hash(conn->session, req->itt, req->ttt);
        if (!scsi_cmd) {
                DERROR("unable to find scsi task %x %x\n", cmd_itt(cmd), cmd_ttt(cmd));
                goto skip_data;
        }

        if (param->data_pdu_inorder && offset != scsi_cmd->exp_offset) {
                DERROR("invalid data offset %x %u %u\n",
                       cmd_itt(scsi_cmd), cmd_ttt(scsi_cmd), cmd->exp_offset);
                goto skip_data;
        }

        if (offset + cmd->pdu.datasize > iscsi_cmd_write_size(scsi_cmd)) {
                DERROR("invalid data length %x %u %u\n",
                       cmd_itt(scsi_cmd), (offset + cmd->pdu.datasize),
                       iscsi_cmd_write_size(scsi_cmd));
                goto skip_data;
        }

        /*
         * Outgoing SCSI data is sent as either solicited data or unsolicited
         * data. Solicited data are send in response to R2T PDUs. Unsolicited
         * data can be sent as part of an ISCSI command PDU ("immediate data")
         * or in separate ISCSI data PDUs.
         *
         * Imemediate data are assumed to originate at offset 0 in the initiator
         * SCSI write-buffer. All other Data PDUs have the buffer offset set
         * explicitly in the PDU header.
         *
         * An initiator may send unsolicited data up to FirstBurstLength as
         * immediate, in a separate PDU sequence or both. All subsequent data
         * MUST be solicited.
         */
        if (scsi_cmd->is_unsolicited_data) {
                if (offset + cmd->pdu.datasize > param->first_burst_length) {
                        DERROR("unsolicited data > first burst length %x %x\n",
                               cmd_itt(cmd), cmd_ttt(cmd));
                        goto skip_data;
                }
        } else {
                if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
                        DERROR("unexpected unsolicited data %x %x\n",
                               cmd_itt(cmd), cmd_ttt(cmd));
                        goto skip_data;
                }
        }

        ret = iscsi_cmd_recv_pdu(conn, scsi_cmd->tio, offset, cmd->pdu.datasize);
        if (unlikely(ret))
                goto skip_data;

        if (scsi_cmd->is_unsolicited_data)
                /* For Solicited Data-Out PDUs, this is decreased in @send_r2t */
                scsi_cmd->r2t_length -= cmd->pdu.datasize;

        scsi_cmd->exp_offset += cmd->pdu.datasize;

        ANALYSIS_END(0, IO_WARN, NULL);

        return 0;
skip_data:
        cmd->pdu.bhs.opcode = ISCSI_OP_DATA_REJECT;
        iscsi_cmd_skip_pdu(cmd);
        return 0;
}

static int cmd_data_rx_end(struct iscsi_cmd *cmd)
{
        int ret;
        struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmd->pdu.bhs;
        struct iscsi_cmd *scsi_cmd;
        struct iscsi_conn *conn = cmd->conn;
        u32 offset;

        ANALYSIS_BEGIN(0);

        scsi_cmd = cmd->req;

        if (conn->read_overflow) {
                DERROR("connection read overflow %x %u\n", cmd_itt(cmd), conn->read_overflow);
                offset = be32_to_cpu(req->buffer_offset);
                offset += cmd->pdu.datasize - conn->read_overflow;

                ret = iscsi_cmd_recv_pdu(conn, scsi_cmd->tio, offset, conn->read_overflow);
                if (unlikely(ret))
                        UNIMPLEMENTED(__DUMP__);
                goto out;
        }

        if (req->flags & ISCSI_FLG_FINAL) {
                if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG))
                        scsi_cmd->is_unsolicited_data = 0;
                else
                        scsi_cmd->outstanding_r2t--;

                /* All Data-Out PDUs received finish, process WRITE command. */
                iscsi_session_push_cmd(scsi_cmd);
        }

        iscsi_cmd_remove(cmd);

        ANALYSIS_END(0, IO_WARN, NULL);

out:
        return 0;
}

static int cmd_data_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_data_in_hdr *rsp = (struct iscsi_data_in_hdr *)&cmd->pdu.bhs;
        struct iscsi_conn *conn = cmd->conn;
        u32 offset;

        iscsi_cmd_set_sn(cmd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
        offset = rsp->buffer_offset;
        rsp->buffer_offset = cpu_to_be32(offset);
        iscsi_cmd_send_pdu_tio(conn, cmd->tio, offset, cmd->pdu.datasize);
        return 0;
}

static int cmd_data_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_data = {
        .name     = "data",
        .req_op   = ISCSI_OP_SCSI_DATA_OUT,
        .rsp_op   = ISCSI_OP_SCSI_DATA_IN,
        .rx_start = cmd_data_rx_start,
        .rx_end   = cmd_data_rx_end,
        .tx_start = cmd_data_tx_start,
        .tx_end   = cmd_data_tx_end,
};

/** ,====================
 * /  SNACK
 * `==============================
 */

static int cmd_snack_rx_start(struct iscsi_cmd *cmd)
{
        int reject;

        reject = ISCSI_REASON_UNSUPPORTED_COMMAND;

        DWARN("Snack command is not supported now\n");

        iscsi_cmd_reject(cmd, reject);

        return 0;
}

static int cmd_snack_rx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_snack = {
        .name     = "snack",
        .req_op   = ISCSI_OP_SNACK_REQ,
        .rsp_op   = -1,
        .rx_start = cmd_snack_rx_start,
        .rx_end   = cmd_snack_rx_end,
};

/** ,====================
 * /  TASK MGT
 * `==============================
 */

static int cmd_task_exec(struct iscsi_cmd *req)
{
        struct iscsi_cmd *rsp;
        struct iscsi_task_mgt_hdr *req_hdr = (struct iscsi_task_mgt_hdr *)&req->pdu.bhs;
        struct iscsi_task_rsp_hdr *rsp_hdr;
        int function = req_hdr->function & ISCSI_FUNCTION_MASK;

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);
        rsp_hdr = (struct iscsi_task_rsp_hdr *)&rsp->pdu.bhs;

        rsp_hdr->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
        rsp_hdr->flags = ISCSI_FLG_FINAL;
        rsp_hdr->itt = req_hdr->itt;
        rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;

        DWARN("Task Management command is not supported now\n");

        switch (function) {
        case ISCSI_FUNCTION_ABORT_TASK:
        case ISCSI_FUNCTION_ABORT_TASK_SET:
        case ISCSI_FUNCTION_CLEAR_ACA:
        case ISCSI_FUNCTION_CLEAR_TASK_SET:
        case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
        case ISCSI_FUNCTION_TARGET_WARM_RESET:
        case ISCSI_FUNCTION_TARGET_COLD_RESET:
        case ISCSI_FUNCTION_TASK_REASSIGN:
        default:
                rsp_hdr->response = ISCSI_RESPONSE_FUNCTION_UNSUPPORTED;
                break;
        }

        iscsi_cmd_init_write(rsp);
        return 0;
}

static int cmd_task_rx_start(struct iscsi_cmd *cmd)
{
        int reject = iscsi_cmd_insert_hash(cmd);

        if (reject)
                goto reject;

        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;

}

static int cmd_task_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static int cmd_task_tx_start(struct iscsi_cmd *cmd)
{
        iscsi_cmd_set_sn(cmd, 1);
        return 0;
}

static int cmd_task_tx_end(struct iscsi_cmd *cmd __attribute__((unused)))
{
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_task = {
        .name     = "task",
        .req_op   = ISCSI_OP_SCSI_TASK_MGT_REQ,
        .rsp_op   = ISCSI_OP_SCSI_TASK_MGT_RSP,
        .rx_start = cmd_task_rx_start,
        .rx_end   = cmd_task_rx_end,
        .cmd_exec = cmd_task_exec,
        .tx_start = cmd_task_tx_start,
        .tx_end   = cmd_task_tx_end,
};

/** ,====================
 * /  TEXT
 * `==============================
 */

static void text_scan_text(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        struct iscsi_param_node *node;
        struct iscsi_conn *conn = req->conn;

        list_for_each_entry(node, &conn->param_list, entry) {
                if (!strcmp(node->key, "SendTargets")) {
                        if (node->val[0] == 0)
                                continue;
                        target_list_entry_build(rsp, strcmp(node->val, "All") ? node->val : NULL);
                } else
                        tio_add_param(rsp, node->key, "NotUnderStood");
        }
}

static int cmd_text_exec(struct iscsi_cmd *req)
{
        struct iscsi_text_req_hdr *req_hdr;
        struct iscsi_cmd *rsp;
        struct iscsi_text_rsp_hdr *rsp_hdr;
        struct iscsi_conn *conn = req->conn;

        req_hdr = (struct iscsi_text_req_hdr *)&req->pdu.bhs;

        rsp = iscsi_cmd_create_rsp_cmd(req, 1);
        rsp_hdr = (struct iscsi_text_rsp_hdr *)&rsp->pdu.bhs;
        rsp_hdr->opcode = ISCSI_OP_TEXT_RSP;
        rsp_hdr->itt = req_hdr->itt;
        rsp_hdr->flags |= ISCSI_FLG_FINAL;
        rsp_hdr->ttt = ISCSI_RESERVED_TAG;

        (void) param_list_build(&conn->param_list, req);
        text_scan_text(req, rsp);
        (void) param_list_destroy(&conn->param_list);

        iscsi_cmd_init_write(rsp);
        return 0;
}

static int cmd_text_rx_start(struct iscsi_cmd *cmd)
{
        int reject;
        struct iscsi_conn *conn = cmd->conn;

        if (conn->state != STATE_FULL) {
                reject = ISCSI_REASON_PROTOCOL_ERROR;
                goto reject;
        }

        if (conn->session_type != SESSION_DISCOVERY) {
                /*
                 * TODO: support Text Command in normal session type
                 */
                reject = ISCSI_REASON_UNSUPPORTED_COMMAND;
                goto reject;
        }

        iscsi_cmd_alloc_data_tio(cmd);

        reject = iscsi_cmd_insert_hash(cmd);
        if (reject)
                goto reject;

        return 0;
reject:
        iscsi_cmd_reject(cmd, reject);
        return 0;
}

static int cmd_text_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static int cmd_text_tx_start(struct iscsi_cmd *cmd)
{
        struct iscsi_conn *conn = cmd->conn;

        iscsi_cmd_set_sn(cmd, 1);
        iscsi_cmd_send_pdu(conn, cmd);
        return 0;
}

static int cmd_text_tx_end(struct iscsi_cmd *cmd)
{
        (void) cmd;
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_text = {
        .name     = "text",
        .req_op   = ISCSI_OP_TEXT_REQ,
        .rsp_op   = ISCSI_OP_TEXT_RSP,
        .rx_start = cmd_text_rx_start,
        .cmd_exec = cmd_text_exec,
        .rx_end   = cmd_text_rx_end,
        .tx_start = cmd_text_tx_start,
        .tx_end   = cmd_text_tx_end,
};

/** ,====================
 * /  VENDOR1
 * `==============================
 */

/*
 * This is used for ISCSI_SCSI_REJECT
 */

static int cmd_vendor1_exec(struct iscsi_cmd *req)
{
        iscsi_cmd_init_write(iscsi_cmd_get_rsp_cmd(req));
        return 0;
}

static int cmd_vendor1_rx_start(struct iscsi_cmd *cmd)
{
        (void) cmd;

        DERROR("Should not come here!\n");
        return 0;
}

static int cmd_vendor1_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_session_push_cmd(cmd);
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_vendor1 = {
        .name     = "vendor1",
        .req_op   = ISCSI_OP_VENDOR1_CMD,
        .rsp_op   = -1,
        .rx_start = cmd_vendor1_rx_start,
        .rx_end   = cmd_vendor1_rx_end,
        .cmd_exec = cmd_vendor1_exec,
};

/** ,====================
 * /  VENDOR2
 * `==============================
 */

/*
 * This is used for ISCSI_PDU_REJECT
 */

static int cmd_vendor2_rx_start(struct iscsi_cmd *cmd)
{
        (void) cmd;

        DERROR("Should not come here!\n");
        return 0;
}

static int cmd_vendor2_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_cmd_init_write(iscsi_cmd_get_rsp_cmd(cmd));
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_vendor2 = {
        .name     = "vendor2",
        .req_op   = ISCSI_OP_VENDOR2_CMD,
        .rsp_op   = -1,
        .rx_start = cmd_vendor2_rx_start,
        .rx_end   = cmd_vendor2_rx_end,
};

/** ,====================
 * /  VENDOR3
 * `==============================
 */

/*
 * This is used for ISCSI_DATA_REJECT
 */

static int cmd_vendor3_rx_start(struct iscsi_cmd *cmd)
{
        (void) cmd;

        DERROR("Should not come here!\n");
        return 0;
}

static int cmd_vendor3_rx_end(struct iscsi_cmd *cmd)
{
        iscsi_cmd_release(cmd, 0);
        return 0;
}

static struct iscsi_cmd_hook cmd_hook_vendor3 = {
        .name     = "vendor3",
        .req_op   = ISCSI_OP_VENDOR3_CMD,
        .rsp_op   = -1,
        .rx_start = cmd_vendor3_rx_start,
        .rx_end   = cmd_vendor3_rx_end,
};

/** ,====================
 * /  NONE COMMAND FOR DEBUG
 * `==============================
 */

static int cmd_non_ops(struct iscsi_cmd *cmd)
{
        (void) cmd;

        iscsi_cmd_reject(cmd, ISCSI_REASON_PROTOCOL_ERROR);
        return 0;
}

static int cmd_bug_ops(struct iscsi_cmd *cmd)
{
        (void) cmd;

        DERROR("Should not come here!\n");
        UNIMPLEMENTED(__DUMP__);

        return 0;
}

static struct iscsi_cmd_hook cmd_hook_none = {
        .name     = "none",
        .req_op   = -1,
        .rsp_op   = -1,
        .rx_start = cmd_non_ops,
        .rx_end   = cmd_bug_ops,
        .cmd_exec = cmd_bug_ops,
        .tx_start = cmd_bug_ops,
        .tx_end   = cmd_bug_ops,
};


/**
 * Init function
 */

static struct iscsi_cmd_hook *cmd_hooks[ISCSI_OP_NR_MAX];

static int iscsi_cmd_hook_register(struct iscsi_cmd_hook *hook)
{
        int ret, req = hook->req_op, rsp = hook->rsp_op;

        if ((req < -1 || req >= ISCSI_OP_NR_MAX) ||
            (rsp < -1 || req >= ISCSI_OP_NR_MAX)) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        if (req != -1) {
                if (cmd_hooks[req] && cmd_hooks[req]->req_op != -1) {
                        ret = EEXIST;
                        GOTO(err_ret, ret);
                }
                cmd_hooks[req] = hook;

                YASSERT(hook->rx_start && hook->rx_end);
        }

        if (rsp != -1) {
                if (cmd_hooks[rsp] && cmd_hooks[rsp]->rsp_op != -1) {
                        ret = EEXIST;
                        GOTO(err_ret, ret);
                }
                cmd_hooks[rsp] = hook;

                YASSERT(hook->tx_start && hook->tx_end);
        }

        return 0;
err_ret:
        return ret;
}

inline struct iscsi_cmd_hook *__attribute__((always_inline)) iscsi_cmd_hook_get(int opcode)
{
        return cmd_hooks[opcode];
}

int iscsi_cmd_hook_init()
{
        u32 i;

        for (i = 0; i < ARRAY_SIZE(cmd_hooks); ++i) {
                cmd_hooks[i] = &cmd_hook_none;
        }

        (void) iscsi_cmd_hook_register(&cmd_hook_async);
        (void) iscsi_cmd_hook_register(&cmd_hook_login);
        (void) iscsi_cmd_hook_register(&cmd_hook_logout);
        (void) iscsi_cmd_hook_register(&cmd_hook_nop);
        (void) iscsi_cmd_hook_register(&cmd_hook_r2t);
        (void) iscsi_cmd_hook_register(&cmd_hook_reject);
        (void) iscsi_cmd_hook_register(&cmd_hook_scsi);
        (void) iscsi_cmd_hook_register(&cmd_hook_data);
        (void) iscsi_cmd_hook_register(&cmd_hook_snack);
        (void) iscsi_cmd_hook_register(&cmd_hook_task);
        (void) iscsi_cmd_hook_register(&cmd_hook_text);
        (void) iscsi_cmd_hook_register(&cmd_hook_vendor1);
        (void) iscsi_cmd_hook_register(&cmd_hook_vendor2);
        (void) iscsi_cmd_hook_register(&cmd_hook_vendor3);

        return 0;
}
