/*
 * chap.c - support for (mutual) CHAP authentication.
 * (C) 2004 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 * available under the terms of the GNU GPL v2.0
 *
 * heavily based on code from iscsid.c:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 *
 * and code taken from UNH iSCSI software:
 *   Copyright (C) 2001-2003 InterOperability Lab (IOL)
 *   University of New Hampshire (UNH)
 *   Durham, NH 03824
 *   licensed under the terms of the GNU GPL v2.0
 */
#include <stdlib.h>

#define DBG_SUBSYS      S_YISCSI

#include "iscsi.h"
#include "md5.h"
#include "sha1.h"
#include "dbg.h"

#define HEX_FORMAT                      0x01
#define BASE64_FORMAT                   0x02

#define CHAP_MD5_DIGEST_LEN             16
#define CHAP_SHA1_DIGEST_LEN            20

#define CHAP_DIGEST_ALG_MD5             5
#define CHAP_DIGEST_ALG_SHA1            7

#define CHAP_INITIATOR_ERROR            -1
#define CHAP_AUTH_ERROR                 -2
#define CHAP_TARGET_ERROR               -3

#define CHAP_AUTH_STATE_START           AUTH_STATE_START
#define CHAP_AUTH_STATE_CHALLENGE       1
#define CHAP_AUTH_STATE_RESPONSE        2

#define CHAP_CHALLENGE_MAX              50

static int chap_initiator_auth_create_challenge(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret, i;
        char *value, *p;
        char text[CHAP_CHALLENGE_MAX * 2 + 8];
        struct iscsi_conn *conn = req->conn;
        static int chap_id;

        value = param_list_find(&conn->param_list, "CHAP_A");
        if (!value) {
                ret = CHAP_INITIATOR_ERROR;
                GOTO(err_ret, ret);
        }

        while ((p = strsep(&value, ","))) {
                if (!strcmp(p, "5")) {
                        conn->auth.chap.digest_alg = CHAP_DIGEST_ALG_MD5;
                        conn->auth_state = CHAP_AUTH_STATE_CHALLENGE;
                        break;
                } else if (!strcmp(p, "7")) {
                        conn->auth.chap.digest_alg = CHAP_DIGEST_ALG_SHA1;
                        conn->auth_state = CHAP_AUTH_STATE_CHALLENGE;
                        break;
                }
        }
        if (!p) {
                ret = CHAP_INITIATOR_ERROR;
                GOTO(err_ret, ret);
        }

        conn->auth.chap.id = ++chap_id;
        sprintf(text, "%u", (unsigned char)conn->auth.chap.id);

        tio_add_param(rsp, "CHAP_A", p);
        tio_add_param(rsp, "CHAP_I", text);

        conn->auth.chap.challenge_size = (random() % (CHAP_CHALLENGE_MAX / 2)) + CHAP_CHALLENGE_MAX / 2;
        conn->auth.chap.challenge = malloc(conn->auth.chap.challenge_size);
        if (!conn->auth.chap.challenge) {
                ret = CHAP_TARGET_ERROR;
                GOTO(err_ret, ret);
        }

        p = text;
        strcpy(p, "0x");
        p += 2;
        for (i = 0; i < conn->auth.chap.challenge_size; ++i) {
                conn->auth.chap.challenge[i] = rand();
                sprintf(p, "%.2hhx", conn->auth.chap.challenge[i]);
                p += 2;
        }
        tio_add_param(rsp, "CHAP_C", text);

        return 0;
err_ret:
        return ret;
}

int chap_check_encoding_format(char *encoded)
{
        int encoding_fmt = -1;

        if (!encoded)
                goto out;
        if ((strlen(encoded) < 3) || (encoded[0] != '0'))
                goto out;
        if (encoded[1] == 'x' || encoded[1] == 'X')
                encoding_fmt = HEX_FORMAT;
        else if (encoded[1] == 'b' || encoded[1] == 'B')
                encoding_fmt = BASE64_FORMAT;

out:
        return encoding_fmt;
}

static inline int decode_hex_digit(char c)
{
        switch (c) {
        case '0' ... '9':
                return c - '0';
        case 'a' ... 'f':
                return c - 'a' + 10;
        case 'A' ... 'F':
                return c - 'A' + 10;
        }
        return 0;
}

static void decode_hex_string(char *hex_string, u8 *intnum, int intlen)
{
        char *ptr;
        int j;

        j = strlen(hex_string);
        ptr = hex_string + j;
        j = --intlen;
        do {
                intnum[j] = decode_hex_digit(*--ptr);
                intnum[j] |= decode_hex_digit(*--ptr) << 4;
                j--;
        } while (ptr > hex_string);

        while (j >= 0)
                intnum[j--] = 0;
}

static u8 decode_base64_digit(char base64)
{
        switch (base64) {
        case '=':
                return 64;
        case '/':
                return 63;
        case '+':
                return 62;
        default:
                if ((base64 >= 'A') && (base64 <= 'Z'))
                        return base64 - 'A';
                else if ((base64 >= 'a') && (base64 <= 'z'))
                        return 26 + (base64 - 'a');
                else if ((base64 >= '0') && (base64 <= '9'))
                        return 52 + (base64 - '0');
                else
                        return -1;
        }
}

static void decode_base64_string(char *string, u8 *intnum, int int_len)
{
        int len, count, intptr, octets;
        u8 num[4];

        (void) int_len;

        if (!string || !intnum)
                goto out;
        len = strlen(string);
        if (!len)
                goto out;
        if ((len % 4))
                goto out;

        count = 0;
        intptr = 0;

        while (count < len - 4) {
                num[0] = decode_base64_digit(string[count]);
                num[1] = decode_base64_digit(string[count + 1]);
                num[2] = decode_base64_digit(string[count + 2]);
                num[3] = decode_base64_digit(string[count + 3]);
                if ((num[0] == 65) || (num[1] == 65) || (num[2] == 65) || (num[3] == 65))
                        goto out;
                count += 4;
                octets = (num[0] << 18) | (num[1] << 12) | (num[2] << 6) | num[3];
                intnum[intptr] = (octets & 0xff0000) >> 16;
                intnum[intptr + 1] = (octets & 0x00ff00) >> 8;
                intnum[intptr + 2] = octets & 0x0000ff;
                intptr += 3;
        }
        num[0] = decode_base64_digit(string[count]);
        num[1] = decode_base64_digit(string[count + 1]);
        num[2] = decode_base64_digit(string[count + 2]);
        num[3] = decode_base64_digit(string[count + 3]);
        if ((num[0] == 64) || (num[1] == 64))
                goto out;
        if (num[2] == 64) {
                if (num[3] != 64)
                        goto out;
                intnum[intptr] = (num[0] << 2) | (num[1] >> 4);
        } else if (num[3] == 64) {
                intnum[intptr] = (num[0] << 2) | (num[1] >> 4);
                intnum[intptr + 1] = (num[1] << 4) | (num[2] >> 2);
        } else {
                octets = (num[0] << 18) | (num[1] << 12) | (num[2] << 6) | num[3];
                intnum[intptr] = (octets & 0xff0000) >> 16;
                intnum[intptr + 1] = (octets & 0x00ff00) >> 8;
                intnum[intptr + 2] = octets & 0x0000ff;
        }
out:
        return;
}

int chap_decode_string(char *encoded, u8 *decode_buf, int buf_len, int encoding_fmt)
{
        int ret = 0;

        if (encoding_fmt == HEX_FORMAT) {
                if ((strlen(encoded) - 2) > (u32)(2 * buf_len)) {
                        DERROR("BUG: buf[%d] !sufficient to decode string[%d]\n",
                               buf_len, (int)strlen(encoded));
                        ret = CHAP_TARGET_ERROR;
                        goto out;
                }
                decode_hex_string(encoded + 2, decode_buf, buf_len);
        } else if (encoding_fmt == BASE64_FORMAT) {
                if ((strlen(encoded) - 2) > (u32)((buf_len - 1) / 3 + 1) * 4) {
                        DERROR("BUG: buf[%d] !sufficient to decode string[%d]\n",
                               buf_len, (int)strlen(encoded));
                        ret = CHAP_TARGET_ERROR;
                        goto out;
                }
                decode_base64_string(encoded + 2, decode_buf, buf_len);
        } else {
                ret = CHAP_INITIATOR_ERROR;
        }

out:
        return ret;
}

void chap_calc_digest_md5(char chap_id, char *secret, int secret_len, u8 *challenge, int challenge_len, u8 *digest)
{
        struct md5_ctx ctx;

        md5_init(&ctx);
        md5_update(&ctx, &chap_id, 1);
        md5_update(&ctx, secret, secret_len);
        md5_update(&ctx, challenge, challenge_len);
        md5_final(&ctx, digest);
}

void chap_calc_digest_sha1(char chap_id, char *secret, int secret_len, u8 *challenge, int challenge_len, u8 *digest)
{
        struct sha1_ctx ctx;

        sha1_init(&ctx);
        sha1_update(&ctx, &chap_id, 1);
        sha1_update(&ctx, secret, secret_len);
        sha1_update(&ctx, challenge, challenge_len);
        sha1_final(&ctx, digest);
}

int account_empty(struct iscsi_conn *conn, int dir);
/*{
        char pass[MAX_NAME_LEN];

        return cops->account_query(conn, dir, pass, pass) ? 1 : 0;
}*/

static int chap_initiator_auth_check_response(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        char name[MAX_NAME_LEN], *value;
        u8 *his_digest = NULL, *our_digest = NULL;
        int digest_len = 0, ret = 0, encoding_format;
        char pass[MAX_NAME_LEN];
        struct iscsi_conn *conn = req->conn;

        (void) rsp;

        value = param_list_find(&conn->param_list, "CHAP_N");
        if (!value) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        YASSERT(strlen(value) < MAX_NAME_LEN);
        strcpy(name, value);
        DBUG("CHAP_N: %s\n", value);

        /* find password in configure file base on initiator name */
        memset(pass, 0x00, sizeof(pass));
        if (conn->session_type == SESSION_NORMAL) {
                if (account_empty(conn, AUTH_DIR_INCOMING)) {
                        goto finish;
                }
        }

        ret = cops->account_query(conn, AUTH_DIR_INCOMING, name, pass);
        if (unlikely(ret)) {
                DWARN("CHAP initiator auth: "
                      "No valid user/pas combination for initiator %s found\n",
                      conn->initiator);
                ret = CHAP_AUTH_ERROR;
                goto out;
        }

        if (conn->session_type == SESSION_NORMAL) {
                if (strcmp(name, value)) {
                        DBUG("CHAP initiator auth: "
                              "No valid user/pas combination for initiator %s found\n",
                              conn->initiator);
                        ret = CHAP_AUTH_ERROR;
                        goto out;
                }
        }

        value = param_list_find(&conn->param_list, "CHAP_R");
        if (!value) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }
        DBUG("CHAP_R: %s\n", value);

        encoding_format = chap_check_encoding_format(value);
        if (encoding_format < 0) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }
        DBUG("encoding_format: %d\n", encoding_format);

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                digest_len = CHAP_MD5_DIGEST_LEN;
                break;
        case CHAP_DIGEST_ALG_SHA1:
                digest_len = CHAP_SHA1_DIGEST_LEN;
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        his_digest = malloc(digest_len);
        if (!his_digest) {
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        our_digest = malloc(digest_len);
        if (!our_digest) {
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        ret = chap_decode_string(value, his_digest, digest_len, encoding_format);
        if (unlikely(ret)) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                chap_calc_digest_md5(conn->auth.chap.id, pass, strlen(pass),
                                     conn->auth.chap.challenge,
                                     conn->auth.chap.challenge_size,
                                     our_digest);
                break;
        case CHAP_DIGEST_ALG_SHA1:
                chap_calc_digest_sha1(conn->auth.chap.id, pass, strlen(pass),
                                      conn->auth.chap.challenge,
                                      conn->auth.chap.challenge_size,
                                      our_digest);
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        if (conn->session_type == SESSION_DISCOVERY) {
                strcpy(conn->auth_username, name);
                strcpy(conn->auth_password, value);
        } else if (memcmp(our_digest, his_digest, digest_len)) {
                ret = CHAP_AUTH_ERROR;
                goto out;
        }

finish:
        conn->state = CHAP_AUTH_STATE_RESPONSE;

        ret = 0;
out:
        free(his_digest);
        free(our_digest);
        return ret;
}

int chap_alloc_decode_buffer(char *encoded, u8 **decode_buf, int encoding_fmt)
{
        int ret, i;
        int decode_len = 0;

        i = strlen(encoded);
        i -= 2;

        if (encoding_fmt == HEX_FORMAT)
                decode_len = (i - 1) / 2 + 1;
        else if (encoding_fmt == BASE64_FORMAT) {
                if (i % 4) {
                        ret = CHAP_INITIATOR_ERROR;
                        goto out;
                }

                decode_len = i / 4 * 3;
                if (encoded[i + 1] == '=')
                        decode_len--;
                if (encoded[i] == '=')
                        decode_len--;
        }

        if (!decode_len) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        *decode_buf = malloc(decode_len);
        if (!*decode_buf) {
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        return decode_len;
out:
        return ret;
}

static inline void encode_hex_string(u8 *intnum, long length, char *string)
{
        int i;
        char *strptr;

        strptr = string;
        for (i = 0; i < length; ++i, strptr += 2)
                sprintf(strptr, "%.2hhx", intnum[i]);
}

static void encode_base64_string(u8 *intnum, long length, char *string)
{
        int count, octets, strptr, delta;
        static const char base64code[] = {
                'A', 'B', 'C', 'D', 'E', 'F', 'G',
                'H', 'I', 'J', 'K', 'L', 'M', 'N',
                'O', 'P', 'Q', 'R', 'S', 'T', 'U',
                'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
                'c', 'd', 'e', 'f', 'g', 'h', 'i',
                'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w',
                'x', 'y', 'z', '0', '1', '2', '3',
                '4', '5', '6', '7', '8', '9', '+',
                '/', '=',
        };

        if ((!intnum) || (!string) || (!length))
                goto out;

        count = octets = strptr = 0;

        while ((delta = (length - count)) > 2) {
                octets = (intnum[count] << 16) | (intnum[count + 1] << 8) | intnum[count + 2];
                string[strptr] = base64code[(octets & 0xfc0000) >> 18];
                string[strptr + 1] = base64code[(octets & 0x03f000) >> 12];
                string[strptr + 2] = base64code[(octets & 0x000fc0) >> 12];
                string[strptr + 3] = base64code[octets & 0x00003f];
                count += 3;
                strptr += 4;
        }

        if (delta == 1) {
                string[strptr] = base64code[(intnum[count] & 0xfc) >> 2];
                string[strptr + 1] = base64code[(intnum[count] & 0x03) << 4];
                string[strptr + 2] = base64code[64];
                string[strptr + 3] = base64code[64];
                strptr += 4;
        } else if (delta == 2) {
                string[strptr] = base64code[(intnum[count] & 0xfc) >> 2];
                string[strptr + 1] = base64code[(intnum[count] & 0x03) << 4 | ((intnum[count + 1] & 0xf0) >> 4)];
                string[strptr + 2] = base64code[(intnum[count + 1] & 0x0f) << 2];
                string[strptr + 3] = base64code[64];
                strptr += 4;
        }
        string[strptr] = 0;
out:
        return;
}

void chap_encode_string(u8 *intnum, int buf_len, char *encode_buf, int encoding_fmt)
{
        encode_buf[0] = '0';
        if (encoding_fmt == HEX_FORMAT) {
                encode_buf[1] = 'x';
                encode_hex_string(intnum, buf_len, encode_buf + 2);
        } else if (encoding_fmt == BASE64_FORMAT) {
                encode_buf[1] = 'b';
                encode_base64_string(intnum, buf_len, encode_buf + 2);
        }
}

static int chap_target_auth_create_response(struct iscsi_cmd *req, struct iscsi_cmd *rsp) 
{
        char chap_id, *value, *response = NULL;
        u8 *challenge = NULL, *digest = NULL;
        int encoding_format, response_len;
        int challenge_len = 0, digest_len = 0, ret = 0;
        char pass[MAX_NAME_LEN], name[MAX_NAME_LEN];
        struct iscsi_conn *conn = req->conn;

        value = param_list_find(&conn->param_list, "CHAP_I");
        if (!value) {
                /* Initiator doesn't want target auth ?! */
                conn->state = STATE_SECURITY_DONE;
                ret = 0;
                goto out;
        }

        chap_id = strtol(value, &value, 10);

        memset(pass, 0x00, sizeof(pass));
        memset(name, 0x00, sizeof(name));

        /* Get name and pass from configure file */
        ret = cops->account_query(conn, AUTH_DIR_OUTGOING, name, pass);
        if (unlikely(ret)) {
                DWARN("CHAP target auth : no outgoing credentials configure");
                ret = CHAP_AUTH_ERROR;
                goto out;
        }

        value = param_list_find(&conn->param_list, "CHAP_C");
        if (!value) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        encoding_format = chap_check_encoding_format(value);
        if (encoding_format < 0) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        DBUG("encoding_format: %d\n", encoding_format);

        ret = chap_alloc_decode_buffer(value, &challenge, encoding_format);
        if (ret <= 0)
                goto out;
        else if (ret > 1024) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        challenge_len = ret;
        ret = 0;

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                digest_len = CHAP_MD5_DIGEST_LEN;
                break;
        case CHAP_DIGEST_ALG_SHA1:
                digest_len = CHAP_SHA1_DIGEST_LEN;
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        if (encoding_format == HEX_FORMAT)
                response_len = 2 * digest_len;
        else
                response_len = ((digest_len - 1) / 3 + 1) * 4;
        /* "0x" / "0b" and '\0' */
        response_len += 3;

        digest = malloc(digest_len);
        if (!digest) {
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        response = malloc(response_len);
        if (!response) {
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        ret = chap_decode_string(value, challenge, challenge_len, encoding_format);
        if (unlikely(ret)) {
                ret = CHAP_INITIATOR_ERROR;
                goto out;
        }

        /*
         * CHAP challenges MUST NOT be reused - RFC3720
         */
        if (challenge_len == conn->auth.chap.challenge_size) {
                if (!memcmp(challenge, conn->auth.chap.challenge, challenge_len)) {
                        ret = CHAP_INITIATOR_ERROR;
                        goto out;
                }
        }

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                chap_calc_digest_md5(chap_id, pass, strlen(pass),
                                     challenge, challenge_len, digest);
                break;
        case CHAP_DIGEST_ALG_SHA1:
                chap_calc_digest_sha1(chap_id, pass, strlen(pass),
                                      challenge, challenge_len, digest);
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto out;
        }

        memset(response, 0x00, response_len);
        chap_encode_string(digest, digest_len, response, encoding_format);
        tio_add_param(rsp, "CHAP_N", name);
        tio_add_param(rsp, "CHAP_R", response);

        conn->state = STATE_SECURITY_DONE;
        ret = 0;
out:
        return ret;
}

/*
 * Initiator                                       target
 *    |                                              |
 *    |        CHAP_A (algorithm)                    |
 *    |  ----------------------------------------->  |
 *    |                                              | 1. Generate ID
 *    |        CHAP_A (algorithm)                    | 2. Generate random string
 *    |        CHAP_I (ID)                           |
 *    |        CHAP_C (random string)                |
 *    |  <-----------------------------------------  |
 *    |                                              |
 *    |        CHAP_N (initiator name)               |
 *    |        CHAP_R (string encryted by pass)      |
 *    |        CHAP_I (ID)                           |
 *    |        CHAP_C (random string)                |
 *    |  ----------------------------------------->  |
 *    |                                              | 1. Get pass by user
 *    |                                              | 2. encryted by pass
 *    |        CHAP_N (target name)                  | 3. compare with CHAP_R
 *    |        CHAP_R (string encryed by pass)       | 4. generate CHAP_R by
 *    |  <-----------------------------------------  |    CHAP_I and CHAP_C
 */

/*
 * cmd_exec_auth_chap - chap auth
 *
 * @req: request command
 * @rsp: response command
 *
 * @return: 0 on success, -1 on initiator error, -2 on auth failed,
 *          -3 on target error.
 */
int cmd_exec_auth_chap(struct iscsi_cmd *req, struct iscsi_cmd *rsp)
{
        int ret = 0;
        struct iscsi_conn *conn = req->conn;

        switch (conn->auth_state) {
        case CHAP_AUTH_STATE_START:
                ret = chap_initiator_auth_create_challenge(req, rsp);
                break;
        case CHAP_AUTH_STATE_CHALLENGE:
                ret = chap_initiator_auth_check_response(req, rsp);
                if (unlikely(ret))
                        break;
                /* fall through */
        case CHAP_AUTH_STATE_RESPONSE:
                ret = chap_target_auth_create_response(req, rsp);
                break;
        default:
                DERROR("BUG: unknow auth_state %ld\n", conn->auth_state);
                ret = CHAP_TARGET_ERROR;
                break;
        }

        return ret;
}

int ns_build_auth_chap(char *name, char *pass, struct iscsi_conn *conn)
{
        int ret, digest_len = 0, encoding_format;
        u8 *his_digest = NULL, *our_digest = NULL;

        if (!strlen(conn->auth_username) ||
            !strlen(conn->auth_password) ||
            strcmp(name, conn->auth_username)) {
                ret = CHAP_TARGET_ERROR;
                goto err_ret;
        }

        encoding_format = chap_check_encoding_format(conn->auth_password);
        if (encoding_format < 0) {
                ret = CHAP_INITIATOR_ERROR;
                goto err_ret;
        }

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                digest_len = CHAP_MD5_DIGEST_LEN;
                break;
        case CHAP_DIGEST_ALG_SHA1:
                digest_len = CHAP_SHA1_DIGEST_LEN;
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto err_ret;
        }

        ret = ymalloc((void **)&his_digest, digest_len);
        if (ret) {
                ret = CHAP_TARGET_ERROR;
                goto err_free;
        }

        ret = ymalloc((void **)&our_digest, digest_len);
        if (ret) {
                ret = CHAP_TARGET_ERROR;
                goto err_free;
        }

        ret = chap_decode_string(conn->auth_password, his_digest, digest_len, encoding_format);
        if (ret) {
                ret = CHAP_INITIATOR_ERROR;
                goto err_free;
        }

        switch (conn->auth.chap.digest_alg) {
        case CHAP_DIGEST_ALG_MD5:
                chap_calc_digest_md5(conn->auth.chap.id, pass, strlen(pass),
                                     conn->auth.chap.challenge,
                                     conn->auth.chap.challenge_size,
                                     our_digest);
                break;
        case CHAP_DIGEST_ALG_SHA1:
                chap_calc_digest_sha1(conn->auth.chap.id, pass, strlen(pass),
                                      conn->auth.chap.challenge,
                                      conn->auth.chap.challenge_size,
                                      our_digest);
                break;
        default:
                ret = CHAP_TARGET_ERROR;
                goto err_free;
        }

        if (memcmp(our_digest, his_digest, digest_len)) {
                ret = CHAP_AUTH_ERROR;
                goto err_free;
        }

        yfree((void **)&his_digest);
        yfree((void **)&our_digest);
        return 0;
err_free:
        if (his_digest)
                yfree((void **)&his_digest);
        if (our_digest)
                yfree((void **)&our_digest);
err_ret:
        return ret;
}
