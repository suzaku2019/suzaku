#ifndef __ISCSI_CHAP_H__
#define __ISCSI_CHAP_H__

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

int chap_check_encoding_format(char *encoded);
int chap_decode_string(char *encoded, u8 *decode_buf, int buf_len, int encoding_fmt);
void chap_calc_digest_md5(char chap_id, char *secret, int secret_len, u8 *challenge, int challenge_len, u8 *digest);
void chap_calc_digest_sha1(char chap_id, char *secret, int secret_len, u8 *challenge, int challenge_len, u8 *digest);
int chap_alloc_decode_buffer(char *encoded, u8 **decode_buf, int encoding_fmt);
void chap_encode_string(u8 *intnum, int buf_len, char *encode_buf, int encoding_fmt);

#endif
