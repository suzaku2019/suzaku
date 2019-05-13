#ifndef __CHK_PROTO_H__
#define __CHK_PROTO_H__


#pragma pack(8)

typedef enum {
        CHKOP_WRITE = 1,
        CHKOP_READ = 2,
        CHKOP_DEL = 3,
        CHKOP_TRUNC = 4,
} chkop_type_t;

#pragma pack(0)

#define YFS_CRC_SEG_LEN (8192 * 8)

#endif
