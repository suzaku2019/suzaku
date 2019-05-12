#ifndef __SDFS_MACRO_H__
#define __SDFS_MACRO_H__

#include "sdfs_id.h"

#if 0

#define MD_INFO "__info__"
#define MD_CHILDREN "__children__"
#define MD_SNAPSHOT "__snapshot__"
#define MD_XATTR "__xattr__"
#define MD_PARENT "__parent__"
#define MD_POOL "__pool__"
#define MD_CHKINFO "__chkinfo__"
#define MD_SNAPSHOT_ID "__snapid__"
#define MD_SNAPSHOT_ATTR "__snapattr__"

#else

#define MD_INFO "info"
#define MD_CHILDREN "children"
#define MD_SNAPSHOT "snapshot" 
#define MD_XATTR "xattr"
#define MD_PARENT "parent"
#define MD_POOL "pool"
#define MD_CHKINFO "chkinfo"
#define MD_SNAPSHOT_ID "snapid"
#define MD_SNAPSHOT_ATTR "snapattr"

#endif          

#define ETCD_TREE "metadata"

#endif
