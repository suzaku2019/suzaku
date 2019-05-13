#ifndef __XATTR_H__
#define __XATTR_H__

//set xattr flag
#define USS_XATTR_DEFAULT (0)
#define USS_XATTR_CREATE  (1 << 0) /* set value, fail if attr already exists */
#define USS_XATTR_REPLACE (1 << 1) /* set value, fail if attr does not exist */
#define USS_XATTR_INVALID (1 << 31)

#endif
