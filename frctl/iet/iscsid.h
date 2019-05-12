#ifndef __ISCSID_H__
#define __ISCSID_H__

#define ISCSID_DRIVER_TCP       1
#define ISCSID_DRIVER_ISER      2

int iscsid_srv(int driver);

#endif
