#ifndef __RINGLOCK_CLI__
#define __RINGLOCK_CLI__

#include "ringlock_rpc.h"

int ringlock_locked(uint32_t type, ltoken_t *_token, int flag);
int ringlock_check(const chkid_t *chkid, int rtype,
                   int flag, ltoken_t *token);
int ringlock_init(uint32_t type);

#endif
