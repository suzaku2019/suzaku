#ifndef __AUTH_H
#define __AUTH_H

#include <stdbool.h>

#include "sdfs_lib.h"

int auth_create(const char *initiator, const char *pool, const char *path);
int auth_rm(const char *initiator, const char *pool, const char *path);
int auth_rm_by_fileid(const char *initiator, const char *fileid);
int unmap_hosts_by_fileid(const char *fileid);
int auth_is_mapping(const char *initiator, const fileid_t *fileid, int *is_mapping);

int auth_rm_all(const char *initiator);
int auth_list(const char *initiator, int output_format);
int auth_get(const char *initiator, char *user, char *pass);

int list_volume_mapped_hosts(const char *volume);
int get_volume_mapped_hosts(const char *fileid, char *hosts[], int *count);
int auth_find_volume(const char *initiator, const char *fileid, int *success);
int auth_inherit(const char *fpool, const char *fpath,
                const char *tpool, const char *tpath);


#endif
