#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>

#define DBG_SUBSYS S_YFSMDS

#include "dir.h"
#include "net_global.h"
#include "sdfs_macro.h"
#include "md.h"
#include "md_db.h"
#include "dbg.h"

static int __kv_get(root_type_t type, const char *key, void *value, size_t *_len)
{
        int ret, len;
        char path[MAX_PATH_LEN];

        snprintf(path, MAX_NAME_LEN, "%d/%s", type, key);
        len = MAX_BUF_LEN;
        ret = etcd_get_bin(ETCD_KV, path, value, &len, NULL);
        if (ret)
                GOTO(err_ret, ret);

        YASSERT(len <= (int)*_len);
        
        return 0;
err_ret:
        return ret;
}

static int __kv_create(root_type_t type, const char *key, const void *value, size_t len)
{
        int ret;
        char path[MAX_PATH_LEN];

        snprintf(path, MAX_NAME_LEN, "%d/%s", type, key);
        ret = etcd_set_bin(ETCD_KV, path, value, len, O_EXCL, -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}


static int __kv_update(root_type_t type, const char *key, const void *value, size_t len)
{
        int ret;
        char path[MAX_PATH_LEN];

        snprintf(path, MAX_NAME_LEN, "%d/%s", type, key);
        ret = etcd_set_bin(ETCD_KV, path, value, len, 0, -1);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

static int __kv_remove(root_type_t type, const char *key)
{
        int ret;
        char path[MAX_PATH_LEN];

        snprintf(path, MAX_NAME_LEN, "%d/%s", type, key);
        ret = etcd_del(ETCD_KV, path);
        if (ret)
                GOTO(err_ret, ret);
        
        return 0;
err_ret:
        return ret;
}


static int __kv_iter(root_type_t type, const char *match, func2_t func, void *ctx)
{
        int ret;
        char path[MAX_PATH_LEN];
        etcd_node_t *array = NULL;

        snprintf(path, MAX_NAME_LEN, "%d", type);
        ret = etcd_list(path, &array);
        if(ret){
                GOTO(err_ret, ret);
        }

        for (int i = 0; i < array->num_node; i++) {
                etcd_node_t *node = array->nodes[i];
                if (strncmp(node->key, match, strlen(match)) == 0) {
                        func(node->key, node->value, ctx);
                }
        }

        free_etcd_node(array);
        
        return 0;
err_ret:
        return ret;
}

kvop_t __kvop__ = {
        .create = __kv_create,
        .get = __kv_get,
        .update = __kv_update,
        .scan = NULL,
        .lock = NULL,
        .unlock = NULL,
        .remove = __kv_remove,
        .iter = __kv_iter,
};
