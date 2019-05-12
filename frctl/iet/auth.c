#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DBG_SUBSYS S_YISCSI

#include "auth.h"
#include "etcd.h"
#include "cJSON.h"
#include "ylib.h"
#include "dbg.h"

#define VOLUME_MAX_CONNECTION 128

static int __path_normalize(const char *path, char *path2)
{
        int i, len, begin, off, flag;

        len = strlen(path);
        off = 0;
        begin = -1;
        flag = 0;
        for(i = 0; i < len; ++i) {
                if (path[i] == '/') {
                        if (begin == -1) {
                                continue;
                        }
                        path2[off++] = '/';
                        strncpy(path2 + off, path + begin, i - begin);
                        off += i - begin;
                        begin = -1;
                } else {
                        flag = 1;
                        if (begin == -1) {
                                begin = i;
                        }
                }
        }

        if (begin != -1 && begin < i) {
                path2[off++] = '/';
                strncpy(path2 + off , path + begin , i - begin);
                off += i - begin;
        }

        if (flag == 0) {
                path2[0] = '/';
                off = 1;
        }
        path2[off] = '\0';

        return 0;
}

int path_head(const char *path, int sep, char *head, char *path2)
{
        char _path[MAX_PATH_LEN];
        int begin = -1, i;
        int found = 0;

        __path_normalize(path, _path);

        if (head)
                head[0] = '\0';

        sep = '/';
        size_t len = strlen(_path);
        for (i=0; i < (int)len; i++) {
                if (_path[i] == sep) {
                        if (begin == -1)
                                continue;

                        strncpy(head, _path + begin, i - begin);
                        head[i - begin] = '\0';
                        strcpy(path2, _path + i);
                        found = 1;
                        break;
                } else {
                        if (begin == -1) {
                                begin = i;
                        }
                }
        }

        if (!found && begin != -1 && begin < i) {
                strncpy(head, _path + begin, i - begin);
                head[i - begin] = '\0';
                strcpy(path2, _path + i);
                found = 1;
        }

        return 0;
}

static int path_prep_for_head(const char *path, char *pool, char *path2)
{
        int ret;
        char _path2[MAX_PATH_LEN];

        ret = path_head(path, '/', pool, _path2);
        if (ret) {
                GOTO(err_ret, ret);
        }

        if (!strlen(pool)) {
                ret = EINVAL;
                GOTO(err_ret, ret);
        }

        __path_normalize(_path2, path2);

        return 0;
err_ret:
        return ret;
}

static int __auth_getid(const char *pool, const char *_path, fileid_t *fileid)
{
        int ret;
        char path[MAX_PATH_LEN];

        snprintf(path, MAX_BUF_LEN, "/%s/%s", pool, _path);
        ret = sdfs_lookup_recurive(path, fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

/**
 * note:建立主机与某个卷间的映射
 */
int auth_create(const char *initiator, const char *pool, const char *path)
{
        int ret;
        fileid_t fileid;
        char realpath[MAX_NAME_LEN * 2];
        char etcdpath[MAX_NAME_LEN * 2];

        ret = __auth_getid(pool, path, &fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        sprintf(realpath, "%s%s", pool, path);
        ret = etcd_mkdir(ETCD_INITIATOR, initiator, 0);
        if (unlikely(ret)) {
                if (ret != EEXIST)
                        GOTO(err_ret, ret);
        }

        char key[MAX_NAME_LEN];
        fid2str(&fileid, key);
        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        ret = etcd_create_text(etcdpath, key, realpath, 0);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

/**
 * note:通过卷名，解除主机与某个卷间的映射
 */
int auth_rm(const char *initiator, const char *pool, const char *path)
{
        int ret;
        fileid_t fileid;
        char etcdpath[MAX_NAME_LEN * 2];

        ret = __auth_getid(pool, path, &fileid);
        if (unlikely(ret)) {
                if (ret == ENOENT)
                        goto out;
                else
                        GOTO(err_ret, ret);
        }

#if ENABLE_ISCSI_CONN_LIST
        ret = md_check_connection(&fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);
#endif

        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        char key[MAX_NAME_LEN];
        fid2str(&fileid, key);
        ret = etcd_del(etcdpath, key);
        if (unlikely(ret)) {
                if (ret != ENOENT)
                        GOTO(err_ret, ret);
        }

out:
        return 0;
err_ret:
        return ret;
}

/**
 * note:通过卷id，解除主机与某个卷间的映射
 */
int auth_rm_by_fileid(const char *initiator, const char *fileid)
{
        int ret;
        char etcdpath[MAX_NAME_LEN * 2];

        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        ret = etcd_del(etcdpath, fileid);
        if (unlikely(ret)) {
                if (ret != ENOENT)
                        GOTO(err_ret, ret);
        }

        return 0;
err_ret:
        return ret;
}

/**
 * note:解除某主机下所有卷的映射
 */
int auth_rm_all(const char *initiator)
{
        int ret, i;
        fileid_t fileid;
        char etcdpath[MAX_NAME_LEN * 2];
        etcd_node_t *list = NULL, *node;
        char pool[MAX_NAME_LEN], path[MAX_NAME_LEN];

        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        ret = etcd_list(etcdpath, &list);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        for (i = 0; i < list->num_node; i++) {
                node = list->nodes[i];
                path_prep_for_head(node->value, pool, path);
                ret = __auth_getid(pool, path, &fileid);
                if (unlikely(ret)) {
                        if (ret != ENOKEY && ret != ENOENT)
                                GOTO(err_free, ret);
                } else {
#if ENABLE_ISCSI_CONN_LIST
                        ret = md_check_connection(&fileid);
                        if (unlikely(ret))
                                GOTO(err_free, ret);
#endif
                }
        }

        free_etcd_node(list);

        ret = etcd_del_dir(ETCD_INITIATOR, initiator, 1);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        return 0;
err_free:
        free_etcd_node(list);
err_ret:
        return ret;
}

/**
 * note:解除卷与主机间的映射
 */
int unmap_hosts_by_fileid(const char *fileid)
{
        int ret, i;
        char *hosts[VOLUME_MAX_CONNECTION];
        int count = 0;

        ret = ymalloc((void **)&hosts, VOLUME_MAX_CONNECTION * MAX_NAME_LEN);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        get_volume_mapped_hosts(fileid, hosts, &count);

        for (i = 0; i < count; i++) {
                auth_rm_by_fileid(hosts[i], fileid);
        }

        yfree((void **)&hosts);
        return 0;
err_ret:
        return ret;
}

int auth_is_mapping(const char *initiator, const fileid_t *fileid, int *is_mapping)
{
        int ret;
        char path[MAX_NAME_LEN];
        char value[MAX_BUF_LEN];

        *is_mapping = 0;

        sprintf(path, "%s/%s", ETCD_INITIATOR, initiator);
        char key[MAX_NAME_LEN];
        fid2str(fileid, key);
        ret = etcd_get_text(path, key, value, NULL);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        *is_mapping = 1;
        return 0;
err_ret:
        return ret;
}

/**
 * note:显示某个主机下映射的卷
 */
int auth_list(const char *initiator, int output_format)
{
        int ret, i;
        char etcdpath[MAX_NAME_LEN * 2];
        etcd_node_t *list = NULL, *node;

        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        ret = etcd_list(etcdpath, &list);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        if (output_format == 1) {
                cJSON *json = cJSON_CreateObject();
                cJSON *array = cJSON_CreateArray();
                cJSON_AddItemToObject(json, initiator, array);
                cJSON *obj = cJSON_CreateObject();
                cJSON_AddItemToArray(array, obj);
                for (i = 0; i < list->num_node; i++) {
                        node = list->nodes[i];
                        cJSON_AddItemToObject(obj, node->key, cJSON_CreateString(node->value));
                }
                printf("%s\n", cJSON_PrintUnformatted(json));
                cJSON_Delete(json);
        } else {
                for (i = 0; i < list->num_node; i++) {
                        node = list->nodes[i];
                        printf("%s: %s\n", node->key, node->value);
                }
        }

        free_etcd_node(list);
        return 0;
err_ret:
        return ret;
}

/**
 * note:获取主机的username和password
 */
int auth_get(const char *initiator, char *username, char *password)
{
        int ret, count = MAX_NAME_LEN;
        char buf[MAX_NAME_LEN];
        char *tmp[MAX_NAME_LEN];

        ret = etcd_get_text(ETCD_CHAP, initiator, buf, NULL);
        if (ret) {
                if (ret == ENOKEY) {
                        DWARN("not found key[%s] in etcd !!!\n", initiator);
                        ret = ENOENT;
                        GOTO(err_ret, ret);
                } else
                        GOTO(err_ret, ret);
        }

        _str_split(buf, ' ', tmp, &count);
        if (count >= 2) {
                strcpy(username, tmp[0]);
                strcpy(password, tmp[1]);
        }

        return 0;
err_ret:
        return ret;
}

/**
 * note:判断主机是否映射了该卷
 */
int auth_find_volume(const char *initiator, const char *fileid, int *success)
{
        int ret, i;
        char etcdpath[MAX_NAME_LEN * 2];
        etcd_node_t *list = NULL, *node;

        sprintf(etcdpath, "%s/%s", ETCD_INITIATOR, initiator);
        ret = etcd_list(etcdpath, &list);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        for (i = 0; i < list->num_node; i++) {
                node = list->nodes[i];
                if (strcmp(node->key, fileid) == 0) {
                        *success = 1;
                        break;
                }
        }

        free_etcd_node(list);
        return 0;
err_ret:
        return ret;
}

/**
 * note:获取卷映射的全部主机
 */
int get_volume_mapped_hosts(const char *fileid, char *hosts[], int *count)
{
        int ret, i, success = 0, idx = 0;
        etcd_node_t *list = NULL, *node;

        ret = etcd_list(ETCD_INITIATOR, &list);
        if (unlikely(ret)) {
                GOTO(err_ret, ret);
        }

        for (i = 0; i < list->num_node; i++) {
                success = 0;
                node = list->nodes[i];
                auth_find_volume(node->key, fileid, &success);
                if (success) {
                        strcpy(hosts[idx], node->key);
                        idx++;
                }
        }

        *count = idx;
        free_etcd_node(list);

        return 0;
err_ret:
        return ret;
}

/**
 * note:显示卷映射的全部主机
 */
int list_volume_mapped_hosts(const char *fileid)
{
        int ret, i, count = 0;
        char *hosts[VOLUME_MAX_CONNECTION];

        ret = ymalloc((void **)&hosts, VOLUME_MAX_CONNECTION * MAX_NAME_LEN);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        get_volume_mapped_hosts(fileid, hosts, &count);

        for (i = 0; i < count; i++) {
                printf("%s\n", hosts[i]);
        }

        yfree((void **)&hosts);
        return 0;
err_ret:
        return ret;
}

/**
 * note:卷的主机映射关系全部被另一个卷继承
 */
int auth_inherit(const char *fpool, const char *fpath,
                const char *tpool, const char *tpath)
{
        int ret, i, count = 0;
        char *hosts[VOLUME_MAX_CONNECTION];
        fileid_t fileid;

        ret = ymalloc((void **)&hosts, VOLUME_MAX_CONNECTION * MAX_NAME_LEN);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        ret = __auth_getid(fpool, fpath, &fileid);
        if (unlikely(ret))
                GOTO(err_ret, ret);

        char key[MAX_NAME_LEN];
        fid2str(&fileid, key);
        get_volume_mapped_hosts(key, hosts, &count);

        for (i = 0; i < count; i++) {
                ret = auth_create(hosts[i], tpool, tpath);
                if (unlikely(ret))
                        DWARN("%s%s map %s failed.\n", tpool, tpath, hosts[i]);
        }

        return 0;
err_ret:
        return ret;
}
