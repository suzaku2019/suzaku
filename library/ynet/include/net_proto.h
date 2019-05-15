#ifndef __NET_PROTO_H__
#define __NET_PROTO_H__

#include <uuid/uuid.h>

#include "sdfs_conf.h"
#include "job_tracker.h"
#include "sdfs_id.h"
#include "dbg.h"

#if USE_EPOLL
#include <sys/epoll.h>
#endif

#define YNET_PORT_RANDOM 0

typedef int (*net_pack_handler)(const nid_t *nid, const sockid_t *sockid, buffer_t *buf);
typedef int (*net_pack_len)(void *, uint32_t, int *msg_len, int *io_len);
typedef int (*net_event_write_handler)(struct epoll_event *ev, void *);
typedef int (*net_event_read_handler)(void *sock, void *ctx);

typedef int (*net1_request_handler)(job_t *, void *sock, void *context);

#define net_request_handler func_t

typedef enum {
        MSG_NULL, //XXX:fix this type
        MSG_HEARTBEAT,
        MSG_LOOKUP,
        MSG_PING,
        MSG_MDP,
        MSG_REPLICA,
        MSG_LEASE,
        MSG_RINGLOCK,
        MSG_RANGE,
        MSG_MDS,
        MSG_MAX,
} net_progtype_t;

typedef struct {
        net_request_handler handler;
        void *context;
} net_prog_t;

/**
 * SUNRPC                   RPC (on CDS)
 * -----------------------------------------------
 * sunrpc_accept_handler    rpc_accept_handler  (for listen socket)
 * net_events_handler       net_events_handler  (for connection socket)
 * sunrpc_pack_len          rpc_pack_len
 * sunrpc_pack_handler      rpc_pack_handler
 * sunrpc_request_handler   cds_request_handler
 * rpc_reply_handler        rpc_reply_handler
 */

#if 0

typedef struct {
        uint32_t head_len; //length of proto head, not suitable for http
        net_pack_len      pack_len;          /*return the length of a pack */
        net_event_handler reader;
        net_event_handler writer;
        net_pack_handler  pack_handler;
        net_reset_handler  reset_handler;
        net_pack_handler  reply_handler;
        net_selfcheck_func selfcheck;
        jobtracker_t *jobtracker;
        net_prog_t  prog[MSG_MAX];
} net_proto_t;

#else

typedef struct {
        uint32_t head_len; //length of proto head, not suitable for http
        net_pack_len      pack_len;          /*return the length of a pack */
        net_event_read_handler reader;
        net_event_write_handler writer;
        net_pack_handler  pack_handler;
        jobtracker_t *jobtracker;
} net_proto_t;

#endif

/*inited in net_lib.c*/

#endif
