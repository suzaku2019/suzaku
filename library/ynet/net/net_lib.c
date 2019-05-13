

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

#define DBG_SUBSYS S_LIBYNET

#include "net_table.h"
#include "net_global.h"
#include "pipe_pool.h"
#include "net_events.h"
#include "../rpc/rpc_proto.h"
#include "sdevent.h"
#include "configure.h"
#include "dbg.h"

net_global_t ng;

extern int nofile_max;
extern int pipe_max;

int net_init(net_proto_t *op)
{
        int ret;
	//int ksubversion;

        YASSERT(NET_HANDLE_LEN >= sizeof(net_handle_t));

        if (op)
                ng.op = *op;

        ng.op.head_len = sizeof(ynet_net_head_t);
        ng.op.writer = ng.op.writer ? ng.op.writer
                : net_events_handle_write;
        ng.op.reader = ng.op.reader ? ng.op.reader
                : net_events_handle_read;
        ng.op.pack_len = ng.op.pack_len ? ng.op.pack_len
                : rpc_pack_len;
        ng.op.pack_handler = ng.op.pack_handler ? ng.op.pack_handler
                : rpc_pack_handler;

        ret = netable_init(ng.daemon);
        if (ret)
                GOTO(err_ret, ret);

        ret = get_nodeid(ng.nodeid, "/dev/shm/sdfs/nodeid");
        if (ret)
                GOTO(err_ret, ret);

        ret = sdevent_init(nofile_max);
        if (ret)
                GOTO(err_ret, ret);

        return 0;
err_ret:
        return ret;
}

int net_destroy(void)
{
#if 0
        sdevents_destroy();

        ret = netable_destroy();
        if (ret)
                GOTO(err_ret, ret);
#endif

        return 0;
}
