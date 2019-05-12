#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <netdb.h>
#include <sys/ioctl.h>
#ifdef __CYGWIN__
#include <net/if.h>
#else
#include <linux/if.h>
#endif

#define DBG_SUBSYS S_YRPC

#include "ynet_net.h"
#include "net_global.h"
#include "main_loop.h"
#include "ylib.h"
#include "ynet_rpc.h"
#include "sdfs_conf.h"
#include "configure.h"
#include "md.h"
#include "../sock/sock_tcp.h"
#include "nodeid.h"
#include "network.h"
#include "dbg.h"
#include "yatomic.h"

#define POLL_TMO 2

int rpc_info2nid(net_handle_t *nh, const ynet_net_info_t *info)
{
        (void) nh;
        (void) info;
        UNIMPLEMENTED(__DUMP__);

        return 0;
                
        //return net_info2nid(nh, info);
}
