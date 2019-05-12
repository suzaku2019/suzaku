project (sdfs)

cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE OFF)

set (USS_VERSION_MAJOR 1)
set (USS_VERSION_MINOR 0)

set(CMAKE_INSTALL_PREFIX "/opt/sdfs")
set(SDFS_HOME "/opt/sdfs")
set(USE_EPOLL 1)

if(VALGRIND)
    ADD_DEFINITIONS(-DCONFIG_VALGRIND_H)
endif(VALGRIND)

if(PERF_MDS)
    ADD_DEFINITIONS(-DCONFIG_PERF_MDS_H)
endif(PERF_MDS)

#set(CMAKE_INSTALL_PREFIX "/tmp/yfs/")
#set(CMAKE_CURRENT_SOURCE_DIR "./")

configure_file (
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cmakeconfig.h.ini"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cmakeconfig.h"
)

execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/get_version.sh ${CMAKE_CURRENT_SOURCE_DIR})

find_package(BISON)
find_package(FLEX)
BISON_TARGET(MyBison ${CMAKE_CURRENT_SOURCE_DIR}/parser/lib/confy.y ${CMAKE_CURRENT_BINARY_DIR}/confy.c)
FLEX_TARGET(MyFlex ${CMAKE_CURRENT_SOURCE_DIR}/parser/lib/confl.l ${CMAKE_CURRENT_BINARY_DIR}/confl.c)
#add_executable(Foo main.cpp ${BISON_MyParser_OUTPUTS})
#ADD_FLEX_BISON_DEPENDENCY(MyBison MyFlex)
#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS_PARSER "-W -Wall -DDEBUG -g -fPIC -Werror=return-type -D_GNU_SOURCE -D_REENTRANT")

set(CMAKE_C_FLAGS "-W -Wall -DDEBUG -g -fPIC -Werror -Wno-implicit-fallthrough -Werror=return-type -Wno-format-truncation -Wno-format-overflow -Wno-misleading-indentation -Wno-deprecated-declarations -Wno-cast-function-type -Wno-int-in-bool-context -Wno-pointer-compare -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -std=c99 -fms-extensions -gsplit-dwarf")

#set(CMAKE_C_FLAGS "-W -Wall -DDEBUG -g -O3 -fPIC -Werror -Wno-stringop-truncation -Wno-stringop-overflow -Wno-implicit-fallthrough -Werror=return-type -Wno-format-truncation -Wno-format-overflow -Wno-misleading-indentation -Wno-deprecated-declarations -Wno-cast-function-type -Wno-int-in-bool-context -Wno-pointer-compare -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -std=c99 -fms-extensions -gsplit-dwarf")

set(CMAKE_C_LIBS sdfs pthread crypt crypto uuid ssl z m curl yajl hiredis)

include_directories(
    /usr/local/include
    #/usr/include/tirpc/
    #${CMAKE_CURRENT_SOURCE_DIR}/license/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs
    ${CMAKE_CURRENT_SOURCE_DIR}/cds
    ${CMAKE_CURRENT_SOURCE_DIR}/parser/include
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/mds
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs
    ${CMAKE_CURRENT_BINARY_DIR}/
)

add_library(sdfs SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/parser/lib/configure.c
    ${CMAKE_CURRENT_BINARY_DIR}/confy.c
    ${CMAKE_CURRENT_BINARY_DIR}/confl.c
    ${CMAKE_CURRENT_BINARY_DIR}/confy.h

    #------ylib------

    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/kv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/timer.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/redis_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/worker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/job_dock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/array_table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/buffer.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/ec_isa_l.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/cmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/ll.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/crc32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/crcrs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/daemon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/dbg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/htab.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/cache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/job_tracker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/lock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/mem_cache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/mem_hugepage.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/nls.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/nls/nls_cp936.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/skiplist.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/stat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/sysutil.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/ylog.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/plock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/tpool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/ytime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/bmap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/privilege.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/md5.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/analysis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/mini_hashtb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/bh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/fnotify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/nodectl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/removed.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/etcd-api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/base64_urlsafe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/cJSON.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/aio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/core_latency.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/corenet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/corenet_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/corenet_connect_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/corenet_maping.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/corerpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/cpuset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/schedule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/gettime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/schedule_thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/schedule/variable.c

    #------ynet------

    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/nodeid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sock_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/sock/sdevent.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_crc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_events.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/network.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/maping.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/heartbeat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/net_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/conn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/net/main_loop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/msgqueue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_proto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_reply.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_request.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_request_old.c
    #${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_reply_old.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ynet/rpc/rpc_table.c

    #------sdfs------

    #${CMAKE_CURRENT_SOURCE_DIR}/license/src/aes.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/redis.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/redis_co.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/redis_pipeline.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/redis_vol.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/redis_conn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_attr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/dir_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/chunk_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/inode_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/kv_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/sdfs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/chunk_replica.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/allocator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/io_analysis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/sdfs_inode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/sdfs_dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/vss.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/volume.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/vs_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/range.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/range_ctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/range_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/cds_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/sdfs_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sdfs/sdfs_chunk_recovery.c
    #${CMAKE_CURRENT_SOURCE_DIR}/license/src/license_helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_pool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_node.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_super.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_file.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_user.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_group.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_quota.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_share.c
    #${CMAKE_CURRENT_SOURCE_DIR}/metadata/md_lvm_qos.c
    ${CMAKE_CURRENT_SOURCE_DIR}/metadata/md.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/super.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/raw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/file_table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/yfs_lib.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/worm_cli_lib.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/quota.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/user.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/group.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/posix_acl.c
    #${CMAKE_CURRENT_SOURCE_DIR}/yfs/libyfs/flock.c

    #------cds------

    ${CMAKE_CURRENT_SOURCE_DIR}/cds/cds.c
    #${CMAKE_CURRENT_SOURCE_DIR}/cds/cds_hb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_alloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_write.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_read.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_redis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_raw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_raw_aio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/disk_io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/diskid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cds/diskio.c

    #------mds------
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_kv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_lease.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/lease_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/lease_cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/partition.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/ringlock_srv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/ringlock_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/ringlock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/pa_srv.c
)

set (MDS_SRC_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_main.c
)

set (CDS_SRC_LIST
	${CMAKE_CURRENT_SOURCE_DIR}/cds/main.c
)

set (FRCTL_SRC_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/iscsid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/digest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/ua.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/md5.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/tio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/sdfsio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/sha1.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/conn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/chap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/target_disk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/iscsi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/param.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/target.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/volume.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/debug.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/iet/cmds.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/main.c
)

add_executable(sdfs.mdctl ${MDS_SRC_LIST})
target_link_libraries(sdfs.mdctl ${CMAKE_C_LIBS} hiredis)

add_executable(sdfs.bactl ${CDS_SRC_LIST})
target_link_libraries(sdfs.bactl ${CMAKE_C_LIBS})

add_executable(sdfs.frctl ${FRCTL_SRC_LIST})
target_link_libraries(sdfs.frctl ${CMAKE_C_LIBS})

#add_executable(sdfs.nlm ${YNLM_SRC_LIST})
#target_link_libraries(sdfs.nlm ${CMAKE_C_LIBS})

add_executable(sdfs.configdump ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.configdump.c)
target_link_libraries(sdfs.configdump ${CMAKE_C_LIBS})

add_executable(sdfs.write ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.write.c)
target_link_libraries(sdfs.write ${CMAKE_C_LIBS})

#add_executable(sdfs.mv ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.mv.c)
#target_link_libraries(sdfs.mv ${CMAKE_C_LIBS})

#add_executable(sdfs.zk ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.zk.c)
#target_link_libraries(sdfs.zk ${CMAKE_C_LIBS})

add_executable(sdfs.cat ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.cat.c)
target_link_libraries(sdfs.cat ${CMAKE_C_LIBS})

add_executable(sdfs.attr ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.attr.c)
target_link_libraries(sdfs.attr ${CMAKE_C_LIBS})

#add_executable(sdfs.objmv ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.objmv.c)
#target_link_libraries(sdfs.objmv ${CMAKE_C_LIBS})

add_executable(sdfs.mkdir ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.mkdir.c)
target_link_libraries(sdfs.mkdir ${CMAKE_C_LIBS})

add_executable(sdfs.mkpool ${CMAKE_CURRENT_SOURCE_DIR}/utils/sdfs.mkpool.c)
target_link_libraries(sdfs.mkpool ${CMAKE_C_LIBS})

add_executable(sdfs.truncate ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.truncate.c)
target_link_libraries(sdfs.truncate ${CMAKE_C_LIBS})

#add_executable(sdfs.mdstat ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.mdstat.c)
#target_link_libraries(sdfs.mdstat ${CMAKE_C_LIBS})

add_executable(sdfs.touch ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.touch.c)
target_link_libraries(sdfs.touch ${CMAKE_C_LIBS})

add_executable(sdfs.perf ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.perf.c)
target_link_libraries(sdfs.perf ${CMAKE_C_LIBS})

#add_executable(test_aio ${CMAKE_CURRENT_SOURCE_DIR}/test/src/test_aio.c ${CMAKE_CURRENT_SOURCE_DIR}/test/src/test_aio_lib.c)
#target_link_libraries(test_aio ${CMAKE_C_LIBS})

set (MDS_SRC_PERF_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_events.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_state_machine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/disk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/diskpool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/nodepool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/nodepool_hdd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/nodepool_ssd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/election.c
    ${CMAKE_CURRENT_SOURCE_DIR}/license/src/license_helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mds/mds_license.c
)

#add_executable(sdfs.perf_mds ${MDS_SRC_PERF_LIST} ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.perf_mds.c)
#target_link_libraries(sdfs.perf_mds ${CMAKE_C_LIBS})

#add_executable(sdfs.prof ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.prof.c)
#target_link_libraries(sdfs.prof ${CMAKE_C_LIBS})

add_executable(sdfs.ls ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.ls.c)
target_link_libraries(sdfs.ls ${CMAKE_C_LIBS})

#add_executable(sdfs.license ${YLICENSE_SRC_LIST})
#target_link_libraries(sdfs.license ${CMAKE_C_LIBS})

set (USS_USER_SRC
	${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.user.c
	${CMAKE_CURRENT_SOURCE_DIR}/ylib/lib/md5.c
)
#add_executable(sdfs.user ${USS_USER_SRC})
#target_link_libraries(sdfs.user ${CMAKE_C_LIBS})

#add_executable(sdfs.group ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.group.c)
#target_link_libraries(sdfs.group ${CMAKE_C_LIBS})

#add_executable(sdfs.health ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/sdfs.health.c)
#target_link_libraries(sdfs.health ${CMAKE_C_LIBS})

add_executable(sdfs.mon ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/sdfs.mon.c)
target_link_libraries(sdfs.mon ${CMAKE_C_LIBS})

#add_executable(sdfs.ln ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.ln.c)
#target_link_libraries(sdfs.ln ${CMAKE_C_LIBS})

add_executable(sdfs.rmdir ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.rmdir.c)
target_link_libraries(sdfs.rmdir ${CMAKE_C_LIBS})

add_executable(sdfs.rm ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.rm.c)
target_link_libraries(sdfs.rm ${CMAKE_C_LIBS})

#add_executable(sdfs.cp ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.cp.c)
#target_link_libraries(sdfs.cp ${CMAKE_C_LIBS})

#add_executable(sdfs.chkstat ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.chkstat.c)
#target_link_libraries(sdfs.chkstat ${CMAKE_C_LIBS})

add_executable(sdfs.stat ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.stat.c)
target_link_libraries(sdfs.stat ${CMAKE_C_LIBS})

add_executable(sdfs.chmod ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.chmod.c)
target_link_libraries(sdfs.chmod ${CMAKE_C_LIBS})

#add_executable(sdfs.clone ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.clone.c)
#target_link_libraries(sdfs.clone ${CMAKE_C_LIBS})

add_executable(sdfs.md5sum ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.md5sum.c)
target_link_libraries(sdfs.md5sum ${CMAKE_C_LIBS})

#add_executable(sdfs.sysop ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.sysop.c)
#target_link_libraries(sdfs.sysop ${CMAKE_C_LIBS})

#add_executable(sdfs.mdsdrop ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.mdsdrop.c)
#target_link_libraries(sdfs.mdsdrop ${CMAKE_C_LIBS})

#add_executable(sdfs.cdstat ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.cdstat.c)
#target_link_libraries(sdfs.cdstat ${CMAKE_C_LIBS})

#add_executable(sdfs.ffc ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.ffc.c)
#target_link_libraries(sdfs.ffc ${CMAKE_C_LIBS})

#add_executable(sdfs.hsm ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.hsm.c)
#target_link_libraries(sdfs.hsm ${CMAKE_C_LIBS})

#add_executable(sdfs.fallocate ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.fallocate.c)
#target_link_libraries(sdfs.fallocate ${CMAKE_C_LIBS})

#add_executable(sdfs.du ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.du.c)
#target_link_libraries(sdfs.du ${CMAKE_C_LIBS})

#add_executable(sdfs.statvfs ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.statvfs.c)
#target_link_libraries(sdfs.statvfs ${CMAKE_C_LIBS})

#set (USS_WORM_SRC
#        ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.worm.c
#)

#add_executable(sdfs.worm ${USS_WORM_SRC})
#target_link_libraries(sdfs.worm ${CMAKE_C_LIBS})

add_executable(sdfs.chown ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.chown.c)
target_link_libraries(sdfs.chown ${CMAKE_C_LIBS})

#add_executable(sdfs.quota ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.quota.c)
#target_link_libraries(sdfs.quota ${CMAKE_C_LIBS})

#add_executable(sdfs.share ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.share.c)
#target_link_libraries(sdfs.share ${CMAKE_C_LIBS})

set (USS_ADMIN_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/uss.admin.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yfs/utils/option.c
)
add_executable(sdfs.admin ${USS_ADMIN_SRC})
target_link_libraries(sdfs.admin ${CMAKE_C_LIBS} hiredis)

install(TARGETS sdfs LIBRARY DESTINATION app/lib)

install(TARGETS sdfs.mdctl RUNTIME DESTINATION app/sbin)
install(TARGETS sdfs.bactl RUNTIME DESTINATION app/sbin)
install(TARGETS sdfs.frctl RUNTIME DESTINATION app/sbin)

install(TARGETS sdfs.configdump RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.write RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.mv RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.zk RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.cat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.attr RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.objmv RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mkdir RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mkpool RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.truncate RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.touch RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.perf RUNTIME DESTINATION app/bin)
# install(TARGETS sdfs.perf_mds RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.prof RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.ls RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.health RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mon RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.ln RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.rmdir RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.rm RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.cp RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.chkstat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.chmod RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.clone RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.md5sum RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.sysop RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.mdsdrop RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.ffc RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.hsm RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.fallocate RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.du RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.license RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.mdstat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.stat RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.cdstat RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.statvfs RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.admin RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.worm RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.chown RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.quota RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.share RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.user RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.group RUNTIME DESTINATION app/bin)

#install(TARGETS test_aio RUNTIME DESTINATION app/test)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/admin DESTINATION app/ FILE_PERMISSIONS OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include DESTINATION app/ FILE_PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

#execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/include/install.sh -i ${CMAKE_INSTALL_PREFIX}/include)

#SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)
IF (EXISTS ${CMAKE_INSTALL_PREFIX}/etc)
    MESSAGE("etc exists, ignore")
ELSE()
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/etc/sdfs.conf DESTINATION etc/)
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/etc/redis.conf.tpl DESTINATION etc/)
ENDIF()
#install(TARGETS ../admin/utils.py RUNTIME DESTINATION admin/)
#install(TARGETS ../admin/instence.py RUNTIME DESTINATION admin/)
#install(TARGETS ../admin/node.py RUNTIME DESTINATION admin/)

#execute_process(COMMAND ln -s CMAKE_INSTALL_PREFIX/app/admin/cluster.py CMAKE_INSTALL_PREFIX/app/bin/uss.cluster)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
#set (CPACK_SET_DESTDIR true)
#set (CPACK_PACKAGE_INSTALL_DIRECTORY "./sdfs")
set (CPACK_PACKAGE_VERSION_MAJOR "${USS_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${USS_VERSION_MINOR}")
include (CPack)
