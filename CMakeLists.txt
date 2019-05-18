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
BISON_TARGET(MyBison ${CMAKE_CURRENT_SOURCE_DIR}/library/config/lib/confy.y ${CMAKE_CURRENT_BINARY_DIR}/confy.c)
FLEX_TARGET(MyFlex ${CMAKE_CURRENT_SOURCE_DIR}/library/config/lib/confl.l ${CMAKE_CURRENT_BINARY_DIR}/confl.c)
#add_executable(Foo main.cpp ${BISON_MyParser_OUTPUTS})
#ADD_FLEX_BISON_DEPENDENCY(MyBison MyFlex)
#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS_PARSER "-W -Wall -DDEBUG -g -fPIC -Werror=return-type -D_GNU_SOURCE -D_REENTRANT")

set(CMAKE_C_FLAGS "-W -Wall -DDEBUG -g -fPIC -Werror -Wno-implicit-fallthrough -Werror=return-type -Wno-format-truncation -Wno-format-overflow -Wno-misleading-indentation -Wno-deprecated-declarations -Wno-cast-function-type -Wno-int-in-bool-context -Wno-pointer-compare -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -std=c99 -fms-extensions -gsplit-dwarf")

#set(CMAKE_C_FLAGS "-W -Wall -DDEBUG -g -O3 -fPIC -Werror -Wno-stringop-truncation -Wno-stringop-overflow -Wno-implicit-fallthrough -Werror=return-type -Wno-format-truncation -Wno-format-overflow -Wno-misleading-indentation -Wno-deprecated-declarations -Wno-cast-function-type -Wno-int-in-bool-context -Wno-pointer-compare -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -std=c99 -fms-extensions -gsplit-dwarf")

set(CMAKE_C_LIBS sdfs pthread crypt crypto uuid ssl z m curl yajl hiredis)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule
    ${CMAKE_CURRENT_SOURCE_DIR}/library/config/include
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs
    ${CMAKE_CURRENT_BINARY_DIR}/
)

add_library(sdfs SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/library/config/lib/configure.c
    ${CMAKE_CURRENT_BINARY_DIR}/confy.c
    ${CMAKE_CURRENT_BINARY_DIR}/confl.c
    ${CMAKE_CURRENT_BINARY_DIR}/confy.h

    #------ylib------

    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/kv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/timer.c
    #${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/redis_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/worker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/job_dock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/config.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/auth.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/array_table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/buffer.c
    #${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/ec_isa_l.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/cmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/ll.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/crc32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/crcrs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/daemon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/dbg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/htab.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/job_tracker.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/lock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/mem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/mem_cache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/mem_hugepage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/path.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/skiplist.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/stat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/sysutil.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/timer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/ylog.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/plock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/tpool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/ytime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/bmap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/privilege.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/md5.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/analysis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/mini_hashtb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/bh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/fnotify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/nodectl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/removed.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/etcd-api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/base64_urlsafe.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/base64.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ylib/lib/cJSON.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/aio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/core_latency.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/corenet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/corenet_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/corenet_connect_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/corenet_maping.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/corerpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/cpuset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/schedule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/gettime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/schedule_thread.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/schedule/variable.c

    #------ynet------

    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/nodeid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sock_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/sock/sdevent.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_crc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_events.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/network.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/maping.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_table.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/heartbeat.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/net_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/conn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/net/main_loop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_lib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/msgqueue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_proto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_passive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_reply.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_xnect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_request.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_xmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/ynet/rpc/rpc_table.c

    #------frctl------

    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_attr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/dir_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/chunk_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/inode_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/kv_etcd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/sdfs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/chunk_replica.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/chunk_recovery.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/diskmap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/disktab.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/io_analysis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/sdfs_inode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/sdfs_dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/vss.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/volume.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/vs_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/range.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/range_ctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/range_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/sdfs_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/sdfs/sdfs_chunk_recovery.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_pool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_chunk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md_file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/metadata/md.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs/dir.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs/file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs/node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs/raw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/frctl/libyfs/yfs_lib.c

    #------bactl------

    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/cds_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/cds.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_alloc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_write.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_sync.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_read.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_fs.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_redis.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_raw.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_raw_aio.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/disk_io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/diskid.c
    ${CMAKE_CURRENT_SOURCE_DIR}/bactl/diskio.c

    #------mdctl------
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/mds_main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/mds_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/mds_kv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/mds_lease.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/lease_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/lease_cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/partition.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/ringlock_srv.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/ringlock_rpc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/ringlock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/pa_srv.c
)

set (MDS_SRC_LIST
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mdctl/mds_main.c
)

set (CDS_SRC_LIST
	${CMAKE_CURRENT_SOURCE_DIR}/bactl/main.c
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

add_executable(sdfs.configdump ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.configdump.c)
target_link_libraries(sdfs.configdump ${CMAKE_C_LIBS})

add_executable(sdfs.write ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.write.c)
target_link_libraries(sdfs.write ${CMAKE_C_LIBS})

#add_executable(sdfs.mv ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.mv.c)
#target_link_libraries(sdfs.mv ${CMAKE_C_LIBS})

#add_executable(sdfs.zk ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.zk.c)
#target_link_libraries(sdfs.zk ${CMAKE_C_LIBS})

add_executable(sdfs.cat ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.cat.c)
target_link_libraries(sdfs.cat ${CMAKE_C_LIBS})

add_executable(sdfs.attr ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.attr.c)
target_link_libraries(sdfs.attr ${CMAKE_C_LIBS})

#add_executable(sdfs.objmv ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.objmv.c)
#target_link_libraries(sdfs.objmv ${CMAKE_C_LIBS})

add_executable(sdfs.mkdir ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.mkdir.c)
target_link_libraries(sdfs.mkdir ${CMAKE_C_LIBS})

add_executable(sdfs.mkpool ${CMAKE_CURRENT_SOURCE_DIR}/utils/sdfs.mkpool.c)
target_link_libraries(sdfs.mkpool ${CMAKE_C_LIBS})

add_executable(sdfs.truncate ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.truncate.c)
target_link_libraries(sdfs.truncate ${CMAKE_C_LIBS})

#add_executable(sdfs.mdstat ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.mdstat.c)
#target_link_libraries(sdfs.mdstat ${CMAKE_C_LIBS})

add_executable(sdfs.touch ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.touch.c)
target_link_libraries(sdfs.touch ${CMAKE_C_LIBS})

#add_executable(sdfs.perf ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.perf.c)
#target_link_libraries(sdfs.perf ${CMAKE_C_LIBS})

add_executable(sdfs.ls ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.ls.c)
target_link_libraries(sdfs.ls ${CMAKE_C_LIBS})

#add_executable(sdfs.health ${CMAKE_CURRENT_SOURCE_DIR}/utils/sdfs.health.c)
#target_link_libraries(sdfs.health ${CMAKE_C_LIBS})

add_executable(sdfs.mon ${CMAKE_CURRENT_SOURCE_DIR}/utils/sdfs.mon.c)
target_link_libraries(sdfs.mon ${CMAKE_C_LIBS})

add_executable(sdfs.rmdir ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.rmdir.c)
target_link_libraries(sdfs.rmdir ${CMAKE_C_LIBS})

add_executable(sdfs.rm ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.rm.c)
target_link_libraries(sdfs.rm ${CMAKE_C_LIBS})

add_executable(sdfs.stat ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.stat.c)
target_link_libraries(sdfs.stat ${CMAKE_C_LIBS})

add_executable(sdfs.chmod ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.chmod.c)
target_link_libraries(sdfs.chmod ${CMAKE_C_LIBS})

add_executable(sdfs.md5sum ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.md5sum.c)
target_link_libraries(sdfs.md5sum ${CMAKE_C_LIBS})

#add_executable(sdfs.fallocate ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.fallocate.c)
#target_link_libraries(sdfs.fallocate ${CMAKE_C_LIBS})

add_executable(sdfs.chown ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.chown.c)
target_link_libraries(sdfs.chown ${CMAKE_C_LIBS})

add_executable(sdfs.chkstat ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.chkstat.c)
target_link_libraries(sdfs.chkstat ${CMAKE_C_LIBS})

add_executable(sdfs.recovery ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.recovery.c)
target_link_libraries(sdfs.recovery ${CMAKE_C_LIBS})


set (USS_ADMIN_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/uss.admin.c
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/option.c
)

add_executable(sdfs.admin ${USS_ADMIN_SRC})
target_link_libraries(sdfs.admin ${CMAKE_C_LIBS} hiredis)

install(TARGETS sdfs LIBRARY DESTINATION app/lib)

install(TARGETS sdfs.mdctl RUNTIME DESTINATION app/sbin)
install(TARGETS sdfs.bactl RUNTIME DESTINATION app/sbin)
install(TARGETS sdfs.frctl RUNTIME DESTINATION app/sbin)

install(TARGETS sdfs.configdump RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.write RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.cat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.attr RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mkdir RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mkpool RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.truncate RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.touch RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.ls RUNTIME DESTINATION app/bin)
#install(TARGETS sdfs.health RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.mon RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.rmdir RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.rm RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.chmod RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.md5sum RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.stat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.admin RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.chkstat RUNTIME DESTINATION app/bin)
install(TARGETS sdfs.recovery RUNTIME DESTINATION app/bin)

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

#execute_process(COMMAND ln -s CMAKE_INSTALL_PREFIX/app/admin/cluster.py CMAKE_INSTALL_PREFIX/app/bin/uss.cluster)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
#set (CPACK_SET_DESTDIR true)
#set (CPACK_PACKAGE_INSTALL_DIRECTORY "./sdfs")
set (CPACK_PACKAGE_VERSION_MAJOR "${USS_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${USS_VERSION_MINOR}")
include (CPack)
