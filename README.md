# Suzaku

Fork from https://github.com/fusionstack/sdfs

Dependencies:
===========================================================
    yum install -y epel-release \
    cmake libtool automake gcc gcc-c++ redhat-lsb \
    libuuid-devel libaio-devel flex bison python2-futurist \
    jemalloc-devel etcd yajl-devel curl-devel redis hiredis-devel \
    python-paramiko redhat-lsb expect gperftools \
    sqlite-devel libattr libattr-devel
    openssl-devel

    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python get-pip.py
    pip install python-etcd futurist

Installation
===========================================================
    cd ${SRC_DIR}
    mkdir build
    cd build
    cmake ..
    make
    sudo make install

Configuration
===========================================================
    vim /opt/sdfs/etc/sdfs.conf 

    update gloconf.networks, if only single host,then add config:solomode on; for example:

    networks {
        192.168.140.0/8;
    }

    vim /etc/hosts

    update hosts, for example:

    192.168.140.1 node1
    192.168.140.2 node2
    192.168.140.3 node3


Create Cluster
===========================================================

    /opt/sdfs/app/admin/cluster.py sshkey --hosts node1,node2,node3
    /opt/sdfs/app/admin/cluster.py create --hosts node1,node2,node3

Create Pool
===========================================================
    sdfs mkpool default

Add disk
===========================================================
    sdfs disk add --pool default --driver raw_aio --device /dev/sdb

Create iSCSI Volume
===========================================================
    sdfs truncate /default/vol1 --size 10G
    sdfs attr -s iscsi -V enable /default/vol1
    iscsiadm -m discovery -t sendtargets -p <ip>

Usage
===========================================================

    sdfs --help

Auto Testing
===========================================================
    cd test
    docker.py
