FROM centos
ENV container docker
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == \
systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]

RUN yum install -y deltarpm
RUN yum -y upgrade
RUN yum install -y epel-release
RUN yum install -y hiredis-devel redis etcd libcurl-devel yajl-devel python-setuptools iproute pdsh numactl-devel numactl-libs rdma-core rdma-core-devel
RUN yum install -y cmake gcc-c++ libtool automake libuuid-devel libaio-devel flex bison openssl-devel python-paramiko redhat-lsb python2-psutil 
RUN yum install -y expect git net-tools openssh-server openssh-server-sysvinit vim nfs-utils sqlite-devel gperftools pdsh pdsh-rcmd-ssh
RUN yum install -y gdb valgrind tree yasm libpciaccess-devel python-prettytable yajl-devel
RUN yum clean all; systemctl enable sshd.service

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py
RUN pip install python-etcd futurist

ADD id_dsa /root/.ssh/
ADD id_dsa.pub /root/.ssh/
ADD authorized_keys /root/.ssh/
ADD rsyncd.conf /etc/
RUN chmod 0600 /root/.ssh/id_dsa
