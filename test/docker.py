#!/usr/bin/env python2
import os
import sys
import errno
import uuid
import getopt
import subprocess
import time

#docker inspect --format='{{.NetworkSettings.IPAddress}}' 9ba0329ace72
#docker exec CID ifconfig
#(echo "mdsmds";sleep 1;echo "mdsmds") | passwd > /dev/null

path = os.path.abspath(os.path.split(os.path.realpath(__file__))[0])
#dock_list = ['sdfs_test1', 'sdfs_test2', 'sdfs_test3', 'sdfs_test4', 'sdfs_test5']
#dock_list = ['sdfs_test1', 'sdfs_test2']
#dock_list = ['sdfs_test1']
tpl = "sdfs"
sdfs = "sdfs"
project = "suzaku"

sys.path.insert(0, "%s/../admin/" %(path))
from buddha import lsb
from utils import _exec_pipe, _put_remote, _exec_system, exec_shell, _derror
#from fail import Fail, fail_exit, VALGRIND_CMD, VALGRIND_KEYWORD
from global_variable import dock_list

def usage():
    print ("usage:")
    print (" step1 : " + sys.argv[0] + " --pull")
    print (" step2 : " + sys.argv[0] + " --build")
    print (" step3 : " + sys.argv[0] + " --run")
    print (" step4 : " + sys.argv[0] + " --conf")
    print ("[step5]: " + sys.argv[0] + " --createcluster")
    print ("[step6]: " + sys.argv[0] + " --cleancluster")
    print ("[step7]: " + sys.argv[0] + " --update")
    print (" step8 : " + sys.argv[0] + " --test [--nofail] [--valgrind]")

    print ("other opts:")
    print (sys.argv[0] + " --list")
    print (sys.argv[0] + " --start")
    print (sys.argv[0] + " --stop")
    print (sys.argv[0] + " --remove")

def docker_list():
    for i in dock_list:
        _exec_system("docker  inspect --format='{{.NetworkSettings.IPAddress}}' %s" % (i), False)

def docker_add_config():
    for i in dock_list:
        _exec_system("docker  exec %s mkdir /boot" %(i), False)
        _exec_system("scp /boot/config-`uname -r` `docker inspect --format='{{.NetworkSettings.IPAddress}}' %s`:/boot" % (i) , False)

def docker_pull():
    errno = _exec_system("docker pull centos:7")
    if errno:
        _derror("Please install docker last version")
        exit(errno)

def docker_build():
    userdir = os.path.expanduser('~')
    if not os.path.exists(userdir + "/.ssh/id_dsa")\
            or not os.path.exists(userdir + "/.ssh/id_dsa.pub"):
        _derror("Please generate ssh key file use 'ssh-keygen -t dsa'")
        exit(1)

    _exec_system("cat ~/.ssh/id_dsa > %s/id_dsa" % (path))
    _exec_system("cat ~/.ssh/id_dsa.pub > %s/id_dsa.pub" % (path))
    _exec_system("cat ~/.ssh/id_dsa.pub > %s/authorized_keys" % (path))
    #_exec_system("cp %s/../rpms/libisal-2.14.0-1.el7.centos.x86_64.rpm %s/libisal-2.14.0-1.el7.centos.x86_64.rpm" % (path, path))
    #_exec_system("cp %s/../rpms/libisal-devel-2.14.0-1.el7.centos.x86_64.rpm %s/libisal-devel-2.14.0-1.el7.centos.x86_64.rpm" % (path, path))

    file_object = open("%s/rsyncd.conf" % (path), 'w')
    file_object.write("[sdfs]\n    path=/tmp\n    readonly=no\n    list=yes")
    file_object.close( )

    errno = _exec_system("docker build --rm -t %s %s" % (tpl, path))
    if errno:
        _derror("Please install docker last version")
        exit(errno)

    _exec_system("rm %s/id_dsa" % (path))
    _exec_system("rm %s/id_dsa.pub" % (path))
    _exec_system("rm %s/authorized_keys" % (path))
    _exec_system("rm %s/rsyncd.conf" % (path))
    #_exec_system("rm %s/libisal-2.14.0-1.el7.centos.x86_64.rpm" % (path))
    #_exec_system("rm %s/libisal-devel-2.14.0-1.el7.centos.x86_64.rpm" % (path))

def get_addr(target):
    ip = _exec_pipe(['docker', 'inspect', "--format='{{.NetworkSettings.IPAddress}}'", target], 0, False)[:-1]
    return ip.strip('\'')

def __docker_start():
    _exec_system("echo '' > /tmp/hosts")
    (distro, release, codename) = lsb.lsb_release()
    for i in dock_list:
        if distro == 'CentOS':
            errno = _exec_system("docker exec %s sed -i 's/^UsePAM yes$/UsePAM no/g' /etc/ssh/sshd_config" % (i))
            if errno:
                _derror("Please install docker last version")
                exit(errno)

            errno = _exec_system("docker exec %s sed -i 's/^#PermitRootLogin yes$/PermitRootLogin yes/g' /etc/ssh/sshd_config" % (i))
            if errno:
                _derror("Please install docker last version")
                exit(errno)

        errno = _exec_system("docker exec %s bash -c \"echo 'mdsmds' | passwd root --stdin\"" % (i))
        if errno:
            _derror("Please install docker last version")
            exit(errno)

        _exec_system(r"docker exec %s sed -i 's/\\h \\W/\\H \\W/g' /etc/bashrc" % (i))

        """
        errno = _exec_system('docker exec %s /etc/init.d/sshd start' % (i))
        if errno:
            _derror("Please install docker last version")
            exit(errno)
        """
        
        errno = _exec_system('docker exec %s /usr/bin/rsync --daemon --config=/etc/rsyncd.conf' % (i))
        if errno:
            _derror("Please install docker last version")
            exit(errno)
        _exec_system("echo %s    %s >> /tmp/hosts" % (get_addr(i), i))


    for i in dock_list:
        try:
            _put_remote(get_addr(i), "/tmp/hosts", "/etc/hosts", user='root', password='mdsmds', timeout=10)
        except Exception, e:
            _derror("put file /tmp/hosts to %s failed, please check sshd is running normal" % i)
            #_exec_system('docker exec %s bash -c \
            #        "sed -i \'s/session    required     pam_loginuid.so/#session    required     pam_loginuid.so/\' /etc/pam.d/sshd"' % i)
            exit(1)

def docker_run():
    for i in dock_list:
        #_exec_system('docker run --name %s -h %s -d -t %s /bin/bash' % (i, i, tpl))
        _exec_system('docker run --name %s -h %s -v /opt/sdfs --privileged=true -ti -v /sys/fs/cgroup:/sys/fs/cgroup:ro -d -t %s' % (i, i, tpl))

    __docker_start()

def docker_stop():
    for i in dock_list:
        _exec_system('docker stop %s' % (i))

def docker_start():
    _exec_system("sysctl -e kernel.core_pattern=/tmp/core/core-%e-%p-%s")

    for i in dock_list:
        _exec_system('docker start %s' % (i))

    __docker_start()

def docker_remove():
    for i in dock_list:
        _exec_system('docker rm %s' % (i))

def docker_exec(cmd, host=None, t='native'):
    if (host == None) :
        host = dock_list[0]
    
    if (t == 'native'):
        print("docker exec %s bash -c '%s'" % (host, cmd))
        (out, err) = exec_shell("docker exec %s bash -c '%s'" % (host, cmd))
        return out
    elif (t == 'ssh'):
        (out, err, stat) = _exec_remote(host, cmd)
        if (stat != 0):
            raise Exp(errno.EINVAL, err)
        else:
            return out
    else:
        raise Exp(errno.EINVAL, "invalid")

def create_disk_fs(pool):
    os.system("sdfs disk add --pool %s --driver filesystem --device fake" % (pool))

def create_disk_block(pool):
    disk_size = 1024 * 1024 * 1024 * 10
    page_size = 1024 * 1024 * 4
    idx = str(uuid.uuid1())
    os.system("mkdir -p /opt/%s/fake_disk" % (sdfs))
    disk_name = "/opt/%s/fake_disk/%s.fake_disk" % (sdfs, idx)
    os.system("truncate %s -s %d" % (disk_name, disk_size))
    os.system("sdfs disk add --pool %s --driver raw_aio --device %s --page_size %d" % (pool, disk_name, page_size))
    
class DockerNode():
    def __init__(self, name):
        #os.system("echo 2097152 > /proc/sys/fs/aio-max-nr")
        self.name = name
        self.addr = get_addr(name)

    def cleanup(self):
        d = sdfs
        cmd = [
            'echo "%s cleanup ..."' % (self.name),
            'pkill -9 sdfs',
            'pkill -9 redis',
            'systemctl stop etcd',
            'rm -rf /opt/%s/data/etcd/' % (d),
            'rm -rf /opt/%s' % (d), 
            'rm -rf /dev/shm/%s' % (d),
            'rm -rf /tmp/core',
            'mkdir -p /tmp/core',
            'mkdir -p /opt/%s' % (d),
            'echo 3 > /proc/sys/vm/drop_caches',
        ]

        for i in cmd:
            docker_exec(i, self.name)

    def make(self):
        cmd = [
            'mkdir -p /tmp/%s/build' % (project),
            'cmake -H/tmp/%s -B/tmp/%s/build' % (project, project),
            'make -j5 -C /tmp/%s/build install' % (project),
            #'bash -c "if [ ! -f /opt/%s/etc/sdfs.conf ];then cp /tmp/%s/test/sdfs.conf /opt/%s/etc/sdfs.conf;fi"' % (sdfs, project, sdfs),
            #"sed -i 's/127.0.0.0/%s/g' /opt/%s/etc/sdfs.conf" % (self.addr, sdfs),
        ]

        for i in cmd:
            docker_exec(i, self.name)
            
    def sync(self):
        newpath = os.path.abspath(path + '/../')
        cmd = 'rsync -varz --progress --no-o --no-g --exclude-from=%s/.gitignore %s root@%s::sdfs' %(newpath, newpath, self.addr)
        errno = _exec_system(cmd)
        if errno:
            _derror("cmd %s fail:%d" %(cmd, errno))
            exit(errno)

    def add_disk_block(self, pool):
        d = sdfs
        disk_size = 1024 * 1024 * 1024 * 10
        page_size = 1024 * 1024 * 4
        idx = str(uuid.uuid1())
        path = "/opt/%s/fake_disk" % (d)
        disk_name = "%s/%s" % (path, idx)

        cmd = [
            'mkdir -p %s' % (path),
            'truncate %s -s %d' % (disk_name, disk_size),
            'sdfs disk add --pool %s --driver raw_aio --device %s --page_size %d' % (pool, disk_name, page_size),
        ]

        for i in cmd:
            docker_exec(i, self.name)

    def add_disk_fs(pool):

        cmd = [
            'sdfs disk add --pool %s --driver filesystem --device fake' % (pool)
        ]
        
        for i in cmd:
            docker_exec(i, self.name)
            
    def add_disk(self, pool):
        
        for i in range(2):
            self.add_disk_block(pool)

    def create(self):
        lst = ""
        for i in dock_list:
            lst = lst + (i + ",")

        lst = lst[:-1]
        if (len(dock_list) == 1):
            solo = "on"
        else:
            solo = "off"
            
        cmd = [
            'cp /tmp/%s/test/sdfs.conf /opt/%s/etc/sdfs.conf' % (project, sdfs),
            'sed -i "s/127.0.0.0/%s/g" /opt/%s/etc/sdfs.conf' % (self.addr, sdfs),
            'sed -i "s/solomode off/solomode %s/g" /opt/%s/etc/sdfs.conf' % (solo, sdfs),
            '/opt/%s/app/admin/cluster.py create --hosts %s' % (sdfs, lst),
        ]

        for i in cmd:
            docker_exec(i, self.name)

    def update(self):
        self.sync()
        self.make()

    def cmd(self, _cmd):
        docker_exec(_cmd, self.name)
        

import sys
import argparse
from argparse import RawTextHelpFormatter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    subparsers = parser.add_subparsers()

    def _update(args):
        dockernode = DockerNode(dock_list[0])
        dockernode.update()
    parser_add = subparsers.add_parser('update', help='update code')
    parser_add.set_defaults(func=_update)
    #parser_add.add_argument("--driver", required=True, help="driver", choices=["filesystem", "raw_aio", "raw_spdk"])
    #parser_add.add_argument("--device", required=True, help="device")
    #parser_add.add_argument("--page_size", default=1024 * 1024 * 4, type=int, help="page size")

    def _list(args):
        docker_list()
    parser_add = subparsers.add_parser('list', help='list docker node')
    parser_add.set_defaults(func=_list)

    def _run(args):
        docker_run()
    parser_add = subparsers.add_parser('run', help='run docker node')
    parser_add.set_defaults(func=_run)

    def _stop(args):
        docker_stop()
    parser_add = subparsers.add_parser('stop', help='stop docker node')
    parser_add.set_defaults(func=_stop)
    
    def _start(args):
        docker_start()
    parser_add = subparsers.add_parser('start', help='start docker node')
    parser_add.set_defaults(func=_start)
    
    def _pull(args):
        docker_pull()
    parser_add = subparsers.add_parser('pull', help='pull docker image')
    parser_add.set_defaults(func=_pull)

    def _build(args):
        docker_build()
    parser_add = subparsers.add_parser('build', help='build docker image')
    parser_add.set_defaults(func=_build)

    def _remove(args):
        docker_remove()
    parser_add = subparsers.add_parser('remove', help='remove docker node')
    parser_add.set_defaults(func=_remove)

    def _cleanup(args):
        for i in dock_list:
            dockernode = DockerNode(i)
            dockernode.cleanup()
    parser_add = subparsers.add_parser('cleanup', help='cleanup docker node')
    parser_add.set_defaults(func=_cleanup)

    def _create(args):
        for i in dock_list:
            dockernode = DockerNode(i)
            dockernode.cleanup()

        dockernode = DockerNode(dock_list[0])
        dockernode.update()
        dockernode.create()
        
        dockernode.cmd("sdfs mkpool %s" % (args.pool))

        for i in dock_list:
            dockernode = DockerNode(i)
            dockernode.add_disk(args.pool)
        
    parser_add = subparsers.add_parser('create', help='create cluster')
    parser_add.add_argument("--pool", default="default", help="default pool name")
    parser_add.set_defaults(func=_create)
    
    
    if (len(sys.argv) == 1):
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)
        
