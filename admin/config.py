#!/usr/bin/env python2.7
#-*- coding: utf-8 -*-

import re
import socket
import os
from utils import Exp, dmsg, dwarn, derror, exec_pipe, exec_shell, \
        get_value

MAX_NUM = 100 #the max count of bactl or mdctl

def _join(p1, p2):
    return os.path.join(p1, p2)

def _str2dict(s):
    """
    [root@test02 build]# /sysy/yfs/app/bin/uss.configdump
    globals.clustername:none
    globals.hostname:test02
    globals.home:/sysy/yfs
    globals.check_mountpoint:0
    """
    if (s[-1] == '\n'):
        s = s[:-1]

    a = s.split('\n')
    d = {}
    for i in a:
        p = i.split(':')
        if (d.get(p[0])):
            raise Exp(errno.EEXIST, "dup key exist")
        try:
            d[p[0].strip()] = i[i.index(":")+1:].strip()
        except IndexError as err:
            print ("str %s" % (s))
            raise
    return d

class Config:
    def __init__(self, home = None, load_config=True):
        self.hostname = socket.gethostname()
        self.home = home
        self.roles = ["bactl", "mdctl", "frctl"]
        if self.home is None:
            self.home = os.path.abspath(os.path.split(os.path.realpath(__file__))[0] + "../../../")
        self.etcd_data_path = os.path.join(self.home, 'data/etcd')
        self.uss_mdctl = _join(self.home, "app/sbin/sdfs.mdctl")
        self.uss_bactl = _join(self.home, "app/sbin/sdfs.bactl")
        self.uss_yfrctl = _join(self.home, "app/sbin/sdfs.frctl")
        self.uss_yiscsi = _join(self.home, "app/sbin/sdfs.iscsi")
        self.uss_fuse = _join(self.home, "app/sbin/sdfs.fuse")
        self.uss_fuse3 = _join(self.home, "app/sbin/sdfs.fuse3")

        self.uss_mkdir = _join(self.home, "app/bin/sdfs.mkdir")
        self.uss_rmdir = _join(self.home, "app/bin/sdfs.rmdir")
        self.uss_touch = _join(self.home, "app/bin/sdfs.touch")
        self.uss_truncate = _join(self.home, "app/bin/sdfs.truncate")
        self.uss_rm = _join(self.home, "app/bin/sdfs.rm")
        self.uss_mv = _join(self.home, "app/bin/sdfs.mv")
        self.uss_ls = _join(self.home, "app/bin/sdfs.ls")
        self.uss_cp = _join(self.home, "app/bin/sdfs.cp")
        self.uss_ln = _join(self.home, "app/bin/sdfs.ln")
        self.uss_configdump = _join(self.home, "app/bin/sdfs.configdump")
        self.uss_objck = _join(self.home, "app/bin/sdfs.objck")
        self.uss_robjck = _join(self.home, "app/bin/sdfs.robjck")
        self.uss_lobjck = _join(self.home, "app/bin/sdfs.lobjck")
        self.uss_mdstat = _join(self.home, "app/bin/sdfs.mdstat")
        self.uss_stat = _join(self.home, "app/bin/sdfs.stat")
        self.uss_statvfs = _join(self.home, "app/bin/sdfs.statvfs")
        self.uss_write = _join(self.home, "app/bin/sdfs.write")
        self.uss_cat = _join(self.home, "app/bin/sdfs.cat")
        self.uss_attr = _join(self.home, "app/bin/sdfs.attr")
        self.uss_lvm = _join(self.home, "app/bin/sdfs.lvm")
        self.uss_admin = _join(self.home, "app/bin/sdfs.admin")
        self.uss_worm = _join(self.home, "app/bin/sdfs.worm")
        self.uss_user = _join(self.home, "app/bin/sdfs.user")
        self.uss_group = _join(self.home, "app/bin/sdfs.group")

        self.uss_node = _join(self.home, "app/admin/node.py")
        self.uss_cluster = _join(self.home, "app/admin/cluster.py")
        self.uss_cleanlog = _join(self.home, "app/admin/cleanlog.sh")
        self.uss_cleancore = _join(self.home, "app/admin/cleancore.sh")
        self.uss_minio = _join(self.home, "app/admin/minio.py")
        self.uss_vip = _join(self.home, "app/admin/vip.py")

        self.sdfs_mon = _join(self.home, "app/bin/sdfs.mon")
        
        self.max_num = MAX_NUM
        self.cluster_conf = os.path.join(self.home, 'etc/cluster.conf')
        self.uss_conf = os.path.join(self.home, 'etc/sdfs.conf')
        self.vip_conf = os.path.join(self.home, 'etc/vip.conf')
        self.__check_env()

        if load_config:
            self.__load_config()

        self.__load_cluster()

    def __check_env(self):
        try:
            cmd = ["python2.7", "-V"]
            exec_pipe(cmd, p=False)
        except Exp, e:
            derror("not found python2.7")
            raise

    def __set_ldconfig(self):
        ldconfig = "/etc/ld.so.conf.d/sdfs.conf"
        libs = ["%s/app/lib" % (self.home), "/usr/local/lib"]

        if os.path.isfile(ldconfig):
            v = get_value(ldconfig)
            if not v.startswith(self.home):
                dwarn("home is: %s, but ldconfig unmatched!!!" % (self.home))
        else:
            for lib in libs:
                cmd = "echo %s >> %s" % (lib, ldconfig)
                exec_shell(cmd)
            exec_shell("ldconfig")

    def __load_config(self):
        self.__set_ldconfig()
        res = exec_pipe([self.uss_configdump], 0, False)
        d = _str2dict(res)

        self.clustername = d['globals.clustername']
        self.hostname = d['globals.hostname']
        self.home = d['globals.home']
        self.check_mountpoint = int(d['globals.check_mountpoint'])
        self.nfs_srv = d['globals.nfs_srv']
        self.wmem_max = int(d['globals.wmem_max'])
        self.rmem_max = int(d['globals.rmem_max'])
        self.master_vip = d['globals.master_vip']
        self.workdir = d['globals.workdir']
        self.testing = int(d['globals.testing'])
        self.valgrind = int(d['globals.valgrind'])
        self.solomode = int(d['globals.solomode'])

    def __parse_line__(self, line, srv):
        #mds = [x.lstrip("mds.") for x in p.findall(line)]
        p = re.compile(r"%s\[[^\]]+\]" % (srv))

        try:
            return p.findall(line)[0].lstrip("%s[" % (srv)).rstrip("]").split(',')
        except:
            return None
        
    def __parse_line(self, line):
        #p = re.compile(r"\d+\.\d+\.\d+\.\d+")
        #hosts = p.findall(line)
        host = line.split(" ")[0]
        #print (line, host)
        #assert(len(hosts) == 1)

        #print line
        mdctl = self.__parse_line__(line, "mdctl")
        bactl = self.__parse_line__(line, "bactl")
        frctl = self.__parse_line__(line, "frctl")

        return (host, mdctl, bactl, frctl)

    def __load_cluster(self):
        conf = os.path.join(self.home, "etc/cluster.conf")
        cluster = {}
        self.cluster = cluster

        if not os.path.isfile(conf):
            #dwarn("not found %s" % (conf))
            return

        with open(conf, "r") as f:
            for line in f.readlines():
                if (line[-1] == '\n'):
                    line = line[:-1]
                cluster.update({line: {"mdctl": ['0'], "bactl": ['0'], "frctl": ['0']}})
        self.cluster = cluster
        #print self.cluster

        try:
            self.service = cluster[self.hostname]
        except:
            derror("node %s not found in cluster.conf" % (self.hostname))
            exit(1)
        
        #print cluster

    def dump_cluster(self, cluster=None, dumpto=None):
        #print (cluster, self.cluster)

        if cluster is None:
            cluster = self.cluster

        conf = dumpto
        if conf is None:
            conf = self.cluster_conf

            
        conf_tmp = conf + ".tmp"
        lines = []
        for h in cluster.keys():
            host = h
            lines.append(host)
        lines = '\n'.join(lines)

        with open(conf_tmp, "w") as f:
            f.write(lines)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
            #print 'fsync', conf_tmp
            #print 'fsync', lines

        if os.path.isfile(conf):
            os.remove(conf)
        os.rename(conf_tmp, conf)


if __name__ == "__main__":
    config = Config()
    print config.home
    print "hello, word!"
