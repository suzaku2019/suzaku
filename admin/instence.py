#!/usr/bin/env python2.7
#-*- coding: utf-8 -*-

import fcntl
import errno
import time
import random
import os
import subprocess
import statvfs

from config import Config
from utils import Exp, derror, dwarn, dmsg, set_value, get_value, \
        exec_shell, exec_pipe
from disk import DiskOp

class Instence(object):
    def __init__(self, role, i, config=None):
        """
        初始化中，不能创建bactl/idx 或 mdctl/idx 目录
        """
        self.config = config
        if self.config is None:
            self.config = Config()
        self.role = role
        self.service = int(i)
        self.cmd = None
        self.home = None
        if self.role == "mdctl":
            self.cmd = self.config.uss_mdctl
            self.home = os.path.join(self.config.home, "data/%s" % (self.role))
        elif self.role == "bactl":
            self.cmd = self.config.uss_bactl
            self.home = os.path.join(self.config.home, "data/%s" % (self.role))
        elif self.role == "frctl":
            os.system("mkdir -p %s/data/frctl" % (self.config.home))
            self.cmd = self.config.uss_yfrctl
            self.home = os.path.join(self.config.home, "data/frctl")

        print (self.role, self.home)
        #print [self.home, self.cmd, self.role]
        self.name = self.home
        self.disk_status = 0;
        self.pid = -1
        self.ppid = -1
        self.deleting = False
        self.deleted = False
        self.skiped = False
        self.nomount = False
        self.nid = None
        try:
            self.nid = get_value(self.home + "/status/nid").strip()
        except Exception, e:
            pass

        try:
            tmp = self.home + '/check_' + str(random.random())
            set_value(tmp, "test")
            os.unlink(tmp)
        except Exception, e:
            derror(e)
            self.disk_status = errno.EIO;

    def __getpid(self, ttyonly=False):
        max_retry = 1000
        i = 0
        while True:
            if (i > max_retry):
                raise Exp(errno.EIO, 'getpid fail')

            if (self.running()):
                while (1):
                    a = get_value(self.home + "/status/status.pid")
                    if (a != ''):
                        self.pid = int(a)
                        break
                    else:
                        time.sleep(0.1)

                while (1):
                    a = get_value(self.home + "/status/parent.pid")
                    if (a != ''):
                        self.ppid = int(a)
                        break
                    else:
                        time.sleep(0.1)

                break
            else:
                time.sleep(0.1)
                i = i + 1

    def running(self):
        if (self.disk_status):
            return False

        path = self.home + "/status/status"
        try:
            fd = open(path, 'r')
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise
            else:
                return False

        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError as err:
            if err.errno != errno.EAGAIN:
                raise
            else:
                buf = get_value(path)
                if (buf == "running\n"):
                    return True
                else:
                    return False

        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        fd.close()
        return False

    def start_redis(self):
        diskop = DiskOp()
        diskop.start_redis()
        
    def _start(self, ttyonly=False):
        cmd = None
        if self.role == "mdctl":
            cmd = "%s --home %s" % (self.config.uss_mdctl, self.home)
        elif self.role == "bactl":
            self.start_redis()
            
            cmd = "%s --home %s" % (self.config.uss_bactl, self.home)
        elif self.role == "frctl":
            #cmd = "systemctl start rpcbind"
            #exec_shell(cmd)

            cmd = "%s --home %s" % (self.config.uss_yfrctl, self.home)
        if (self.disk_status):
            derror(' * %s [disk error]' % (cmd), ttyonly)
            return 1

        if (self.nomount):
            derror(' * %s [no mount]' % (cmd), ttyonly)
            return 1

        if (self.deleted):
            derror(' * %s [deleted]' % (cmd), ttyonly)
            return 1

        if (self.skiped):
            derror(' * %s [skiped]' % (cmd), ttyonly)
            return 1

        if (self.running()):
            dwarn(' * %s [running]' % (cmd), ttyonly)
            return 1

        if self.config.testing and self.config.valgrind:
            valgrind = "valgrind --tool=memcheck --leak-check=full  --show-reachable=yes -v "
            logdir = "%s/log/" % (self.config.home)
            os.system("mkdir -p %s" % (logdir))
            vallog = "%s/log/valgrind.%s.%s.log" % (self.config.home, self.role, self.service)
            cmd = "%s %s -f >>%s 2>&1 &" % (valgrind, cmd, vallog)
            dmsg(cmd)

        if (cmd == None) :
            derror(' * %s skip' % (self.home), ttyonly)
            return

        subprocess.call(cmd, shell=True, close_fds=True)

        try:
            self.__getpid(ttyonly)
        except Exp, e:
            dwarn('%s' % (e.err), ttyonly)
            return e.errno

        dmsg(' * %s [ok]' % (cmd), ttyonly)
        return 0

    def start(self, ttyonly=False):
        self._start(ttyonly)

    def _stop(self, ttyonly=False):
        if (self.role == 'redis'):
            return

        if (self.nomount):
            derror(' * %s [no mount]' % (self.cmd), ttyonly)
            return False

        if (self.running() == 0):
            derror("%s already stopped" % self.cmd, ttyonly)
            return 0

        try:
            self.__getpid(ttyonly)
        except Exp, e:
            dwarn('%s' % (e.err), ttyonly)
            return e.errno

        #os.system("kill -USR2 %u" % self.ppid)
        #os.system("kill -USR2 %u" % self.pid)

        dmsg("stop %s %s,%s" % (self.home, self.pid, ttyonly))
        #temporary solution for bug #2096
        os.system("kill -USR2 %u" % (self.ppid))
        os.system("kill -USR2 %u" % (self.pid))
        #os.system("kill -9 %u" % self.pid)

        time.sleep(0.1)

        if (self.running()):
            time.sleep(1.5)
            dwarn("%s, still running, sleep 1" % (self.name), ttyonly)
            time.sleep(1)
            if (self.running()):
                derror ("stop %s pid /%u" % (self.name, self.pid), ttyonly)
                os.system("kill -9 %u" % (self.pid))

        i = 0
        max_retry = 1000
        while True:
            if (i > max_retry):
                derror("stop instence %u fail" %(i), ttyonly)
                return errno.EIO
            if (self.running() == False):
                break
            else:
                time.sleep(0.01)
                i = i + 1

    def stop(self, ttyonly=False):
        self._stop(ttyonly)

    def _get_rs(self, cmd):
        try:
            rs, _ = exec_shell(cmd, p=False, need_return=True)
        except Exp, e:
            dwarn(e)
            rs = 0

        return str(rs).strip()

    def get_total(self):
        if 'bactl' in self.home:
            vfs = os.statvfs(self.home)
            total = vfs[statvfs.F_BLOCKS] * vfs[statvfs.F_BSIZE] / (1024)
        else:
            total = 0

        return total

    def get_used(self):
        if 'bactl' in self.home:
            vfs = os.statvfs(self.home)
            total = vfs[statvfs.F_BLOCKS] * vfs[statvfs.F_BSIZE] / (1024)
            free = vfs[statvfs.F_BFREE] * vfs[statvfs.F_BSIZE] / (1024)
            used = total - free
        else:
            used = 0

        return used

if __name__ == "__main__":
    print "hello, word!"
