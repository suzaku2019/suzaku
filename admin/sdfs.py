#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import errno
import argparse
import os
import time
import sys
import string
import uuid
import json
import subprocess

from utils import mutil_exec, check_crontab, unset_crontab, Exp, \
                  check_sysctl, lock_file, derror, dwarn,\
                  human_readable, dev_mountpoints, dev_lsblks, \
                  dev_mkfs_ext4, dev_uuid, dev_childs, fstab_del_mount, \
                  dev_clean, ssh_set_nopassword, put_remote, dmsg, \
                  exec_remote, lsb_release, check_ip_valid, mutil_exec_futures, \
                  get_mask_by_addr

def usage():
    print ("usage:\n"
           "cluster ops:\n"
           "    cluster\n"
           "    node\n"
           "file system ops:\n"
           "    mkpool\n"
           "    mkdir\n"
           "    ls\n"
           "    touch\n"
           "    stat\n"
           "    attr\n"
           "    cat\n"
           "    ln\n"
           "    mv\n"
           "    rmdir\n"
           "    truncate\n"
           "    write\n"
           "admin ops:\n"
           "    disk\n"
           "    chkstat\n"
           "    recovery\n"
           "    mon\n"
           )


def is_c_type(cmd):
    lst = ['mkpool', 'mkdir', 'ls', 'touch', 'stat', 'attr', 'cat',
           'ln', 'mv', 'rmdir', 'truncate', 'write',
           'chkstat', 'recovery']
    if cmd in lst:
        return True
    else:
        return False

def run_c_type(cmd, argv):
    from config import Config
    config = Config()
    array = ["%s/app/bin/sdfs.%s" % (config.home, cmd)] + argv

    c = str(array)[1:-1].replace(',', ' ')
    os.system(c)
    #exec_pipe(array, 0, False, 0)

def is_python_type(cmd):
    lst = ['cluster', 'node', 'mon', 'disk']
    if cmd in lst:
        return True
    else:
        return False
    
def run_python_type(cmd, argv):
    from config import Config
    config = Config()
    
    array = ["python2", "%s/app/admin/%s.py" % (config.home, cmd)] + argv
    c = str(array)[1:-1].replace(',', ' ')
    os.system(c)

if __name__ == "__main__":
    if (len(sys.argv) == 1):
        usage()
        sys.exit(1)

    cmd = sys.argv[1]
    argv = sys.argv[2:]

    if is_c_type(cmd):
        run_c_type(cmd, argv)
    elif is_python_type(cmd):
        run_python_type(cmd, argv)
    else:
        usage()
        sys.exit(1)
