#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import sys
import errno

admin = os.path.abspath(os.path.split(os.path.realpath(__file__))[0] + '/../admin')
sys.path.insert(0, admin)

from utils import  _dwarn, _dmsg, _derror, _exec_pipe, _exec_pipe1, _exec_system, _str2dict

dock_list = []
site_count = 0
rack_count = 0
host_count = 0

def generate_docker_list(s_count=1, r_count=1, h_count=1):
    host_list = []

    global site_count
    global rack_count
    global host_count

    site_count = s_count
    rack_count = r_count
    host_count = h_count

    hc = 1;
    for s in range(s_count):
        for r in range(r_count):
            for h in range(h_count):
                host = 'site%d.rack%d.host%d' % (s+1, r+1, hc)
                hc = hc + 1
                host_list.append(host)

    return host_list

dock_list = generate_docker_list()

if __name__ == '__main__':
    print dock_list
    print 'site_count : ', site_count
    print 'rack_count : ', rack_count
    print 'host_count : ', host_count
    print 'configdump : ', config

