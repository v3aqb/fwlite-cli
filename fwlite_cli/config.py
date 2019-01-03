#!/usr/bin/env python

# Copyright (C) 2014-2019 v3aqb

# This file is part of fwlite-cli.

# Fwlite-cli is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Fwlite-cli is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with fwlite-cli.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import socket
import logging
import logging.handlers
import traceback
from collections import defaultdict

from ipaddress import IPv4Address, ip_address

from .parent_proxy import ParentProxyList, ParentProxy
from .get_proxy import get_proxy
from .redirector import redirector
from .util import SConfigParser, parse_hostport
from .resolver import resolver
from .plugin_manager import plugin_register


PAC = '''
var wall_proxy = "__PROXY__";
var direct = "DIRECT;";

/*
 * Copyright (C) 2014 breakwa11
 * https://github.com/breakwa11/gfw_whitelist
 */

var subnetIpRangeList = [
0,1,
167772160,184549376,    //10.0.0.0/8
2886729728,2887778304,  //172.16.0.0/12
3232235520,3232301056,  //192.168.0.0/16
2130706432,2130706688   //127.0.0.0/24
];

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {
    // check if the ipv4 format (TODO: ipv6)
    //   http://home.deds.nl/~aeron/regex/
    var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
    if (re_ipv4.test(host)) {
        // in theory, we can add chnroutes test here.
        // but that is probably too much an overkill.
        return true;
    }
}
function convertAddress(ipchars) {
    var bytes = ipchars.split('.');
    var result = (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    (bytes[3]);
    return result >>> 0;
}
function isInSubnetRange(ipRange, intIp) {
    for ( var i = 0; i < 10; i += 2 ) {
        if ( ipRange[i] <= intIp && intIp < ipRange[i+1] )
            return true;
    }
}
function getProxyFromDirectIP(strIp) {
    var intIp = convertAddress(strIp);
    if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
        return direct;
    }
    return wall_proxy;
}
function isInDomains(domain_dict, host) {
    var suffix;
    var pos1 = host.lastIndexOf('.');

    suffix = host.substring(pos1 + 1);
    if (suffix == "cn") {
        return true;
    }

    var domains = domain_dict[suffix];
    if ( domains === undefined ) {
        return false;
    }
    host = host.substring(0, pos1);
    var pos = host.lastIndexOf('.');

    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) {
                return true;
            } else {
                return false;
            }
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return true;
        }
        pos = host.lastIndexOf('.', pos - 1);
    }
}
function FindProxyForURL(url, host) {
    url=""+url;
    host=""+host;
    if ( isPlainHostName(host) === true ) {
        return direct;
    }
    if ( check_ipv4(host) === true ) {
        return getProxyFromDirectIP(host);
    }
    return wall_proxy;
}

'''


class Config(object):
    def __init__(self, conf_path, gui):
        self.logger = logging.getLogger('config')
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.GUI = gui
        self.conf_path = os.path.abspath(conf_path)
        self.conf_dir = os.path.dirname(self.conf_path)
        self.local_path = os.path.join(self.conf_dir, 'local.txt')
        self.gfwlist_path = os.path.join(self.conf_dir, 'gfwlist.txt')
        self.apnic_path = os.path.join(self.conf_dir, 'delegated-apnic-latest.txt')

        self.userconf = SConfigParser(interpolation=None)
        self.reload()

        if not os.path.exists(self.local_path):
            self.logger.warning('"local.txt" not found! creating...')
            with open(self.local_path, 'w') as f:
                f.write('''\
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

        if not os.path.exists(self.gfwlist_path):
            self.logger.warning('"gfwlist.txt" not found! downloading...')
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            urlopen = opener.open

            gfwlist_url = self.userconf.dget('FWLite', 'gfwlist_url', 'https://raw.githubusercontent.com/v3aqb/gfwlist/master/gfwlist.txt')
            r = urlopen(gfwlist_url)
            data = r.read()
            if r.getcode() == 200 and data:
                with open(self.gfwlist_path, 'wb') as localfile:
                    localfile.write(data)

        if not os.path.exists(self.apnic_path):
            self.logger.warning('"delegated-apnic-latest.txt" not found! downloading...')
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            urlopen = opener.open

            apnic_url = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
            r = urlopen(apnic_url)
            data = r.read()
            if r.getcode() == 200 and data:
                with open(self.apnic_path, 'wb') as localfile:
                    localfile.write(data)

        self.timeout = self.userconf.dgetint('FWLite', 'timeout', 4)
        ParentProxy.DEFAULT_TIMEOUT = self.timeout
        self.gate = self.userconf.dgetint('FWLite', 'gate', 1)
        if self.gate < 0:
            self.logger.warning('gate < 0, set to 0')
            self.gate = 0
        ParentProxy.GATE = self.gate
        self.parentlist = ParentProxyList()
        self.HOSTS = defaultdict(list)
        self.rproxy = self.userconf.dgetbool('FWLite', 'rproxy', False)

        listen = self.userconf.dget('FWLite', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        try:
            csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            csock.connect(('8.8.8.8', 53))
            (addr, port) = csock.getsockname()
            csock.close()
            self.local_ip = addr
        except socket.error:
            self.local_ip = '127.0.0.1'

        ip = self.local_ip
        self.PAC = PAC.replace('__PROXY__', 'PROXY %s:%s' % (ip, self.listen[1]))
        if self.userconf.dget('FWLite', 'pac', ''):
            if os.path.isfile(self.userconf.dget('FWLite', 'pac', '')):
                self.PAC = open(self.userconf.dget('FWLite', 'pac', '')).read()

        self.PAC = self.PAC.encode()

        self.profile_num = len(self.userconf.dget('FWLite', 'profile', '13'))

        for k, v in self.userconf.items('plugin'):
            self.logger.info('register plugin: %s %s' % (k, v))
            plugin_register(k, v)

        if self.userconf.dget('FWLite', 'parentproxy', ''):
            self.addparentproxy('direct', '%s 0' % self.userconf.dget('FWLite', 'parentproxy', ''))
            self.addparentproxy('local', 'direct 100')
        else:
            self.addparentproxy('direct', 'direct 0')

        ParentProxy.set_via(self.parentlist.direct)

        for k, v in self.userconf.items('parents'):
            self.addparentproxy(k, v)

        if not self.rproxy and len([k for k in self.parentlist.httpsparents() if k.httpspriority < 100]) == 0:
            self.logger.warning('No parent proxy available!')

        self.maxretry = self.userconf.dgetint('FWLite', 'maxretry', 4)

        def addhost(host, ip):
            try:
                ipo = ip_address(ip)
                if isinstance(ipo, IPv4Address):
                    self.HOSTS[host].append((2, ip))
                else:
                    self.HOSTS[host].append((10, ip))
            except Exception:
                self.logger.warning('unsupported host: %s' % ip)
                sys.stderr.write(traceback.format_exc() + '\n')
                sys.stderr.flush()

        for host, ip in self.userconf.items('hosts'):
            addhost(host, ip)

        remotedns = self.userconf.dget('dns', 'remotedns', '8.8.8.8')
        self.logger.info('remotedns: ' + remotedns)
        self.remotedns = [parse_hostport(dns, 53) for dns in remotedns.split('|')]

        self.REDIRECTOR = redirector(self)
        self.GET_PROXY = get_proxy(self)
        bad_ip = set(self.userconf.dget('dns', 'bad_ip', '').split('|'))
        apf = None if self.rproxy else [self.GET_PROXY.gfwlist, self.GET_PROXY.local]
        self.resolver = resolver(apf, bad_ip)

    def reload(self):
        self.userconf.read(self.conf_path)

    def confsave(self):
        with open(self.conf_path, 'w') as f:
            self.userconf.write(f)

    def addparentproxy(self, name, proxy):
        self.parentlist.addstr(name, proxy)

    def stdout(self, text=''):
        if self.GUI:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()
