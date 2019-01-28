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
from .util import SConfigParser
from .resolver import resolver
from .plugin_manager import plugin_register
from .port_forward import ForwardManager
from .plugin_manager import PluginManager


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


def url_retreive(url, path, proxy):
    import urllib.request
    if proxy.proxy:
        if proxy.scheme == 'http' and '|' not in proxy.proxy:
            proxy_handler = urllib.request.ProxyHandler(
                {'http': proxy.proxy,
                 'https': proxy.proxy})
        else:
            # proxy not supported
            with open(path, 'w') as localfile:
                localfile.write('\n')
            return
    else:
        proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler)
    urlopen = opener.open

    r = urlopen(url)
    data = r.read()
    if r.getcode() == 200 and data:
        with open(path, 'wb') as localfile:
            localfile.write(data)


class Config(object):
    def __init__(self, conf_path, gui):
        self.logger = logging.getLogger('config')
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        ParentProxy.conf = self

        self._started = False
        self.GUI = gui
        self.conf_path = os.path.abspath(conf_path)
        self.conf_dir = os.path.dirname(self.conf_path)
        self.local_path = os.path.join(self.conf_dir, 'local.txt')
        self.gfwlist_path = os.path.join(self.conf_dir, 'gfwlist.txt')
        self.china_ip_path = os.path.join(self.conf_dir, 'china_ip_list.txt')
        self.adblock_path = os.path.join(self.conf_dir, 'adblock.txt')

        self.userconf = SConfigParser(interpolation=None)
        self.reload()

        self.timeout = self.userconf.dgetint('FWLite', 'timeout', 4)
        self.profile = self.userconf.dget('FWLite', 'profile', '134')
        if '1' not in self.profile:
            self.profile += '1'
        if '3' not in self.profile:
            self.profile += '3'
        self.maxretry = self.userconf.dgetint('FWLite', 'maxretry', 4)
        self.rproxy = self.userconf.dgetbool('FWLite', 'rproxy', False)

        listen = self.userconf.dget('FWLite', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        ParentProxy.DEFAULT_TIMEOUT = self.timeout

        self.gate = self.userconf.dgetint('FWLite', 'gate', 2)
        if self.gate < 0:
            self.logger.warning('gate < 0, set to 0')
            self.gate = 0
        ParentProxy.GATE = self.gate

        for k, v in self.userconf.items('plugin'):
            plugin_register(k, v)

        self.plugin_manager = PluginManager(self)
        self.port_forward = ForwardManager(self)
        self.parentlist = ParentProxyList(self)
        # add proxy created my fwlite self
        for i, profile in enumerate(self.profile):
            self.addparentproxy('FWLITE:%s' % profile, 'http://127.0.0.1:%d' % (self.listen[1] + i))

        if self.userconf.dget('FWLite', 'parentproxy', ''):
            self.addparentproxy('_D1R3CT_', '%s 0' % self.userconf.dget('FWLite', 'parentproxy', ''))
        else:
            self.addparentproxy('_D1R3CT_', 'direct 0')

        for k, v in self.userconf.items('parents'):
            if k in ('_D1R3CT_', '_L0C4L_'):
                self.logger.error('proxy name %s is protected!')
                continue
            self.addparentproxy(k, v)

        if not self.rproxy and len([k for k in self.parentlist.parents() if k._priority < 100]) == 0:
            self.logger.warning('No parent proxy available!')

        for k, v in self.userconf.items('port_forward'):
            # k: port
            # v: target / target proxy
            # using proxy FWLITE:1
            try:
                target, _, proxy = v.partition(' ')
                target = (v.rsplit(':', 1)[0], int(v.rsplit(':', 1)[1]))
                proxy = proxy or ('FWLITE:' + self.profile[0])
                port = int(k)
                self.port_forward.add(target, proxy, port)
            except Exception as e:
                self.logger.error(repr(e))
                self.logger.error(traceback.format_exc())

        self.HOSTS = defaultdict(list)

        def addhost(host, ip):
            try:
                ipo = ip_address(ip)
                if isinstance(ipo, IPv4Address):
                    self.HOSTS[host].append((2, ip))
                else:
                    self.HOSTS[host].append((10, ip))
            except Exception:
                self.logger.error('unsupported host: %s' % ip)
                self.logger.error(traceback.format_exc())

        for host, ip in self.userconf.items('hosts'):
            addhost(host, ip)

        if not os.path.exists(self.local_path):
            self.logger.warning('"local.txt" not found! creating...')
            with open(self.local_path, 'w') as f:
                f.write('''\
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

        if not os.path.exists(self.gfwlist_path):
            self.logger.info(repr(self.parentlist.direct))
            self.logger.warning('"gfwlist.txt" not found! downloading...')
            gfwlist_url = self.userconf.dget('FWLite', 'gfwlist_url', 'https://raw.githubusercontent.com/v3aqb/gfwlist/master/gfwlist.txt')
            url_retreive(gfwlist_url, self.gfwlist_path, self.parentlist.direct)

        if not os.path.exists(self.china_ip_path):
            self.logger.warning('"china_ip_list.txt" not found! downloading...')
            apnic_url = 'https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt'
            url_retreive(apnic_url, self.china_ip_path, self.parentlist.direct)

        if not os.path.exists(self.adblock_path):
            self.logger.warning('"adblock.txt" not found! downloading...')
            adblock_url = self.userconf.dget('FWLite', 'adblock_url', 'https://hosts.nfz.moe/127.0.0.1/basic/hosts')
            url_retreive(adblock_url, self.adblock_path, self.parentlist.direct)

        # prep PAC
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
        if text == 'all':
            self._started = True
        if not self._started:
            return
        if self.GUI:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()

    @property
    def adblock_enable(self):
        return self.userconf.dgetbool('FWLite', 'adblock', False)

    @adblock_enable.setter
    def adblock_enable(self, val):
        self.userconf.set('FWLite', 'adblock', '1' if val else '0')
        self.confsave()

    @property
    def gfwlist_enable(self):
        return self.userconf.dgetbool('FWLite', 'gfwlist', True)

    @gfwlist_enable.setter
    def gfwlist_enable(self, val):
        self.userconf.set('FWLite', 'gfwlist', '1' if val else '0')
        self.confsave()
