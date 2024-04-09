#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2014-2018 v3aqb

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

import base64
import logging
from ipaddress import ip_address

from repoze.lru import lru_cache

from .ipfilter import NetFilter

CHINA_IP_LIST = [
    # Tencent Hong Kong
    '124.156.188.0/22',
    '129.226.96.0/20',
    # '182.254.0.0/16',
    # '203.205.128.0/17',
]

BLOCKED_IP_LIST = [
    # google
    '8.8.8.8',
    '8.8.4.4',
    # Control D
    '76.76.2.0',
    '76.76.10.0',
    # Quad9
    '9.9.9.9',
    '149.112.112.112',
    # OpenDNS
    '208.67.222.222',
    '208.67.220.220',
    '208.67.222.123',
    '208.67.220.123',
    # Cloudflare
    '1.1.1.1',
    '1.0.0.1',
    # CleanBrowsing
    '185.228.168.9',
    '185.228.169.9',
    # Alternate DNS
    '76.76.19.19',
    '76.223.122.150',
    # AdGuard DNS
    '94.140.14.14',
    '76.223.122.150',
    # AdGuard DNS
    '94.140.14.14',
    '94.140.15.15',
    # Comodo
    '8.26.56.26',
    '8.20.247.20',
    # CenturyLink (Level3)
    '205.171.3.66',
    '205.171.202.166',
    '4.2.2.1',
    '4.2.2.2',
    '4.2.2.3',
    '4.2.2.4',
    '4.2.2.5',
    # Norton DNS
    '198.153.192.1',
    '198.153.194.1',
    # Verisign
    '64.6.64.6',
    '64.6.65.6',

    # telegram https://core.telegram.org/resources/cidr.txt
    '91.108.56.0/22',
    '91.108.4.0/22',
    '91.108.8.0/22',
    '91.108.16.0/22',
    '91.108.12.0/22',
    '149.154.160.0/20',
    '91.105.192.0/23',
    '91.108.20.0/22',
    '185.76.151.0/24',
    '2001:b28:f23d::/48',
    '2001:b28:f23f::/48',
    '2001:67c:4e8::/48',
    '2001:b28:f23c::/48',
    '2a0a:f280::/32',
]


class get_proxy:
    """docstring for parent_proxy"""
    logger = logging.getLogger('get_proxy')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)

    def __init__(self, cic, load_local=None):
        self.cic = cic
        from .apfilter import ap_filter
        self.gfwlist = ap_filter()
        self.chinalist = ap_filter()
        self.adblock = set()
        self.local = ap_filter()
        self.ignore = ap_filter()  # used by rules like "||twimg.com auto"
        self.reset = ap_filter()
        self.china_ip_filter = NetFilter()
        self.host_not_in_china = set()

        if load_local is not None:
            iter_ = load_local
        else:
            try:
                with open(self.cic.conf.local_path) as f:
                    iter_ = f.readlines()
            except UnicodeDecodeError:
                with open(self.cic.conf.local_path, encoding='utf8') as f:
                    iter_ = f.readlines()
        for line in iter_:
            if line.startswith(('!', '[', '#')):
                continue
            if not line.strip():
                continue
            rule, _, dest = line.strip().partition(' ')
            if dest:  # |http://www.google.com/path forcehttps
                self.add_redirect(rule, dest)
            else:
                self.add_temp(line)

    def load(self):
        if self.cic.conf.rproxy:
            return

        self.load_gfwlist()
        self.load_china_ip_list()

    def load_gfwlist(self):
        self.logger.info('loading gfwlist...')
        from .apfilter import ap_filter
        self.gfwlist = ap_filter()
        self.chinalist = ap_filter()
        self.adblock = set()
        self.reset = ap_filter()

        try:
            with open(self.cic.conf.gfwlist_path, encoding='utf8') as gfwlist:
                data = gfwlist.read()
                if '!' not in data:
                    data = ''.join(data.split())
                    data = base64.b64decode(data).decode()
                for line in data.splitlines():
                    self.gfwlist.add(line)
        except Exception as err:
            self.logger.warning('gfw_list is corrupted! %r', err, exc_info=True)

        for addr in BLOCKED_IP_LIST:
            self.gfwlist.add(addr)

        try:
            with open(self.cic.conf.chinalist_path, encoding='utf8') as chinalist:
                for line in chinalist:
                    if line.strip():
                        self.chinalist.add(f'||{line.strip()}')
        except Exception as err:
            self.logger.warning('china_list is corrupted! %r', err, exc_info=True)

        try:
            with open(self.cic.conf.adblock_path, encoding='utf8') as adblock:
                for line in adblock:
                    self.adblock.add(line)
        except Exception as err:
            self.logger.warning('adblock is corrupted! %r', err, exc_info=True)


    def load_china_ip_list(self):
        self.logger.info('loading china_ip_list.txt...')
        self.china_ip_filter = NetFilter()

        with open(self.cic.conf.china_ip_path, encoding='utf8') as f:
            for line in f:
                if line.strip() and '#' not in line:
                    self.china_ip_filter.add(line.strip())
        self.logger.info('loading china_ip_list_v6.txt...')
        with open(self.cic.conf.china_ipv6_path, encoding='utf8') as f:
            for line in f:
                if line.strip() and '#' not in line:
                    self.china_ip_filter.add(line.strip())
        for network in CHINA_IP_LIST:
            self.china_ip_filter.add(network)

    def add_redirect(self, rule, dest):
        if dest.lower() == 'auto':
            self.add_ignore(rule)
            return
        if dest.lower() == 'reset':
            self.reset.add(rule)
            return
        return self.cic.redir_o.add_redirect(rule, dest, self)

    def add_ignore(self, rule):
        '''called by redirector'''
        from .apfilter import ap_rule
        self.ignore.add(ap_rule(rule))

    @lru_cache(1024)
    def ip_in_china(self, host, ip):
        if ip in self.china_ip_filter:
            self.logger.info('%s in china', host or ip)
            return True
        self.logger.info('%s not in china', host or ip)
        if host:
            self.host_not_in_china.add(host)
        return False

    def isgfwed_resolver(self, host, mode=1):
        if self.cic.conf.rproxy:
            return None
        url = 'http://%s/' % host
        result = self.local.match(url, host)
        if result is not None:
            return result

        if self.ignore.match(url, host):
            return None

        if self.chinalist.match(url, host):
            return False

        if self.cic.conf.gfwlist_enable:
            result = self.gfwlist.match(url, host)
            if result is not None:
                return result

        if mode >= 3 and host in self.host_not_in_china:
            return True
        return None

    def isgfwed(self, url, host, port, ip, mode=1):
        if mode == 0:
            return False

        if host in self.cic.conf.HOSTS:
            return None

        if ip is None:
            self.logger.error('%s:%s ip is None.', host, port)
            return True

        if ip.is_loopback:
            return False

        if mode == 5:
            return True

        if int(ip) and ip.is_private:
            return False

        if mode == 4:
            return True

        result = self.local.match(url, host)
        if result is not None:
            return result

        if self.chinalist.match(url, host):
            return False

        if int(ip) == 0:
            return True

        if self.ignore.match(url, host):
            return None

        if self.cic.conf.gfwlist_enable:
            result = self.gfwlist.match(url, host)
            if result is not None:
                return result

        if self.ip_in_china(host, ip):
            return False

        if mode == 2 and url.startswith('http://'):
            return True

        if mode == 3:
            return True

        if self.cic.conf.HOSTS.get(host):
            return None

        if self.cic.conf.gfwlist_enable and self.gfwlist.match(url, host):
            return True
        return None

    def get_proxy(self, url, host, command, ip, mode=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443)
            mode:  0 -- direct
                   1 -- auto:        proxy if local_rule, direct if ip in china or override, proxy if gfwlist
                   2 -- encrypt:     proxy if local_rule, direct if ip in china or override, proxy if gfwlist or http
                   3 -- chnroute:    proxy if local_rule, direct if ip in china or override, proxy for all
                   4 -- global:      proxy if not local
                   5 -- global:      proxy if not localhost
        '''
        if host:
            host, port = host
        else:
            port = 0

        gfwed = self.isgfwed(url, host, port, ip, mode)

        if self.cic.conf.adblock_enable and host in self.adblock:
            return []

        if self.reset.match(url):
            return []

        if gfwed is False:
            if ip and ip.is_private:
                return [self.cic.conf.parentlist.local or self.cic.conf.parentlist.direct]
            return [self.cic.conf.parentlist.direct]

        parentlist = self.cic.conf.parentlist.get_proxy_list(host)

        if gfwed:
            if not parentlist:
                self.logger.warning('%s %s:%s No parent proxy available.', command, host, port)
                return []
        else:
            parentlist.insert(0, self.cic.conf.parentlist.direct)

        if len(parentlist) > self.cic.conf.maxretry + 1:
            parentlist = parentlist[:self.cic.conf.maxretry + 1]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s', command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None')
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if success:
            if '_D1R3CT_' in failed_parents:
                rule = '||%s' % requesthost[0]
                if rule not in self.local.rules:
                    resp_time = self.cic.conf.parentlist.direct.get_avg_resp_time(requesthost[0])
                    resp_time = resp_time - self.cic.conf.gate
                    exp = pow(resp_time, 2.5) if resp_time > 1 else 1
                    self.add_temp(rule, min(exp, 60))

    def add_temp(self, rule, exp=None):
        # add temp rule for &exp minutes
        rule = rule.strip()
        if rule not in self.local.rules:
            self.local.add(rule, (exp * 60) if exp else None)
            self.logger.info('add autoproxy rule: %s%s', rule, (' expire in %.1f min' % exp) if exp else '')
            self.cic.conf.stdout('local')

    def inspect(self, url, host):
        result = f'get_proxy_inspect: {url}\n'

        try:
            ip_ = ip_address(host)
            result += f'ip in china: {repr(self.ip_in_china(None, ip_))}\n'
        except ValueError:
            pass

        result += f'chinalist match: {repr(self.chinalist.match(url, host))}\n'
        result += f'local match: {repr(self.local.match(url, host))}\n'
        result += f'ignore match: {repr(self.ignore.match(url, host))}\n'
        result += f'gfwlist match: {repr(self.gfwlist.match(url, host))}\n'
        result += f'adlock match: {repr(host in self.adblock)}\n'
        result += f'reset match: {repr(self.reset.match(url, host))}\n'
        result += f'host not in china(dynamic): {repr(host in self.host_not_in_china)}\n'
        result += f'Hosts: {repr(self.cic.conf.HOSTS.get(host))}\n\n'

        return result
