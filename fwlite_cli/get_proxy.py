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
import random
import logging

from repoze.lru import lru_cache


class get_proxy(object):
    """docstring for parent_proxy"""
    logger = logging.getLogger('get_proxy')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)

    def __init__(self, conf):
        self.conf = conf
        self.config()

    def config(self):
        from .apfilter import ap_filter
        self.gfwlist = ap_filter()
        self.local = ap_filter()
        self.ignore = ap_filter()  # used by rules like "||twimg.com auto"
        self.china_ip_list = []

        for line in open(self.conf.local_path):
            if line.startswith('!'):
                continue
            rule, _, dest = line.strip().partition(' ')
            if dest:  # |http://www.google.com/url forcehttps
                self.add_redirect(rule, dest)
            else:
                self.add_rule(line, local=True)

        if self.conf.rproxy is False:
            self.logger.info('loading gfwlist...')
            try:
                with open(self.conf.gfwlist_path) as f:
                    data = f.read()
                    if '!' not in data:
                        data = ''.join(data.split())
                        data = base64.b64decode(data).decode()
                    for line in data.splitlines():
                        self.add_rule(line)
            except Exception as e:
                self.logger.warning('gfwlist is corrupted! %r' % e)

            self.logger.info('loading delegated-apnic-latest.txt...')
            with open(self.conf.apnic_path) as f:
                from ipaddress import ip_address
                for line in f:
                    if line.startswith('apnic|CN|ipv4|'):
                        ip, cnt = line.split("|")[3:5]
                        ip = int(ip_address(ip))
                        cnt = int(cnt)
                        self.china_ip_list.append((ip, cnt))
                self.china_ip_list = sorted(self.china_ip_list)

    def redirect(self, hdlr):
        return self.conf.REDIRECTOR.redirect(hdlr)

    def add_redirect(self, rule, dest):
        return self.conf.REDIRECTOR.add_redirect(rule, dest, self)

    def bad302(self, uri):
        return self.conf.REDIRECTOR.bad302(uri)

    def add_ignore(self, rule):
        '''called by redirector'''
        from .apfilter import ap_rule
        self.ignore.add(ap_rule(rule))

    def add_rule(self, line, local=False):
        try:
            apfilter = self.local if local else self.gfwlist
            apfilter.add(line)
        except ValueError as e:
            self.logger.debug('create autoproxy rule failed: %s' % e)

    @lru_cache(1024)
    def ip_in_china(self, host, ip):
        ip = int(ip)

        def binary_search(arr, hkey):
            start = 0
            end = len(arr)
            while start <= end:
                mid = start + (end - start) // 2

                if arr[mid][0] < hkey:
                    start = mid + 1
                elif arr[mid][0] > hkey:
                    end = mid - 1
                else:
                    return mid
            return end
        index = binary_search(self.china_ip_list, ip)

        if index == -1:
            return False
        maxip = self.china_ip_list[index][0] + self.china_ip_list[index][1]
        if ip < maxip:
            self.logger.info('%s in china' % host)
            return True
        return False

    def ifgfwed(self, uri, host, port, ip, level=1):
        if level == 0:
            return False

        if self.conf.rproxy:
            return None

        if int(ip) == 0:
            return True

        if ip.is_loopback:
            return False

        if level == 5:
            return True

        if ip.is_private:
            return False

        if level == 4:
            return True

        a = self.local.match(uri, host)
        if a is not None:
            return a

        if self.ignore.match(uri, host):
            return None

        if self.conf.gfwlist_enable and\
                uri.startswith('http://') and\
                self.gfwlist.match('http://%s/' % host, host):
            return True

        if self.ip_in_china(host, ip):
            return None

        if level == 2 and uri.startswith('http://'):
            return True

        if self.conf.HOSTS.get(host):
            return None

        if level == 3:
            return True

        if self.conf.gfwlist_enable and self.gfwlist.match(uri, host):
            return True

    def get_proxy(self, uri, host, command, ip, level=1):
        '''
            decide which parentproxy to use.
            url:  'www.google.com:443'
                  'http://www.inxian.com'
            host: ('www.google.com', 443) (without port number is allowed)
            level: 0 -- direct
                   1 -- auto:        proxy if local_rule, direct if ip in china or override, proxy if gfwlist
                   2 -- encrypt all: proxy if local_rule, direct if ip in china or override, proxy if gfwlist or not https
                   3 -- chnroute:    proxy if local_rule, direct if ip in china or override, proxy for all
                   4 -- global:      proxy if not local
                   5 -- global:      proxy if not localhost
        '''
        host, port = host

        ifgfwed = self.ifgfwed(uri, host, port, ip, level)

        if ifgfwed is False:
            if ip and ip.is_private:
                return [self.conf.parentlist.local or self.conf.parentlist.direct]
            return [self.conf.parentlist.direct]

        parentlist = self.conf.parentlist.parents()

        def priority(parent):
            return parent.priority(command, host)

        if len(parentlist) > 1:
            # random.shuffle(parentlist)
            parentlist = sorted(parentlist, key=priority)

        if ifgfwed:
            if not parentlist:
                self.logger.warning('No parent proxy available, direct connection is used')
                return [self.conf.parentlist.get('direct')]
        else:
            parentlist.insert(0, self.conf.parentlist.direct)

        if len(parentlist) == 1 and parentlist[0] is self.conf.parentlist.get('direct'):
            return parentlist

        if len(parentlist) > self.conf.maxretry:
            parentlist = parentlist[:self.conf.maxretry]
        return parentlist

    def notify(self, command, url, requesthost, success, failed_parents, current_parent, time=0):
        self.logger.debug('notify: %s %s %s, failed_parents: %r, final: %s' % (command, url, 'Success' if success else 'Failed', failed_parents, current_parent or 'None'))
        failed_parents = [k for k in failed_parents if 'pooled' not in k]
        if success:
            if 'direct' in failed_parents:
                rule = '||%s' % requesthost[0]
                if rule not in self.local.rules:
                    resp_time = self.conf.parentlist.get('direct').get_avg_resp_time(requesthost[0])
                    exp = pow(resp_time, 2.5) if resp_time > 1 else 1
                    self.add_temp(rule, min(exp, 60))
                    self.conf.stdout()

    def add_temp(self, rule, exp=None, quiet=False):
        # add temp rule for &exp minutes
        rule = rule.strip()
        if rule not in self.local.rules:
            self.local.add(rule, (exp * 60) if exp else None)
            self.logger.info('add autoproxy rule: %s%s' % (rule, (' expire in %.1f min' % exp) if exp else ''))
