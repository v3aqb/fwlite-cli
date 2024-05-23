#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Copyright (C) 2024 v3aqb

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


from __future__ import print_function, division

import sys
import time
import re
from threading import Thread
import urllib.parse
import logging
try:
    from .ipfilter import NetFilter
except ImportError:
    from ipfilter import NetFilter

logger = logging.getLogger('V2Filter')
logger.setLevel(logging.INFO)


dn = re.compile(r'^[0-9a-zA-Z\-\._]+$')


class V2Filter:

    def __init__(self, lst=None):
        self.host_endswith = set()
        self.host_match = set()
        self.net_filter = NetFilter()
        self.rules = set()
        self.expire = {}
        if lst:
            for rule in lst:
                self.add(rule)

    def add(self, rule, expire=None):
        '''
            IP: 形如"127.0.0.1"。
            CIDR: 形如"10.0.0.0/8".
            HOSTS: 0.0.0.0 adblock.com, 完整匹配域名部分
            ||domain.com: 子域名
            (不做，当成子域名)纯字符串: 当此字符串匹配目标域名中任意部分，该规则生效。比如"sina.com"可以匹配"sina.com"、"sina.com.cn"和"www.sina.com"，但不匹配"sina.cn"。
            (不做，忽略, log)正则表达式: 由"regexp:"开始，余下部分是一个正则表达式。当此正则表达式匹配目标域名时，该规则生效。例如"regexp:\\.goo.*\\.com$"匹配"www.google.com"、"fonts.googleapis.com"，但不匹配"google.com"。
            子域名 (推荐): 由"domain:"开始，余下部分是一个域名。当此域名是目标域名或其子域名时，该规则生效。例如"domain:v2ray.com"匹配"www.v2ray.com"、"v2ray.com"，但不匹配"xv2ray.com"。
            完整匹配: 由"full:"开始，余下部分是一个域名。当此域名完整匹配目标域名时，该规则生效。例如"full:v2ray.com"匹配"v2ray.com"但不匹配"www.v2ray.com"。
        '''
        rule = rule.strip()
        if len(rule) < 3 or rule.startswith(('!', '[', '#')):
            return
        if ' ' in rule:
            if not rule.startswith('0.0.0.0'):
                return
            _, _, domain = rule.partition(' ')
            domain, _, _ = domain.partition(' ')
            rule = f'full:{domain}'
        if rule in self.rules:
            logger.debug('%s already in filter', rule)
            return
        if rule.startswith('regexp:'):
            logger.info('%s ignored: regexp', rule)
            return
        try:
            if rule.startswith('full:'):
                self._add_domain_match(rule[5:])
            elif rule.startswith('domain:'):
                self.add(rule[7:], expire)
                return
            elif rule.startswith('||'):
                self.add(rule[2:], expire)
                return
            else:
                self._add_domain(rule)
        except ValueError as err:
            logger.debug(repr(err))
        else:
            self.rules.add(rule)
            self.expire[rule] = expire
            if expire:
                Thread(target=self.remove, args=(rule, expire)).start()

    def _add_domain(self, domain):
        try:
            self.net_filter.add(domain)
            return
        except ValueError:
            pass
        if self.match(None, domain):
            raise ValueError(f'{domain} already listed')
        if not dn.match(domain):
            raise ValueError(f'{domain} not fqdn')
        self.host_endswith.add(domain)

    def _remove_domain(self, domain):
        try:
            self.net_filter.remove(domain)
            return
        except ValueError:
            pass
        self.host_endswith.discard(domain)

    def _add_domain_match(self, domain):
        if self.match(None, domain):
            raise ValueError(f'{domain} already listed')
        if not dn.match(domain):
            raise ValueError(f'{domain} not fqdn')
        self.host_match.add(domain)

    def _remove_domain_match(self, rule):
        domain = rule.rstrip('/')[4:]
        self.host_match.discard(domain)

    def match(self, url, host):
        if host in self.net_filter:
            return True
        if host in self.host_match:
            return True
        subhost_lst = ['.'.join(host.split('.')[i:]) for i in range(len(host.split('.')))]
        if any(subhost in self.host_endswith for subhost in subhost_lst):
            return True
        return None

    def remove(self, rule, delay=None):
        if delay:
            time.sleep(delay)
        if rule not in self.rules:
            return
        if rule.startswith('regexp:'):
            logger.info('%s ignored: regexp', rule)
            return
        if rule.startswith('full:'):
            self._remove_domain_match(rule[5:])
        elif rule.startswith('domain:'):
            self._remove_domain(rule[7:])
        else:
            self._remove_domain(rule)
        self.rules.discard(rule)
        del self.expire[rule]
        if '-GUI' in sys.argv:
            sys.stdout.write('local\n')
            sys.stdout.flush()


def test():
    gfwlist = V2Filter()
    t = time.perf_counter()
    with open('../proxy-list.txt', encoding='utf8') as f:
        for line in f:
            gfwlist.add(line)

    gfwlist.add('85.17.73.0/24')
    print('loading: %fs' % (time.perf_counter() - t))
    print('result for inxian: %r' % gfwlist.match(None, 'www.inxian.com'))
    print('result for twitter: %r' % gfwlist.match(None, 'twitter.com'))
    print('result for 163: %r' % gfwlist.match(None, 'www.163.com'))
    print('result for alipay: %r' % gfwlist.match(None, 'www.alipay.com'))
    print('result for qq: %r' % gfwlist.match(None, 'www.qq.com'))
    print('result for google.com.au: %r' % gfwlist.match(None, 'www.google.com.au'))
    print('result for riseup.net:443: %r' % gfwlist.match(None, 'riseup.net'))
    print('result for 85.17.73.31: %r' % ('85.17.73.31' in gfwlist.net_filter))
    print('result for 127.0.0.1: %r' % ('127.0.0.1' in gfwlist.net_filter))
    print('total: %d' % len(gfwlist.rules))
    url = 'http://news.163.com/16/1226/18/C97U4AI50001875N.html'
    host = urllib.parse.urlparse(url).hostname
    print('%s, %s' % (url, host))
    print(gfwlist.match(None, host))
    t = time.perf_counter()
    for _ in range(10000):
        gfwlist.match(None, host)
    print(f'10000 query for {url}, {time.perf_counter() - t}s')


if __name__ == "__main__":
    test()
