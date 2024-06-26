#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Copyright (C) 2014-2023 v3aqb

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
import re
import time
from threading import Thread
from collections import defaultdict
import urllib.parse
import logging
try:
    from .util import parse_hostport
    from .ipfilter import NetFilter
except ImportError:
    from util import parse_hostport
    from ipfilter import NetFilter

logger = logging.getLogger('apfilter')
logger.setLevel(logging.INFO)


class ExpiredError(Exception):
    def __init__(self, rule):
        self.rule = rule
        super().__init__()


class APRule:

    def __init__(self, rule, msg=None, expire=None):
        self.rule = rule.strip()
        if len(self.rule) < 3 or self.rule.startswith(('!', '[')) or \
                '#' in self.rule or ' ' in self.rule:
            raise ValueError(f"invalid abp_rule: {self.rule}")
        self.msg = msg
        self.expire = expire
        self.override = self.rule.startswith('@@')
        self._regex = self._parse()

    def _parse(self):
        def parse(rule):
            if rule.startswith('||'):
                regex = rule.replace('.', r'\.').replace('/', '')\
                    .replace('*', '[^/]*')\
                    .replace('||', r'^(?:https?://)?(?:[^/]+\.)?')
                return re.compile(regex)
            if rule.startswith('/') and rule.endswith('/'):
                return re.compile(rule[1:-1])
            if rule.startswith('|https://'):
                index = rule.find('/', 9)
                regex = rule[9:] if index == -1 else rule[9:index]
                regex = regex.replace('.', r'\.').replace('*', '[^/]*')
                regex = r'^(?:https://)?%s(?:[:/])' % regex
                return re.compile(regex)

            regex = rule.replace('.', r'\.').replace('?', r'\?')\
                .replace('*', '.*').replace('^', r'[\/:]')
            regex = re.sub(r'^\|', r'^', regex)
            regex = re.sub(r'\|$', r'$', regex)
            if not rule.startswith(('|', 'http://')):
                regex = re.sub(r'^', r'^http://.*', regex)
            return re.compile(regex)

        return parse(self.rule[2:]) if self.override else parse(self.rule)

    def match(self, url):
        if self.expire and self.expire < time.time():
            raise ExpiredError(self)
        return self._regex.search(url)

    def __repr__(self):
        if self.expire:
            return f'<APRule: {self.rule} exp @ {self.expire}>'
        return f'<APRule: {self.rule}>'


class APFilter:
    KEYLEN = 9

    def __init__(self, lst=None):
        self.excludes = []
        self.slow = []
        self.host_endswith = set()
        self.host_endswith_exclude = set()
        self.fast = defaultdict(list)
        self.net_filter = NetFilter()
        self.net_filter_exclude = NetFilter()
        self.rules = set()
        self.expire = {}
        if lst:
            for rule in lst:
                self.add(rule)

    def add(self, rule, expire=None):
        rule = rule.strip()
        if len(rule) < 3 or rule.startswith(('!', '[', '#')):
            return
        if ' ' in rule:
            if not rule.startswith('0.0.0.0'):
                return
            _, _, rule = rule.partition(' ')
        if rule in self.rules:
            logger.debug('%s already in filter', rule)
            return
        if rule.startswith('||') and '*' not in rule:
            self._add_domain(rule)
        elif rule.startswith('@@||') and '*' not in rule:
            self._add_domain_exclude(rule)
        elif rule.startswith('@@|'):
            # strip and treat as domain rule
            rule = '@@||' + urllib.parse.urlparse(rule[3:]).hostname
            return self.add(rule)
        elif rule.startswith('|https://'):
            if '*' in rule:
                logger.info('%s ignored, "*"" in rule', rule)
                return
            # strip and treat as domain rule
            rule = '||' + urllib.parse.urlparse(rule[1:]).hostname
            return self.add(rule)
        elif rule.startswith(('@', '/')):
            self._add_slow(rule)
        elif rule.startswith('|http://') and\
                any(len(s) >= (self.KEYLEN) for s in rule[1:].split('*')):
            hostname = urllib.parse.urlparse(rule[1:]).hostname.strip('.*')
            if '*' not in hostname:
                return self.add('||' + hostname)
            self._add_fast(rule)
        else:
            # some small key word, treat as domain rule
            try:
                self.net_filter.add(rule)
            except ValueError:
                if '.' in rule and '*' not in rule and len(rule) < self.KEYLEN:
                    return self.add('||' + rule.strip('.'))
                self._add_fast(rule)

        self.rules.add(rule)
        self.expire[rule] = expire
        if expire:
            Thread(target=self.remove, args=(rule, expire)).start()

    def _add_fast(self, rule):
        rule_t = rule[1:] if rule.startswith('|') else rule
        lst = [s for s in rule_t.split('*') if len(s) >= self.KEYLEN]
        if not lst:
            logger.info('%s ignored, short', rule)
            return
        rule_o = APRule(rule)
        key = lst[-1][self.KEYLEN * -1:]
        self.fast[key].append(rule_o)

    def _add_slow(self, rule):
        rule_o = APRule(rule)
        lst = self.excludes if rule_o.override else self.slow
        lst.append(rule_o)

    def _add_domain_exclude(self, rule):
        rule = rule.rstrip('/^')
        domain = rule[4:]
        try:
            self.net_filter_exclude.add(domain)
            return
        except ValueError:
            pass
        if domain in self.host_endswith_exclude:
            logger.error('%s already in domains_exclude', rule)
            return
        self.host_endswith_exclude.add(domain)

    def _add_domain(self, rule):
        rule = rule.rstrip('/^')
        domain = rule[2:]
        try:
            self.net_filter.add(domain)
            return
        except ValueError:
            pass
        if domain in self.host_endswith:
            logger.error('%s already in domains', rule)
            return
        self.host_endswith.add(domain)

    def match(self, url, host=None, domain_only=False):
        if host is None:
            if '://' in url:
                host = urllib.parse.urlparse(url).hostname
            else:  # www.google.com:443
                host = parse_hostport(url)[0]
        if '://' not in url:
            url = f'https://{host}/'
        if self._listmatch(self.excludes, url):
            return False
        if self._domainmatch(host) is not None:
            return self._domainmatch(host)
        if domain_only:
            return None
        if self._fastmatch(url):
            return True
        if self._listmatch(self.slow, url):
            return True
        return None

    def _domainmatch(self, host):
        if host in self.net_filter_exclude:
            return False
        if host in self.net_filter:
            return True
        host_split = host.split('.')
        lst = ['.'.join(host_split[i:]) for i in range(len(host_split))]
        if any(host in self.host_endswith_exclude for host in lst):
            return False
        if any(host in self.host_endswith for host in lst):
            return True
        return None

    def _fastmatch(self, url):
        if url.startswith('http://'):
            i, j = 0, self.KEYLEN
            while j <= len(url):
                key = url[i:j]
                if key in self.fast:
                    if self._listmatch(self.fast[key], url):
                        return True
                i, j = i + 1, j + 1
        return None

    @staticmethod
    def _listmatch(lst, url):
        return any(r.match(url) for r in lst)

    def remove_domain(self, rule):
        domain = rule.rstrip('/')[2:]
        try:
            self.net_filter.remove(domain)
            return
        except ValueError:
            pass
        self.host_endswith.discard(domain)

    def remove_domain_exclude(self, rule):
        domain = rule.rstrip('/')[4:]
        try:
            self.net_filter_exclude.remove(domain)
            return
        except ValueError:
            pass
        self.host_endswith_exclude.discard(domain)

    def remove_fast(self, rule):
        rule_t = rule[1:] if rule.startswith('|') else rule
        lst = [s for s in rule_t.split('*') if len(s) >= self.KEYLEN]
        if not lst:
            logger.info('%s ignored, short', rule)
            return
        key = lst[-1][self.KEYLEN * -1:]
        for rule_o in self.fast[key][:]:
            if rule_o.rule == rule:
                self.fast[key].remove(rule_o)
                if not self.fast[key]:
                    del self.fast[key]
                break

    def remove(self, rule, delay=None):
        if delay:
            time.sleep(delay)
        if rule not in self.rules:
            return
        if rule.startswith('||') and '*' not in rule:
            self.remove_domain(rule)
        elif rule.startswith('@@||') and '*' not in rule:
            self.remove_domain_exclude(rule)
        elif rule.startswith('@@|'):
            # strip and treat as domain rule
            rule = '@@||' + urllib.parse.urlparse(rule[3:]).hostname
            self.remove_domain_exclude(rule)
        elif rule.startswith('|https://'):
            # strip and treat as domain rule
            rule = '||' + urllib.parse.urlparse(rule[1:]).hostname
            self.remove_domain(rule)
        elif rule.startswith(('@', '/')):
            lst = self.excludes if rule.startswith('@') else self.slow
            for rule_o in lst[:]:
                if rule_o.rule == rule:
                    lst.remove(rule_o)
                    break
        elif rule.startswith('|http://') and\
                any(len(s) >= (self.KEYLEN) for s in rule[1:].split('*')):
            self.remove_fast(rule)
        else:
            try:
                self.net_filter.remove(rule)
            except ValueError:
                self.remove_fast(rule)
        self.rules.discard(rule)
        del self.expire[rule]
        if '-GUI' in sys.argv:
            sys.stdout.write('local\n')
            sys.stdout.flush()


def test():
    gfwlist = APFilter()
    t = time.perf_counter()
    with open('../gfwlist.txt') as f:
        data = f.read()
        if '!' not in data:
            import base64
            data = ''.join(data.split())
            data = base64.b64decode(data).decode()
        for line in data.splitlines():
            # if line.startswith('||'):
            try:
                gfwlist.add(line)
            except Exception:
                pass
        del data
    print('loading: %fs' % (time.perf_counter() - t))

    test_result = {
        'inxian': gfwlist.match('http://www.inxian.com', 'www.inxian.com'),
        'twitter': gfwlist.match('twitter.com:443', 'twitter.com'),
        '163': gfwlist.match('http://www.163.com', 'www.163.com'),
        'alipay': gfwlist.match('www.alipay.com:443', 'www.alipay.com'),
        'qq': gfwlist.match('http://www.qq.com', 'www.qq.com'),
        'keyword': gfwlist.match('http://te.com/iredmail.org', 'www.test.com'),
        'url_startswith': gfwlist.match('http://ff.im/whatever', 'ff.im'),
        'google.com.au': gfwlist.match('www.google.com.au:443', 'www.google.com.au'),
        'riseup.net:443': gfwlist.match('riseup.net:443', 'riseup.net'),
        '85.17.73.31': '85.17.73.31' in gfwlist.net_filter,
        '127.0.0.1': '127.0.0.1' in gfwlist.net_filter,
    }

    for test, result in test_result.items():
        print(f'result for {test}: {result}')

    url = 'http://news.163.com/16/1226/18/C97U4AI50001875N.html'
    host = urllib.parse.urlparse(url).hostname
    print('%s, %s' % (url, host))
    print(gfwlist.match(url, host))
    t = time.perf_counter()
    for _ in range(10000):
        gfwlist.match(url, host)
    print('KEYLEN = %d' % gfwlist.KEYLEN)
    print('10000 query for %s, %fs' % (url, time.perf_counter() - t))
    o1 = len(gfwlist.rules) - (len(gfwlist.excludes) + len(gfwlist.slow))
    print(f'O(1): {o1}')
    print('O(n): %d' % (len(gfwlist.excludes) + len(gfwlist.slow)))
    print('domain rules: %d' % len(gfwlist.host_endswith))
    print('total: %d' % len(gfwlist.rules))
    print(repr(gfwlist.net_filter))

    fast_key_list = gfwlist.fast.keys()
    fast_key_list = sorted(fast_key_list, key=lambda x: len(gfwlist.fast[x]))
    for key in fast_key_list[-10:]:
        print('%r : %d' % (key, len(gfwlist.fast[key])))


if __name__ == "__main__":
    test()
