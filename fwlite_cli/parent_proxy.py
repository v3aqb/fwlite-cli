#!/usr/bin/env python
# coding:utf-8

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

import time
import logging

import urllib
from urllib.parse import unquote

logger = logging.getLogger('parent_proxy')

UDP_SUPPORT = ('', 'ss', 'hxs2', 'hxs3', 'hxs3s', 'hxs4')
RESPONSE_LIMIT = 14


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class DefaultDict(dict):
    def __init__(self, default):
        self.default = default
        super().__init__(self)

    def __missing__(self, key):
        return self.default


class ParentProxy:
    DIRECT = None
    DEFAULT_TIMEOUT = 8
    GATE = 5
    PROBATION = 16
    via = None
    conf = None

    def __init__(self, name, proxy, via=False):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087<|more proxies> <optional int: priority>"
        '''
        proxy, _, priority = proxy.partition(' ')
        priority = priority or 99
        if name == '_D1R3CT_':
            priority = 0
        if name == '_L0C4L_':
            priority = -1
            proxy = ''
        if name.startswith('FWLITE:'):
            priority = -1

        if proxy == 'direct':
            proxy = ''
        self.name = name
        proxy_list = proxy.split('|')
        self.proxy = proxy
        if len(proxy_list) > 1:
            self.via = ParentProxy('via', '|'.join(proxy_list[1:]), True)
            if self.via.name == 'via':
                self.via.name = '%s://%s:%s' % (self.via.scheme, self.via.hostname, self.via.port)
            if '//' not in proxy_list[0]:
                if proxy_list[0] not in self.conf.parentlist:
                    raise ValueError('proxy %s not exist.' % proxy_list[0])
                if self.conf.parentlist.get(proxy_list[0]).get_via().name != '_D1R3CT_':
                    logger.warning('proxy chain of %s will NOT be used.', proxy_list[0])
        if proxy_list[0] and '//' not in proxy_list[0] and via:
            if proxy_list[0] not in self.conf.parentlist:
                raise ValueError('proxy %s not exist.' % proxy_list[0])
            self.parse = self.conf.parentlist.get(proxy_list[0]).parse
            self.name = self.conf.parentlist.get(proxy_list[0]).name
            if len(proxy_list) == 1:
                self.via = self.conf.parentlist.get(proxy_list[0]).get_via()
        else:
            self.parse = urllib.parse.urlparse(proxy_list[0])

        self.scheme = self.parse.scheme
        self.username = unquote(self.parse.username) if self.parse.username else None
        self.password = unquote(self.parse.password) if self.parse.password else None
        self.hostname = self.parse.hostname
        self.port = self.parse.port
        self.peername = (self.hostname, self.port)  # for plugin only
        if self.proxy:
            if self.scheme:
                if ':' in self.hostname:
                    self.short = '%s://[%s]:%s' % (self.scheme, self.peername[0], self.peername[1])
                else:
                    self.short = '%s://%s:%s' % (self.scheme, self.peername[0], self.peername[1])
            else:
                self.short = self.proxy
        else:
            self.short = 'direct'

        self.query = urllib.parse.parse_qs(self.parse.query)
        plugin = self.query.get('plugin', [None, ])[0]
        self.plugin_info = plugin.split(';') if plugin else None
        if self.plugin_info:
            self.port = self.conf.plugin_manager.add(self.peername, self.plugin_info, self.via)
            self.hostname = '127.0.0.1'

        self.priority = int(float(priority))
        self.timeout = self.DEFAULT_TIMEOUT

        self.avg_resp_time = self.GATE
        self.avg_resp_time_ts = 0
        self.avg_resp_time_by_host = DefaultDict(self.GATE)
        self.avg_resp_time_by_host_ts = DefaultDict(0)
        self.avg_resp_time_by_host['udp'] = self.GATE if self.scheme in UDP_SUPPORT else 99
        self.last_limit_reach = 0

        self.country_code = self.query.get('location', [''])[0] or None
        self.last_ckeck = 0

    def get_priority(self, method=None, host=None):
        result = self.priority
        score = self.get_avg_resp_time() + self.get_avg_resp_time(host)
        logger.debug('penalty %s to %s: %.2f', self.name, host, score * 2)
        result += score * 2
        logger.debug('proxy %s to %s expected response time: %.3f', self.name, host, score)
        return result

    def log(self, host, rtime):
        if host != 'udp':
            r = 0.14 if rtime > self.avg_resp_time else 0.2
            self.avg_resp_time = r * rtime + (1 - r) * self.avg_resp_time
            self.avg_resp_time_ts = time.monotonic()
        if host:
            self.avg_resp_time_by_host[host] = 0.2 * rtime + (1 - 0.2) * self.avg_resp_time_by_host[host]
            self.avg_resp_time_by_host_ts[host] = time.monotonic()
        if self.avg_resp_time > RESPONSE_LIMIT:
            if not self.last_limit_reach:
                self.last_limit_reach = time.monotonic()
        if self.avg_resp_time < self.GATE:
            self.last_limit_reach = 0

        logger.debug('%s to %s: %.3fs avg: %.3fs %.3fs', self.name, host, rtime,
                     self.avg_resp_time, self.avg_resp_time_by_host[host])
        self.conf.stdout('proxy')

    def get_avg_resp_time(self, host=None):
        if host:
            if host in self.avg_resp_time_by_host:
                if time.monotonic() - self.avg_resp_time_by_host_ts[host] > 60:
                    self.avg_resp_time_by_host_ts[host] = time.monotonic()
                    if self.avg_resp_time_by_host[host] > self.GATE and \
                            self.avg_resp_time_by_host[host] <= 16:
                        self.log(host, self.GATE)
        elif time.monotonic() - self.avg_resp_time_ts > 60:
            self.avg_resp_time_ts = time.monotonic()
            if self.avg_resp_time > self.GATE:
                self.log(host, self.GATE)

        if self.avg_resp_time > RESPONSE_LIMIT:
            if time.monotonic() - self.last_limit_reach < self.PROBATION:
                return RESPONSE_LIMIT - 0.1
        result = self.avg_resp_time_by_host[host] if host in self.avg_resp_time_by_host else self.avg_resp_time
        return result

    @classmethod
    def set_via(cls, proxy):
        cls.via = proxy
        cls.DIRECT = cls('_DIRECT', 'direct -1')

    def get_via(self):
        if self.via == self or self.plugin_info:
            return self.DIRECT
        if self.DIRECT == self:
            return None
        return self.via

    def __str__(self):
        return self.name or self.short

    def __repr__(self):
        return '<ParentProxy: %s %s>' % (self.name, self.priority)


class ParentProxyList:
    def __init__(self, conf):
        self.conf = conf
        self.direct = None
        self.local = None
        self._parents = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy))
        self.conf.stdout('proxy')

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        if parentproxy.name in self.dict:
            logger.warning('%s already in ParentProxyList, overwrite', parentproxy.name)
            self.remove(parentproxy.name)
        logger.info('add parent: %s: %s', parentproxy.name, parentproxy.short)
        if parentproxy.name not in ('_L0C4L_', ):
            self.dict[parentproxy.name] = parentproxy
        if parentproxy.name == '_D1R3CT_':
            self.direct = parentproxy
            ParentProxy.set_via(self.direct)
            if parentproxy.proxy:
                self.addstr('_L0C4L_', 'direct -1')
            return
        if parentproxy.name == '_L0C4L_':
            self.local = parentproxy
            return

        if 0 <= parentproxy.priority <= 100:
            self._parents.add(parentproxy)

    def remove(self, name):
        if name in ('_D1R3CT_', '_L0C4L_') or name not in self.dict:
            return
        if 'FWLITE:' in name:
            return
        pxy = self.dict.get(name)
        del self.dict[name]
        self._parents.discard(pxy)
        self.conf.stdout('proxy')

    def get_proxy_list(self, host=None):
        parentlist = list(self._parents)

        def priority(parent):
            return parent.get_priority(host)

        if len(parentlist) > 1:
            # random.shuffle(parentlist)
            parentlist = sorted(parentlist, key=priority)

        parentlist = [proxy for proxy in parentlist if proxy.get_avg_resp_time(host) < RESPONSE_LIMIT]
        return parentlist

    def get(self, key):
        return self.dict.get(key)

    def __contains__(self, key):
        return key in self.dict
