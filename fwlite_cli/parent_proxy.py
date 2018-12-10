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

import time
import logging
try:
    import urllib.parse as urlparse
    urlquote = urlparse.quote
    urlunquote = urlparse.unquote
except ImportError:
    import urlparse
    import urllib2
    urlquote = urllib2.quote
    urlunquote = urllib2.unquote


logger = logging.getLogger('parent_proxy')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


class default_1_dict(dict):
    def __missing__(self, key):
        return 1


class ParentProxy(object):
    via = None
    DEFAULT_TIMEOUT = 8
    avg_resp_time = 1
    avg_resp_time_ts = 0
    avg_resp_time_by_host = default_1_dict()
    avg_resp_time_by_host_ts = default_1_dict()

    def __init__(self, name, proxy):
        '''
        name: str, name of parent proxy
        proxy: "http://127.0.0.1:8087<|more proxies> <optional int: httppriority> <optional int: httpspriority>"
        '''
        proxy, _, priority = proxy.partition(' ')
        httppriority, _, httpspriority = priority.partition(' ')
        httpspriority, _, timeout = httpspriority.partition(' ')
        httppriority = httppriority or 99
        httpspriority = httpspriority or httppriority
        timeout = timeout or self.DEFAULT_TIMEOUT

        if proxy == 'direct':
            proxy = ''
        elif proxy and '//' not in proxy:
            proxy = 'http://' + proxy
        self.name = name
        proxy_list = proxy.split('|')
        self.proxy = proxy_list[0]
        if len(proxy_list) > 1:
            self.via = ParentProxy('via', '|'.join(proxy_list[1:]))
            self.via.name = '%s://%s:%s' % (self.via.scheme, self.via.hostname, self.via.port)
        self.parse = urlparse.urlparse(self.proxy)

        self.scheme = self.parse.scheme
        self.username = urlunquote(self.parse.username) if self.parse.username else None
        self.password = urlunquote(self.parse.password) if self.parse.password else None
        self.hostname = self.parse.hostname
        self.port = self.parse.port
        self._host_port = (self.hostname, self.port)  # for plugin only

        self.query = urlparse.parse_qs(self.parse.query)
        plugin = self.query.get('plugin', [None, ])[0]
        self.plugin_info = plugin.split(';') if plugin else None
        if self.plugin_info:
            from .plugin_manager import plugin_manager
            plugin_manager.add(self._host_port, self.plugin_info)
            self.hostname = '127.0.0.1'
            self.port = plugin_manager.get(self._host_port)

        self.id = self.query.get('id', [self.name, ])[0]

        self.httppriority = int(httppriority)
        self.httpspriority = int(httpspriority)
        self.timeout = int(timeout)
        self.country_code = self.query.get('location', [''])[0] or None
        self.last_ckeck = 0
        if self.parse.scheme.lower() == 'sni':
            self.httppriority = -1
            logger.warning('sni proxy is detectable by GFW, server ip can be blocked.')

    def priority(self, method=None, host=None):
        result = self.httpspriority if method is 'CONNECT' else self.httppriority

        score = self.get_avg_resp_time() + self.get_avg_resp_time(host)
        logger.debug('penalty %s to %s: %.2f' % (self.name, host, score * 5))
        result += score * 5
        logger.debug('proxy %s to %s expected response time: %.3f' % (self.name, host, score))
        return result

    def log(self, host, rtime):
        self.avg_resp_time = 0.87 * self.get_avg_resp_time() + (1 - 0.87) * rtime
        self.avg_resp_time_by_host[host] = 0.87 * self.get_avg_resp_time(host) + (1 - 0.87) * rtime
        self.avg_resp_time_ts = self.avg_resp_time_by_host_ts[host] = time.time()
        logger.debug('%s to %s: %.3fs avg: %.3fs' % (self.name, host, rtime, self.avg_resp_time))

    def get_avg_resp_time(self, host=None):
        if host is None:
            if time.time() - self.avg_resp_time_ts > 360:
                if self.avg_resp_time > 1:
                    self.avg_resp_time *= 0.93
                self.avg_resp_time_ts = time.time()
            return self.avg_resp_time
        if time.time() - self.avg_resp_time_by_host_ts[host] > 360:
            if self.avg_resp_time_by_host[host] > 1:
                self.avg_resp_time_by_host[host] *= 0.93
            self.avg_resp_time_by_host_ts[host] = time.time()
        return self.avg_resp_time_by_host[host] or self.avg_resp_time

    @classmethod
    def set_via(cls, proxy):
        cls.via = proxy

    def get_via(self):
        if self.via == self:
            return None
        return self.via

    def __str__(self):
        return self.name or ('%s://%s:%s' % (self.parse.scheme, self.parse.hostname, self.parse.port))

    def __repr__(self):
        return '<ParentProxy: %s %s %s>' % (self.name or 'direct', self.httppriority, self.httpspriority)


class ParentProxyList(object):
    def __init__(self):
        self.direct = None
        self.local = None
        self._httpparents = set()
        self._httpsparents = set()
        self.dict = {}

    def addstr(self, name, proxy):
        self.add(ParentProxy(name, proxy))

    def add(self, parentproxy):
        assert isinstance(parentproxy, ParentProxy)
        if parentproxy.parse.scheme:
            s = '%s://%s:%s' % (parentproxy.parse.scheme, parentproxy.parse.hostname, parentproxy.parse.port)
        else:
            s = 'None'
        if parentproxy.name in self.dict:
            logger.warning('%s already in ParentProxyList, overwrite' % parentproxy.name)
            self.remove(parentproxy.name)
        logger.info('add parent: %s: %s' % (parentproxy.name, s))
        self.dict[parentproxy.name] = parentproxy
        if parentproxy.name == 'direct':
            self.direct = parentproxy
            return
        if parentproxy.name == 'local':
            self.local = parentproxy
            return
        if 0 <= parentproxy.httppriority <= 100:
            self._httpparents.add(parentproxy)
        if 0 <= parentproxy.httpspriority <= 100:
            self._httpsparents.add(parentproxy)

    def remove(self, name):
        if name == 'direct' or name not in self.dict:
            return 1
        a = self.dict.get(name)
        del self.dict[name]
        self._httpparents.discard(a)
        self._httpsparents.discard(a)

    def httpparents(self):
        return list(self._httpparents)

    def httpsparents(self):
        return list(self._httpsparents)

    def get(self, key):
        return self.dict.get(key)
