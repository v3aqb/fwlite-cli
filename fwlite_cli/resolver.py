
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

import asyncio
import socket
import logging
import itertools
from ipaddress import ip_address

logger = logging.getLogger('resolver')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class DNSCache:
    def __init__(self, timeout=60):
        self.pool = {}  # {domain: result}
        self.err_pool = {}  # {domain: Exception}
        self.intv = 10
        self.count = timeout // self.intv
        self.timerwheel = [set() for _ in range(self.count)]  # a list of socket object
        self.timerwheel_iter = itertools.cycle(range(self.count))
        self.timerwheel_index = next(self.timerwheel_iter)
        self.purge_task = None

    def put(self, domain, result):
        # soc: (reader, writer)
        if isinstance(result, Exception):
            self.err_pool[domain] = result
        else:
            self.pool[domain] = result
            self.timerwheel[self.timerwheel_index].add(domain)
        if not self.purge_task:
            self.purge_task = asyncio.ensure_future(self._purge())

    def get(self, domain):
        result = self.pool.get(domain, None)
        if result:
            return result
        return self.err_pool.get(domain, None)

    async def _purge(self):
        while 1:
            await asyncio.sleep(self.intv)
            self.err_pool.clear()
            self.timerwheel_index = next(self.timerwheel_iter)
            for domain in list(self.timerwheel[self.timerwheel_index]):
                if domain in self.pool:
                    del self.pool[domain]
            self.timerwheel[self.timerwheel_index].clear()


DC = DNSCache()
LOCK = {}


async def getaddrinfo(host, port):
    loop = asyncio.get_event_loop()
    fut = loop.getaddrinfo(host, port)
    result = await asyncio.wait_for(fut, timeout=4)
    return result


async def resolve(host, port=None):
    if host not in LOCK:
        LOCK[host] = asyncio.Lock()
    async with LOCK[host]:
        result = DC.get(host)
        if result:
            if isinstance(result, Exception):
                raise result
            return result

        err = None
        try:
            result = await getaddrinfo(host, port)
            result = [(i[0], i[4][0]) for i in result]
            DC.put(host, result)
            return result
        except (OSError, asyncio.TimeoutError, LookupError) as err_:
            err = err_
        DC.put(host, err)
        raise err


class Resolver:
    def __init__(self, cic):
        self.cic = cic
        self.bad_ip = set(cic.conf.userconf.dget('dns', 'bad_ip', '').split('|'))
        self.zero = ip_address('0.0.0.0')

    def is_poisoned(self, domain, mode):
        if self.cic.get_proxy_o and self.cic.get_proxy_o.isgfwed_resolver(domain, mode):
            return True
        return False

    async def resolve(self, host, port):
        ''' return
        '''
        logger.debug('entering %s.resolve(%s)', self.__class__.__name__, host)
        try:
            ip = ip_address(host)
            return [(socket.AF_INET if ip.version == 4 else socket.AF_INET6, host), ]
        except ValueError:
            pass

        try:
            # resolve
            result = await resolve(host, port)
            if result[0][1] in self.bad_ip:
                return []
            return result
        except (OSError, asyncio.TimeoutError, LookupError) as err:
            logger.warning('resolving %s failed: %r', host, err)
            return []

    async def get_ip_address(self, addr, mode):
        logger.debug('entering %s.get_ip_address(%s)', self.__class__.__name__, addr)
        host, port = addr
        try:
            return ip_address(host)
        except ValueError:
            pass
        if self.is_poisoned(host, mode):
            return self.zero
        try:
            result = await self.resolve(host, port)
            result_v4 = [ip for ip in result if ip[0] == socket.AF_INET]
            if result_v4:
                ipaddr = ip_address(result_v4[0][1])
            else:
                ipaddr = ip_address(result[0][1])
            return ipaddr
        except IndexError:
            return self.zero
