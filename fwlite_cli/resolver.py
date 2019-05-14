
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
import logging
from ipaddress import ip_address


logger = logging.getLogger('resolver')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


async def getaddrinfo(host, port):
    loop = asyncio.get_event_loop()
    fut = loop.getaddrinfo(host, port)
    result = await asyncio.wait_for(fut, timeout=2)
    return result


async def resolve(host, port):
    result = await getaddrinfo(host, port)
    return [(i[0], i[4][0]) for i in result]


class resolver:
    def __init__(self, apfilter_list, bad_ip):
        self.apfilter_list = apfilter_list
        self.bad_ip = bad_ip

    def is_poisoned(self, domain):
        if not self.apfilter_list:
            return
        url = 'http://%s/' % domain
        for apfilter in self.apfilter_list:
            if apfilter.match(url, domain):
                return True

    async def resolve(self, host, port, dirty=False):
        ''' return
        '''
        logger.debug('entering %s.resolve(%s)' % (self.__class__.__name__, host))
        try:
            ip = ip_address(host)
            return [(2 if ip.version == 4 else 10, host), ]
        except Exception:
            pass
        if self.is_poisoned(host):
            if dirty:
                return []
            else:
                raise NotImplementedError
        try:
            # resolve
            result = await resolve(host, port)
            if result[0][1] in self.bad_ip:
                return []
            return result
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning('resolving %s failed: %r' % (host, e))
            return []

    async def get_ip_address(self, host):
        logger.debug('entering %s.get_ip_address(%s)' % (self.__class__.__name__, host))
        try:
            return ip_address(host)
        except Exception:
            try:
                result = await self.resolve(host, 0, dirty=True)
                result = [ip for ip in result if ip[0] == 4]
                return ip_address(result[0][1])
            except asyncio.CancelledError:
                raise
            except IndexError:
                return ip_address(u'0.0.0.0')
