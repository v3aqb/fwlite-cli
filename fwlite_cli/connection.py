#!/usr/bin/env python
# coding: UTF-8

# Copyright (C) 2014-2015 v3aqb

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

import socket
import logging

import asyncio

from .parent_proxy import ParentProxy

logger = logging.getLogger('conn')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


async def _create_connection(protocol, addr, port, timeout, iplist=None, tcp_nodelay=True):
    '''
        iplist: for Hosts only
    '''
    loop = asyncio.get_running_loop()
    if iplist:
        # ipv4 goes first
        iplist = sorted(iplist, key=lambda item: item[0])
        err = None
        for res in iplist:
            _, addr = res
            try:
                fut = loop.create_connection(lambda: protocol, addr, port)
                transport, _ = await asyncio.wait_for(fut, timeout=timeout)
                return transport
            except Exception as exc:
                err = exc
        raise err
    try:
        fut = loop.create_connection(lambda: protocol, addr, port, happy_eyeballs_delay=0.25)
        transport, _ = await asyncio.wait_for(fut, timeout=timeout)
    except TypeError:
        fut = loop.create_connection(lambda: protocol, addr, port)
        transport, _ = await asyncio.wait_for(fut, timeout=timeout)

    soc = transport.get_extra_info('socket')
    soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if tcp_nodelay else 0)
    return transport


async def open_connection(addr, port, proxy=None, timeout=8, iplist=None, tunnel=False, limit=65536, tcp_nodelay=True):
    if not isinstance(proxy, ParentProxy):
        logger.warning('parentproxy is not a ParentProxy instance, please check. %s', proxy)
        proxy = ParentProxy(proxy or 'null', proxy or '')

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=limit, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = await create_connection(protocol, addr, port, proxy, timeout, iplist, tunnel, limit, tcp_nodelay)
    # protocol is for Reader, transport is for Writer
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer, proxy.name


async def create_connection(protocol, addr, port, proxy=None, timeout=8, iplist=None, tunnel=True, limit=65536, tcp_nodelay=True):
    loop = asyncio.get_running_loop()
    if not proxy or not proxy.proxy:
        transport = await _create_connection(protocol, addr, port, timeout, iplist, tcp_nodelay)
        transport.set_write_buffer_limits(limit)
        return transport
    if proxy.scheme == 'ss':
        from .ssocks import ss_create_connection
        transport = await ss_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay)
        return transport
    if proxy.scheme in ('http', 'socks5'):
        if tunnel:
            from .proxy_client import ProxyClientProtocol
            connected_cb = loop.create_future()
            p_protocol = ProxyClientProtocol(protocol, connected_cb, (addr, port),
                                             proxy=proxy.scheme,
                                             proxy_auth=(proxy.username, proxy.password))
            transport = await create_connection(p_protocol, proxy.hostname, proxy.port, proxy.get_via())
            await connected_cb
        else:
            transport = await create_connection(protocol, proxy.hostname, proxy.port, proxy.get_via())
        return transport
    if proxy.scheme == 'hxs2':
        from .hxsocks2 import hxs2_create_connection
        transport = await hxs2_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay)
        return transport
    if proxy.scheme in ('hxs3', 'hxs3s'):
        from .hxsocks3 import hxs3_create_connection
        transport = await hxs3_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay)
        return transport
    if proxy.scheme == 'hxs4':
        from .hxsocks4 import hxs4_create_connection
        transport = await hxs4_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay)
        return transport
    raise ValueError(0, f'parentproxy {proxy.name} not supported!')
