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

import base64
import struct
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


async def _open_connection(addr, port, timeout, iplist, limit=65536, tcp_nodelay=True):
    if iplist:
        # ipv4 goes first
        iplist = sorted(iplist, key=lambda item: item[0])
        err = None
        for res in iplist:
            _, addr = res
            try:
                fut = asyncio.open_connection(addr, port, limit=limit)
                remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
                if tcp_nodelay:
                    soc = remote_writer.transport.get_extra_info('socket')
                    soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return remote_reader, remote_writer
            except Exception as exc:
                err = exc
        raise err
    try:
        fut = asyncio.open_connection(addr, port, limit=limit, happy_eyeballs_delay=0.25)
        remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
    except TypeError:
        fut = asyncio.open_connection(addr, port, limit=limit)
        remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)

    soc = remote_writer.transport.get_extra_info('socket')
    soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if tcp_nodelay else 0)
    return remote_reader, remote_writer


async def open_connection(addr, port, proxy=None, timeout=8, iplist=None, tunnel=False, limit=65536, tcp_nodelay=True):
    if not isinstance(proxy, ParentProxy):
        logger.warning('parentproxy is not a ParentProxy instance, please check. %s', proxy)
        proxy = ParentProxy(proxy or 'null', proxy or '')

    # create connection
    if not proxy.proxy:
        remote_reader, remote_writer = await _open_connection(addr, port, timeout, iplist, limit, tcp_nodelay)
        return remote_reader, remote_writer, proxy.name
    if proxy.scheme == 'http':
        remote_reader, remote_writer, _ = await open_connection(proxy.hostname,
                                                                proxy.port,
                                                                proxy.get_via(),
                                                                timeout=timeout,
                                                                tunnel=True,
                                                                limit=limit,
                                                                tcp_nodelay=tcp_nodelay)
        if tunnel:
            # send connect request
            req = ['CONNECT %s:%s HTTP/1.1\r\n' % (addr, port), ]
            if proxy.username:
                auth = '%s:%s' % (proxy.username, proxy.password)
                req.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(auth.encode()).decode())
            req.append('Host: %s:%s\r\n\r\n' % (addr, port))
            remote_writer.write(''.join(req).encode())

            fut = remote_reader.readuntil(b'\r\n\r\n')
            data = await asyncio.wait_for(fut, timeout=2)
            if b'200' not in data.splitlines()[0]:
                raise IOError(0, 'create tunnel via %s failed! %s' % (proxy.name, data.splitlines()[0]))
        return remote_reader, remote_writer, proxy.name
    if proxy.scheme == 'socks5':
        remote_reader, remote_writer, _ = await open_connection(proxy.hostname,
                                                                proxy.port,
                                                                proxy.get_via(),
                                                                timeout=timeout,
                                                                tunnel=True,
                                                                limit=limit,
                                                                tcp_nodelay=tcp_nodelay)
        remote_writer.write(b"\x05\x02\x00\x02" if proxy.username else b"\x05\x01\x00")
        data = await remote_reader.readexactly(2)
        if data == b'\x05\x02':  # basic auth
            remote_writer.write(b''.join([b"\x01",
                                          bytes((len(proxy.username), )),
                                          proxy.username.encode(),
                                          bytes((len(proxy.password), )),
                                          proxy.password.encode()]))
            data = await remote_reader.readexactly.recv(2)
        assert data[1] == 0  # no auth needed or auth passed
        remote_writer.write(b''.join([b"\x05\x01\x00\x03",
                                      bytes((len(addr), )),
                                      addr.encode(),
                                      struct.pack(b">H", port)]))
        data = await remote_reader.readexactly(4)
        assert data[1] == 0
        if data[3] == 1:  # read ipv4 addr
            await remote_reader.readexactly(4)
        elif data[3] == 3:  # read host addr
            size = await remote_reader.readexactly(1)
            size = ord(size)
            await remote_reader.readexactly(size)
        elif data[3] == 4:  # read ipv6 addr
            await remote_reader.readexactly(16)
        await remote_reader.readexactly(2)  # read port
        return remote_reader, remote_writer, proxy.name
    if proxy.scheme == 'ss':
        from .ssocks import ss_connect
        remote_reader, remote_writer = await ss_connect(proxy, timeout, addr, port, limit, tcp_nodelay)
        return remote_reader, remote_writer, proxy.name
    if proxy.scheme == 'hxs2':
        from .hxsocks2 import hxs2_connect
        remote_reader, remote_writer, name = await hxs2_connect(proxy, timeout, addr, port, limit, tcp_nodelay)
        return remote_reader, remote_writer, name
    if proxy.scheme in ('hxs3', 'hxs3s'):
        from .hxsocks3 import hxs3_connect
        remote_reader, remote_writer, name = await hxs3_connect(proxy, timeout, addr, port, limit, tcp_nodelay)
        return remote_reader, remote_writer, name
    if proxy.scheme == 'hxs4':
        from .hxsocks4 import hxs4_connect
        remote_reader, remote_writer, name = await hxs4_connect(proxy, timeout, addr, port, limit, tcp_nodelay)
        return remote_reader, remote_writer, name
    raise ValueError(0, f'parentproxy {proxy.name} not supported!')
