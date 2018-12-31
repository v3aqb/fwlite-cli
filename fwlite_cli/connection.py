#!/usr/bin/env python
# coding: UTF-8

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
import struct
import logging

import asyncio
import ipaddress

from .parent_proxy import ParentProxy
from .base_handler import read_response_line, read_header_data

logger = logging.getLogger('conn')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


def do_tunnel(soc, netloc, pp):
    s = ['CONNECT %s:%s HTTP/1.1\r\n' % (netloc[0], netloc[1]), ]
    if pp.username:
        a = '%s:%s' % (pp.username, pp.password)
        s.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode()))
    s.append('Host: %s:%s\r\n\r\n' % (netloc[0], netloc[1]))
    soc.sendall(''.join(s).encode())
    remoterfile = soc.makefile('rb', 0)
    line, version, status, reason = read_response_line(remoterfile)
    if status != 200:
        raise IOError(0, 'create tunnel via %s failed!' % pp.name)
    read_header_data(remoterfile)


def get_ip_address(self, host):
    try:
        return ipaddress(host)
    except Exception:
        return ipaddress('1.1.1.1')


def request_is_loopback(addr):
    try:
        ip = get_ip_address(addr)
        if ip.is_loopback:
            return ip
    except Exception:
        pass


async def _open_connection(addr, port, timeout, iplist):
    if iplist:
        # ipv4 goes first
        iplist = sorted(iplist, key=lambda item: item[0])
        err = None
        for res in iplist:
            af, addr = res
            try:
                fut = asyncio.open_connection(addr, port)
                remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
                return remote_reader, remote_writer
            except Exception as e:
                err = e
        raise err

    fut = asyncio.open_connection(addr, port)
    remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=timeout)
    return remote_reader, remote_writer


async def open_connection(addr, port, proxy=None, timeout=3, iplist=[], tunnel=False):
    if proxy and not isinstance(proxy, ParentProxy):
        logger.warning('parentproxy is not a ParentProxy instance, please check. %s' % (proxy))
        proxy = ParentProxy(proxy, proxy)

    # do security check here
    if request_is_loopback(addr):
        raise ValueError('connect to localhost denied!')

    # create connection
    if not proxy.proxy:
        remote_reader, remote_writer = await _open_connection(addr, port, timeout, iplist)
        return remote_reader, remote_writer, proxy.name
    elif proxy.scheme == 'http':
        remote_reader, remote_writer, _ = await open_connection(proxy.hostname, proxy.port, proxy.get_via(), timeout=timeout, tunnel=True)
        if tunnel:
            # send connect request
            s = ['CONNECT %s:%s HTTP/1.1\r\n' % (addr, port), ]
            if proxy.username:
                a = '%s:%s' % (proxy.username, proxy.password)
                s.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(a.encode()))
            s.append('Host: %s:%s\r\n\r\n' % (addr, port))
            remote_writer.write(''.join(s).encode())

            fut = remote_reader.readuntil(b'\r\n\r\n')
            data = await asyncio.wait_for(fut, timeout=2)
            if b'200' not in data.splitlines()[0]:
                raise IOError(0, 'create tunnel via %s failed!' % proxy.name)
        return remote_reader, remote_writer, proxy.name
    elif proxy.scheme == 'socks5':
        remote_reader, remote_writer = await open_connection(proxy.hostname, proxy.port, proxy.get_via(), timeout=timeout, tunnel=True)
        remote_writer.write(b"\x05\x02\x00\x02" if proxy.username else b"\x05\x01\x00")
        data = await remote_reader.readexactly(2)
        if data == b'\x05\x02':  # basic auth
            remote_writer.write(b''.join([b"\x01",
                                          chr(len(proxy.username)).encode(),
                                          proxy.username.encode(),
                                          chr(len(proxy.password)).encode(),
                                          proxy.password.encode()]))
            data = await remote_reader.readexactly.recv(2)
        assert data[1] == b'\x00'  # no auth needed or auth passed
        remote_writer.write(b''.join([b"\x05\x01\x00\x03",
                                      chr(len(addr)).encode(),
                                      addr.encode(),
                                      struct.pack(b">H", port)]))
        data = await remote_reader.readexactly(4)
        assert data[1] == b'\x00'
        if data[3] == b'\x01':  # read ipv4 addr
            await remote_reader.readexactly(4)
        elif data[3] == b'\x03':  # read host addr
            size = await remote_reader.readexactly(1)
            size = ord(size)
            await remote_reader.readexactly(size)
        elif data[3] == b'\x04':  # read ipv6 addr
            await remote_reader.readexactly(16)
        await remote_reader.readexactly(2)  # read port
        return remote_reader, remote_writer, proxy.name
    elif proxy.scheme == 'ss':
        from .shadowsocks import ss_connect
        remote_reader, remote_writer = await ss_connect(proxy, timeout, addr, port)
        return remote_reader, remote_writer, proxy.name
    elif proxy.scheme == 'hxs2':
        from .hxsocks2 import hxs2_connect
        remote_reader, remote_writer, name = await hxs2_connect(proxy, timeout, addr, port)
        return remote_reader, remote_writer, name
    else:
        raise IOError(0, 'parentproxy %s not supported!' % proxy.name)