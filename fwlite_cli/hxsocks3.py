#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2022 v3aqb

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


from builtins import chr

import struct
import time
import hmac
import hashlib
import random
import ssl
import logging
import asyncio
from ipaddress import ip_address

import websockets.client
from websockets.exceptions import ConnectionClosed

from hxcrypto import InvalidTag, ECC

from fwlite_cli.parent_proxy import ParentProxy
from fwlite_cli.hxscommon import ConnectionLostError, HxsConnection, ReadFrameError


def set_logger():
    logger = logging.getLogger('hxs3')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


MAX_CONNECTION = 2

CONN_MANAGER = {}  # (server, parentproxy): manager


async def hxs3_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme in ('hxs3', 'hxs3s')

    # get hxs2 connection
    for _ in range(MAX_CONNECTION + 1):
        try:
            conn = await hxs3_get_connection(proxy, timeout, tcp_nodelay)

            soc = await conn.connect(addr, port, timeout)

            reader, writer = await asyncio.open_connection(sock=soc, limit=limit)
            return reader, writer, conn.name
        except ConnectionLostError:
            continue
    raise ConnectionResetError(0, 'get hxs3 connection failed.')


async def hxs3_get_connection(proxy, timeout, tcp_nodelay):
    if proxy.name not in CONN_MANAGER:
        CONN_MANAGER[proxy.name] = ConnectionManager()
    conn = await CONN_MANAGER[proxy.name].get_connection(proxy, timeout, tcp_nodelay)
    return conn


class ConnectionManager:
    def __init__(self):
        self.connection_list = []
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger('hxs3')
        self._err = None
        self._err_time = 0

    async def get_connection(self, proxy, timeout, tcp_nodelay):
        # choose / create and return a connection
        async with self._lock:
            if len(self.connection_list) < MAX_CONNECTION and\
                    not [conn for conn in self.connection_list if not conn.is_busy()]:
                if self._err and time.time() - self._err_time < 6:
                    raise self._err  # pylint: disable=E0702
                connection = Hxs3Connection(proxy, self)
                try:
                    await connection.get_key(timeout, tcp_nodelay)
                except (OSError, asyncio.TimeoutError, ConnectionClosed) as err:
                    asyncio.ensure_future(connection.close())
                    self._err = ConnectionResetError(0, 'hxsocks3 get_key() failed: %r' % err)
                    self._err_time = time.time()
                    raise self._err  # pylint: disable=E0702
                else:
                    self._err = None
                    self.connection_list.append(connection)
        list_ = sorted(self.connection_list, key=lambda item: item.busy())
        return list_[0]

    def remove(self, conn):
        # this connection is not accepting new streams anymore
        if conn in self.connection_list:
            self.connection_list.remove(conn)


def is_ipaddr(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


class Hxs3Connection(HxsConnection):
    bufsize = 65535 - 22

    def __init__(self, proxy, manager):
        super().__init__(proxy, manager)
        self.logger = logging.getLogger('hxs3')

    async def send_frame_data(self, ct_):
        try:
            await self.remote_writer.send(ct_)
            self._stat_total_sent += len(ct_)
            self._stat_sent_tp += len(ct_)
            self._last_count += 1
        except ConnectionClosed:
            self.connection_lost = True

    async def read_frame(self, intv):
        try:
            fut = self.remote_writer.recv()
            frame_data = await asyncio.wait_for(fut, timeout=intv)
            frame_data = self._cipher.decrypt(frame_data)
            self._stat_total_recv += len(frame_data)
            self._stat_recv_tp += len(frame_data)
            return frame_data
        except (ConnectionClosed, RuntimeError, InvalidTag, OSError) as err:
            raise ReadFrameError(err) from err

    async def get_key(self, timeout, tcp_nodelay):
        self.logger.debug('hxsocks3 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        ssl_ctx = None
        scheme = 'ws'
        if self.proxy.scheme == 'hxs3s':
            scheme = 'wss'
            ssl_ctx = ssl.create_default_context()
            if is_ipaddr(self.proxy.hostname):
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

        uri = '%s://%s:%d/%s' % (scheme, self.proxy.hostname, self.proxy.port, self.proxy.parse.path)
        self.remote_writer = await websockets.client.connect(uri, ssl=ssl_ctx, compression=None,
                                                             ping_interval=None,
                                                             read_limit=2 ** 18,
                                                             write_limit=2 ** 18,)
        self._socport = self.remote_writer.local_address[1]

        # prep key exchange request
        ecc = ECC(32)
        pubk = ecc.get_pub_key()
        timestamp = struct.pack('>I', int(time.time()) // 30)
        data = b''.join([chr(len(pubk)).encode('latin1'),
                         pubk,
                         hmac.new(psw.encode() + usn.encode(), timestamp, hashlib.sha256).digest(),
                         bytes((self.mode, )),
                         bytes(random.randint(64, 450))])
        data = chr(0).encode() + data

        # send key exchange request
        await self.remote_writer.send(data)

        # read server response
        fut = self.remote_writer.recv()
        data = await asyncio.wait_for(fut, timeout=timeout)

        self.key_exchange(data, usn, psw, pubk, ecc)

    async def close(self):
        if self.remote_writer:
            await self.remote_writer.close()
