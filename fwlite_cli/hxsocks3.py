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
from fwlite_cli.hxscommon import HxsConnection
from fwlite_cli.hxscommon import ConnectionLostError, ConnectionDenied, ReadFrameError
from fwlite_cli.hxscommon import CLIENT_AUTH_PADDING, MAX_CONNECTION
from fwlite_cli.util import cipher_test

# see "openssl ciphers" command for cipher names
CIPHERS_A = [
'TLS_AES_256_GCM_SHA384',
'TLS_CHACHA20_POLY1305_SHA256',
'TLS_AES_128_GCM_SHA256',
'ECDHE-ECDSA-AES256-GCM-SHA384',
'ECDHE-ECDSA-AES128-GCM-SHA256',
'ECDHE-ECDSA-CHACHA20-POLY1305',
'ECDHE-ECDSA-AES256-SHA384',
'ECDHE-ECDSA-AES128-SHA256',
]
CIPHERS_C = [
'TLS_CHACHA20_POLY1305_SHA256',
'TLS_AES_256_GCM_SHA384',
'TLS_AES_128_GCM_SHA256',
'ECDHE-ECDSA-CHACHA20-POLY1305',
'ECDHE-ECDSA-AES128-GCM-SHA256',
'ECDHE-ECDSA-AES256-GCM-SHA384',
'ECDHE-ECDSA-AES128-SHA256',
'ECDHE-ECDSA-AES256-SHA384',
]
CIPHERS = ':'.join(CIPHERS_A if cipher_test[2] < 1.2 else CIPHERS_C)


def set_logger():
    logger = logging.getLogger('hxs3')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)
    logger.info(repr(cipher_test))


set_logger()


CONN_MANAGER = {}  # (server, parentproxy): manager


async def hxs3_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme in ('hxs3', 'hxs3s')

    # get hxs3 connection
    for _ in range(MAX_CONNECTION + 1):
        try:
            conn = await hxs3_get_connection(proxy, timeout, tcp_nodelay)

            soc = await conn.connect(addr, port, timeout)

            reader, writer = await asyncio.open_connection(sock=soc, limit=limit)
            return reader, writer, conn.name
        except ConnectionLostError as err:
            logger = logging.getLogger('hxs3')
            logger.info('connect %s:%d fail: %r %s', addr, port, err, proxy.name)
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
                    raise ConnectionDenied(self._err)
                connection = Hxs3Connection(proxy, self)
                try:
                    await connection.get_key(timeout, tcp_nodelay)
                except Exception as err:
                    asyncio.ensure_future(connection.close())
                    self._err = repr(err)
                    self._err_time = time.time()
                    raise ConnectionResetError(0, 'hxsocks3 get_key() failed: %r' % err) from err
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

    async def read_frame(self, timeout=30):
        try:
            fut = self.remote_writer.recv()
            frame_data = await asyncio.wait_for(fut, timeout=timeout)
            frame_data = self._cipher.decrypt(frame_data)
            self._stat_total_recv += len(frame_data)
            self._stat_recv_tp += len(frame_data)
            return frame_data
        except (ConnectionClosed, RuntimeError, InvalidTag) as err:
            raise ReadFrameError(err) from err

    async def get_key(self, timeout, tcp_nodelay):
        self.logger.debug('hxsocks3 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        ctx = None
        scheme = 'ws'
        if self.proxy.scheme == 'hxs3s':
            scheme = 'wss'
            # ctx = ssl.create_default_context()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.set_ciphers(CIPHERS)
            if 'insecure' in self.proxy.query or is_ipaddr(self.proxy.hostname):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

        if ":" in self.proxy.hostname:
            uri = '%s://[%s]:%d%s' % (scheme, self.proxy.hostname, self.proxy.port, self.proxy.parse.path)
        else:
            uri = '%s://%s:%d%s' % (scheme, self.proxy.hostname, self.proxy.port, self.proxy.parse.path)
        self.remote_writer = await websockets.client.connect(uri, ssl=ctx, compression=None,
                                                             ping_interval=None,
                                                             ping_timeout=None,
                                                             max_size=2 ** 17,
                                                             max_queue=2 ** 4,
                                                             read_limit=2 ** 16,
                                                             write_limit=2 ** 16,)
        self._socport = self.remote_writer.local_address[1]

        # prep key exchange request
        ecc = ECC(32)
        pubk = ecc.get_pub_key()
        timestamp = struct.pack('>I', int(time.time()) // 30)
        data = b''.join([bytes((len(pubk), )),
                         pubk,
                         hmac.new(psw.encode() + usn.encode(), timestamp, hashlib.sha256).digest(),
                         bytes((self.mode, )),
                         bytes(random.randint(CLIENT_AUTH_PADDING // 16, CLIENT_AUTH_PADDING))])
        data = bytes((0, )) + data

        # send key exchange request
        await self.remote_writer.send(data)

        # read server response
        fut = self.remote_writer.recv()
        data = await asyncio.wait_for(fut, timeout=timeout)

        self.key_exchange(data, usn, psw, pubk, ecc)

    async def close(self):
        if self.remote_writer:
            await self.remote_writer.close()
