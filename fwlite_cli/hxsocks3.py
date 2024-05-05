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


import time
import ssl
import logging
import asyncio
from ipaddress import ip_address

from asyncio import get_running_loop, StreamReader, StreamReaderProtocol, StreamWriter

import websockets.client
from websockets.exceptions import ConnectionClosed

from hxcrypto import InvalidTag

from .parent_proxy import ParentProxy
from .hxscommon import HxsConnection, HC, get_client_auth
from .hxscommon import ConnectionLostError, ConnectionDenied, ReadFrameError
from .transport import FWTransport

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
CIPHERS = ':'.join(CIPHERS_A)


def set_logger():
    logger = logging.getLogger('hxs3')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


CONN_MANAGER = {}  # (server, parentproxy): manager


async def hxs3_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme in ('hxs3', 'hxs3s')

    loop = get_running_loop()
    reader = StreamReader(limit=limit, loop=loop)
    protocol = StreamReaderProtocol(reader, loop=loop)
    # get hxs3 connection
    for _ in range(HC.MAX_CONNECTION + 1):
        try:
            conn = await hxs3_get_connection(proxy, timeout, tcp_nodelay)
            transport = FWTransport(loop, protocol, conn)
            transport.set_write_buffer_limits(limit)
            await transport.connect(addr, port, timeout, tcp_nodelay)
            writer = StreamWriter(transport, protocol, reader, loop)
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
            if len(self.connection_list) < HC.MAX_CONNECTION and\
                    not [conn for conn in self.connection_list if not conn.is_busy()]:
                if self._err and time.time() - self._err_time < 6:
                    if not self.connection_list:
                        raise ConnectionDenied(self._err)
                else:
                    connection = Hxs3Connection(proxy, self)
                    try:
                        await connection.get_key(timeout, tcp_nodelay)
                    except Exception as err:
                        asyncio.ensure_future(connection.wait_closed())
                        self._err = repr(err)
                        self._err_time = time.time()
                        if not self.connection_list:
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

    def __init__(self, proxy, manager, limit):
        super().__init__(proxy, manager, limit)
        self.logger = logging.getLogger('hxs3')
        self._sendq = asyncio.Queue()
        self._sending = False
        self._wbuffer_size = 0

    async def get_key(self, timeout, tcp_nodelay):
        self.logger.debug('hxsocks3 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        ctx = None
        scheme = 'ws'
        hostname = self.proxy.hostname
        if self.proxy.scheme == 'hxs3s':
            scheme = 'wss'
            # ctx = ssl.create_default_context()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # ctx.set_alpn_protocols(["http/1.1"])
            # ctx.set_ciphers(CIPHERS)
            if 'insecure' in self.proxy.query or is_ipaddr(self.proxy.hostname):
                hostname = self.proxy.query.get('host', [self.proxy.hostname, ])[0]
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        else:
            hostname = None

        if ":" in self.proxy.hostname:
            url = '%s://[%s]:%d%s' % (scheme, self.proxy.hostname, self.proxy.port, self.proxy.parse.path)
        else:
            url = '%s://%s:%d%s' % (scheme, self.proxy.hostname, self.proxy.port, self.proxy.parse.path)

        self._remote_writer = await websockets.client.connect(
            url, ssl=ctx, compression=None,
            server_hostname=hostname,
            ping_interval=None,
            ping_timeout=None,
            max_size=self._limit * 2,
            max_queue=2,
            read_limit=self._limit * 2,
            write_limit=self._limit * 2,
            tcp_nodelay=tcp_nodelay)
        self._socport = self._remote_writer.local_address[1]

        # prep key exchange request
        data, pubk, ecc = get_client_auth(32, usn, psw, self.mode)

        data = bytes((0, )) + data

        # send key exchange request
        await self._remote_writer.send(data)

        # read server response
        fut = self._remote_writer.recv()
        data = await asyncio.wait_for(fut, timeout=timeout)

        self.key_exchange(data, usn, psw, pubk, ecc)

    async def _read_frame(self, timeout=30):
        try:
            fut = self._remote_writer.recv()
            frame_data = await asyncio.wait_for(fut, timeout=timeout)
            frame_data = self._cipher.decrypt(frame_data)
            return frame_data
        except (ConnectionClosed, RuntimeError, InvalidTag) as err:
            raise ReadFrameError(err) from err

    def send_frame_data(self, ct_):
        self._sendq.put_nowait(ct_)
        self._wbuffer_size += len(ct_)
        asyncio.ensure_future(self._maybe_start_sending())

    async def _maybe_start_sending(self):
        if self._sending:
            return
        self._sending = True
        while True:
            try:
                ct_ = self._sendq.get_nowait()
            except asyncio.QueueEmpty:
                return
            if self.connection_lost:
                self._sendq.task_done()
                continue
            try:
                await self._remote_writer.send(ct_)
            except ConnectionClosed:
                self.connection_lost = True
            finally:
                self._sendq.task_done()
        self._sending = False

    async def drain(self):
        if self.connection_lost:
            raise ConnectionError(0, 'ConnectionClosed')
        await self._sendq.join()
        self._wbuffer_size = 0

    def close(self):
        return

    async def wait_closed(self):
        if self._remote_writer:
            await self._remote_writer.close()

    def get_conn_buffer_size(self):
        return self._wbuffer_size
