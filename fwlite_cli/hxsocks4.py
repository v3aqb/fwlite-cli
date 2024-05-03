#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2017-2023 v3aqb

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
import base64
import logging
import asyncio
from asyncio import Lock

from hxcrypto import InvalidTag, AEncryptor

from fwlite_cli.parent_proxy import ParentProxy
from fwlite_cli.hxscommon import HxsConnection, HC, CTX, get_client_auth_2
from fwlite_cli.hxscommon import ConnectionLostError, ConnectionDenied, ReadFrameError


def set_logger():
    logger = logging.getLogger('hxs4')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()

CONN_MANAGER = {}  # (server, parentproxy): manager


async def hxs4_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme == 'hxs4'

    # get hxs2 connection
    for _ in range(HC.MAX_CONNECTION + 1):
        try:
            conn = await hxs4_get_connection(proxy, timeout, tcp_nodelay)

            soc = await conn.connect(addr, port, timeout)

            reader, writer = await asyncio.open_connection(sock=soc, limit=limit)
            return reader, writer, conn.name
        except ConnectionLostError as err:
            logger = logging.getLogger('hxs4')
            logger.info('connect %s:%d fail: %r %s', addr, port, err, proxy.name)
            continue
    raise ConnectionResetError(0, 'get hxs4 connection failed.')


async def hxs4_get_connection(proxy, timeout, tcp_nodelay):
    if proxy.name not in CONN_MANAGER:
        CONN_MANAGER[proxy.name] = ConnectionManager()
    conn = await CONN_MANAGER[proxy.name].get_connection(proxy, timeout, tcp_nodelay)
    return conn


class ConnectionManager:
    def __init__(self):
        self.connection_list = []
        self._lock = Lock()
        self.logger = logging.getLogger('hxs4')
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
                    connection = Hxs4Connection(proxy, self)
                    try:
                        await connection.get_key(timeout, tcp_nodelay)
                    except Exception as err:
                        asyncio.ensure_future(connection.close())
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


class Hxs4Connection(HxsConnection):
    bufsize = 65535 - 22

    def __init__(self, proxy, manager):
        super().__init__(proxy, manager)
        self.logger = logging.getLogger('hxs4')
        self.b85encode = int(self.proxy.query.get('b85encode', ['1'])[0])

    async def get_key(self, timeout, tcp_nodelay):
        self.logger.debug('hxsocks4 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        from .connection import open_connection
        self.remote_reader, self.remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True,
            limit=262144,
            tcp_nodelay=tcp_nodelay)
        self.remote_writer.transport.set_write_buffer_limits(131072)
        self._socport = self.remote_writer.get_extra_info('sockname')[1]

        # prep key exchange request
        self._pskcipher = AEncryptor(self._psk.encode(), self.method, CTX, role=1)
        data, pubk, ecc = get_client_auth_2(self._pskcipher.key_len, usn, psw, self.mode, self.b85encode)

        ct_ = self._pskcipher.encrypt(data)
        if self.b85encode:
            ct_ = base64.b85encode(ct_)

        # send key exchange request
        self.remote_writer.write(ct_)
        await self.remote_writer.drain()

        # read server response
        data = b''
        for _ in range(10):
            try:
                fut = self.remote_reader.read(self.bufsize)
                buf = await asyncio.wait_for(fut, timeout=timeout / 10)
                if not buf:
                    raise ConnectionResetError(0, 'hxs4 read server response Error, EOF')
                data += buf
                if len(data) > self._pskcipher.iv_len:
                    data_ = base64.b85decode(data) if self.b85encode else data
                    auth = self._pskcipher.decrypt(data_)
                    self.key_exchange(auth, usn, psw, pubk, ecc)
                    return
            except (InvalidTag, ValueError, asyncio.TimeoutError):
                continue
        raise ConnectionResetError(0, 'hxs4 read server response Error, timeout: %s' % timeout)

    async def _read_frame(self, timeout=30):
        try:
            frame_len = await self._rfile_read(2, timeout)
            if self.encrypt_frame_len:
                frame_len = self._flen_cipher.decrypt(frame_len)
            frame_len, = struct.unpack('>H', frame_len)
        except (OSError, asyncio.IncompleteReadError) as err:
            # destroy connection
            raise ReadFrameError(err) from err

        # read frame_data
        try:
            frame_data = await self._rfile_read(frame_len, timeout=HC.READ_FRAME_TIMEOUT)
            frame_data = self._cipher.decrypt(frame_data)
            return frame_data
        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, InvalidTag) as err:
            raise ReadFrameError(err) from err

    def send_frame_data(self, ct_):
        frame_len = struct.pack('>H', len(ct_))
        if self.encrypt_frame_len:
            frame_len = self._flen_cipher.encrypt(frame_len)
        self.remote_writer.write(frame_len + ct_)

    async def drain(self):
        try:
            await self.remote_writer.drain()
        except OSError:
            self.connection_lost = True

    def close(self):
        if self.remote_writer:
            if not self.remote_writer.is_closing():
                self.remote_writer.close()

    async def wait_closed(self):
        try:
            await self.remote_writer.wait_closed()
        except OSError:
            pass

    async def _rfile_read(self, size, timeout=None):
        if timeout:
            fut = self.remote_reader.readexactly(size)
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        return await self.remote_reader.readexactly(size)
