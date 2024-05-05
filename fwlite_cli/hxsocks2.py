#!/usr/bin/env python
# coding:utf-8

# Copyright (C) 2017-2022 v3aqb

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
import logging
import asyncio
from asyncio import Lock, get_running_loop, StreamReader, StreamReaderProtocol, StreamWriter

from hxcrypto import InvalidTag, is_aead, Encryptor

from .parent_proxy import ParentProxy
from .hxscommon import HxsConnection
from .hxscommon import ConnectionLostError, ConnectionDenied, ReadFrameError
from .hxscommon import HC, get_client_auth
from .ssocks import SS_SUBKEY_2022
from .transport import FWTransport


def set_logger():
    logger = logging.getLogger('hxs2')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()

CONN_MANAGER = {}  # (server, parentproxy): manager


async def hxs2_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    # Entry Point
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme == 'hxs2'

    loop = get_running_loop()
    reader = StreamReader(limit=limit, loop=loop)
    protocol = StreamReaderProtocol(reader, loop=loop)
    # get hxs2 connection
    for _ in range(HC.MAX_CONNECTION + 1):
        try:
            conn = await hxs2_get_connection(proxy, timeout, limit, tcp_nodelay)
            transport = FWTransport(loop, protocol, conn)
            transport.set_write_buffer_limits(limit)
            await transport.connect(addr, port, timeout, tcp_nodelay)
            writer = StreamWriter(transport, protocol, reader, loop)
            return reader, writer, conn.name
        except ConnectionLostError as err:
            logger = logging.getLogger('hxs2')
            logger.info('connect %s:%d fail: %r %s', addr, port, err, proxy.name)
            continue
    raise ConnectionResetError(0, 'get hxs2 connection failed.')


async def hxs2_get_connection(proxy, timeout, limit, tcp_nodelay):
    if proxy.name not in CONN_MANAGER:
        CONN_MANAGER[proxy.name] = ConnectionManager()
    conn = await CONN_MANAGER[proxy.name].get_connection(proxy, timeout, limit, tcp_nodelay)
    return conn


class ConnectionManager:
    def __init__(self):
        self.connection_list = []
        self._lock = Lock()
        self.logger = logging.getLogger('hxs2')
        self._err = None
        self._err_time = 0

    async def get_connection(self, proxy, timeout, limit, tcp_nodelay):
        # choose / create and return a connection
        async with self._lock:
            if len(self.connection_list) < HC.MAX_CONNECTION and\
                    not [conn for conn in self.connection_list if not conn.is_busy()]:
                if self._err and time.time() - self._err_time < 6:
                    if not self.connection_list:
                        raise ConnectionDenied(self._err)
                else:
                    connection = Hxs2Connection(proxy, self, limit)
                    try:
                        await connection.get_key(timeout, tcp_nodelay)
                    except Exception as err:
                        connection.close()
                        self._err = repr(err)
                        self._err_time = time.time()
                        if not self.connection_list:
                            raise ConnectionResetError(0, 'hxsocks2 get_key() failed: %r' % err) from err
                    else:
                        self._err = None
                        self.connection_list.append(connection)
        list_ = sorted(self.connection_list, key=lambda item: item.busy())
        return list_[0]

    def remove(self, conn):
        # this connection is not accepting new streams anymore
        if conn in self.connection_list:
            self.connection_list.remove(conn)


class Hxs2Connection(HxsConnection):
    bufsize = 65535 - 22

    def __init__(self, proxy, manager, limit):
        super().__init__(proxy, manager, limit)
        self.logger = logging.getLogger('hxs2')

    async def get_key(self, timeout, tcp_nodelay):
        self.logger.debug('hxsocks2 getKey')
        usn, psw = (self.proxy.username, self.proxy.password)
        self.logger.info('%s connect to server', self.name)
        from .connection import open_connection
        self._remote_reader, self._remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True,
            limit=self._limit * 2,
            tcp_nodelay=tcp_nodelay)
        self._socport = self._remote_writer.get_extra_info('sockname')[1]

        # prep key exchange request
        self._pskcipher = Encryptor(self._psk, self.method, role=0)

        data, pubk, ecc = get_client_auth(self._pskcipher.key_len, usn, psw, self.mode)

        data = bytes((20, )) + struct.pack('>H', len(data)) + data

        ct_ = self._pskcipher.encrypt(data)

        # send key exchange request
        self._remote_writer.write(ct_)
        await self._remote_writer.drain()

        # read server response
        if is_aead(self.method):
            if self._pskcipher.ctx == SS_SUBKEY_2022:
                ct_len = await self._rfile_read(self._pskcipher.iv_len * 2 + 27, timeout)
            else:
                ct_len = await self._rfile_read(self._pskcipher.iv_len + 18, timeout)
            ct_len = self._pskcipher.decrypt(ct_len)[-2:]
            ct_len, = struct.unpack('!H', ct_len)
            ct_ = await self._rfile_read(ct_len + 16)
            ct_ = self._pskcipher.decrypt(ct_)
            data = ct_[2:]  # first 2 bytes is data length
        else:
            resp_len = await self._rfile_read(self._pskcipher.iv_len + 2, timeout)
            resp_len = self._pskcipher.decrypt(resp_len)
            resp_len, = struct.unpack('>H', resp_len)
            data = await self._rfile_read(resp_len)
            data = self._pskcipher.decrypt(data)

        self.key_exchange(data, usn, psw, pubk, ecc)

    async def _read_frame(self, timeout=30):
        try:
            frame_len = await self._rfile_read(2, timeout)
            if self.encrypt_frame_len:
                frame_len = self._flen_cipher.decrypt(frame_len)
            frame_len, = struct.unpack('>H', frame_len)
        except (ConnectionError, asyncio.IncompleteReadError) as err:
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
        self._remote_writer.write(frame_len + ct_)

    async def drain(self):
        await self._remote_writer.drain()

    def close(self):
        if self._remote_writer:
            if not self._remote_writer.is_closing():
                self._remote_writer.close()

    async def wait_closed(self):
        try:
            await self._remote_writer.wait_closed()
        except OSError:
            pass

    async def _rfile_read(self, size, timeout=None):
        if timeout:
            fut = self._remote_reader.readexactly(size)
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        return await self._remote_reader.readexactly(size)

    def get_conn_buffer_size(self):
        return self._remote_writer.transport.get_write_buffer_size()
