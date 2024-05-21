#!/usr/bin/env python
# coding:utf-8

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

from builtins import chr

import base64
import struct
import time
import random
import logging
import asyncio
from asyncio import get_running_loop, StreamReader, StreamReaderProtocol, StreamWriter

from hxcrypto import BufEmptyError, InvalidTag, is_aead, Encryptor, SS_SUBKEY_2022


def set_logger():
    logger = logging.getLogger('ss')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class IncompleteChunk(Exception):
    pass


async def ss_connect(proxy, timeout, addr, port, limit, tcp_nodelay):
    loop = get_running_loop()
    reader = StreamReader(limit=limit, loop=loop)
    protocol = StreamReaderProtocol(reader, loop=loop)
    transport = await ss_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay)
    # protocol is for Reader, transport is for Writer
    writer = StreamWriter(transport, protocol, reader, loop)
    return reader, writer


async def ss_create_connection(protocol, addr, port, proxy, timeout, limit, tcp_nodelay):
    conn = SSConn(proxy, limit)
    transport = await conn.create_connection(protocol, addr, port, timeout, tcp_nodelay)
    return transport


class SSConn:
    bufsize = 16383
    tcp_timeout = 600

    def __init__(self, proxy, limit):
        self.logger = logging.getLogger('ss')
        self.proxy = proxy
        self._limit = limit
        self._loop = None
        ssmethod, sspassword = self.proxy.username, self.proxy.password
        if sspassword is None:
            ssmethod, sspassword = base64.b64decode(ssmethod).decode().split(':', 1)
        ssmethod = ssmethod.lower()

        self._address = None
        self._port = 0
        self._c_protocol = None
        self._remote_reader = None
        self._remote_writer = None
        self._task = None

        self.aead = is_aead(ssmethod)
        self.__crypto = Encryptor(sspassword, ssmethod, role=0)
        self._connected = False
        self._last_active = time.monotonic()
        self._closing = False
        # if eof recieved
        self._remote_eof = False
        self._client_eof = False
        self._data_recved = False
        self._buf = b''
        self._reading = asyncio.Event()
        self._reading.set()

    async def _read(self):
        if self.aead:
            fut = self._remote_reader.readexactly(18)
            data = await asyncio.wait_for(fut, timeout=6)
            data = self.__crypto.decrypt(data)
            _len, = struct.unpack("!H", data)
            fut = self._remote_reader.readexactly(_len + 16)
            try:
                data = await asyncio.wait_for(fut, timeout=4)
            except asyncio.TimeoutError as err:
                raise IncompleteChunk() from err
        else:
            fut = self._remote_reader.read(self.bufsize)
            data = await asyncio.wait_for(fut, timeout=6)
        return self.__crypto.decrypt(data)

    async def _forward_from_remote(self):
        # read from remote, decrypt, sent to client
        if self.aead:
            # read first chunk
            if self.__crypto.ctx == SS_SUBKEY_2022:
                fut = self._remote_reader.readexactly(self.__crypto.iv_len * 2 + 27)
            else:
                fut = self._remote_reader.readexactly(self.__crypto.iv_len + 18)
            try:
                data = await asyncio.wait_for(fut, timeout=12)
                data = self.__crypto.decrypt(data)
                if self.__crypto.ctx == SS_SUBKEY_2022:
                    _, timestamp = struct.unpack(b'!BQ', data[:9])
                    diff = time.time() - timestamp
                    if abs(diff) > 30:
                        raise ValueError('timestamp error, diff: %ds' % diff)
                data_len, = struct.unpack(b'!H', data[-2:])
                fut = self._remote_reader.readexactly(data_len + 16)
                data = await asyncio.wait_for(fut, timeout=4)
                data = self.__crypto.decrypt(data)
                self._c_protocol.data_received(data)
                await self.drain()
            except (asyncio.TimeoutError, InvalidTag, ValueError, asyncio.IncompleteReadError, ConnectionError) as err:
                self.logger.error('read first chunk fail: %r', err, exc_info=False)
                self._remote_eof = True
                self.close(err)
                return

        while True:
            try:
                data = await self._read()
                self._last_active = time.monotonic()
                self._data_recved = True
            except asyncio.TimeoutError as err:
                idle_time = time.time() - self._last_active
                if self._client_eof and idle_time > 60:
                    self.close(err)
                    break
                continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, IncompleteChunk, ConnectionError) as err:
                self.close(err)
                break

            if not data:
                break
            try:
                self._c_protocol.data_received(data)
                await self.drain()
            except ConnectionError as err:
                self._remote_eof = True
                self.close(err)
                return
        self._remote_eof = True
        try:
            self._c_protocol.eof_received()
        except ConnectionError:
            pass

    async def create_connection(self, protocol, addr, port, timeout, tcp_nodelay):
        self._address = addr
        self._port = port
        self._loop = asyncio.get_running_loop()
        from .connection import open_connection
        self._remote_reader, self._remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True,
            limit=self._limit,
            tcp_nodelay=tcp_nodelay)
        asyncio.ensure_future(self._forward_from_remote())
        self._c_protocol = protocol
        return self

    def close(self, exc=None):
        if not self._closing:
            self._closing = True
            self._remote_writer.close()
            self._reading.set()
            self._loop.call_soon(self._call_connection_lost, exc)

    def is_closing(self):
        return self._closing

    def write(self, data):
        """encrypt, sent to server"""
        self._last_active = time.monotonic()
        if not self._connected:
            header = b''.join([chr(3).encode(),
                               chr(len(self._address)).encode('latin1'),
                               self._address.encode(),
                               struct.pack(b">H", self._port)])
            if self.__crypto.ctx == SS_SUBKEY_2022:
                padding_len = random.randint(0, 255)
                header += struct.pack(b"!H", padding_len)
                header += bytes(padding_len)
            self._connected = True
            self._remote_writer.write(self.__crypto.encrypt(header + data))
        else:
            self._remote_writer.write(self.__crypto.encrypt(data))

    def set_write_buffer_size(self, high=None, low=None):
        return self._remote_writer.transport.set_write_buffer_size(high, low)

    def get_write_buffer_size(self):
        return self._remote_writer.transport.get_write_buffer_size()

    def write_eof(self):
        if self._client_eof:
            return
        self._client_eof = True
        self._remote_writer.write_eof()

    def pause_reading(self):
        self._reading.clear()

    def resume_reading(self):
        self._reading.set()

    async def drain(self):
        if self.is_closing():
            raise ConnectionResetError
        await self._reading.wait()

    def _call_connection_lost(self, exc):
        try:
            if self._c_protocol:
                self._c_protocol.connection_lost(exc)
        finally:
            self._remote_writer.close()
