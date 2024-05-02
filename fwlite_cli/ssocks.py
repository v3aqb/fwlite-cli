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

import sys
import base64
import struct
import socket
import time
import random
import logging
import asyncio

from hxcrypto import BufEmptyError, InvalidTag, is_aead, Encryptor, SS_SUBKEY, SS_SUBKEY_2022

from fwlite_cli.parent_proxy import ParentProxy


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
    if not isinstance(proxy, ParentProxy):
        proxy = ParentProxy(proxy, proxy)
    assert proxy.scheme == 'ss'

    # connect to ss server
    context = SSConn(proxy)
    reader, writer = await context.connect(addr, port, timeout, limit, tcp_nodelay)
    return reader, writer


class SSConn:
    bufsize = 16383
    tcp_timeout = 600

    def __init__(self, proxy, ):
        self.logger = logging.getLogger('ss')
        self.proxy = proxy
        ssmethod, sspassword = self.proxy.username, self.proxy.password
        if sspassword is None:
            ssmethod, sspassword = base64.b64decode(ssmethod).decode().split(':', 1)
        ssmethod = ssmethod.lower()

        self._address = None
        self._port = 0
        self._client_reader = None
        self._client_writer = None
        self._remote_reader = None
        self._remote_writer = None
        self._task = None

        self.aead = is_aead(ssmethod)
        self._crypto = Encryptor(sspassword, ssmethod, role=0)
        self._connected = False
        self._last_active = time.time()
        # if eof recieved
        self._remote_eof = False
        self._client_eof = False
        self._data_recved = False
        self._buf = b''

    async def connect(self, addr, port, timeout, limit, tcp_nodelay):
        self._address = addr
        self._port = port

        from .connection import open_connection
        self._remote_reader, self._remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True,
            limit=131072,
            tcp_nodelay=tcp_nodelay)
        self._remote_writer.transport.set_write_buffer_limits(65536)

        # create socket_pair
        sock_a, sock_b = socket.socketpair()
        if sys.platform == 'win32':
            sock_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._client_reader, self._client_writer = await asyncio.open_connection(sock=sock_b)
        self._client_writer.transport.set_write_buffer_limits(65536)

        # start forward
        self._task = asyncio.ensure_future(self._forward())

        # return reader, writer
        reader, writer = await asyncio.open_connection(sock=sock_a, limit=limit)
        return reader, writer

    async def create_connection(self, addr, port, transport):
        self._address = addr
        self._port = port
        self._transport = transport

    async def _forward(self):

        tasks = [asyncio.create_task(self._forward_from_client()),
                 asyncio.create_task(self._forward_from_remote()),
                 ]
        await asyncio.wait(tasks)
        for writer in (self._remote_writer, self._client_writer):
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _forward_from_client(self):
        # read from client, encrypt, sent to server
        while True:
            fut = self._client_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                self._last_active = time.time()
            except asyncio.TimeoutError:
                continue
            except OSError:
                self._remote_writer.close()
                break

            if not data:
                break
            if not self._connected:
                header = b''.join([chr(3).encode(),
                                   chr(len(self._address)).encode('latin1'),
                                   self._address.encode(),
                                   struct.pack(b">H", self._port)])
                if self._crypto.ctx == SS_SUBKEY_2022:
                    padding_len = random.randint(0, 255)
                    header += struct.pack(b"!H", padding_len)
                    header += bytes(padding_len)
                self._connected = True
                self._remote_writer.write(self._crypto.encrypt(header + data))
            else:
                self._remote_writer.write(self._crypto.encrypt(data))
            try:
                await self._remote_writer.drain()
            except ConnectionError:
                break
        self._client_eof = True
        try:
            self._remote_writer.write_eof()
        except ConnectionError:
            pass

    async def _read(self):
        if self.aead:
            fut = self._remote_reader.readexactly(18)
            data = await asyncio.wait_for(fut, timeout=6)
            data = self._crypto.decrypt(data)
            _len, = struct.unpack("!H", data)
            fut = self._remote_reader.readexactly(_len + 16)
            try:
                data = await asyncio.wait_for(fut, timeout=4)
            except asyncio.TimeoutError as err:
                raise IncompleteChunk() from err
        else:
            fut = self._remote_reader.read(self.bufsize)
            data = await asyncio.wait_for(fut, timeout=6)
        return self._crypto.decrypt(data)

    async def _forward_from_remote(self):
        # read from remote, decrypt, sent to client

        if self.aead:
            # read first chunk
            if self._crypto.ctx == SS_SUBKEY_2022:
                fut = self._remote_reader.readexactly(self._crypto.iv_len * 2 + 27)
            else:
                fut = self._remote_reader.readexactly(self._crypto.iv_len + 18)
            try:
                data = await asyncio.wait_for(fut, timeout=12)
                data = self._crypto.decrypt(data)
                if self._crypto.ctx == SS_SUBKEY_2022:
                    _, timestamp = struct.unpack(b'!BQ', data[:9])
                    diff = time.time() - timestamp
                    if abs(diff) > 30:
                        raise ValueError('timestamp error, diff: %.3f' % diff)
                data_len, = struct.unpack(b'!H', data[-2:])
                fut = self._remote_reader.readexactly(data_len + 16)
                data = await asyncio.wait_for(fut, timeout=4)
                data = self._crypto.decrypt(data)
                self._client_writer.write(data)
            except (asyncio.TimeoutError, InvalidTag, ValueError, asyncio.IncompleteReadError) as err:
                self.logger.error('read first chunk fail: %r', err, exc_info=False)
                self._remote_eof = True
                try:
                    self._client_writer.write_eof()
                except ConnectionError:
                    pass
                return

        while True:
            try:
                data = await self._read()
                self._last_active = time.time()
                self._data_recved = True
            except asyncio.TimeoutError:
                idle_time = time.time() - self._last_active
                if self._client_eof and idle_time > 60:
                    self._client_writer.close()
                    break
                continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, IncompleteChunk):
                self._client_writer.close()
                break

            if not data:
                break
            try:
                self._client_writer.write(data)
                await self._client_writer.drain()
            except ConnectionError:
                break
        self._remote_eof = True
        try:
            self._client_writer.write_eof()
        except ConnectionError:
            pass
