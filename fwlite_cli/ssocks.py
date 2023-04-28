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

from hxcrypto import BufEmptyError, InvalidTag, is_aead, Encryptor

from fwlite_cli.parent_proxy import ParentProxy

SS_SUBKEY = "ss-subkey"
SS_SUBKEY_2022 = 'shadowsocks 2022 session subkey'


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
        self.client_reader = None
        self.client_writer = None
        self.remote_reader = None
        self.remote_writer = None
        self.task = None

        self.aead = is_aead(ssmethod)
        self.crypto = Encryptor(sspassword, ssmethod, role=0)
        self.connected = False
        self.last_active = time.time()
        # if eof recieved
        self.remote_eof = False
        self.client_eof = False
        self.data_recved = False
        self._buf = b''

    async def connect(self, addr, port, timeout, limit, tcp_nodelay):
        self._address = addr
        self._port = port

        from .connection import open_connection
        self.remote_reader, self.remote_writer, _ = await open_connection(
            self.proxy.hostname,
            self.proxy.port,
            proxy=self.proxy.get_via(),
            timeout=timeout,
            tunnel=True,
            limit=131072,
            tcp_nodelay=tcp_nodelay)
        # self.remote_writer.transport.set_write_buffer_limits(262144)

        # create socket_pair
        sock_a, sock_b = socket.socketpair()
        if sys.platform == 'win32':
            sock_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client_reader, self.client_writer = await asyncio.open_connection(sock=sock_b)
        self.client_writer.transport.set_write_buffer_limits(262144)

        # start forward
        self.task = asyncio.ensure_future(self.forward())

        # return reader, writer
        reader, writer = await asyncio.open_connection(sock=sock_a, limit=limit)
        return reader, writer

    async def forward(self):

        tasks = [asyncio.create_task(self.forward_from_client()),
                 asyncio.create_task(self.forward_from_remote()),
                 ]
        await asyncio.wait(tasks)
        for writer in (self.remote_writer, self.client_writer):
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def forward_from_client(self):
        # read from client, encrypt, sent to server
        while True:
            fut = self.client_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                self.last_active = time.time()
            except asyncio.TimeoutError:
                continue
            except OSError:
                self.remote_writer.close()
                break

            if not data:
                break
            if not self.connected:
                header = b''.join([chr(3).encode(),
                                   chr(len(self._address)).encode('latin1'),
                                   self._address.encode(),
                                   struct.pack(b">H", self._port)])
                if self.crypto.ctx == SS_SUBKEY_2022:
                    padding_len = random.randint(0, 255)
                    header += struct.pack(b"!H", padding_len)
                    header += bytes(padding_len)
                self.connected = True
                self.remote_writer.write(self.crypto.encrypt(header + data))
            else:
                self.remote_writer.write(self.crypto.encrypt(data))
            try:
                await self.remote_writer.drain()
            except ConnectionError:
                break
        self.client_eof = True
        try:
            self.remote_writer.write_eof()
        except ConnectionError:
            pass

    async def _read(self):
        if self.aead:
            fut = self.remote_reader.readexactly(18)
            data = await asyncio.wait_for(fut, timeout=6)
            data = self.crypto.decrypt(data)
            _len, = struct.unpack("!H", data)
            fut = self.remote_reader.readexactly(_len + 16)
            try:
                data = await asyncio.wait_for(fut, timeout=4)
            except asyncio.TimeoutError as err:
                raise IncompleteChunk() from err
        else:
            fut = self.remote_reader.read(self.bufsize)
            data = await asyncio.wait_for(fut, timeout=6)
        return self.crypto.decrypt(data)

    async def forward_from_remote(self):
        # read from remote, decrypt, sent to client

        if self.aead:
            # read first chunk
            if self.crypto.ctx == SS_SUBKEY_2022:
                fut = self.remote_reader.readexactly(self.crypto.iv_len * 2 + 27)
            else:
                fut = self.remote_reader.readexactly(self.crypto.iv_len + 18)
            try:
                data = await asyncio.wait_for(fut, timeout=12)
                data = self.crypto.decrypt(data)
                if self.crypto.ctx == SS_SUBKEY_2022:
                    _, timestamp = struct.unpack(b'!BQ', data[:9])
                    diff = time.time() - timestamp
                    if abs(diff) > 30:
                        raise ValueError('timestamp error, diff: %.3f' % diff)
                data_len, = struct.unpack(b'!H', data[-2:])
                fut = self.remote_reader.readexactly(data_len + 16)
                data = await asyncio.wait_for(fut, timeout=4)
                data = self.crypto.decrypt(data)
                self.client_writer.write(data)
            except (asyncio.TimeoutError, InvalidTag, ValueError, asyncio.IncompleteReadError) as err:
                self.logger.error('read first chunk fail: %r', err, exc_info=False)
                self.remote_eof = True
                try:
                    self.client_writer.write_eof()
                except ConnectionError:
                    pass
                return

        while True:
            try:
                data = await self._read()
                self.last_active = time.time()
                self.data_recved = True
            except asyncio.TimeoutError:
                idle_time = time.time() - self.last_active
                if self.client_eof and idle_time > 60:
                    self.client_writer.close()
                    break
                continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, IncompleteChunk):
                self.client_writer.close()
                break

            if not data:
                break
            try:
                self.client_writer.write(data)
                await self.client_writer.drain()
            except ConnectionError:
                break
        self.remote_eof = True
        try:
            self.client_writer.write_eof()
        except ConnectionError:
            pass
