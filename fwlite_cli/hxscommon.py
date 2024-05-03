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


import sys
import os
import struct
import socket
import time
import hmac
import math
import io
import hashlib
import random
import asyncio
from asyncio import Event, Lock, Semaphore

from hxcrypto import ECC, AEncryptor, InvalidSignature, method_supported
from hxcrypto.encrypt import EncryptorStream

from fwlite_cli.parent_proxy import ParentProxy
from fwlite_cli.hxs_udp2 import on_dgram_recv

DEFAULT_METHOD = 'chacha20-ietf-poly1305'  # for hxsocks2 handshake
FAST_METHOD = 'chacha20-ietf-poly1305'
DEFAULT_MODE = 0
DEFAULT_HASH = 'sha256'
CTX = b'hxsocks2'

OPEN = 0
EOF_SENT = 1  # SENT END_STREAM
EOF_RECV = 2  # RECV END_STREAM
CLOSED = 3

KNOWN_HOSTS = {}
RECV = 0
SEND = 1

DATA = 0
HEADERS = 1
# PRIORITY = 2
RST_STREAM = 3
SETTINGS = 4
# PUSH_PROMISE = 5
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8
# CONTINUATION = 9
UDP_DGRAM2 = 21

PONG = 1
END_STREAM_FLAG = 1
FLOW_CONTROL = 128

# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        with open('./.hxs_known_hosts/' + fname, 'rb') as f:
            KNOWN_HOSTS[fname[:-5]] = f.read()

CLIENT_ID = os.urandom(8)


class ConnectionLostError(Exception):
    pass


class ConnectionDenied(Exception):
    def __init__(self, err):
        super().__init__()
        self.err = err
        self.repr = 'HxsConnectionDenied: ' + err

    def __repr__(self):
        return self.repr


class ReadFrameError(Exception):
    def __init__(self, err):
        super().__init__()
        self.err = err


def get_client_auth(key_len, usn, psw, mode):
    ecc = ECC(key_len)
    pubk = ecc.get_pub_key()
    timestamp = struct.pack('>I', int(time.time()) // 30)
    data = b''.join([bytes((len(pubk), )),
                     pubk,
                     hmac.new(psw.encode() + usn.encode(), timestamp, hashlib.sha256).digest(),
                     bytes((mode, )),
                     ])
    data += bytes(random.randint(HC.CLIENT_AUTH_PADDING // 2, HC.CLIENT_AUTH_PADDING))
    return data, pubk, ecc


def get_client_auth_2(key_len, usn, psw, mode, b85encode):
    ecc = ECC(key_len)
    pubk = ecc.get_pub_key()
    timestamp = struct.pack('>I', int(time.time()) // 30)
    data = b''.join([bytes((len(pubk), )),  # 91, 120, 158, 44, 68 for curve P256R1, P384R1, P521R1, x25519, x448
                     pubk,
                     hmac.new(psw.encode() + usn.encode(), timestamp, hashlib.sha256).digest(),
                     bytes((mode, )),
                     ])
    # keylen = 256, len(data) = 192 (158 + 32 + 2)
    # keylen = 192, len(data) = 154
    # keylen = 128, len(data) = 125
    # x25519, len(data) = 78
    # x448, len(data) = 102
    if b85encode:
        padding_len_low = math.ceil((HC.CLIENT_AUTH_PADDING // 2 - len(data) * 0.25 - 8) * 0.8)
        padding_len_high = math.ceil((HC.CLIENT_AUTH_PADDING - len(data) * 0.25 - 8) * 0.8)
    else:
        padding_len_low = HC.CLIENT_AUTH_PADDING // 2
        padding_len_high = HC.CLIENT_AUTH_PADDING
    data += bytes(random.randint(max(padding_len_low, 0), max(padding_len_high, 0)))
    return data, pubk, ecc


class HC:
    MAX_STREAM_ID = 32767
    MAX_CONNECTION = 2
    CLIENT_WRITE_BUFFER = 131072
    CONNECTING_LIMIT = 3

    READ_FRAME_TIMEOUT = 8
    PING_TIMEOUT = 8
    IDLE_TIMEOUT = 300
    PING_INTV = 3
    PING_INTV_2 = 20

    CLIENT_AUTH_PADDING = 256
    HEADER_SIZE = 256
    PING_SIZE = 256
    PONG_SIZE = 256
    PING_FREQ = 0.2
    FRAME_SIZE_LIMIT = 16383 - 22
    FRAME_SPLIT_FREQ = 0.3
    WINDOW_SIZE = (4096, 65536, 1048576 * 4)


class ForwardContext:
    def __init__(self, conn, stream_id, host, send_w, recv_w):
        self.host = host  # (host, port)
        self.drain_lock = asyncio.Lock()
        self.last_active = time.monotonic()
        self.resume_reading = asyncio.Event()
        self.resume_reading.set()

        # eof recieved
        self.stream_status = OPEN
        # traffic, for log
        self.traffic_from_client = 0
        self.traffic_from_remote = 0
        # traffic, for flow control
        self.sent_rate = 0
        self.sent_rate_max = 0
        self.sent_counter = 0
        self.recv_rate = 0
        self.recv_rate_max = 0
        self.recv_counter = 0

        self._monitor_task = None

        self._conn = conn
        self._stream_id = stream_id
        self.fc_enable = bool(send_w)
        if send_w or stream_id == 0:
            self._monitor_task = asyncio.ensure_future(self.monitor())
        self.send_w = send_w
        self._lock = asyncio.Lock()
        self._window_open = asyncio.Event()
        self._window_open.set()
        self.recv_w = recv_w
        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        self._recv_w_counter = 0

    async def acquire(self, size):
        async with self._lock:
            await self._window_open.wait()
            self.traffic_from_client += size
            self.sent_counter += size
            self.last_active = time.monotonic()
            if self.fc_enable:
                self.send_w -= size
                if self.send_w <= 0:
                    self._window_open.clear()

    def data_recv(self, size):
        self.traffic_from_remote += size
        self.recv_counter += size
        self.last_active = time.monotonic()
        if self.fc_enable:
            self._recv_w_counter += size
            # update window later
            if self._recv_w_counter > self.recv_w // 2:
                w_counter = self._recv_w_counter
                self._recv_w_counter = 0
                payload = struct.pack('>I', w_counter)
                payload += bytes(random.randint(self._conn.HEADER_SIZE // 4 - 4, self._conn.HEADER_SIZE - 4))
                asyncio.ensure_future(self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload))

    def enable_fc(self, send_w, recv_w):
        self.fc_enable = bool(send_w)
        self.send_w = send_w
        self.recv_w = recv_w
        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        if not self._monitor_task:
            self._monitor_task = asyncio.ensure_future(self.monitor())

    def new_recv_window(self, new_window):
        # change recv window
        new_window = int(new_window)
        if new_window < self._conn.WINDOW_SIZE[0]:
            new_window = self._conn.WINDOW_SIZE[0]
        if new_window > self._conn.WINDOW_SIZE[2]:
            new_window = self._conn.WINDOW_SIZE[2]
        old_size = self.recv_w
        self.recv_w = new_window
        self._recv_w_counter += new_window - old_size
        if self._recv_w_counter > self.recv_w // 2:
            w_counter = self._recv_w_counter
            self._recv_w_counter = 0
            payload = struct.pack('>I', w_counter)
            payload += bytes(random.randint(self._conn.HEADER_SIZE // 4 - 4, self._conn.HEADER_SIZE - 4))
            asyncio.ensure_future(self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload))
        self._conn.logger.debug('%s: update window form %s to %s', self._conn.name, old_size, self.recv_w)

    def reduce_window(self, rtt):
        if self.fc_enable:
            if self.recv_rate < self._conn.WINDOW_SIZE[1]:
                return
            self._recv_w_max = self.recv_w
            new_window = self.recv_rate * rtt * 0.75
            new_window = max(new_window, self.recv_w * 0.75)
            self.new_recv_window(new_window)

    def increase_window(self, rtt):
        if self.fc_enable:
            if self.recv_rate * rtt * 2.7 < self.recv_w:
                return
            self._recv_w_min = self.recv_w
            if self._recv_w_max > self.recv_w:
                new_window = (self.recv_w + self._recv_w_max) // 2
                new_window = max(new_window, self.recv_w + self._conn.WINDOW_SIZE[0])
                self.new_recv_window(new_window)
            else:
                new_window = self.recv_rate * rtt * 2.7
                new_window = min(new_window, self.recv_w * 1.25)
                self.new_recv_window(new_window)

    def window_update(self, size):
        self.send_w += size
        if self.send_w > 0:
            self._window_open.set()

    async def monitor(self):
        while self.stream_status is OPEN:
            await asyncio.sleep(1)
            self.sent_rate_max = max(self.sent_rate_max, self.sent_counter)
            self.sent_rate = 0.2 * self.sent_counter + self.sent_rate * 0.8
            self.sent_counter = 0
            self.recv_rate_max = max(self.recv_rate_max, self.recv_counter)
            self.recv_rate = 0.2 * self.recv_counter + self.recv_rate * 0.8
            self.recv_counter = 0


class HxsConnection(HC):
    bufsize = 65535 - 22

    def __init__(self, proxy, manager):
        if not isinstance(proxy, ParentProxy):
            proxy = ParentProxy(proxy, proxy)
        self.logger = None
        self.proxy = proxy
        self.name = self.proxy.name
        self._manager = manager
        self.connected = 0
        self.connection_lost = False
        self.udp_event = None

        self._psk = self.proxy.query.get('PSK', [''])[0]
        self.method = self.proxy.query.get('method', [DEFAULT_METHOD])[0].lower()  # for handshake
        default_mode = DEFAULT_MODE
        if self.proxy.scheme == 'hxs4':
            default_mode |= 2
        self.mode = int(self.proxy.query.get('mode', [default_mode])[0])
        if self.mode & 2 and 'rc4' not in method_supported:
            self.mode &= 0b11111101
        if self.method == 'rc4-md5':
            self.mode |= 1
        self._mode = 0
        self.hash_algo = self.proxy.query.get('hash', [DEFAULT_HASH])[0].upper()
        self.encrypt_frame_len = False
        self._flen_cipher = None

        self.remote_reader = None
        self.remote_writer = None
        self._socport = None

        self._pskcipher = None
        self._cipher = None
        self._next_stream_id = 1
        self._settings_async_drain = False

        self._client_writer = {}
        self._remote_connected_event = {}
        self._stream_ctx = {}
        self._stream_ctx[0] = ForwardContext(conn=self, stream_id=0, host=('', 0), send_w=0, recv_w=0)
        self._stream_task = {}
        self._last_recv = time.monotonic()
        self._last_send = time.monotonic()
        self._last_ping = 0
        self._last_ping_log = 0
        self._ping_id = None
        self._ping_time = 0
        self._pinging = 0
        self._ponging = 0
        self._connection_task = None
        self._connection_stat = None
        self._setting_sent = False

        self._buffer_size_ewma = 0
        self._rtt = 0.5
        self._rtt_ewma = 1

        self._stat_total_recv = 1
        self._stat_total_sent = 1

        self._lock = Lock()
        self._connecting_lock = Semaphore(self.CONNECTING_LIMIT)

    async def connect(self, addr, port, timeout=3):
        self.logger.debug('hxsocks send connect request')
        async with self._connecting_lock:
            if self.connection_lost:
                self._manager.remove(self)
                raise ConnectionLostError(0, 'hxs connection lost')
            if not self.connected:
                self._manager.remove(self)
                raise ConnectionResetError(0, 'hxs not connected.')
            # send connect request
            payload = b''.join([bytes((len(addr), )),
                                addr.encode(),
                                struct.pack('>H', port),
                                bytes(random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE)),
                                ])
            stream_id = self._next_stream_id
            self._next_stream_id += 1
            if self._next_stream_id > self.MAX_STREAM_ID:
                self.logger.error('MAX_STREAM_ID reached')
                self._manager.remove(self)

            self._stream_ctx[stream_id] = ForwardContext(self, stream_id, (addr, port), 0, 0)
            await self.send_frame(HEADERS, OPEN, stream_id, payload)
            # asyncio.ensure_future(self.send_ping_sequence())
            # self._ponging = max(self._ponging, 4)

            # wait for server response
            event = Event()
            self._remote_connected_event[stream_id] = event

            # await event.wait()
            fut = event.wait()
            try:
                await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                self.logger.error('%s connect %s timeout %ds',
                                  self.name, f'{addr}:{port}', timeout)
                del self._remote_connected_event[stream_id]
                asyncio.ensure_future(self.send_ping())
                raise

        del self._remote_connected_event[stream_id]

        if self._stream_ctx[stream_id].stream_status == OPEN:
            socketpair_a, socketpair_b = socket.socketpair()
            if sys.platform == 'win32':
                socketpair_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                socketpair_b.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            reader, writer = await asyncio.open_connection(sock=socketpair_b, limit=131072)
            writer.transport.set_write_buffer_limits(self.CLIENT_WRITE_BUFFER)

            self._client_writer[stream_id] = writer
            self._stream_ctx[stream_id].last_active = time.monotonic()
            # start forwarding
            self._stream_task[stream_id] = asyncio.ensure_future(self.read_from_client(stream_id, reader))
            return socketpair_a
        if self.connection_lost:
            raise ConnectionLostError(0, 'hxs connection lost after request sent')
        raise ConnectionResetError(0, 'remote connect to %s:%d failed.' % (addr, port))

    async def read_from_client(self, stream_id, client_reader):
        self.logger.debug('start read from client')

        count = 0
        while not self.connection_lost:
            await self._stream_ctx[stream_id].resume_reading.wait()
            fut = client_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                self._stream_ctx[stream_id].last_active = time.monotonic()
            except asyncio.TimeoutError:
                continue
            except ConnectionError:
                self.close_stream(stream_id)
                return

            if not data:
                # close stream(LOCAL)
                self.write_eof(stream_id)
                break

            if self._stream_ctx[stream_id].stream_status & EOF_SENT:
                self.logger.error('data recv from client, while stream EOF_SENT!')
                self.close_stream(stream_id)
                return
            if count < 5:
                await self.send_data_frame(stream_id, data, more_padding=True)
                count += 1
            else:
                await self.send_data_frame(stream_id, data)
        while time.monotonic() - self._stream_ctx[stream_id].last_active < 12:
            await asyncio.sleep(6)
        self.close_stream(stream_id)

    async def send_frame(self, type_, flags, stream_id, payload=None):
        if self.connection_lost:
            self.logger.debug('send_frame: connection closed. %s', self.name)
            return
        if not self._setting_sent:
            self._setting_sent = True
            payload = struct.pack('>I', self.WINDOW_SIZE[1])
            payload += bytes(random.randint(self.HEADER_SIZE // 4 - 4, self.HEADER_SIZE - 4))
            await self.send_frame(SETTINGS, 0, 1 | FLOW_CONTROL, payload)
        if type_ != PING:
            self._last_send = time.monotonic()
        elif flags == 0:
            self._last_ping = time.monotonic()

        if not payload:
            payload = bytes(random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE))

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct_ = self._cipher.encrypt(data)

        self.logger.debug('send_frame type: %d, stream_id: %d, size: %d %s', type_, stream_id, len(ct_), self.name)
        async with self._lock:
            await self.send_frame_data(ct_)
            self._stat_total_sent += len(ct_)

    async def send_ping(self, size=0):
        if self._ping_time:
            await self.send_pong(0, size)
            return
        if not size:
            size = self.PING_SIZE
        self._ping_id = random.randint(1, 32767)
        self._ping_time = time.monotonic()
        await self.send_frame(PING, 0, self._ping_id, bytes(random.randint(size // 4, size)))

    async def send_ping_sequence(self):
        count = random.randint(3, 8)
        if self._pinging:
            self._pinging = max(self._pinging, count)
            return
        self._pinging = count
        while self._pinging:
            await asyncio.sleep(random.random() * 0.2)
            if self._ping_time:
                continue
            await self.send_ping(self.PONG_SIZE)
            self._pinging -= 1

    async def send_pong(self, sid=0, size=0):
        if not size:
            size = self.PONG_SIZE
        await self.send_frame(PING, PONG, sid, bytes(random.randint(size // 4, size)))

    async def send_one_data_frame(self, stream_id, data, more_padding=False):
        if self._stream_ctx[stream_id].stream_status & EOF_SENT:
            return
        await self._stream_ctx[stream_id].acquire(len(data))
        await self._stream_ctx[0].acquire(len(data))
        payload = struct.pack('>H', len(data)) + data
        diff = self.FRAME_SIZE_LIMIT - len(data)
        if 0 <= diff < self.FRAME_SIZE_LIMIT * 0.05:
            padding = bytes(diff)
        elif self.bufsize - len(data) < 255:
            padding = bytes(self.bufsize - len(data))
        else:
            diff = 1024 - len(data)
            if diff > 0 and more_padding:
                padding_len = random.randint(max(diff - 100, diff, 0), diff + 512)
            else:
                padding_len = random.randint(8, 64)
            padding = bytes(padding_len)
        payload += padding
        await self.send_frame(DATA, 0, stream_id, payload)

    async def send_data_frame(self, stream_id, data, more_padding=False):
        data_len = len(data)
        if data_len > self.FRAME_SIZE_LIMIT and random.random() < self.FRAME_SPLIT_FREQ:
            data = io.BytesIO(data)
            data_ = data.read(random.randint(64, self.FRAME_SIZE_LIMIT))
            while data_:
                await self.send_one_data_frame(stream_id, data_)
                if random.random() < self.PING_FREQ:
                    await self.send_ping(1024)
                data_ = data.read(random.randint(64, self.FRAME_SIZE_LIMIT))
                await asyncio.sleep(0)
        else:
            await self.send_one_data_frame(stream_id, data, more_padding)
        try:
            buffer_size = self.remote_writer.transport.get_write_buffer_size()
            self._buffer_size_ewma = self._buffer_size_ewma * 0.87 + buffer_size * 0.13
        except AttributeError:
            pass

    async def read_from_connection(self):
        self.logger.debug('start read from connection')
        while not self.connection_lost:
            try:
                # read frame
                timeout = self.PING_TIMEOUT if self._ping_time else 30
                try:
                    frame_data = await self.read_frame(timeout)
                except ReadFrameError as err:
                    # destroy connection
                    if not self.connection_lost:
                        self.logger.error('read frame error: %r', err.err)
                    break
                except asyncio.TimeoutError:
                    self.logger.error('read frame error: TimeoutError')
                    continue
                # parse chunk_data
                # +------+-------------------+----------+
                # | type | flags | stream_id | payload  |
                # +------+-------------------+----------+
                # |  1   |   1   |     2     | Variable |
                # +------+-------------------+----------+

                header, payload = frame_data[:4], frame_data[4:]
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
                payload = io.BytesIO(payload)
                self.logger.debug('recv frame_type: %s, stream_id: %s, size: %s %s',
                                  frame_type, stream_id, len(frame_data), self.name)

                if frame_type in (DATA, HEADERS, RST_STREAM, UDP_DGRAM2):
                    self._last_recv = time.monotonic()
                    if self._ponging:
                        if random.random() < 0.8:
                            await self.send_pong()
                            self._ponging -= 1
                    elif random.random() < self.PING_FREQ:
                        await self.send_pong()

                if frame_type == DATA:  # 0
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    self._stream_ctx[0].data_recv(len(data))
                    self._stream_ctx[stream_id].data_recv(len(data))

                    # first 2 bytes of payload indicates data_len, the rest would be padding
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('len(data) != data_len')
                        break

                    # sent data to stream
                    for _ in range(5):
                        if stream_id not in self._client_writer:
                            await asyncio.sleep(0)

                    if self._stream_ctx[stream_id].stream_status & EOF_RECV:
                        # from server send buffer
                        self.logger.debug('DATA recv Stream CLOSED, status: %s',
                                          self._stream_ctx[stream_id].stream_status)
                        continue

                    try:
                        self._stream_ctx[stream_id].last_active = time.monotonic()
                        self._client_writer[stream_id].write(data)
                        await self.client_writer_drain(stream_id)
                    except (OSError, KeyError) as err:
                        self.logger.error('send data to stream fail. %r', err)
                        # client error, reset stream
                        self.close_stream(stream_id)
                elif frame_type == HEADERS:  # 1
                    if frame_flags == END_STREAM_FLAG:
                        self._stream_ctx[stream_id].stream_status |= EOF_RECV
                        if stream_id in self._client_writer:
                            try:
                                self._client_writer[stream_id].write_eof()
                            except OSError:
                                self._stream_ctx[stream_id].stream_status = CLOSED
                        if self._stream_ctx[stream_id].stream_status == CLOSED:
                            self.close_stream(stream_id)
                    else:
                        if stream_id in self._remote_connected_event:
                            self._stream_ctx[stream_id].stream_status = OPEN
                            self._remote_connected_event[stream_id].set()
                        else:
                            addr = '%s:%s' % self._stream_ctx[stream_id].host
                            self.logger.info('%s stream open, client closed, %s', self.name, addr)
                            self._stream_ctx[stream_id].stream_status = CLOSED
                            await self.send_frame(RST_STREAM, 0, stream_id)
                elif frame_type == RST_STREAM:  # 3
                    self._stream_ctx[stream_id].stream_status = CLOSED
                    if stream_id in self._remote_connected_event:
                        self._remote_connected_event[stream_id].set()
                    self.close_stream(stream_id)
                elif frame_type == SETTINGS:
                    if stream_id & 1:
                        self._settings_async_drain = True
                    if stream_id & FLOW_CONTROL:
                        send_w = struct.unpack('>I', payload.read(4))[0]
                        self.logger.info(f'send_w: {send_w}')
                        self._stream_ctx[0].enable_fc(send_w, self.WINDOW_SIZE[1])
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        await self.send_pong(stream_id, self.PING_SIZE)
                    elif self._ping_time and self._ping_id == stream_id:
                        resp_time = time.monotonic() - self._ping_time
                        self._rtt = min(self._rtt, resp_time)
                        self._rtt_ewma = resp_time * 0.2 + self._rtt_ewma * 0.8
                        self._ping_time = 0
                        if resp_time < 1:
                            self.proxy.log(None, resp_time)
                        if time.monotonic() - self._last_ping_log > 60:
                            self._last_ping_log = time.monotonic()
                            self.logger.info('%s response time %.3fs',
                                             self.name, resp_time)
                            self.print_status()
                        if max(self._rtt_ewma, resp_time) < self._rtt * 1.5:
                            self._stream_ctx[0].increase_window(self._rtt)
                        if resp_time > self._rtt * 2:
                            self._last_ping_log = time.monotonic()
                            self.logger.info('%s response time %.3fs',
                                             self.name, resp_time)
                            self.print_status()
                            self._stream_ctx[0].reduce_window(self._rtt)
                elif frame_type == GOAWAY:  # 7
                    # no more new stream
                    max_stream_id = payload.read(2)
                    self._manager.remove(self)
                    for stream_id, client_writer in self._client_writer:
                        if stream_id > max_stream_id:
                            # reset stream
                            client_writer.close()
                            try:
                                await client_writer.wait_closed()
                            except ConnectionError:
                                pass
                elif frame_type == WINDOW_UPDATE:  # 8
                    if self._settings_async_drain and stream_id:
                        if frame_flags == 1:
                            self._stream_ctx[stream_id].resume_reading.clear()
                        else:
                            self._stream_ctx[stream_id].resume_reading.set()
                    else:
                        size = struct.unpack('>I', payload.read(4))[0]
                        self._stream_ctx[stream_id].window_update(size)
                elif frame_type == UDP_DGRAM2:  # 21
                    on_dgram_recv(payload)
            except Exception as err:
                self.logger.error('CONNECTION BOOM! %r', err, exc_info=True)
                break
        # out of loop, destroy connection
        self.connection_lost = True
        self._manager.remove(self)
        self.logger.warning('out of loop %s, lasting %ds', self.proxy.name, time.monotonic() - self.connected)
        self.print_status()

        for stream_id, event in self._remote_connected_event.items():
            if isinstance(event, Event):
                self._stream_ctx[stream_id].stream_status = CLOSED
                event.set()

        task_list = []
        for stream_id in self._client_writer:
            self._stream_ctx[stream_id].stream_status = CLOSED
            if not self._client_writer[stream_id].is_closing():
                self._client_writer[stream_id].close()
                task_list.append(self._client_writer[stream_id])
        self._client_writer = {}
        task_list = [asyncio.create_task(w.wait_closed()) for w in task_list]
        if task_list:
            await asyncio.wait(task_list)
        await self.close()

    def key_exchange(self, data, usn, psw, pubk, ecc):
        data = io.BytesIO(data)

        resp_code = data.read(1)[0]
        if resp_code == 0:
            self.logger.debug('hxsocks read key exchange respond')
            pklen, scertlen, siglen = struct.unpack(b'!BBB', data.read(3))

            server_key = data.read(pklen)
            auth = data.read(32)
            server_cert = data.read(scertlen)
            signature = data.read(siglen)
            self._mode = data.read(1)[0]

            # TODO: ask user if a certificate should be accepted or not.
            host, port = self.proxy._host_port
            host = host.replace(':', '_')
            server_id = f'{host}_{port}'
            if server_id not in KNOWN_HOSTS:
                self.logger.info('hxs: server %s new cert %s saved.',
                                 server_id, hashlib.sha256(server_cert).hexdigest()[:8])
                with open('./.hxs_known_hosts/' + server_id + '.cert', 'wb') as f:
                    f.write(server_cert)
                    KNOWN_HOSTS[server_id] = server_cert
            elif KNOWN_HOSTS[server_id] != server_cert:
                self.logger.error('hxs: server %s certificate mismatch! PLEASE CHECK!', server_id)
                raise ConnectionResetError(0, 'hxs: bad certificate')

            if auth == hmac.new(psw.encode(), pubk + server_key + usn.encode(), hashlib.sha256).digest():
                try:
                    ECC.verify_with_pub_key(server_cert, auth, signature, self.hash_algo)
                    shared_secret = ecc.get_dh_key(server_key)
                    self.logger.debug('hxs key exchange success')
                    if self._mode & 1:
                        self._cipher = EncryptorStream(shared_secret, 'rc4-md5', check_iv=False, role=2)
                        self.bufsize += 16
                    else:
                        self._cipher = AEncryptor(shared_secret, FAST_METHOD, CTX, check_iv=False, role=2)
                    if self._mode & 2:
                        self.encrypt_frame_len = True
                        md5 = hashlib.md5()
                        md5.update(shared_secret)
                        md5.update(b'encrypt_flen')
                        key = md5.digest()
                        self._flen_cipher = EncryptorStream(key, 'rc4', check_iv=False)
                        self._flen_cipher.encrypt(bytes(1024))
                        self._flen_cipher.decrypt(bytes(1024))
                    # start reading from connection
                    self.connected = time.monotonic()
                    self._connection_task = asyncio.ensure_future(self.read_from_connection())
                    self._connection_stat = asyncio.ensure_future(self.monitor())
                    return
                except InvalidSignature:
                    self.logger.error('hxs getKey Error: server auth failed, bad signature')
            else:
                self.logger.error('hxs getKey Error: server auth failed, bad username or password')
        else:
            self.logger.error('hxs getKey Error. bad password or timestamp.')
        raise ConnectionResetError(0, 'hxs getKey Error')

    def count(self):
        return len(self._client_writer)

    async def monitor(self):
        while not self.connection_lost:
            delay = random.normalvariate(1, sigma=1 / 4)
            if delay < 0:
                continue
            await asyncio.sleep(delay)
            self.update_stat()
            if self._ping_time and time.monotonic() - self._last_recv > self.PING_TIMEOUT and \
                    time.monotonic() - self._ping_time > self.PING_TIMEOUT:
                self.logger.warning('server ping no response %s in %ds',
                                    self.proxy.name, time.monotonic() - self._ping_time)
                break
            idle_time = time.monotonic() - max(self._last_recv, self._last_send)
            if not self.count() and idle_time > self.IDLE_TIMEOUT:
                self.logger.info('connection idle %s', self.proxy.name)
                break

            if time.monotonic() - self._last_ping > self.PING_INTV_2:
                await self.send_ping()
                continue
            if time.monotonic() - self._last_ping > self.PING_INTV:
                if self._stream_ctx[0].recv_counter > self.WINDOW_SIZE[0] or \
                        self._stream_ctx[0].sent_counter > self.WINDOW_SIZE[0]:
                    await self.send_ping()
            continue
        self.connection_lost = True

        for stream_id, event in self._remote_connected_event.items():
            if isinstance(event, Event):
                self._stream_ctx[stream_id].stream_status = CLOSED
                event.set()

        task_list = []
        for stream_id in self._client_writer:
            self._stream_ctx[stream_id].stream_status = CLOSED
            if not self._client_writer[stream_id].is_closing():
                self._client_writer[stream_id].close()
                task_list.append(self._client_writer[stream_id])
        self._client_writer = {}
        task_list = [asyncio.create_task(w.wait_closed()) for w in task_list]
        if task_list:
            await asyncio.wait(task_list)
        await self.close()

    def update_stat(self):
        try:
            buffer_size = self.remote_writer.transport.get_write_buffer_size()
            self._buffer_size_ewma = self._buffer_size_ewma * 0.8 + buffer_size * 0.2
        except AttributeError:
            pass

    def busy(self):
        return self._rtt_ewma

    def is_busy(self):
        if self._connecting_lock.locked():
            return True
        if self._buffer_size_ewma > 2048:
            return True
        if self._stream_ctx[0].recv_rate_max > 262144:
            return self._stream_ctx[0].recv_rate > self._stream_ctx[0].recv_rate_max * 0.5 or \
                self._stream_ctx[0].sent_rate > self._stream_ctx[0].sent_rate_max * 0.5
        return False

    def print_status(self):
        if not self.connected:
            return
        self.logger.info('%s:%s next_id: %s, rtt ewma: %.3fs min: %.3fs', self.name, self._socport, self._next_stream_id, self._rtt_ewma, self._rtt)
        self.logger.info('recv_tp_max: %8d, ewma: %8d, recv_w: %8d', self._stream_ctx[0].recv_rate_max, self._stream_ctx[0].recv_rate, self._stream_ctx[0].recv_w)
        self.logger.info('sent_tp_max: %8d, ewma: %8d, send_w: %8d', self._stream_ctx[0].sent_rate_max, self._stream_ctx[0].sent_rate, self._stream_ctx[0].send_w)
        self.logger.info('buffer_ewma: %8d, active stream: %6d', self._buffer_size_ewma, self.count())
        self.logger.info('total_recv: %d, data_recv: %d %.3f',
                         self._stat_total_recv, self._stream_ctx[0].traffic_from_remote,
                         self._stream_ctx[0].traffic_from_remote / self._stat_total_recv)
        self.logger.info('total_sent: %d, data_sent: %d %.3f',
                         self._stat_total_sent, self._stream_ctx[0].traffic_from_client,
                         self._stream_ctx[0].traffic_from_client / self._stat_total_sent)

    async def client_writer_drain(self, stream_id):
        if self._settings_async_drain:
            asyncio.ensure_future(self.async_drain(stream_id))
        else:
            await self._client_writer[stream_id].drain()

    async def async_drain(self, stream_id):
        if stream_id not in self._client_writer:
            return
        wbuffer_size = self._client_writer[stream_id].transport.get_write_buffer_size()
        if wbuffer_size <= self.CLIENT_WRITE_BUFFER:
            return

        async with self._stream_ctx[stream_id].drain_lock:
            try:
                # tell client to stop reading
                await self.send_frame(WINDOW_UPDATE, 1, stream_id)
                await self._client_writer[stream_id].drain()
                # tell client to resume reading
                await self.send_frame(WINDOW_UPDATE, 0, stream_id)
            except (OSError, KeyError):
                self.close_stream(stream_id)
                return

    async def get_key(self, timeout, tcp_nodelay):
        raise NotImplementedError

    async def send_frame_data(self, ct_):
        raise NotImplementedError

    async def read_frame(self, timeout=30):
        frame_data = await self._read_frame(timeout)
        self._stat_total_recv += len(frame_data)
        return frame_data

    async def _read_frame(self, timeout=30):
        raise NotImplementedError

    async def close(self):
        raise NotImplementedError

    async def send_dgram2(self, udp_sid, data):
        # remote addr included in data, as shadowsocks format
        payload = CLIENT_ID
        payload += struct.pack(b'!LH', udp_sid, len(data))
        payload += data
        payload += bytes(random.randint(self.PING_SIZE // 4, self.PING_SIZE))
        await self.send_frame(UDP_DGRAM2, 0, 0, payload)

    def write_eof_stream(self, stream_id):
        if not self._stream_ctx[stream_id].stream_status & EOF_SENT:
            self._stream_ctx[stream_id].stream_status |= EOF_SENT

        if self._stream_ctx[stream_id].stream_status == CLOSED:
            self.close_stream(stream_id)
            return
        asyncio.ensure_future(self.send_frame(HEADERS, END_STREAM_FLAG, stream_id))

    def close_stream(self, stream_id):
        if not self._stream_ctx[stream_id].resume_reading.is_set():
            self._stream_ctx[stream_id].resume_reading.set()
        if self._stream_ctx[stream_id].stream_status != CLOSED:
            asyncio.ensure_future(self.send_frame(RST_STREAM, 0, stream_id))
            self._stream_ctx[stream_id].stream_status = CLOSED
        if stream_id in self._client_writer:
            writer = self._client_writer[stream_id]
            del self._client_writer[stream_id]
            if not writer.is_closing():
                writer.close()

    def abort_stream(self, stream_id):
        self.close_stream(stream_id)
