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


import os
import struct
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

from .parent_proxy import ParentProxy
from .hxs_udp2 import on_dgram_recv

DEFAULT_METHOD = 'chacha20-ietf-poly1305'  # for hxsocks2 handshake
FAST_METHOD = 'chacha20-ietf-poly1305'
DEFAULT_MODE = 0
DEFAULT_HASH = 'sha256'
CTX = b'hxsocks2'
MODE_RC4MD5 = 1
MODE_ENC_FLEN = 2

OPEN = 0
EOF_FROM_ENDPOINT = 1
EOF_FROM_CONN = 2
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
    FRAME_SIZE_LIMIT = 4096 - 22
    FRAME_SIZE_LIMIT2 = 1024 - 22
    FRAME_SPLIT_FREQ = 0.3
    WINDOW_SIZE = (4096, 65536, 1048576 * 4)


class ForwardContext:
    def __init__(self, conn, stream_id, host, send_w, recv_w):
        self.host = host  # (host, port)
        self.drain_lock = asyncio.Lock()
        self.last_active = time.monotonic()
        self._buffer = bytearray()
        self._writing = False
        self._writable = asyncio.Event()  # block when buffer is full
        self._writable.set()
        self._eof_pending = False
        self._closing = False

        # eof recieved
        self.stream_status = OPEN
        # traffic, for log
        self.traffic_from_endpoint = 0
        self.traffic_from_conn = 0
        self._from_endpoint_count = 0
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
        self._fc_enable = bool(send_w)
        if send_w or stream_id == 0:
            self._monitor_task = asyncio.ensure_future(self.monitor())
        self.send_w = send_w or float('inf')
        self._lock = asyncio.Lock()
        self._window_open = asyncio.Event()  # blocked when cannot send to connection
        self._window_open.set()
        self.recv_w = recv_w
        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        self._recv_w_counter = 0

    async def acquire(self, size):
        ''' called before send data to connection, or maybe after'''
        async with self._lock:
            await self._window_open.wait()
            self.traffic_from_endpoint += size
            self.sent_counter += size
            self.last_active = time.monotonic()
            self.send_w -= size
            if self.send_w <= 0:
                self._window_open.clear()

    def data_recv(self, size):
        '''data recv from connection, maybe update window'''
        self.traffic_from_conn += size
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
                self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload)

    def enable_fc(self, send_w, recv_w):
        if self.fc_enable:
            raise ValueError('fc already enabled')
        self._fc_enable = bool(send_w)
        self.send_w = send_w
        self.recv_w = recv_w
        self._recv_w_max = recv_w
        self._recv_w_min = recv_w
        if not self._monitor_task:
            self._monitor_task = asyncio.ensure_future(self.monitor())

    @property
    def fc_enable(self):
        return self._fc_enable

    def new_recv_window(self, new_window):
        # change recv window
        new_window = int(new_window)
        new_window = max(new_window, self._conn.WINDOW_SIZE[0])
        new_window = max(new_window, self._conn.WINDOW_SIZE[2])
        old_size = self.recv_w
        self.recv_w = new_window
        self._recv_w_counter += new_window - old_size
        if self._recv_w_counter > self.recv_w // 2:
            w_counter = self._recv_w_counter
            self._recv_w_counter = 0
            payload = struct.pack('>I', w_counter)
            payload += bytes(random.randint(self._conn.HEADER_SIZE // 4 - 4, self._conn.HEADER_SIZE - 4))
            self._conn.send_frame(WINDOW_UPDATE, 0, self._stream_id, payload)
        self._conn.logger.debug(f'{self._conn.name}: update window form {old_size} to {self.recv_w}')

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
        if size < 0:
            self.send_w = size
            self._window_open.clear()
            return
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

    def write(self, data):
        '''data recieved from endpoint, send to connection'''
        if self.stream_status & EOF_FROM_ENDPOINT:
            return
        self._from_endpoint_count += 1
        self._buffer.extend(data)
        if len(self._buffer) > self._conn.bufsize:
            self._writable.clear()
        asyncio.ensure_future(self._maybe_start_writing())

    async def _maybe_start_writing(self):
        if self._writing:
            return
        self._writing = True
        while self._buffer:
            # write buffer to conn
            more_padding = self._from_endpoint_count < 5
            data_len = len(self._buffer)
            frame_size_limit = self._conn.FRAME_SIZE_LIMIT2 if more_padding else self._conn.FRAME_SIZE_LIMIT
            if data_len > frame_size_limit and (more_padding or random.random() < self._conn.FRAME_SPLIT_FREQ):
                data = self._buf_read(random.randint(64, frame_size_limit))
                await self.send_one_data_frame(data, more_padding, frag=len(data) < data_len)
                await asyncio.sleep(0.01)
            else:
                data = self._buf_read()
                await self.send_one_data_frame(data, more_padding)
        if self._eof_pending:
            self._write_eof()
        if self._closing:
            self._close()
        # after self._buffer is empty
        self._writing = False
        self._writable.set()

    def _buf_read(self, n=None):
        if not n:
            n = self._conn.bufsize
        if len(self._buffer) <= n:
            data = bytes(self._buffer)
            self._buffer.clear()
        else:
            data = bytes(self._buffer[:n])
            del self._buffer[:n]
        return data

    async def send_one_data_frame(self, data, more_padding, frag=False):
        if self.stream_status & EOF_FROM_ENDPOINT:
            return
        await self._conn.acquire(len(data))
        await self.acquire(len(data))
        self._conn.send_one_data_frame(self._stream_id, data, more_padding, frag=frag)

    def get_write_buffer_size(self):
        return len(self._buffer)

    async def drain(self):
        await self._writable.wait()
        if self._closing:
            raise ConnectionError(0, 'ForwardContext closed')

    def write_eof(self):
        if self._buffer:
            self._eof_pending = True
            return
        self._write_eof()

    def _write_eof(self):
        if not self.stream_status & EOF_FROM_ENDPOINT:
            self.stream_status |= EOF_FROM_ENDPOINT
            self._conn.send_frame(HEADERS, END_STREAM_FLAG, self._stream_id)
        if self.stream_status == CLOSED:
            self._conn.close_stream(self._stream_id)

    def close(self):
        if self._closing:
            return
        self._closing = True
        if self._buffer:
            return
        self._close()

    def _close(self):
        if self.stream_status != CLOSED:
            self._conn.send_frame(RST_STREAM, 0, self._stream_id)
            self.stream_status = CLOSED
        self._writable.set()

    def is_closing(self):
        return self._closing


class HxsConnection(HC):
    bufsize = 65535 - 22

    def __init__(self, proxy, manager, limit):
        if not isinstance(proxy, ParentProxy):
            proxy = ParentProxy(proxy, proxy)
        self.proxy = proxy
        self._manager = manager
        self._limit = limit
        self.logger = None
        self.name = self.proxy.name
        self.connected = 0
        self.connection_lost = False
        self.udp_event = None

        self._psk = self.proxy.query.get('PSK', [''])[0]
        self.method = self.proxy.query.get('method', [DEFAULT_METHOD])[0].lower()  # for handshake
        default_mode = DEFAULT_MODE
        if self.proxy.scheme == 'hxs4':
            default_mode |= MODE_ENC_FLEN
        self.mode = int(self.proxy.query.get('mode', [default_mode])[0])
        if self.mode & MODE_ENC_FLEN and 'rc4' not in method_supported:
            self.mode &= 0b11111101
        if self.method == 'rc4-md5':
            self.mode |= MODE_RC4MD5
        self._mode = 0
        self.hash_algo = self.proxy.query.get('hash', [DEFAULT_HASH])[0].upper()
        self.encrypt_frame_len = False
        self._flen_cipher = None

        self._remote_reader = None
        self._remote_writer = None
        self._socport = None

        self._pskcipher = None
        self._cipher = None
        self._next_stream_id = 1
        self._settings_async_drain = False

        self._stream_transport = {}
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

    def send_frame(self, type_, flags, stream_id, payload=None):
        if self.connection_lost:
            self.logger.debug('send_frame: connection closed. %s', self.name)
            return
        if not self._setting_sent:
            self._setting_sent = True
            _payload = struct.pack('>I', self.WINDOW_SIZE[1])
            _payload += bytes(random.randint(self.HEADER_SIZE // 4 - 4, self.HEADER_SIZE - 4))
            self.send_frame(SETTINGS, 0, 1 | FLOW_CONTROL, _payload)
        if type_ != PING:
            self._last_send = time.monotonic()
        elif flags == 0:
            self._last_ping = time.monotonic()

        if not payload:
            payload = bytes(random.randint(self.HEADER_SIZE // 4, self.HEADER_SIZE))

        header = struct.pack('>BBH', type_, flags, stream_id)
        ct_ = self._cipher.encrypt(header + payload)

        self.logger.debug('send_frame type: %d, stream_id: %d, size: %d %s', type_, stream_id, len(ct_), self.name)

        self.send_frame_data(ct_)
        self._stat_total_sent += len(ct_)

    def send_ping(self, size=0):
        if self._ping_time:
            self.send_pong(0, size)
            return
        if not size:
            size = self.PING_SIZE
        self._ping_id = random.randint(1, 32767)
        self._ping_time = time.monotonic()
        self.send_frame(PING, 0, self._ping_id, bytes(random.randint(size // 4, size)))

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
            self.send_ping(self.PONG_SIZE)
            self._pinging -= 1

    def send_pong(self, sid=0, size=0):
        if not size:
            size = self.PONG_SIZE
        self.send_frame(PING, PONG, sid, bytes(random.randint(size // 4, size)))

    def send_one_data_frame(self, stream_id, data, more_padding=False, frag=False):
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
        flag = 1 if frag else 0
        self.send_frame(DATA, flag, stream_id, payload)

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

                if frame_type == DATA:  # 0
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    self._stream_ctx[0].data_recv(data_len)

                    # first 2 bytes of payload indicates data_len, the rest would be padding
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('len(data) != data_len')
                        break

                    if frame_flags & 1:
                        self.send_pong()
                    elif self._ponging:
                        if random.random() < 0.8:
                            self.send_pong()
                            self._ponging -= 1
                    elif random.random() < self.PING_FREQ:
                        self.send_pong()

                    # sent data to stream
                    for _ in range(5):
                        if stream_id not in self._stream_transport:
                            await asyncio.sleep(0)

                    if self._stream_ctx[stream_id].stream_status & EOF_FROM_CONN:
                        # from server send buffer
                        self.logger.debug('DATA recv Stream CLOSED, status: %s',
                                          self._stream_ctx[stream_id].stream_status)
                        continue

                    try:
                        self._stream_ctx[stream_id].last_active = time.monotonic()
                        self._stream_transport[stream_id].data_from_conn(data)
                        await self.client_writer_drain(stream_id, data_len)
                    except (OSError, KeyError) as err:
                        self.logger.error('send data to stream fail. %r', err)
                        # client error, reset stream
                        self.close_stream(stream_id)
                elif frame_type == HEADERS:  # 1
                    if frame_flags == END_STREAM_FLAG:
                        self._stream_ctx[stream_id].stream_status |= EOF_FROM_CONN
                        if stream_id in self._stream_transport:
                            try:
                                self._stream_transport[stream_id].eof_from_conn()
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
                            self.send_frame(RST_STREAM, 0, stream_id)
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
                        self._stream_ctx[0].enable_fc(send_w, self.WINDOW_SIZE[1])
                elif frame_type == PING:  # 6
                    if frame_flags == 0:
                        self.send_pong(stream_id, self.PING_SIZE)
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
                    for stream_id in self._stream_transport:
                        if stream_id > max_stream_id:
                            # reset stream
                            self.close_stream(stream_id)
                elif frame_type == WINDOW_UPDATE:  # 8
                    if not self._stream_ctx[stream_id].fc_enable:
                        self._settings_async_drain = True
                        if frame_flags == 0:
                            # pause reading
                            self._stream_ctx[stream_id].window_update(float('inf'))
                        else:
                            # resume reading
                            self._stream_ctx[stream_id].window_update(-1)
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

        for stream_id in self._stream_transport:
            self.close_stream(stream_id)

        await asyncio.sleep(1)
        self.close()
        await self.wait_closed()

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
            host, port = self.proxy.peername
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
                    if self._mode & MODE_RC4MD5:
                        self._cipher = EncryptorStream(shared_secret, 'rc4-md5', check_iv=False, role=2)
                        self.bufsize += 16
                    else:
                        self._cipher = AEncryptor(shared_secret, FAST_METHOD, CTX, check_iv=False, role=2)
                    if self._mode & MODE_ENC_FLEN:
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
        return len(self._stream_transport)

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
                self.send_ping()
                continue
            if time.monotonic() - self._last_ping > self.PING_INTV:
                if self._stream_ctx[0].recv_counter > self.WINDOW_SIZE[0] or \
                        self._stream_ctx[0].sent_counter > self.WINDOW_SIZE[0]:
                    self.send_ping()
            continue
        self.connection_lost = True

        await asyncio.sleep(1)
        self.close()
        await self.wait_closed()

    def update_stat(self):
        try:
            buffer_size = self._remote_writer.transport.get_write_buffer_size()
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
        ctx = self._stream_ctx[0]
        self.logger.info('%s:%s next_id: %s, rtt ewma: %.3fs min: %.3fs', self.name, self._socport,
                         self._next_stream_id, self._rtt_ewma, self._rtt)
        self.logger.info('recv_tp_max: %8d, ewma: %8d, recv_w: %8d', ctx.recv_rate_max, ctx.recv_rate, ctx.recv_w)
        self.logger.info('sent_tp_max: %8d, ewma: %8d, send_w: %8d', ctx.sent_rate_max, ctx.sent_rate, ctx.send_w)
        self.logger.info('buffer_ewma: %8d, active stream: %6d', self._buffer_size_ewma, self.count())
        self.logger.info('total_recv: %d, data_recv: %d %.3f', self._stat_total_recv, ctx.traffic_from_conn,
                         ctx.traffic_from_conn / self._stat_total_recv)
        self.logger.info('total_sent: %d, data_sent: %d %.3f', self._stat_total_sent, ctx.traffic_from_endpoint,
                         ctx.traffic_from_endpoint / self._stat_total_sent)

    async def client_writer_drain(self, stream_id, data_len):
        if self._stream_ctx[stream_id].is_closing():
            raise ConnectionError
        if self._settings_async_drain or self._stream_ctx[stream_id].fc_enable:
            asyncio.ensure_future(self.async_drain(stream_id, data_len))
        else:
            await self._stream_transport[stream_id].drain()
            self._stream_ctx[stream_id].data_recv(data_len)

    async def async_drain(self, stream_id, data_len):
        if stream_id not in self._stream_transport:
            return
        wbuffer_size = self._stream_ctx[stream_id].get_write_buffer_size()
        if wbuffer_size <= self.CLIENT_WRITE_BUFFER:
            self._stream_ctx[stream_id].data_recv(data_len)
            return

        async with self._stream_ctx[stream_id].drain_lock:
            try:
                # tell client to stop reading
                if not self._stream_ctx[stream_id].fc_enable:
                    self.send_frame(WINDOW_UPDATE, 1, stream_id)
                await self._stream_transport[stream_id].drain()
                # tell client to resume reading
                if not self._stream_ctx[stream_id].fc_enable:
                    self.send_frame(WINDOW_UPDATE, 0, stream_id)
                self._stream_ctx[stream_id].data_recv(data_len)
            except (OSError, KeyError):
                self.close_stream(stream_id)

    async def read_frame(self, timeout=30):
        frame_data = await self._read_frame(timeout)
        self._stat_total_recv += len(frame_data)
        return frame_data

    async def send_dgram2(self, udp_sid, data):
        # remote addr included in data, as shadowsocks format
        payload = CLIENT_ID
        payload += struct.pack(b'!LH', udp_sid, len(data))
        payload += data
        payload += bytes(random.randint(self.PING_SIZE // 4, self.PING_SIZE))
        self.send_frame(UDP_DGRAM2, 0, 0, payload)

    async def get_key(self, timeout, tcp_nodelay):
        raise NotImplementedError

    async def _read_frame(self, timeout=30):
        raise NotImplementedError

    def send_frame_data(self, ct_):
        raise NotImplementedError

    async def drain(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    async def wait_closed(self):
        raise NotImplementedError

    async def create_connection(self, addr, port, timeout, transport, _):
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
            self.send_frame(HEADERS, OPEN, stream_id, payload)
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
                self._stream_ctx[stream_id].stream_status = CLOSED
                self.send_ping()
                raise

        del self._remote_connected_event[stream_id]

        if self._stream_ctx[stream_id].stream_status == OPEN:
            self._stream_transport[stream_id] = transport
            self._stream_ctx[stream_id].last_active = time.monotonic()
            # start forwarding
            return stream_id
        if self.connection_lost:
            raise ConnectionLostError(0, 'hxs connection lost after request sent')
        raise ConnectionResetError(0, f'remote connect to {addr}:{port} failed.')

    async def acquire(self, size):
        await self._stream_ctx[0].acquire(size)

    def write_stream(self, data, stream_id):
        self._stream_ctx[stream_id].write(data)

    def get_conn_buffer_size(self):
        raise NotImplementedError

    def get_stream_buffer_size(self, stream_id):
        return self._stream_ctx[stream_id].get_write_buffer_size()

    def get_write_buffer_size(self, stream_id):
        if stream_id not in self._stream_ctx:
            return 0
        return max(self.get_conn_buffer_size(), self.get_stream_buffer_size(stream_id))

    async def drain_stream(self, stream_id):
        '''push data to connection, and block until able to write more'''
        await self._stream_ctx[stream_id].drain()
        await self.drain()

    def write_eof_stream(self, stream_id):
        self._stream_ctx[stream_id].write_eof()

    def close_stream(self, stream_id):
        loop = asyncio.get_event_loop()
        loop.call_soon(self._close_stream, stream_id)

    def _close_stream(self, stream_id):
        if stream_id in self._stream_transport:
            transport = self._stream_transport[stream_id]
            del self._stream_transport[stream_id]
            transport.close()

    def abort_stream(self, stream_id):
        self.close_stream(stream_id)
