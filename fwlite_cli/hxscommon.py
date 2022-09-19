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


from builtins import chr

import sys
import os
import struct
import socket
import time
import hmac
import io
import hashlib
import random
import traceback
import asyncio
from asyncio import Event, Lock

from hxcrypto import ECC, AEncryptor, InvalidSignature
from hxcrypto.encrypt import EncryptorStream

from fwlite_cli.parent_proxy import ParentProxy
from fwlite_cli.socks5udp import UDPRelayInterface
from fwlite_cli.util import cipher_test

DEFAULT_METHOD = 'chacha20-ietf-poly1305'  # for hxsocks2 handshake
FAST_METHOD = 'aes-128-gcm' if cipher_test[2] < 1.2 else 'chacha20-ietf-poly1305'
DEFAULT_MODE = '0' if cipher_test[1] < 0.1 else '1'
DEFAULT_HASH = 'sha256'
CTX = b'hxsocks2'
MAX_STREAM_ID = 65530
MAX_CONNECTION = 2
CLIENT_WRITE_BUFFER = 524288
CONN_TIMEOUT = 600
STREAM_TIMEOUT = 600

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
UDP_ASSOCIATE = 20

PONG = 1
END_STREAM_FLAG = 1

# load known certs
if not os.path.exists('./.hxs_known_hosts'):
    os.mkdir('./.hxs_known_hosts')
for fname in os.listdir('./.hxs_known_hosts'):
    if fname.endswith('.cert') and os.path.isfile(os.path.join('./.hxs_known_hosts', fname)):
        KNOWN_HOSTS[fname[:-5]] = open('./.hxs_known_hosts/' + fname, 'rb').read()


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


class UDPRelayHxs2(UDPRelayInterface):
    def __init__(self, udp_server, stream_id, hxs2conn, client_addr):
        super().__init__(udp_server, hxs2conn.proxy, client_addr)
        self.hxs2conn = hxs2conn
        self.stream_id = stream_id

    async def _send(self, addr, port, dgram, data):
        # datagram recieved from client, relay to server
        await self.hxs2conn.send_data_frame(self.stream_id, data)

    def write(self, data):
        asyncio.ensure_future(self.on_remote_recv(data))

    async def drain(self):
        return

    def is_closing(self):
        return self._close

    def close(self, close_server=True):
        super().close(close_server)
        asyncio.ensure_future(self.hxs2conn.close_stream(self.stream_id))

    async def wait_closed(self):
        return


class HxsConnection:
    bufsize = 65535 - 22

    def __init__(self, proxy, manager):
        if not isinstance(proxy, ParentProxy):
            proxy = ParentProxy(proxy, proxy)
        self.logger = None
        self.proxy = proxy
        self.name = self.proxy.name
        self.timeout = 6  # read frame_data timeout
        self._manager = manager
        self._ping_test = False
        self._ping_time = 0
        self.connected = False
        self.connection_lost = False
        self.udp_relay_support = None
        self.udp_event = None

        self._psk = self.proxy.query.get('PSK', [''])[0]
        self.method = self.proxy.query.get('method', [DEFAULT_METHOD])[0].lower()  # for handshake
        self.mode = int(self.proxy.query.get('mode', [DEFAULT_MODE])[0])
        if self.method == 'rc4-md5':
            self.mode = 1
        self.hash_algo = self.proxy.query.get('hash', [DEFAULT_HASH])[0].upper()

        self.remote_reader = None
        self.remote_writer = None
        self._socport = None

        self._pskcipher = None
        self._cipher = None
        self._next_stream_id = 1
        self._settings_async_drain = None

        self._client_writer = {}
        self._client_status = {}
        self._client_resume_reading = {}
        self._client_drain_lock = {}
        self._stream_status = {}
        self._stream_addr = {}
        self._stream_task = {}
        self._last_active = {}
        self._last_active_c = time.monotonic()
        self._last_ping_log = 0
        self._connection_task = None
        self._connection_stat = None

        self._last_direction = SEND
        self._last_count = 0
        self._buffer_size_ewma = 0
        self._recv_tp_max = 0
        self._recv_tp_ewma = 0
        self._sent_tp_max = 0
        self._sent_tp_ewma = 0

        self._stat_data_recv = 0
        self._stat_total_recv = 1
        self._stat_recv_tp = 0
        self._stat_data_sent = 0
        self._stat_total_sent = 1
        self._stat_sent_tp = 0

        self._lock = Lock()

    async def connect(self, addr, port, timeout=3):
        self.logger.debug('hxsocks send connect request')
        if self.connection_lost:
            self._manager.remove(self)
            raise ConnectionLostError(0, 'hxs connection lost')
        if not self.connected:
            self._manager.remove(self)
            raise ConnectionResetError(0, 'hxs not connected.')
        # send connect request
        payload = b''.join([chr(len(addr)).encode('latin1'),
                            addr.encode(),
                            struct.pack('>H', port),
                            b'\x00' * random.randint(64, 255),
                            ])
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        if self._next_stream_id > MAX_STREAM_ID:
            self.logger.error('MAX_STREAM_ID reached')
            self._manager.remove(self)

        await self.send_frame(HEADERS, OPEN, stream_id, payload)
        self._stream_addr[stream_id] = (addr, port)

        # wait for server response
        event = Event()
        self._client_status[stream_id] = event
        self._client_resume_reading[stream_id] = asyncio.Event()
        self._client_resume_reading[stream_id].set()

        # await event.wait()
        fut = event.wait()
        try:
            await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self.logger.error('%s connect %s no response, timeout=%d',
                              self.name, '%s:%d' % (addr, port), timeout)
            del self._client_status[stream_id]
            self.print_status()
            await self.send_ping()
            raise

        del self._client_status[stream_id]

        if self._stream_status[stream_id] == OPEN:
            socketpair_a, socketpair_b = socket.socketpair()
            if sys.platform == 'win32':
                socketpair_a.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                socketpair_b.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            reader, writer = await asyncio.open_connection(sock=socketpair_b, limit=131072)
            writer.transport.set_write_buffer_limits(CLIENT_WRITE_BUFFER)

            self._client_writer[stream_id] = writer
            self._last_active[stream_id] = time.monotonic()
            self._client_drain_lock[stream_id] = asyncio.Lock()
            # start forwarding
            self._stream_task[stream_id] = asyncio.ensure_future(self.read_from_client(stream_id, reader))
            return socketpair_a
        await self.send_ping()
        raise ConnectionResetError(0, 'remote connect to %s:%d failed.' % (addr, port))

    async def read_from_client(self, stream_id, client_reader):
        self.logger.debug('start read from client')

        while not self.connection_lost:
            await self._client_resume_reading[stream_id].wait()
            fut = client_reader.read(self.bufsize)
            try:
                data = await asyncio.wait_for(fut, timeout=6)
                self._last_active[stream_id] = time.monotonic()
            except asyncio.TimeoutError:
                if time.monotonic() - self._last_active[stream_id] < STREAM_TIMEOUT and\
                        self._stream_status[stream_id] == OPEN:
                    continue
                data = b''
            except ConnectionError:
                await self.close_stream(stream_id)
                return

            if not data:
                # close stream(LOCAL)
                self._stream_status[stream_id] |= EOF_SENT
                await self.send_frame(HEADERS, END_STREAM_FLAG, stream_id, bytes(random.randint(8, 256)))
                break

            if self._stream_status[stream_id] & EOF_SENT:
                self.logger.error('data recv from client, while stream is closed!')
                await self.close_stream(stream_id)
                return
            await self.send_data_frame(stream_id, data)
        while time.monotonic() - self._last_active[stream_id] < 12:
            await asyncio.sleep(6)
        await self.close_stream(stream_id)

    async def send_frame(self, type_, flags, stream_id, payload):
        self.logger.debug('send_frame type: %d, stream_id: %d', type_, stream_id)
        if self.connection_lost:
            self.logger.error('send_frame: connection closed. %s', self.name)
            return
        if type_ != PING:
            self._last_active_c = time.monotonic()
        elif flags == 0:
            self._ping_time = time.monotonic()

        if type_ == DATA and self._last_direction == RECV:
            self._last_direction = SEND
            self._last_count = 0
        self._last_count += 1

        header = struct.pack('>BBH', type_, flags, stream_id)
        data = header + payload
        ct_ = self._cipher.encrypt(data)

        await self.send_frame_data(ct_)

        if self._settings_async_drain is None and random.random() < 0.1:
            self._settings_async_drain = False
            await self.send_frame(SETTINGS, 0, 1, bytes(random.randint(64, 256)))
        if type_ == DATA and self._last_count > 5 and random.random() < 0.1:
            await self.send_ping(False)

    async def send_ping(self, test=True):
        if self._ping_time == 0:
            self._ping_test = test
            await self.send_frame(PING, 0, 0, bytes(random.randint(64, 256)))

    async def send_one_data_frame(self, stream_id, data):
        payload = struct.pack('>H', len(data)) + data
        diff = self.bufsize - len(data)
        payload += bytes(random.randint(min(diff, 8), min(diff, 255)))
        await self.send_frame(DATA, 0, stream_id, payload)

    async def send_data_frame(self, stream_id, data):
        data_len = len(data)
        if data_len > 16386 and random.random() < 0.1:
            data = io.BytesIO(data)
            data_ = data.read(random.randint(256, 16386 - 22))
            while data_:
                await self.send_one_data_frame(stream_id, data_)
                if random.random() < 0.1:
                    await self.send_frame(PING, 0, 0, bytes(random.randint(256, 1024)))
                data_ = data.read(random.randint(256, 8192 - 22))
                await asyncio.sleep(0)
        else:
            await self.send_one_data_frame(stream_id, data)
        self._stat_data_sent += data_len
        try:
            buffer_size = self.remote_writer.transport.get_write_buffer_size()
            self._buffer_size_ewma = self._buffer_size_ewma * 0.87 + buffer_size * 0.13
        except AttributeError:
            pass

    async def udp_associate(self, udp_server, client_addr):
        if self.connection_lost:
            self._manager.remove(self)
            raise ConnectionLostError(0, 'hxs connection lost')
        if not self.connected:
            self._manager.remove(self)
            raise ConnectionResetError(0, 'hxs not connected.')
        if self.udp_relay_support is None:
            # ask server for udp_support
            await self.send_frame(UDP_ASSOCIATE, OPEN, 0, bytes(random.randint(64, 256)))
            if not self.udp_event:
                self.udp_event = Event()
            fut = self.udp_event.wait()
            try:
                await asyncio.wait_for(fut, timeout=self.timeout)
            except asyncio.TimeoutError:
                if not self.udp_relay_support:
                    self.udp_relay_support = False
                    self.logger.error('%s does not seem to support UDP_ASSOCIATE, timeout: %d', self.name, self.timeout)
        if not self.udp_relay_support:
            raise ConnectionResetError(0, '%s does not seem to support UDP_ASSOCIATE' % self.name)
        # send udp_assicoate request
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        if self._next_stream_id > MAX_STREAM_ID:
            self.logger.error('MAX_STREAM_ID reached')
            self._manager.remove(self)

        await self.send_frame(UDP_ASSOCIATE, OPEN, stream_id, bytes(random.randint(64, 256)))
        self._stream_status[stream_id] = OPEN
        self._client_resume_reading[stream_id] = asyncio.Event()
        self._client_resume_reading[stream_id].set()
        relay = UDPRelayHxs2(udp_server, stream_id, self, client_addr)
        self._client_writer[stream_id] = relay
        return relay

    async def read_from_connection(self):
        self.logger.debug('start read from connection')
        while not self.connection_lost:
            try:
                # read frame
                intv = 3 if self._ping_test else 6
                try:
                    frame_data = await self.read_frame(intv)
                except asyncio.TimeoutError:
                    if self._ping_test and time.monotonic() - self._ping_time > 6:
                        self.logger.warning('server ping no response %s in %ds',
                                            self.proxy.name, time.monotonic() - self._ping_time)
                        break
                    if time.monotonic() - self._last_active_c > CONN_TIMEOUT:
                        self.logger.info('time.monotonic() - last_active_c > %s', CONN_TIMEOUT)
                        break
                    if time.monotonic() - self._last_active_c > 60 and not self.count():
                        self.logger.info('connection idle %s', self.proxy.name)
                        break
                    if time.monotonic() - self._last_active_c > 10:
                        if not self._ping_test:
                            await self.send_ping()
                    continue
                except ReadFrameError as err:
                    # destroy connection
                    self.logger.error('read frame error: %r', err.err)
                    break

                # parse chunk_data
                # +------+-------------------+----------+
                # | type | flags | stream_id | payload  |
                # +------+-------------------+----------+
                # |  1   |   1   |     2     | Variable |
                # +------+-------------------+----------+

                header, payload = frame_data[:4], frame_data[4:]
                frame_type, frame_flags, stream_id = struct.unpack('>BBH', header)
                payload = io.BytesIO(payload)
                self.logger.debug('recv frame_type: %s, stream_id: %s, size: %s',
                                  frame_type, stream_id, len(frame_data))

                if frame_type == DATA and self._last_direction == SEND:
                    self._last_direction = RECV
                    self._last_count = 0
                self._last_count += 1

                if self._last_count > 5 and random.random() < 0.2:
                    await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 256)))

                if frame_type == DATA:  # 0
                    self._last_active_c = time.monotonic()
                    if self._stream_status[stream_id] & EOF_RECV:
                        # from server send buffer
                        self.logger.debug('DATA recv Stream CLOSED, status: %s',
                                          self._stream_status[stream_id])
                        continue
                    # first 2 bytes of payload indicates data_len, the rest would be padding
                    data_len, = struct.unpack('>H', payload.read(2))
                    data = payload.read(data_len)
                    if len(data) != data_len:
                        # something went wrong, destory connection
                        self.logger.error('len(data) != data_len')
                        break

                    # sent data to stream
                    try:
                        self._last_active[stream_id] = time.monotonic()
                        self._client_writer[stream_id].write(data)
                        await self.client_writer_drain(stream_id)
                        self._stat_data_recv += data_len
                    except OSError:
                        # client error, reset stream
                        asyncio.ensure_future(self.close_stream(stream_id))
                elif frame_type == HEADERS:  # 1
                    self._last_active_c = time.monotonic()
                    if self._next_stream_id == stream_id:
                        # server is not supposed to open a new stream
                        # send connection error?
                        break
                    if stream_id < self._next_stream_id:
                        if frame_flags == END_STREAM_FLAG:
                            self._stream_status[stream_id] |= EOF_RECV
                            if stream_id in self._client_writer:
                                try:
                                    self._client_writer[stream_id].write_eof()
                                except OSError:
                                    self._stream_status[stream_id] = CLOSED
                            if self._stream_status[stream_id] == CLOSED:
                                asyncio.ensure_future(self.close_stream(stream_id))
                        else:
                            # confirm a stream is opened
                            if stream_id in self._client_status:
                                self._stream_status[stream_id] = OPEN
                                self._client_status[stream_id].set()
                            else:
                                addr = '%s:%s' % self._stream_addr[stream_id]
                                self.logger.info('%s stream open, client closed, %s', self.name, addr)
                                self._stream_status[stream_id] = CLOSED
                                await self.send_frame(RST_STREAM, 0, stream_id,
                                                      bytes(random.randint(8, 256)))
                elif frame_type == RST_STREAM:  # 3
                    self._last_active_c = time.monotonic()
                    self._stream_status[stream_id] = CLOSED
                    if stream_id in self._client_status:
                        self._client_status[stream_id].set()
                    asyncio.ensure_future(self.close_stream(stream_id))
                elif frame_type == SETTINGS:
                    if stream_id == 1:
                        self._settings_async_drain = True
                elif frame_type == PING:  # 6
                    if frame_flags == PONG:
                        resp_time = time.monotonic() - self._ping_time
                        if time.monotonic() - self._last_ping_log > 30:
                            self.logger.info('server response time: %.3f %s, stream %s',
                                             resp_time,
                                             self.proxy.name,
                                             self.count())
                            self._last_ping_log = time.monotonic()
                            if resp_time < 0.5:
                                self.proxy.log('', resp_time)
                        self._ping_test = False
                        self._ping_time = 0
                    else:
                        await self.send_frame(PING, PONG, 0, bytes(random.randint(64, 2048)))
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
                    if frame_flags == 1:
                        self._client_resume_reading[stream_id].clear()
                    else:
                        self._client_resume_reading[stream_id].set()
                elif frame_type == UDP_ASSOCIATE:  # 20
                    if stream_id == 0:
                        self.udp_relay_support = True
                        if self.udp_event:
                            self.udp_event.set()
            except Exception as err:
                self.logger.error('CONNECTION BOOM! %r', err)
                self.logger.error(traceback.format_exc())
                break
        # out of loop, destroy connection
        self.connection_lost = True
        self._manager.remove(self)
        self.logger.warning('out of loop %s', self.proxy.name)
        self.logger.info('total_recv: %d, data_recv: %d %.3f',
                         self._stat_total_recv, self._stat_data_recv,
                         self._stat_data_recv / self._stat_total_recv)
        self.logger.info('total_sent: %d, data_sent: %d %.3f',
                         self._stat_total_sent, self._stat_data_sent,
                         self._stat_data_sent / self._stat_total_sent)
        self.print_status()

        for sid, status in self._client_status.items():
            if isinstance(status, Event):
                self._stream_status[sid] = CLOSED
                status.set()

        task_list = []
        for stream_id in self._client_writer:
            self._stream_status[stream_id] = CLOSED
            if not self._client_writer[stream_id].is_closing():
                self._client_writer[stream_id].close()
                task_list.append(self._client_writer[stream_id])
        self._client_writer = {}
        task_list = [asyncio.create_task(w.wait_closed()) for w in task_list]
        task_list.append(asyncio.create_task(self.close()))
        if task_list:
            await asyncio.wait(task_list)

    def key_exchange(self, data, usn, psw, pubk, ecc):
        data = io.BytesIO(data)

        resp_code = data.read(1)[0]
        if resp_code == 0:
            self.logger.debug('hxsocks read key exchange respond')
            pklen = data.read(1)[0]
            scertlen = data.read(1)[0]
            siglen = data.read(1)[0]

            server_key = data.read(pklen)
            auth = data.read(32)
            server_cert = data.read(scertlen)
            signature = data.read(siglen)
            mode = data.read(1)[0]

            # TODO: ask user if a certificate should be accepted or not.
            host, port = self.proxy._host_port
            server_id = '%s_%d' % (host, port)
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
                    if mode == 1:
                        self._cipher = EncryptorStream(shared_secret, 'rc4-md5', check_iv=False)
                        self.bufsize += 16
                    else:
                        self._cipher = AEncryptor(shared_secret, FAST_METHOD, CTX, check_iv=False)
                    # start reading from connection
                    self._connection_task = asyncio.ensure_future(self.read_from_connection())
                    self._connection_stat = asyncio.ensure_future(self.stat())
                    self.connected = True
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

    async def stat(self):
        while not self.connection_lost:
            await asyncio.sleep(1)
            self._recv_tp_ewma = self._recv_tp_ewma * 0.8 + self._stat_recv_tp * 0.2
            if self._recv_tp_ewma > self._recv_tp_max:
                self._recv_tp_max = self._recv_tp_ewma
            self._stat_recv_tp = 0
            self._sent_tp_ewma = self._sent_tp_ewma * 0.8 + self._stat_sent_tp * 0.2
            if self._sent_tp_ewma > self._sent_tp_max:
                self._sent_tp_max = self._sent_tp_ewma
            self._stat_sent_tp = 0
            try:
                buffer_size = self.remote_writer.transport.get_write_buffer_size()
                self._buffer_size_ewma = self._buffer_size_ewma * 0.8 + buffer_size * 0.2
            except AttributeError:
                pass

    def busy(self):
        return self._recv_tp_ewma + self._sent_tp_ewma

    def is_busy(self):
        return self._buffer_size_ewma > 2048 or \
            (self._recv_tp_max > 524288 and self._recv_tp_ewma > self._recv_tp_max * 0.3) or \
            (self._sent_tp_max > 262144 and self._sent_tp_ewma > self._sent_tp_max * 0.3)

    def print_status(self):
        if not self.connected:
            return
        self.logger.info('%s:%s status:', self.name, self._socport)
        self.logger.info('recv_tp_max: %8d, ewma: %8d', self._recv_tp_max, self._recv_tp_ewma)
        self.logger.info('sent_tp_max: %8d, ewma: %8d', self._sent_tp_max, self._sent_tp_ewma)
        self.logger.info('buffer_ewma: %8d, stream: %6d', self._buffer_size_ewma, self.count())

    async def close_stream(self, stream_id):
        if not self._client_resume_reading[stream_id].is_set():
            self._client_resume_reading[stream_id].set()
        if self._stream_status[stream_id] != CLOSED:
            await self.send_frame(RST_STREAM, 0, stream_id, bytes(random.randint(8, 256)))
            self._stream_status[stream_id] = CLOSED
        if stream_id in self._client_writer:
            writer = self._client_writer[stream_id]
            del self._client_writer[stream_id]
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def client_writer_drain(self, stream_id):
        if self._settings_async_drain:
            asyncio.ensure_future(self.async_drain(stream_id))
        else:
            await self._client_writer[stream_id].drain()

    async def async_drain(self, stream_id):
        if isinstance(self._client_writer[stream_id], UDPRelayHxs2):
            return
        wbuffer_size = self._client_writer[stream_id].transport.get_write_buffer_size()
        if wbuffer_size <= CLIENT_WRITE_BUFFER:
            return

        async with self._client_drain_lock[stream_id]:
            try:
                # tell client to stop reading
                await self.send_frame(WINDOW_UPDATE, 1, stream_id, bytes(random.randint(64, 256)))
                await self._client_writer[stream_id].drain()
                # tell client to resume reading
                await self.send_frame(WINDOW_UPDATE, 0, stream_id, bytes(random.randint(64, 256)))
            except OSError:
                await self.close_stream(stream_id)
                return

    async def get_key(self, timeout, tcp_nodelay):
        raise NotImplementedError

    async def send_frame_data(self, ct_):
        raise NotImplementedError

    async def read_frame(self, intv):
        raise NotImplementedError

    async def close(self):
        raise NotImplementedError
