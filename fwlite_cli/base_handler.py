
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

import sys
import email
import struct
import socket
import ipaddress
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler
from http import HTTPStatus

import asyncio
from asyncio import TimeoutError, IncompleteReadError

from .util import set_keepalive

__version__ = '0'


async def read_response_line(reader, timeout=1, first_byte=b''):
    # GET / HTTP/1.1\r\n
    # HTTP/1.1 200 OK\r\n
    fut = reader.readline()
    request_line = await asyncio.wait_for(fut, timeout=timeout)
    request_line = first_byte + request_line

    if not request_line.endswith(b'\n'):
        raise asyncio.TimeoutError()

    try:
        a, b, c = request_line.strip().split(b' ', 2)
    except ValueError as err:
        raise ValueError('request_line: %r, %r' % (request_line, err)) from err
    return request_line, a, b, c


async def read_header_data(reader, timeout=1):
    header_data = b''
    while True:
        fut = reader.readline()
        line = await asyncio.wait_for(fut, timeout=timeout)
        header_data += line
        if not line.strip():
            break
    return header_data


async def read_headers(reader, timeout=1):
    header_data = await read_header_data(reader, timeout)
    parser = email.parser.Parser(_class=HTTPMessage)
    headers = parser.parsestr(header_data.decode('iso-8859-1'))
    return header_data, headers


class BaseHandler(BaseHTTPRequestHandler):
    bufsize = 65536
    server_version = "BaseHTTPServer/" + __version__
    default_request_version = "HTTP/1.1"

    def __init__(self, server):  # pylint: disable=super-init-not-called
        # Not calling super-init, not for TCPServer
        self.server = server
        self.conf = server.conf
        self.timeout = self.conf.timeout
        self.tcp_timeout = self.conf.tcp_timeout
        self.server_addr = (self.server.addr, self.server.port)
        response = b'\x05\x00\x00'
        self.socks5_udp_response = response
        self.logger = server.logger
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.client_reader = None
        self.client_writer = None
        self.close_connection = True
        self.req_count = 0
        self.path = ''
        self.headers = None

    async def handle(self, client_reader, client_writer):
        self.client_reader = client_reader
        self.client_writer = client_writer
        # self.client_writer.transport.set_write_buffer_limits(65536)
        if self.server.conf.tcp_nodelay:
            soc = self.client_writer.transport.get_extra_info('socket')
            soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.client_address = client_writer.get_extra_info('peername')
        self.logger.debug('incoming connection %s', self.client_address)

        self.wfile = client_writer

        self.remote_writer = None

        self.close_connection = True
        self.request_host = None

        await self._handle()

        if self.client_writer:
            self.client_writer.close()
            try:
                await self.client_writer.wait_closed()
            except OSError:
                pass

    async def _handle(self):
        fut = self.client_reader.readexactly(1)
        try:
            first_byte = await asyncio.wait_for(fut, timeout=10)
        except (TimeoutError, IncompleteReadError, ConnectionError):
            return
        if first_byte == b'\x05':
            self.close_connection = True
            await self.handle_socks5()
        else:
            await self.handle_one_request(first_byte)
            while not self.close_connection:
                await self.handle_one_request()
        if self.remote_writer:
            self.logger.error('BaseHandler: remote_writer in handler.')

    def pre_request_init(self):
        self.req_count += 1
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.close_connection = True

    async def handle_socks5(self):
        self.pre_request_init()
        self.command = 'CONNECT'
        # Client greeting
        fut = self.client_reader.readexactly(1)
        try:
            auth_len = await asyncio.wait_for(fut, timeout=1)
        except ConnectionError:
            return
        fut = self.client_reader.readexactly(auth_len[0])
        auth = await asyncio.wait_for(fut, timeout=1)
        if b'\x00' not in auth:
            self.logger.error('socks5 auth not supported')
            self.client_writer.write(b'\x05\xff')
            return
        self.client_writer.write(b'\x05\x00')
        # Client connection request
        fut = self.client_reader.readexactly(4)
        try:
            request = await asyncio.wait_for(fut, timeout=1)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return
        addrtype = request[3]
        if addrtype == 1:  # ipv4
            fut = self.client_reader.readexactly(4)
            addr = await asyncio.wait_for(fut, timeout=1)
            addr = socket.inet_ntoa(addr)
        elif addrtype == 3:  # hostname
            fut = self.client_reader.readexactly(1)
            addrlen = await asyncio.wait_for(fut, timeout=1)
            fut = self.client_reader.readexactly(addrlen[0])
            addr = await asyncio.wait_for(fut, timeout=1)
            addr = addr.decode()
        elif addrtype == 4:  # ipv6
            fut = self.client_reader.readexactly(16)
            addr = await asyncio.wait_for(fut, timeout=1)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
            addr = '[' + addr + ']'
        else:
            self.logger.error('socks5 bad addr type')
            self.client_writer.write(
                b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        fut = self.client_reader.readexactly(2)
        port = await asyncio.wait_for(fut, timeout=1)
        port = struct.unpack(b">H", port)[0]

        if request[1] == 2:
            self.logger.error('socks5 BIND not supported')
            self.client_writer.write(
                b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        if request[1] == 3:
            self.command = 'UDP_ASSOCIATE'
            self.path = 'udp'
            if sys.platform == 'win32' and sys.version_info < (3, 8):
                self.logger.error('socks5 UDP ASSOCIATE not supported')
                # self.client_writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            if not self.server.udp_enable:
                self.logger.error('socks5 UDP ASSOCIATE not enable')
                # self.client_writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            await self.relay_udp()
            return
        # gather request info for CONNECT method...
        self.path = '%s:%s' % (addr, port)

        await self.do_CONNECT(socks5=True)  # pylint: disable=E1101

    async def relay_udp(self):
        soc = self.client_writer.transport.get_extra_info('socket')
        set_keepalive(soc)

        udp_server = await self.server.get_udp_server(self)
        addr = await udp_server.bind()
        buf = self.socks5_udp_response
        serverip = ipaddress.ip_address(addr[0])
        buf += b'\x01' if serverip.version == 4 else b'\x04'
        buf += serverip.packed
        buf += struct.pack(b'>H', addr[1])
        self.client_writer.write(buf)
        try:
            await self.client_reader.read()
        except OSError:
            pass

    async def handle_one_request(self, first_byte=b''):
        self.pre_request_init()

        try:
            # read request line
            self.requestline, command, path, request_version = \
                await read_response_line(self.client_reader, 60, first_byte)

            # read headers
            _, self.headers = await read_headers(self.client_reader)
        except (asyncio.TimeoutError, ConnectionError) as err:
            self.logger.debug('base_handler read request failed! %r', err)
            self.close_connection = True
            return
        except ValueError as err:
            self.logger.error('base_handler read request failed! %r', err)
            self.close_connection = True
            return

        try:
            self.command = command.decode('ascii')
            self.path = path.decode('ascii')
            self.request_version = request_version.decode('ascii')
        except UnicodeDecodeError:
            self.logger.error('Bad requestline: %r', self.requestline)
            self.close_connection = True
            return
        base_version_number = self.request_version.split('/', 1)[1]
        version_number = base_version_number.split(".")
        version_number = int(version_number[0]), int(version_number[1])
        if version_number == (1, 1):
            self.close_connection = False

        # look for a Connection directive
        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif conntype.lower() == 'keep-alive':
            self.close_connection = False

        # call method function
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.logger.error('%s NOT_IMPLEMENTED', mname)
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED,
                "Unsupported method (%r)" % self.command)
            await self.client_writer.drain()
            return
        method = getattr(self, mname)
        await method()

    def log_message(self, _format, *args):
        pass
