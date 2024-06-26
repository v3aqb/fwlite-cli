
# Copyright (C) 2014-2019 v3aqb

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

import logging
import re
import io
import base64
import json
import time

import urllib.parse as urlparse
from ipaddress import ip_address

import asyncio
import asyncio.streams

from .socks5udp import Socks5UDPServer
from .connection import open_connection
from .base_handler import BaseHandler, read_header_data, read_headers
from .httputil import ConnectionPool
from .util import extract_tls_extension, parse_hostport
from .hxscommon import ConnectionDenied

MAX_TIMEOUT = 16
MAX_TIMEOUT2 = 300
WELCOME = '''<!DOCTYPE html>
<html>
<body>
<p>fwlite running...</p>
<p><a href="http://{host}:{port}/api/log">Check Log</a></p>
<p><a href="http://{host}:{port}/api/localrule">Local Rule</a></p>
<p><a href="http://{host}:{port}/api/proxy">Proxy</a></p>
</body>
</html>'''
UDP_SCHEME = ['',
              'ss',
              'hxs2',
              ]


class ClientError(Exception):
    def __init__(self, err):
        self.err = err
        super().__init__()


class ClientReadError(ClientError):
    def __repr__(self):
        return 'ClientReadError: ' + repr(self.err)


class ClientWriteError(ClientError):
    def __repr__(self):
        return 'ClientWriteError: ' + repr(self.err)


class ForwardContext:
    def __init__(self, target):
        self.last_active = time.monotonic()
        self.first_send = 0
        self.target = target
        self.forward_break = False
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # link status
        self.writeable = True
        self.readable = True
        # result
        self.err = None
        # count
        self.fcc = 0
        self.frc = 0

    def from_client(self):
        self.fcc += 1
        self.last_active = time.monotonic()
        if not self.first_send:
            self.first_send = time.monotonic()

    def from_remote(self):
        self.frc += 1
        self.last_active = time.monotonic()

    @property
    def retryable(self):
        return self.frc == 0

    def __repr__(self):
        lasting = time.monotonic() - self.first_send if self.first_send else 0
        return f'{self.target} fc: {self.fcc} fr: {self.frc} leof: {self.local_eof}, exist {lasting:.2f}s'


class Server:

    def __init__(self, addr, port, _class, mode, conf):
        self._class = _class
        self.mode = mode
        self.addr = addr
        self.port = port
        self.conf = conf
        self.udp_enable = self.conf.udp_enable
        self.udp_server_holder = {}  # {client_ip: socks5_udp_server}
        self.server = None
        self.lock = asyncio.Lock()

        self.logger = logging.getLogger('fwlite_%d' % port)
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: %s %s', port, mode)

    async def handle(self, reader, writer):
        _handler = self._class(self)
        await _handler.handle(reader, writer)

    async def _start(self):
        self.server = await asyncio.start_server(self.handle, self.addr, self.port, limit=65536)

    def start(self):
        asyncio.ensure_future(self._start())

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def get_udp_server(self, handler):
        async with self.lock:
            client_ip = handler.client_address[0]
            if client_ip not in self.udp_server_holder:
                self.udp_server_holder[client_ip] = Socks5UDPServer(handler, self.conf.udp_timeout)
            return self.udp_server_holder[client_ip]


class BaseProxyHandler(BaseHandler):
    def __init__(self, server):
        super().__init__(server)
        self.mode = self.server.mode
        self.shortpath = ''  # for logging
        self._proxylist = None
        self.path = ''
        self.ppname = ''
        self.pproxy = None
        self.rbuffer = []
        self.wbuffer = []
        self.wbuffer_size = 0
        self.retryable = True
        self.request_host = None
        # for dns, GET method hostname, gfwlist domain match, getproxy log, getproxy priority
        self.client_writer = None
        self.remote_reader = None
        self.remote_writer = None
        self.request_ip = None
        self.retry_count = 0
        self.failed_parents = []
        self.close_connection = True
        self.timeout = MAX_TIMEOUT2
        self.ctimeout = MAX_TIMEOUT

    def pre_request_init(self):
        super().pre_request_init()

        self.shortpath = ''
        self._proxylist = None
        self.ppname = ''
        self.pproxy = None
        self.rbuffer = []
        self.wbuffer = []
        self.wbuffer_size = 0
        self.retryable = True
        self.request_host = None
        self.remote_reader = None
        self.remote_writer = None
        self.request_ip = None
        self.retry_count = 0
        self.failed_parents = []

    def write(self, code=200, msg=None, ctype=None, data=b''):
        '''
        Write http response to client.

        For PAC and rpc-api only.
        '''
        if msg and not isinstance(msg, bytes):
            msg = msg.encode('UTF-8')
        if not isinstance(data, bytes):
            data = data.encode('UTF-8')
        self.send_response(code, msg)
        if ctype:
            self.send_header('Content-type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.wfile.write(data)

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header('Connection', 'keep_alive')
        self.send_header("Content-Length", '0')
        self.end_headers()

    async def client_reader_read(self, size, timeout=1):
        fut = self.client_reader.read(size)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except (asyncio.TimeoutError, ConnectionError) as err:
            raise ClientReadError(err) from err

    async def client_reader_readexactly(self, size, timeout=1):
        fut = self.client_reader.readexactly(size)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as err:
            raise ClientReadError(err) from err

    async def client_reader_readline(self, timeout=1):
        fut = self.client_reader.readline()
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError) as err:
            raise ClientReadError(err) from err

    async def client_reader_readuntil(self, sep, timeout=1):
        fut = self.client_reader.readuntil(sep)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError) as err:
            raise ClientReadError(err) from err

    async def _client_writer_write(self, data):  # pylint: disable=E0203
        # write to self.client_writer
        self.retryable = False
        # self.traffic_count[1] += len(data)
        self.client_writer.write(data)
        try:
            await self.client_writer.drain()
        except ConnectionError as err:
            self.client_writer = None
            raise ClientWriteError(err) from err

    async def client_writer_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                await self._client_writer_write(b''.join(self.wbuffer))
                self.wbuffer = []
            if data:
                await self._client_writer_write(data)

    async def read_resp_line(self, timeout):
        fut = self.remote_reader.readline()
        response_line = await asyncio.wait_for(fut, timeout)
        split = response_line.split()
        if len(split) < 2:
            self.logger.error(f'incomplete response line: {response_line:r}')
            raise ValueError('incomplete response line')
        protocol_version = split[0]
        response_status = split[1]
        reason = b' '.join(split[2:])
        status = int(response_status)
        return response_line, protocol_version, status, reason


class http_handler(BaseProxyHandler):
    HTTPCONN_POOL = ConnectionPool()

    async def do_GET(self):
        # self.logger.info('req_count %s' % self.req_count)
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            self.send_error(400, explain='GET ftp:// not supported')
            return

        if self.path == '/pac':
            if self.headers['Host'].startswith(self.conf.local_ip):
                self.write(msg=self.conf.PAC, ctype='application/x-ns-proxy-autoconfig')
                return

        # transparent proxy
        if self.path.startswith('/'):
            if 'Host' not in self.headers:
                self.send_error(400, explain='Host not in headers')
                return
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)

        # fix request
        if self.path.startswith('http://http://'):
            self.path = self.path[7:]

        parse = urlparse.urlparse(self.path)

        self.shortpath = '%s://%s%s%s' % (parse.scheme,
                                          parse.netloc,
                                          parse.path.split(':')[0],
                                          '?' if parse.query else '')

        self.request_host = parse_hostport(parse.netloc, 80)

        # if self.request_host[1] == 80:
        #     self.headers['Host'] = self.request_host[0]
        # else:
        #     self.headers['Host'] = '%s:%d' % (self.request_host)

        # redirector
        new_url = self.conf.cic.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s', new_url, self.command, self.shortpath)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.send_error(int(new_url))
                return
            if new_url.lower() == 'return':
                # request handled by redirector, return
                self.logger.info('%s %s return', self.command, self.shortpath)
                return
            if all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # sort by priority?
                # random.shuffle(self._proxylist)
            else:
                self.logger.info('redirect %s %s', self.shortpath, new_url)
                self.redirect(new_url)
                return

        self.shortpath = '%s://%s%s%s' % (parse.scheme,
                                          parse.netloc,
                                          parse.path.split(':')[0],
                                          '?' if parse.query else '')

        self.request_ip = await self.conf.cic.resolver.get_ip_address(self.request_host, self.mode)

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] == self.conf.listen[1]:
                    if parse.path == '/' and self.command == 'GET':
                        self.write(200, data=WELCOME.format(host=self.request_host[0],
                                                            port=self.request_host[1]),
                                   ctype='text/html; charset=utf-8')
                        return
                    await self.api(parse)
                    return
            else:
                self.send_error(403)
                return

        if str(self.request_ip) == self.client_writer.get_extra_info('sockname')[0]:
            if self.request_host[1] == self.conf.listen[1]:
                if parse.path == '/' and self.command == 'GET':
                    self.write(200, data=WELCOME.format(host=self.request_host[0],
                                                        port=self.request_host[1]),
                               ctype='text/html; charset=utf-8')
                    return
                if not self.conf.remoteapi:
                    self.send_error(403)
                    return
                await self.api(parse)
                await self.client_writer.drain()
                return

        del_headers = \
            ['Proxy-Connection',
             'Proxy-Authenticate',
             'X-Forwarded-For',
             ]
        for header in del_headers:
            if header in self.headers:
                del self.headers[header]

        await self._do_GET()

    async def _do_GET(self, retry=False):
        try:
            if retry:
                self.failed_parents.append(self.ppname)
                self.retry_count += 1
                if self.retry_count > 10:
                    self.retryable = False
                    self.logger.error('retry time exceeded 10, pls check!')
                if self.command not in ('GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'):
                    self.retryable = False
            if not self.retryable:
                self.close_connection = True
                self.conf.cic.notify(self.command, self.shortpath, self.request_host, False,
                                     self.failed_parents, self.ppname)
                self.logger.warning(f'{self.command} {self.shortpath} not retryable.')
                return

            self.set_timeout()

            if self.getparent():
                # if no more proxy available
                self.conf.cic.notify(self.command, self.shortpath, self.request_host, False,
                                     self.failed_parents, self.ppname)
                self.logger.warning(f'{self.command} {self.shortpath} no more proxy available.')
                return self.send_error(504, explain='no more proxy available')

            # try get from connection pool
            if not self.failed_parents:
                result = self.HTTPCONN_POOL.get((self.client_address[0], self.request_host))
                if result:
                    self._proxylist.insert(0, self.conf.parentlist.get(self.ppname))
                    sock, self.ppname = result
                    self.remote_reader, self.remote_writer = sock
                    self.logger.info('%s %s via %s (pooled)',
                                     self.command, self.shortpath, self.ppname)

            if not self.remote_writer:
                iplist = []
                if self.pproxy.name == '_D1R3CT_' and \
                        self.request_host[0] in self.conf.HOSTS and \
                        not self.failed_parents:
                    iplist = self.conf.HOSTS.get(self.request_host[0])
                    self._proxylist.insert(0, self.pproxy)

                self.logger.info('%s %s via %s',
                                 self.command, self.shortpath, self.pproxy.name)

                addr, port = self.request_host
                # addr, port, proxy=None, timeout=3, iplist=None, tunnel=False
                self.remote_reader, self.remote_writer, self.ppname = \
                    await open_connection(addr, port, self.pproxy, self.ctimeout, iplist, False)

                if self.ppname != self.pproxy.name:
                    self._proxylist.insert(0, self.pproxy)

            # write buffer for retry
            self.wbuffer = []
            self.wbuffer_size = 0
            # prep request header
            req = []
            if self.pproxy.proxy.startswith('http'):
                req.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
                if self.pproxy.username:
                    auth = '%s:%s' % (self.pproxy.username, self.pproxy.password)
                    req.append('Proxy-Authorization: Basic %s' % base64.b64encode(auth.encode()).decode())
            else:
                req.append('%s /%s %s\r\n' % (self.command,
                                              '/'.join(self.path.split('/')[3:]),
                                              self.request_version))
            # Does the client want to close connection after this request?
            conntype = self.headers.get('Connection', "")
            if self.request_version >= "HTTP/1.1":
                self.close_connection |= 'close' in conntype.lower()
            else:
                self.close_connection |= 'keep_alive' in conntype.lower()
            if 'Upgrade' in self.headers:
                self.close_connection = True
                self.logger.warning('Upgrade header found! (%s)', self.headers['Upgrade'])
                # del self.headers['Upgrade']

            for key, val in self.headers.items():
                if isinstance(val, bytes):
                    val = val.decode('latin1')
                req.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in key.split("-")]), val))
            req.append("\r\n")
            data = ''.join(req).encode('latin1')

            # send request header
            self.remote_writer.write(data)
            # self.traffic_count[0] += len(data)

            # Expect
            skip = False
            if 'Expect' in self.headers:
                try:
                    response_line, protocol_version, response_status, _ = \
                        await self.read_resp_line(self.ctimeout)
                except (asyncio.TimeoutError, ValueError, OSError) as err:
                    # TODO: probably the server don't handle Expect well.
                    self.logger.warning('read response line error(Expect): %r', err)
                else:
                    if response_status == 100:
                        hdata = await read_header_data(self.remote_reader, timeout=self.ctimeout)
                        await self._client_writer_write(response_line + hdata)
                    else:
                        skip = True
            # send request body
            if not skip:
                if "Content-Length" in self.headers:
                    if "," in self.headers["Content-Length"]:
                        # Proxies sometimes cause Content-Length headers to get
                        # duplicated.  If all the values are identical then we can
                        # use them but if they differ it's an error.
                        pieces = re.split(r',\s*', self.headers["Content-Length"])
                        if any(i != pieces[0] for i in pieces):
                            raise ValueError("Multiple unequal Content-Lengths: %r" %
                                             self.headers["Content-Length"])
                        self.headers["Content-Length"] = pieces[0]
                    content_length = int(self.headers["Content-Length"])
                else:
                    content_length = None
                if "chunked" in self.headers.get("Transfer-Encoding", ""):
                    if self.rbuffer:
                        self.remote_writer.write(b''.join(self.rbuffer))
                    flag = 1
                    req_body_len = 0
                    while flag:
                        trunk_lenth = await self.client_reader_readline()
                        if self.retryable:
                            self.rbuffer.append(trunk_lenth)
                            req_body_len += len(trunk_lenth)
                        self.remote_writer.write(trunk_lenth)
                        trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                        flag = trunk_lenth != 2
                        data = self.client_reader_readexactly(trunk_lenth)
                        if self.retryable:
                            self.rbuffer.append(data)
                            req_body_len += len(data)
                        self.remote_writer.write(data)
                        await self.remote_writer.drain()
                        if req_body_len > 102400:
                            self.retryable = False
                            self.rbuffer = []
                elif content_length is not None:
                    if content_length > 102400:
                        self.retryable = False
                    if self.rbuffer:
                        data = b''.join(self.rbuffer)
                        content_length -= len(data)
                        self.remote_writer.write(data)
                    while content_length:
                        data = await self.client_reader_readexactly(min(self.bufsize,
                                                                        content_length))
                        if not data:
                            break
                        content_length -= len(data)
                        if self.retryable:
                            self.rbuffer.append(data)
                        self.remote_writer.write(data)
                        await self.remote_writer.drain()
                elif self.command == 'POST':
                    self.close_connection = True
                    while True:
                        data = await self.client_reader_read(self.bufsize)
                        if not data:
                            self.remote_writer.send_eof()
                            break
                        self.remote_writer.write(data)
                        await self.remote_writer.drain()
            # read response line
            timelog = time.monotonic()
            response_line, protocol_version, response_status, _ = await self.read_resp_line(self.timeout)
            rtime = time.monotonic() - timelog
            # read response headers
            while response_status == 100:
                hdata = await read_header_data(self.remote_reader, timeout=self.ctimeout)
                await self._client_writer_write(response_line + hdata)
                response_line, protocol_version, response_status, _ = \
                    await self.read_resp_line(self.ctimeout)

            header_data, response_header = await read_headers(self.remote_reader, self.ctimeout)

            # check response headers
            conntype = response_header.get('Connection', "")
            if protocol_version >= b"HTTP/1.1":
                remote_close = 'close' in conntype.lower()
            else:
                remote_close = 'keep_alive' not in conntype.lower()
            if 'Upgrade' in response_header:
                self.close_connection = remote_close = True
            if "Content-Length" in response_header:
                if "," in response_header["Content-Length"]:
                    # Proxies sometimes cause Content-Length headers to get
                    # duplicated.  If all the values are identical then we can
                    # use them but if they differ it's an error.
                    pieces = re.split(r',\s*', response_header["Content-Length"])
                    if any(i != pieces[0] for i in pieces):
                        raise ValueError("Multiple unequal Content-Lengths: %r" %
                                         response_header["Content-Length"])
                    response_header["Content-Length"] = pieces[0]
                content_length = int(response_header["Content-Length"])
            else:
                content_length = None

            await self.client_writer_write(response_line)
            await self.client_writer_write(header_data)
            # read response body
            if self.command == 'HEAD' or response_status in (204, 205, 304):
                pass
            elif 'chunked' in response_header.get("Transfer-Encoding", ""):
                flag = 1
                while flag:
                    trunk_lenth = await self.remote_reader.readline()
                    await self.client_writer_write(trunk_lenth)
                    trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                    flag = trunk_lenth != 2
                    while trunk_lenth:
                        data = await self.remote_reader.read(min(self.bufsize, trunk_lenth))
                        # self.logger.info('chunk data received %d %s', len(data), self.path)
                        trunk_lenth -= len(data)
                        await self.client_writer_write(data)
            elif content_length is not None:
                while content_length:
                    data = await self.remote_reader.read(min(self.bufsize, content_length))
                    if not data:
                        raise ConnectionError(0, 'remote socket closed')
                    # self.logger.info('content_length data received %d %s', len(data), self.path)
                    content_length -= len(data)
                    await self.client_writer_write(data)
            elif 'Upgrade' in response_header:
                # if Upgrade in headers, websocket?
                #     forward tcp
                self.logger.info('Upgrade: %s', response_header['Upgrade'])
                self.close_connection = True
                self.retryable = False
                # flush writer buf
                await self.client_writer_write()

                # start forwarding...
                context = ForwardContext(self.path)
                context = await self.forward(context, timeout=60)
                if context.timeout:
                    # no response from server
                    pass
            elif content_length is None:
                # http/1.0 response, content_lenth not in header
                #     read response body until connection closed
                self.close_connection = True
                while True:
                    data = await self.remote_reader.read(self.bufsize)
                    if not data:
                        break
                    await self.client_writer_write(data)
            else:
                self.logger.error('forward response body error.')

            await self.client_writer_write()
            self.conf.cic.notify(self.command, self.shortpath, self.request_host, True,
                                 self.failed_parents, self.ppname)
            self.conf.proxy_log(self.pproxy, self.request_host[0], rtime)
            if remote_close or self.close_connection:
                self.remote_writer.close()
                try:
                    await self.remote_writer.wait_closed()
                except ConnectionError:
                    pass
                self.close_connection = True
            else:
                # keep for next request
                self.HTTPCONN_POOL.put((self.client_address[0], self.request_host),
                                       (self.remote_reader, self.remote_writer),
                                       self.ppname)
            self.remote_writer = None
        except ConnectionDenied as err:
            self.logger.warning('%s %s via %s failed on connect! %r',
                                self.command, self.shortpath or self.path, self.ppname, err)
            self.close_connection = True
            return
        except ClientError as err:
            self.logger.error('ClientError: %r', err)
            self.close_connection = True
            self.remote_writer.close()
            try:
                await self.remote_writer.wait_closed()
            except ConnectionError:
                pass
            self.remote_writer = None
            return
        except (asyncio.TimeoutError,
                OSError, ValueError, asyncio.IncompleteReadError) as err:
            if self.remote_writer:
                self.remote_writer.close()
                try:
                    await self.remote_writer.wait_closed()
                except ConnectionError:
                    pass
                self.remote_writer = None
            if self.ppname:
                self.logger.warning('%s %s via %s failed: %r',
                                    self.command, self.shortpath, self.ppname, err)
                self.conf.proxy_log(self.pproxy, self.request_host[0], MAX_TIMEOUT)
                await self._do_GET(True)
                return
            self.conf.cic.notify(self.command, self.shortpath, self.request_host, False,
                                 self.failed_parents, self.ppname)
            return self.send_error(504)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = do_GET

    async def do_CONNECT(self, socks5=False):
        self.close_connection = True
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')

        if socks5:
            self.client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        else:
            self.client_writer.write(self.protocol_version.encode() + b" 200 Connection established\r\n\r\n")

        self.rbuffer = []
        gfwed = False
        # fix SNI
        try:
            data = await self.client_reader_read(4)

            if data.startswith(b'\x16\x03'):
                # parse SNI
                data += await self.client_reader_read(8192)
                try:
                    tls_extensions = extract_tls_extension(data)
                    server_name = tls_extensions.get(0, b'')[5:].decode()
                    esni1 = 0xffce in tls_extensions
                    esni7 = 0xff02 in tls_extensions
                    esni = esni1 or esni7
                    gfwed = esni1
                    if server_name:
                        self.shortpath = server_name
                except Exception:
                    self.logger.info('date_len %d' % len(data), exc_info=True)
            elif data in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'OPTI', b'PATC', b'TRAC'):
                data += await self.client_reader_read(8192)
                for line in data.splitlines():
                    if line.startswith(b'Host: '):
                        self.shortpath = parse_hostport(line.strip().decode()[6:])[0]
                        break
        except ClientError:
            return

        if data:
            self.rbuffer.append(data)

        self.request_host = parse_hostport(self.path, 443)
        if self.shortpath:
            if self.path.startswith(self.shortpath):
                self.shortpath = None
            else:
                self.logger.info('SNI_REWRITE: path: %s, sni: %s', self.path, self.shortpath)
                self.request_host = (self.shortpath, self.request_host[1])
                self.shortpath = '%s:%d' % self.request_host

        # redirector
        new_url = self.conf.cic.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s', new_url, self.command, self.path)
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.logger.info('%s %s send error %s', self.command, self.path, new_url)
                return
            if all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # random.shuffle(self._proxylist)

        self.request_ip = await self.conf.cic.resolver.get_ip_address(self.request_host, self.mode)

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] in range(self.conf.listen[1],
                                                 self.conf.listen[1] + len(self.conf.profile)):
                    # prevent loop
                    return
            else:
                return
        await self._do_CONNECT(gfwed=gfwed)

    async def _do_CONNECT(self, retry=False, gfwed=False):
        if retry:
            self.failed_parents.append(self.ppname)
            self.retry_count += 1
            if self.retry_count > 10:
                self.logger.error('retry time exceeded 10, pls check!')
                return

        if self.getparent(gfwed=gfwed):
            self.conf.cic.notify(self.command, self.shortpath or self.path, self.request_host,
                                 False, self.failed_parents, self.ppname)
            return

        iplist = None
        if self.pproxy.name == '_D1R3CT_' and\
                self.request_host[0] in self.conf.HOSTS and not self.failed_parents:
            iplist = self.conf.HOSTS.get(self.request_host[0])
            self._proxylist.insert(0, self.pproxy)

        self.set_timeout()

        do_reconnect = False
        try:
            self.logger.info('%s %s via %s. %s', self.command, self.shortpath or self.path,
                             self.pproxy.name, self.client_address[1])
            path = self.path if self.pproxy.name == '_D1R3CT_' else self.shortpath or self.path
            addr, port = parse_hostport(path, 443)
            self.remote_reader, self.remote_writer, self.ppname = \
                await open_connection(addr, port, self.pproxy, self.ctimeout, iplist, True)
        except ConnectionDenied as err:
            self.logger.warning('%s %s via %s failed on connect! %r',
                                self.command, self.shortpath or self.path, self.ppname, err)
            self.conf.cic.notify(self.command, self.shortpath or self.path, self.request_host,
                                 False, self.failed_parents, self.ppname)
            do_reconnect = True
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError) as err:
            self.logger.warning('%s %s via %s failed on connect! %r',
                                self.command, self.shortpath or self.path, self.ppname, err)
            self.conf.proxy_log(self.pproxy, self.request_host[0], MAX_TIMEOUT)
            self.conf.cic.notify(self.command, self.shortpath or self.path, self.request_host,
                                 False, self.failed_parents, self.ppname)
            do_reconnect = True
        except Exception:
            self.conf.cic.notify(self.command, self.shortpath or self.path, self.request_host,
                                 False, self.failed_parents, self.ppname)
            self.logger.error('CONNECT create connection failed.', exc_info=True)
            return
        self.logger.debug('%s connected', self.path)

        if do_reconnect:
            await self._do_CONNECT(True)
            return

        # forward
        context = ForwardContext(self.path)
        await self.forward(context)
        if context.retryable:
            self.logger.info('%r', context)
            self.conf.proxy_log(self.pproxy, self.request_host[0], MAX_TIMEOUT)
            self.conf.cic.notify(self.command, self.shortpath or self.path, self.request_host,
                                 False, self.failed_parents, self.ppname)
            if not context.local_eof:
                await self._do_CONNECT(retry=True)

    async def forward(self, context, timeout=None):
        if not timeout:
            timeout = self.tcp_timeout

        tasks = [asyncio.create_task(self.forward_from_client(self.client_reader,
                                                              self.remote_writer,
                                                              context, timeout)),
                 asyncio.create_task(self.forward_from_remote(self.remote_reader,
                                                              self.client_writer,
                                                              context, timeout)),
                 ]
        try:
            await asyncio.wait(tasks)
        finally:
            self.remote_writer.close()
            try:
                await self.remote_writer.wait_closed()
            except OSError:
                pass
            self.remote_writer = None

    async def forward_from_client(self, read_from, write_to, context, timeout):
        if self.command == 'CONNECT':
            # send self.rbuffer
            if self.rbuffer:
                write_to.write(b''.join(self.rbuffer))
                context.from_client()
        while not context.local_eof:
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=1)
            except asyncio.TimeoutError:
                if context.forward_break:
                    return
                idle_time = time.monotonic() - context.last_active
                if idle_time > self.ctimeout and context.remote_eof:
                    self.logger.debug('forward_from_client timeout with eof recieved from remote')
                    break
                if idle_time > timeout:
                    self.logger.debug('forward_from_client idle timeout, %ss', timeout)
                    break
                continue
            except OSError as err:
                self.logger.debug('forward_from_client %r', err)
                context.local_eof = True
                context.remote_eof = True
                write_to.close()
                return

            if not data:
                self.logger.debug('forward_from_client no data')
                break
            if context.retryable:
                self.rbuffer.append(data)
            context.from_client()
            try:
                write_to.write(data)
                await write_to.drain()
            except (OSError, RuntimeError):
                context.remote_eof = True
                return
        # client closed, tell remote
        context.local_eof = True
        try:
            write_to.write_eof()
        except (OSError, RuntimeError):
            pass

    async def forward_from_remote(self, read_from, write_to, context, timeout):
        while not context.remote_eof:
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, 1)
            except OSError as err:
                self.logger.debug('forward_from_remote %s %r', context.target, err)
                context.forward_break = True
                break
            except asyncio.TimeoutError:
                idle_time = time.monotonic() - context.last_active
                if self.request_host[1] < 1024 and context.retryable and idle_time > self.timeout:
                    self.logger.info('forward_from_remote timeout, retryable')
                    context.forward_break = True
                    break
                if context.local_eof and idle_time > self.ctimeout:
                    self.logger.debug('forward_from_remote timeout with eof recieved from client')
                    break
                continue

            if not data:
                self.logger.debug('forward_from_remote no data')
                break

            if context.retryable:
                # first response
                rtime = time.monotonic() - context.first_send
                if self.command == 'CONNECT':
                    # log server response time
                    self.conf.proxy_log(self.pproxy, self.request_host[0], rtime)
                    self.conf.cic.notify(self.command,
                                         self.shortpath or self.path,
                                         self.request_host,
                                         True,
                                         self.failed_parents,
                                         self.ppname)
            context.from_remote()
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionError:
                # client closed
                self.logger.debug('forward_from_remote client closed.')
                context.remote_eof = True
                context.local_eof = True
                return
        context.remote_eof = True
        if not context.retryable:
            try:
                write_to.write_eof()
            except (OSError, RuntimeError):
                pass

    def getparent(self, gfwed=False):
        if self._proxylist is None:
            mode = max(3, self.mode) if gfwed else self.mode
            self._proxylist = self.conf.cic.get_proxy(
                self.shortpath or self.path, self.request_host, self.command,
                self.request_ip, mode)
        if not self._proxylist:
            self.ppname = ''
            self.pproxy = None
            if self.failed_parents:
                self.logger.error('no more proxy available.')
            return 1
        self.pproxy = self._proxylist.pop(0)
        self.ppname = self.pproxy.name
        return 0

    def set_timeout(self):
        if self._proxylist:
            if self.ppname == '_D1R3CT_':
                self.ctimeout = self.conf.timeout
            else:
                self.ctimeout = min(2 ** len(self.failed_parents) + self.conf.timeout - 1,
                                    MAX_TIMEOUT)
        else:
            self.ctimeout = self.conf.timeout
        self.timeout = MAX_TIMEOUT2 if self.request_ip.is_private else MAX_TIMEOUT

    async def api(self, parse):
        '''
        path: supported command
        /api/localrule: GET POST DELETE
        '''
        self.logger.debug('api %s %s', self.command, self.path)
        # read request body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 102400:
            return
        body = io.BytesIO()
        while content_length:
            data = await self.client_reader_readexactly(min(self.bufsize, content_length))
            if not data:
                return
            content_length -= len(data)
            body.write(data)
        body = body.getvalue()

        # check password
        if self.conf.remotepass:
            if 'Authorization' not in self.headers:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic')
                self.send_header("Content-Length", '0')
                self.end_headers()
                return

            auth = self.headers['Authorization'].split()[1]
            _password = base64.b64decode(auth).decode().split(':', 1)[1]
            if _password != self.conf.remotepass:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic')
                self.send_header("Content-Length", '0')
                self.end_headers()
                return

        if parse.path == '/api/localrule' and self.command == 'GET':
            data = json.dumps(self.conf.cic.list_localrule(), indent=4)
            self.write(code=200, data=data, ctype='application/json')
            return
        if parse.path == '/api/localrule' and self.command == 'POST':
            # accept a json encoded tuple: (str rule, int exp)
            rule, exp = json.loads(body)
            self.conf.cic.add_localrule(rule, exp)
            self.write(200)
            return
        if parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = base64.urlsafe_b64decode(parse.path[15:].encode('latin1')).decode()
                self.conf.cic.del_localrule(rule)
                self.write(200)
                return
            except Exception as err:
                self.logger.error('api error /api/localrule/', exc_info=True)
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/inspect':
            url = body.decode('utf8')
            result = self.conf.cic.inspect(url)
            self.write(200, data=result, ctype='text/plain')
            return
        if parse.path == '/api/redirector' and self.command == 'GET':
            data = json.dumps(self.conf.cic.list_redir(), indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/redirector' and self.command == 'POST':
            # accept a json encoded tuple: (str rule, str dest)
            rule, dest = json.loads(body)
            self.conf.cic.add_redir(rule, dest)
            self.write(200)
            return
        if parse.path.startswith('/api/redirector/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                rule = base64.urlsafe_b64decode(rule).decode()
                self.conf.cic.del_redir(rule)
                self.write(200)
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/proxy' and self.command == 'GET':
            data = self.conf.list_proxy()
            data = json.dumps(data, indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/proxy' and self.command == 'POST':
            # accept a json encoded tuple: (str name, str proxy)
            name, proxy = json.loads(body)
            if 'FWLITE:' in name:
                self.send_error(400)
                return
            if name == '_L0C4L_':
                self.send_error(400)
                return
            try:
                self.conf.add_proxy(name, proxy)
                self.write(200)
            except ValueError:
                self.send_error(400)
            return
        if parse.path.startswith('/api/proxy/') and self.command == 'DELETE':
            try:
                proxy_name = parse.path[11:]
                proxy_name = base64.urlsafe_b64decode(proxy_name).decode()
                self.conf.del_proxy(proxy_name)
                self.write(200)
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path.startswith('/api/proxy/') and self.command == 'GET':
            try:
                proxy_name = parse.path[11:]
                proxy_name = base64.urlsafe_b64decode(proxy_name).decode()
                proxy = self.conf.get_proxy(proxy_name)
                self.write(200, data=proxy, ctype='text/plain')
                return
            except Exception as err:
                self.send_error(404, repr(err))
                return
        if parse.path == '/api/forward' and self.command == 'GET':
            data = self.conf.list_forward()
            data = json.dumps(data, indent=4)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/forward' and self.command == 'POST':
            # accept a json encoded tuple: (str target, str proxy, int port)
            target, proxy, port = json.loads(body)
            self.conf.add_forward(target, proxy, port)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path.startswith('/api/forward/') and self.command == 'DELETE':
            data = parse.path[13:]
            port = int(data)
            self.conf.del_forward(port)
            self.write(200)
            return
        if parse.path == '/api/gfwlist' and self.command == 'GET':
            self.write(200, data=json.dumps(self.conf.gfwlist_enable), ctype='application/json')
            return
        if parse.path == '/api/gfwlist' and self.command == 'POST':
            self.conf.gfwlist_enable = json.loads(body)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/adblock' and self.command == 'GET':
            self.write(200, data=json.dumps(self.conf.adblock_enable), ctype='application/json')
            return
        if parse.path == '/api/adblock' and self.command == 'POST':
            self.conf.adblock_enable = json.loads(body)
            self.write(200, data=data, ctype='application/json')
            return
        if parse.path == '/api/exit' and self.command == 'GET':
            self.conf.stop()
            self.write(200, data='Done!', ctype='text/html')
            return
        if parse.path == '/api/log' and self.command == 'GET':
            self.write(200, data=self.conf.get_log(), ctype='text/plain; charset=utf-8')
            return
        self.logger.error('api %s not exist.' % parse.path)
        self.send_error(404)
