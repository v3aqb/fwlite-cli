
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
import struct
import base64
import json
import time
import traceback
import email
from http.client import HTTPMessage

import urllib.parse as urlparse
from ipaddress import ip_address

import asyncio
import asyncio.streams

from .connection import open_connection
from .base_handler import base_handler, read_header_data
from .httputil import httpconn_pool

MAX_TIMEOUT = 16


class ClientError(Exception):
    def __init__(self, err):
        self.err = err


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def extract_server_name(packet):
    # https://github.com/phuslu/sniproxy/blob/master/sniproxy_py3.py
    if packet.startswith(b'\x16\x03'):
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length + 2)
        extensions_length, = struct.unpack('>h', stream.read(2))
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            if etype == 0:
                server_name = edata[5:].decode()
                return server_name


class ForwardContext:
    def __init__(self):
        self.last_active = time.time()
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # link status
        self.writeable = True
        self.readable = True
        # result
        self.timeout = None
        self.retryable = True
        self.timelog = 0


class handler_factory:

    def __init__(self, addr, port, _class, profile, conf):
        self._class = _class
        self.profile = profile
        self.addr = addr
        self.port = port
        self.conf = conf

        self.logger = logging.getLogger('fwlite_%d' % port)
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: {}'.format(port, profile))

    async def handle(self, reader, writer):
        _handler = self._class(self)
        await _handler.handle(reader, writer)


class http_handler(base_handler):
    HTTPCONN_POOL = httpconn_pool()

    def __init__(self, server):
        self.ssrealip = None
        self.shortpath = ''
        self._proxylist = None
        self.conf = server.conf
        self.ppname = ''
        self.rbuffer = []
        self.retryable = True
        base_handler.__init__(self, server)

    def write(self, code=200, msg=None, ctype=None, data=b''):
        '''
        Write http response to client.

        For PAC and rpc-api only.
        '''
        if msg is None:
            msg = b''
        if not isinstance(msg, bytes):
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
        except asyncio.CancelledError:
            raise
        except Exception as e:
            err = e
        raise ClientError(err)

    async def client_reader_readexactly(self, size, timeout=1):
        fut = self.client_reader.readexactly(size)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as e:
            err = e
        raise ClientError(err)

    async def client_reader_readline(self, timeout=1):
        fut = self.client_reader.readline()
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as e:
            err = e
        raise ClientError(err)

    async def client_reader_readuntil(self, sep, timeout=1):
        fut = self.client_reader.readuntil(sep)
        err = None
        try:
            data = await asyncio.wait_for(fut, timeout=timeout)
            return data
        except asyncio.CancelledError:
            raise
        except Exception as e:
            err = e
        raise ClientError(err)

    def _wfile_write(self, data):
        # write to self.client_writer
        self.retryable = False
        # self.traffic_count[1] += len(data)
        self.client_writer.write(data)

    def wfile_write(self, data=None):
        if data is None:
            self.retryable = False
        if self.retryable and data:
            self.wbuffer.append(data)
            self.wbuffer_size += len(data)
            if self.wbuffer_size > 102400:
                self.retryable = False
        else:
            if self.wbuffer:
                self._wfile_write(b''.join(self.wbuffer))
                self.wbuffer = []
            if data:
                self._wfile_write(data)

    def log_message(self, format, *args):
        pass

    async def read_resp_line(self):
        fut = self.remote_reader.readline()
        response_line = await asyncio.wait_for(fut, self.timeout)
        split = response_line.split()
        if len(split) < 2:
            self.logger.error('incomplete response line: %r' % response_line)
            raise ValueError('incomplete response line')
        protocol_version = split[0]
        response_status = split[1]
        response_reason = b' '.join(split[2:])
        response_status = int(response_status)
        return response_line, protocol_version, response_status, response_reason

    async def do_GET(self):
        # self.logger.info('req_count %s' % self.req_count)
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')
        if self.path.lower().startswith('ftp://'):
            return self.send_error(400)

        if self.path == '/pac':
            if self.headers['Host'].startswith(self.conf.local_ip):
                return self.write(msg=self.conf.PAC, ctype='application/x-ns-proxy-autoconfig')

        # transparent proxy
        if self.path.startswith('/'):
            if 'Host' not in self.headers:
                return self.send_error(403)
            self.path = 'http://%s%s' % (self.headers['Host'], self.path)

        # fix request
        if self.path.startswith('http://http://'):
            self.path = self.path[7:]

        parse = urlparse.urlparse(self.path)

        self.shortpath = '%s://%s%s%s%s' % (parse.scheme, parse.netloc, parse.path.split(':')[0], '?' if parse.query else '', ':' if ':' in parse.path else '')

        # redirector
        new_url = self.conf.GET_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s' % (new_url, self.command, self.shortpath or self.path))
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.send_error(int(new_url))
                return
            elif new_url.lower() == 'return':
                # request handled by redirector, return
                self.logger.info('{} {} {} return'.format(self.command, self.shortpath or self.path, self.client_address[0]))
                return
            elif new_url.lower() == 'reset':
                self.close_connection = 1
                self.logger.info('{} {} {} reset'.format(self.command, self.shortpath or self.path, self.client_address[0]))
                return
            elif all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # TODO: sort by priority?
                # random.shuffle(self._proxylist)
            else:
                self.logger.info('redirect {} {}'.format(self.shortpath or self.path, new_url))
                self.redirect(new_url)
                return

        parse = urlparse.urlparse(self.path)

        # gather info
        if 'Host' not in self.headers:
            self.logger.warning('"Host" not in self.headers')
            request_host = parse_hostport(parse.netloc, 80)
        else:
            host = parse_hostport(self.headers['Host'], 80)
            netloc = parse_hostport(parse.netloc, 80)
            if host != netloc:
                self.logger.warning('Host and URI mismatch! %s %s' % (self.path, self.headers['Host']))
                # self.headers['Host'] = parse.netloc
            request_host = parse_hostport(self.headers['Host'], 80)

        self.request_host = request_host

        # self.shortpath = '%s://%s%s%s%s' % (parse.scheme, parse.netloc, parse.path.split(':')[0], '?' if parse.query else '', ':' if ':' in parse.path else '')
        self.request_ip = await self.conf.resolver.get_ip_address(self.request_host[0])

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] in range(self.conf.listen[1], self.conf.listen[1] + self.conf.profile_num):
                    await self.api(parse)
                    return
            else:
                self.send_error(403)
                return

        if str(self.request_ip) == self.client_writer.get_extra_info('sockname')[0]:
            if self.request_host[1] in range(self.conf.listen[1], self.conf.listen[1] + len(self.conf.userconf.dget('FWLite', 'profile', '134'))):
                if self.conf.userconf.dgetbool('FWLite', 'remoteapi', False):
                    await self.api(parse)
                    await self.client_writer.drain()
                    return
                self.send_error(403)
                return

        if 'X-Forwarded-For' in self.headers:
            del self.headers['X-Forwarded-For']

        for h in ['Proxy-Connection', 'Proxy-Authenticate']:
            if h in self.headers:
                del self.headers[h]

        await self._do_GET()

    async def _do_GET(self, retry=False):
        try:
            if retry:
                self.failed_parents.append(self.ppname)
                self.retry_count += 1
                if self.retry_count > 10:
                    self.logger.error('retry time exceeded 10, pls check!')
                    return
            if not self.retryable:
                self.close_connection = 1
                self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False, self.failed_parents, self.ppname)
                return

            self.set_timeout()

            if self.getparent():
                # if no more proxy available
                self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False, self.failed_parents, self.ppname)
                return self.send_error(504)

            # try get from connection pool
            if not self.failed_parents:
                result = self.HTTPCONN_POOL.get((self.client_address[0], self.request_host))
                if result:
                    self._proxylist.insert(0, self.conf.parentlist.get(self.ppname))
                    sock, self.ppname = result
                    self.remote_reader, self.remote_writer = sock
                    self.logger.info('{} {} via {}. {}'.format(self.command, self.shortpath or self.path, self.ppname, self.client_address[1]))

            if not self.remote_writer:
                iplist = []
                if self.pproxy.name == 'direct' and self.request_host[0] in self.conf.HOSTS and not self.failed_parents:
                    iplist = self.conf.HOSTS.get(self.request_host[0])
                    self._proxylist.insert(0, self.pproxy)

                self.logger.info('{} {} via {}. {}'.format(self.command, self.shortpath or self.path, self.pproxy.name, self.client_address[1]))

                addr, port = self.request_host
                # addr, port, proxy=None, timeout=3, iplist=[], tunnel=False
                self.remote_reader, self.remote_writer, self.ppname = await open_connection(addr, port, self.pproxy, self.timeout, iplist, False)

                if self.ppname != self.pproxy.name:
                    self._proxylist.insert(0, self.pproxy)

            # write buffer for retry
            self.wbuffer = []
            self.wbuffer_size = 0
            # prep request header
            s = []
            if self.pproxy.proxy.startswith('http'):
                s.append('%s %s %s\r\n' % (self.command, self.path, self.request_version))
                if self.pproxy.username:
                    a = '%s:%s' % (self.pproxy.username, self.pproxy.password)
                    s.append('Proxy-Authorization: Basic %s' % base64.b64encode(a.encode()))
            else:
                s.append('%s /%s %s\r\n' % (self.command, '/'.join(self.path.split('/')[3:]), self.request_version))
            # Does the client want to close connection after this request?
            conntype = self.headers.get('Connection', "")
            if self.request_version >= "HTTP/1.1":
                self.close_connection |= 'close' in conntype.lower()
            else:
                self.close_connection |= 'keep_alive' in conntype.lower()
            if 'Upgrade' in self.headers:
                self.close_connection = True
                self.logger.warning('Upgrade header found! (%s)' % self.headers['Upgrade'])
                # del self.headers['Upgrade']
            else:
                # always try to keep connection alive
                self.headers['Connection'] = 'keep_alive'

            for k, v in self.headers.items():
                if isinstance(v, bytes):
                    v = v.decode('latin1')
                s.append("%s: %s\r\n" % ("-".join([w.capitalize() for w in k.split("-")]), v))
            s.append("\r\n")
            data = ''.join(s).encode('latin1')

            # send request header
            self.remote_writer.write(data)
            # self.traffic_count[0] += len(data)

            # Expect
            skip = False
            if 'Expect' in self.headers:
                try:
                    response_line, protocol_version, response_status, response_reason = \
                        await self.read_resp_line()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # TODO: probably the server don't handle Expect well.
                    self.logger.warning('read response line error: %r' % e)
                else:
                    if response_status == 100:
                        hdata = await read_header_data(self.remote_reader)
                        self._wfile_write(response_line + hdata)
                    else:
                        skip = True
            # send request body
            if not skip:
                content_length = int(self.headers.get('Content-Length', 0))
                if self.headers.get("Transfer-Encoding") and self.headers.get("Transfer-Encoding") != "identity":
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
                        if req_body_len > 102400:
                            self.retryable = False
                            self.rbuffer = []
                elif content_length > 0:
                    if content_length > 102400:
                        self.retryable = False
                    if self.rbuffer:
                        s = b''.join(self.rbuffer)
                        content_length -= len(s)
                        self.remote_writer.write(s)
                    while content_length:
                        data = await self.client_reader_readexactly(min(self.bufsize, content_length))
                        if not data:
                            break
                        content_length -= len(data)
                        if self.retryable:
                            self.rbuffer.append(data)
                        self.remote_writer.write(data)
                # read response line
                timelog = time.clock()
                fut = self.remote_reader.readline()
                response_line, protocol_version, response_status, response_reason = \
                    await self.read_resp_line()
                rtime = time.clock() - timelog
            # read response headers
            while response_status == 100:
                # hdata = await read_header_data(self.remote_reader)
                fut = self.remote_reader.readuntil(b'\r\n\r\n')
                hdata = await asyncio.wait_for(fut, self.timeout)
                self._wfile_write(response_line + hdata)
                fut = self.remote_reader.readline()
                response_line, protocol_version, response_status, response_reason = \
                    await self.read_resp_line()
            fut = self.remote_reader.readuntil(b'\r\n\r\n')
            header_data = await asyncio.wait_for(fut, self.timeout)
            response_header = email.parser.Parser(_class=HTTPMessage).parsestr(header_data.decode('iso-8859-1'))

            # check response headers
            conntype = response_header.get('Connection', "")
            if protocol_version >= b"HTTP/1.1":
                remote_close = 'close' in conntype.lower()
            else:
                remote_close = 'keep_alive' in conntype.lower()
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

            if response_status in (301, 302) and self.conf.GET_PROXY.bad302(response_header.get('Location')):
                raise IOError(0, 'Bad 302!')

            self.wfile_write(response_line)
            self.wfile_write(header_data)
            # read response body
            if self.command == 'HEAD' or response_status in (204, 205, 304):
                pass
            elif response_header.get("Transfer-Encoding") and response_header.get("Transfer-Encoding") != "identity":
                flag = 1
                while flag:
                    trunk_lenth = await self.remote_reader.readline()
                    self.wfile_write(trunk_lenth)
                    trunk_lenth = int(trunk_lenth.strip(), 16) + 2
                    flag = trunk_lenth != 2
                    while trunk_lenth:
                        data = await self.remote_reader.read(min(self.bufsize, trunk_lenth))
                        # self.logger.info('chunk data received %d %s' % (len(data), self.path))
                        trunk_lenth -= len(data)
                        self.wfile_write(data)
            elif content_length is not None:
                while content_length:
                    data = await self.remote_reader.read(min(self.bufsize, content_length))
                    if not data:
                        raise IOError(0, 'remote socket closed')
                    # self.logger.info('content_length data received %d %s' % (len(data), self.path))
                    content_length -= len(data)
                    self.wfile_write(data)
            else:
                # websocket?
                self.logger.warning('websocket?')
                self.close_connection = True
                self.retryable = False
                # flush writer buf
                self.wfile_write()
                # start forwarding...

                context = await self.forward()
                if context.timeout:
                    # no response from server
                    pass

            self.wfile_write()
            self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, True if response_status < 400 else False, self.failed_parents, self.ppname, rtime)
            self.pproxy.log(self.request_host[0], rtime)
            if remote_close or self.close_connection:
                self.remote_writer.write_eof()
                self.remote_writer.close()
                self.remote_writer = None
                self.close_connection = True
            else:
                # keep for next request
                self.HTTPCONN_POOL.put((self.client_address[0], self.request_host), (self.remote_reader, self.remote_writer), self.ppname if '(pooled)' in self.ppname else (self.ppname + '(pooled)'))
                self.remote_writer = None
        except ClientError:
            self.logger.error('client error')
            self.close_connection = True
            return
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError, ValueError, asyncio.IncompleteReadError) as e:
            if self.remote_writer:
                try:
                    self.remote_writer.write_eof()
                except ConnectionResetError:
                    pass
                self.remote_writer.close()
                self.remote_writer = None
            await self.on_GET_Error(e)
        except Exception as e:
            self.close_connection = True
            self.logger.error(repr(e))
            self.logger.error(traceback.format_exc())

    async def on_GET_Error(self, e):
        if self.ppname:
            self.logger.warning('{} {} via {} failed: {}'.format(self.command, self.shortpath, self.ppname, repr(e)))
            self.pproxy.log(self.request_host[0], MAX_TIMEOUT)
            await self._do_GET(True)
            return
        self.conf.GET_PROXY.notify(self.command, self.shortpath, self.request_host, False, self.failed_parents, self.ppname)
        return self.send_error(504)

    do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = do_GET

    async def do_CONNECT(self):
        self.close_connection = True
        if isinstance(self.path, bytes):
            self.path = self.path.decode('latin1')

        self._wfile_write(self.protocol_version.encode() + b" 200 Connection established\r\n\r\n")

        # TODO: ClientError
        try:
            data = await self.client_reader_read(4)

            if data.startswith(b'\x16\x03'):
                # parse SNI
                data += await self.client_reader_read(8196)
                try:
                    server_name = extract_server_name(data)
                    self.logger.debug('sni: %s' % server_name)
                    self.logger.debug('path: %s' % self.path)
                    if server_name and server_name not in self.path:
                        host, _, port = self.path.partition(':')
                        self.path = '%s:%s' % (server_name, port)
                        self.logger.info('CONNECT: SNI rewrite path: %s' % self.path)
                except Exception:
                    pass
        except ClientError:
            return

        self.request_host = parse_hostport(self.path)

        self.rbuffer = []
        if data:
            self.rbuffer.append(data)

        # redirector
        new_url = self.conf.GET_PROXY.redirect(self)
        if new_url:
            self.logger.debug('redirect %s, %s %s' % (new_url, self.command, self.path))
            if new_url.isdigit() and 400 <= int(new_url) < 600:
                self.logger.info('{} {} {} send error {}'.format(self.command, self.shortpath or self.path, self.client_address[0], new_url))
                return
            elif new_url.lower() in ('reset', 'adblock', 'return'):
                self.logger.info('{} {} {} reset'.format(self.command, self.shortpath or self.path, self.client_address[0]))
                return
            elif all(u in self.conf.parentlist.dict.keys() for u in new_url.split()):
                self._proxylist = [self.conf.parentlist.get(u) for u in new_url.split()]
                # random.shuffle(self._proxylist)

        self.request_ip = await self.conf.resolver.get_ip_address(self.request_host[0])

        if self.request_ip.is_loopback:
            if ip_address(self.client_address[0]).is_loopback:
                if self.request_host[1] in range(self.conf.listen[1], self.conf.listen[1] + self.conf.profile_num):
                    # prevent loop
                    return
            else:
                return
        await self._do_CONNECT()

    async def _do_CONNECT(self, retry=False):
        if retry:
            self.failed_parents.append(self.ppname)
            self.pproxy.log(self.request_host[0], MAX_TIMEOUT)
            self.retry_count += 1
            if self.retry_count > 10:
                self.logger.error('retry time exceeded 10, pls check!')
                return

        if self.getparent():
            self.conf.GET_PROXY.notify(self.command, self.path, self.path, False, self.failed_parents, self.ppname)
            return

        iplist = None
        if self.pproxy.name == 'direct' and self.request_host[0] in self.conf.HOSTS and not self.failed_parents:
            iplist = self.conf.HOSTS.get(self.request_host[0])
            self._proxylist.insert(0, self.pproxy)

        self.set_timeout()

        try:
            self.logger.info('{} {} via {}. {}'.format(self.command, self.path, self.pproxy.name, self.client_address[1]))
            addr, port = parse_hostport(self.path, 443)
            self.remote_reader, self.remote_writer, self.ppname = await open_connection(addr, port, self.pproxy, self.timeout, iplist, True)
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, ConnectionRefusedError, asyncio.IncompleteReadError, ConnectionResetError) as e:
            self.logger.warning('%s %s via %s failed on connect! %r' % (self.command, self.path, self.ppname, e))
            self.conf.GET_PROXY.notify(self.command, self.path, self.request_host, False, self.failed_parents, self.ppname)
            await self._do_CONNECT(True)
            return
        self.logger.debug('%s connected' % self.path)

        if self.ppname != self.pproxy.name:
            self._proxylist.insert(0, self.pproxy)

        # forward
        context = await self.forward()

        # check, report, retry
        if context.retryable and not context.local_eof:
            # self.logger.warning('%s %s via %s forward failed! retry...' % (self.command, self.path, self.ppname))
            self.conf.GET_PROXY.notify(self.command, self.path, self.request_host, False, self.failed_parents, self.ppname)
            await self._do_CONNECT(True)
            return

    async def forward(self):
        context = ForwardContext()

        tasks = [self.forward_from_client(self.client_reader, self.remote_writer, context),
                 self.forward_from_remote(self.remote_reader, self.client_writer, context),
                 ]
        try:
            await asyncio.wait(tasks)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(repr(e))
            self.logger.error(traceback.format_exc())
            context.err = e
        self.remote_writer.close()
        return context

    async def forward_from_client(self, read_from, write_to, context, timeout=60):
        if self.command == 'CONNECT':
            # send self.rbuffer
            if self.rbuffer:
                self.remote_writer.write(b''.join(self.rbuffer))
                context.timelog = time.clock()
        while True:
            intv = 1 if context.retryable else 5
            try:
                fut = self.client_reader.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=intv)
            except asyncio.TimeoutError:
                if time.time() - context.last_active > timeout or context.remote_eof:
                    data = b''
                else:
                    continue
            except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
                data = b''

            if not data:
                break
            try:
                context.last_active = time.time()
                if context.retryable:
                    self.rbuffer.append(data)
                if not context.timelog:
                    context.timelog = time.clock()
                write_to.write(data)
                await write_to.drain()
            except ConnectionResetError:
                context.local_eof = True
                return
        context.local_eof = True
        # client closed, tell remote
        try:
            write_to.write_eof()
        except ConnectionResetError:
            pass

    async def forward_from_remote(self, read_from, write_to, context, timeout=60, rtimeout=60):
        count = 0
        while True:
            intv = 1 if context.retryable else 5
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, intv)
                count += 1
            except ConnectionResetError:
                data = b''
            except (asyncio.TimeoutError, OSError):
                if time.time() - context.last_active > timeout or context.local_eof:
                    data = b''
                elif context.retryable and time.time() - context.last_active > self.timeout:
                    data = b''
                else:
                    continue

            if not data:
                break
            try:
                context.last_active = time.time()
                if count == 1:
                    rtime = time.clock() - context.timelog
                if count == 3 and self.command == 'CONNECT':
                    # log server response time
                    self.pproxy.log(self.request_host[0], rtime)
                    self.conf.GET_PROXY.notify(self.command, self.path, self.request_host, True, self.failed_parents, self.ppname, rtime)
                context.retryable = False
                write_to.write(data)
                await write_to.drain()
            except (ConnectionResetError, ConnectionAbortedError):
                # client closed
                context.remote_eof = True
                context.retryable = False
                break
        context.remote_eof = True
        context.remote_recv_count = count

        # DO NOT CLOSE Client Connection, for possible retry
        # try:
        #     write_to.write_eof()
        # except (ConnectionResetError, OSError):
        #     pass

    def getparent(self):
        if self._proxylist is None:
            self._proxylist = self.conf.GET_PROXY.get_proxy(self.path, self.request_host, self.command, self.request_ip, self.server.profile)
        if not self._proxylist:
            self.ppname = ''
            self.pproxy = None
            return 1
        self.pproxy = self._proxylist.pop(0)
        self.ppname = self.pproxy.name

    def set_timeout(self):
        if self._proxylist:
            if self.ppname == 'direct':
                self.timeout = self.conf.timeout
            else:
                self.timeout = min(2 ** len(self.failed_parents) + self.conf.timeout + 1, MAX_TIMEOUT)
        else:
            self.timeout = MAX_TIMEOUT

    async def api(self, parse):
        '''
        path: supported command
        /api/localrule: GET POST DELETE
        '''
        self.logger.debug('{} {}'.format(self.command, self.path))
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
        if parse.path == '/api/localrule' and self.command == 'GET':
            data = json.dumps([(rule, self.conf.GET_PROXY.local.expire[rule]) for rule in self.conf.GET_PROXY.local.rules])
            self.write(code=200, data=data, ctype='application/json')
            return
        elif parse.path == '/api/localrule' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, int exp)'
            rule, exp = json.loads(body)
            result = self.conf.GET_PROXY.add_temp(rule, exp)
            self.write(200)
            self.conf.stdout()
            return
        elif parse.path.startswith('/api/localrule/') and self.command == 'DELETE':
            try:
                rule = base64.urlsafe_b64decode(parse.path[15:].encode('latin1')).decode()
                expire = self.conf.GET_PROXY.local.remove(rule)
                self.write(200, data=json.dumps([rule, expire]), ctype='application/json')
                self.conf.stdout()
                return
            except Exception as e:
                self.logger.error(traceback.format_exc())
                self.send_error(404, repr(e))
                return
        elif parse.path == '/api/redirector' and self.command == 'GET':
            data = json.dumps([(index, rule[0].rule, rule[1]) for index, rule in enumerate(self.conf.REDIRECTOR.redirlst)])
            self.write(200, data=data, ctype='application/json')
            return
        elif parse.path == '/api/redirector' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, str dest)'
            rule, dest = json.loads(body)
            self.conf.GET_PROXY.add_redirect(rule, dest)
            self.write(200)
            self.conf.stdout()
            return
        elif parse.path.startswith('/api/redirector/') and self.command == 'DELETE':
            try:
                rule = urlparse.parse_qs(parse.query).get('rule', [''])[0]
                if rule:
                    assert base64.urlsafe_b64decode(rule).decode() == self.conf.REDIRECTOR.redirlst[int(parse.path[16:])][0].rule
                rule, dest = self.conf.REDIRECTOR.redirlst.pop(int(parse.path[16:]))
                self.write(200, data=json.dumps([int(parse.path[16:]), rule.rule, dest]), ctype='application/json')
                self.conf.stdout()
                return
            except Exception as e:
                self.send_error(404, repr(e))
                return
        elif parse.path == '/api/proxy' and self.command == 'GET':
            data = [(p.name, ('%s://%s:%s' % (p.scheme, p._host_port[0], p._host_port[1])) if p.proxy else '', p._priority) for k, p in self.conf.parentlist.dict.items()]
            data = sorted(data, key=lambda item: item[0])
            data = json.dumps(sorted(data, key=lambda item: item[2]))
            self.write(200, data=data, ctype='application/json')
            return
        elif parse.path == '/api/proxy' and self.command == 'POST':
            'accept a json encoded tuple: (str rule, str dest)'
            name, proxy = json.loads(body)
            self.conf.addparentproxy(name, proxy)
            self.conf.userconf.set('parents', name, proxy)
            self.conf.confsave()
            self.write(200, data=data, ctype='application/json')
            self.conf.stdout()
            return
        elif parse.path.startswith('/api/proxy/') and self.command == 'DELETE':
            try:
                self.conf.parentlist.remove(parse.path[11:])
                if self.conf.userconf.has_option('parents', parse.path[11:]):
                    self.conf.userconf.remove_option('parents', parse.path[11:])
                    self.conf.confsave()
                self.write(200, data=parse.path[11:], ctype='application/json')
                self.conf.stdout()
                return
            except Exception as e:
                self.send_error(404, repr(e))
                return
        elif parse.path.startswith('/api/proxy/') and self.command == 'GET':
            try:
                proxy_name = parse.path[11:]
                proxy = self.conf.parentlist.get(proxy_name)
                self.write(200, data=proxy.proxy, ctype='text/plain')
                return
            except Exception as e:
                self.send_error(404, repr(e))
                return
        elif parse.path == '/api/gfwlist' and self.command == 'GET':
            self.write(200, data=json.dumps(self.conf.userconf.dgetbool('FWLite', 'gfwlist', True)), ctype='application/json')
            return
        elif parse.path == '/api/gfwlist' and self.command == 'POST':
            self.conf.userconf.set('FWLite', 'gfwlist', '1' if json.loads(body) else '0')
            self.conf.confsave()
            self.write(200, data=data, ctype='application/json')
            self.conf.stdout()
            return
        elif parse.path == '/api/remotedns' and self.command == 'POST':
            'accept a json encoded tuple: (str host, str server)'
            try:
                from .parent_proxy import ParentProxy
                from .resolver import TCP_Resolver
                host, server = json.loads(body)
                server = [parse_hostport(server.encode(), 53)]
                port = self.conf.listen[1]
                proxy = ParentProxy('foo', 'http://127.0.0.1:%d' % port)
                resolver = TCP_Resolver(server, proxy)
                result = resolver.resolve(host)
                result = [r[1] for r in result]
                self.write(200, data=json.dumps(result), ctype='application/json')
            except Exception:
                result = traceback.format_exc()
                self.write(200, data=json.dumps(result.split()), ctype='application/json')
            return
        elif parse.path == '/api/exit' and self.command == 'GET':
            from .plugin_manager import plugin_manager
            plugin_manager.cleanup()
            self.write(200, data='Done!', ctype='text/html')
            import sys
            sys.exit()
        elif parse.path == '/' and self.command == 'GET':
            self.write(200, data='Hello World!', ctype='text/html')
            return
        self.send_error(404)
