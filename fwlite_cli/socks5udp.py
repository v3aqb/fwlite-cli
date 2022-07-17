
import io
import ipaddress
import socket
import struct
import time
import logging

import base64
import traceback

import asyncio
import asyncio_dgram

from hxcrypto import Encryptor, InvalidTag, IVError

logger = logging.getLogger('socks5udp')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


class Socks5UDPServer:
    '''
    created after recieving UDP_ASSOCIATE request
    '''
    def __init__(self, parent, timeout=300):
        self.parent = parent
        self.client_addr = None
        self.client_stream = None
        self.timeout = timeout
        self.logger = logger

        self.proxy = None
        self.lock = asyncio.Lock()
        self.close_event = asyncio.Event()
        self.init_time = time.monotonic()
        self.log_sent = False
        self.last_active = None

        self.udp_relay = None

        self._closed = False
        self.client_recv_task = None

    async def bind(self):
        client_ip = self.parent.client_address[0]
        stream = await asyncio_dgram.connect((client_ip, 53))
        interface = stream.sockname[0]
        stream.close()
        self.client_stream = await asyncio_dgram.bind((interface, 0))
        # tell client the port number
        self.parent.write_udp_reply(self.client_stream.sockname)
        self.logger.info('start udp relay, %s', self.client_stream.sockname)
        self.client_recv_task = asyncio.ensure_future(self.recv_from_client())

    async def recv_from_client(self):
        # start reading... until timeout
        while not self._closed:
            try:
                fut = self.client_stream.recv()
                data, client_addr = await asyncio.wait_for(fut, timeout=6)
                self.last_active = time.monotonic()
            except asyncio.TimeoutError:
                if not self.log_sent and time.monotonic() - self.init_time > self.timeout * 2:
                    if self.last_active:
                        self.logger.warning('udp no response')
                    else:
                        self.logger.warning('udp not used')
                    break
                if not self.last_active:
                    continue
                if time.monotonic() - self.last_active > self.timeout:
                    self.logger.warning('udp idle')
                    break
                continue
            except OSError:
                if not self.last_active and self.proxy:
                    self.log_sent = True
                    self.proxy.log('udp', 20)
                break
            # source check
            if not self.client_addr:
                self.client_addr = client_addr
            if client_addr != self.client_addr:
                self.logger.warning('client_addr not match, drop')
                continue
            frag = data[2]
            if frag:
                self.logger.warning('frag set, drop')
                continue
            # get relay, send
            try:
                await self.on_client_recv(data[3:])
            except OSError:
                break
        self.logger.info('udp relay finish, %ds, closed: %s',
                         time.monotonic() - self.init_time, self._closed)
        self.close(True)
        # tell socks5 server to close connection
        self.close_event.set()

    async def on_client_recv(self, data):
        data_io = io.BytesIO(data)
        addrtype = data_io.read(1)[0]
        if addrtype == 1:  # ipv4
            addr = data_io.read(4)
            addr = socket.inet_ntoa(addr)
        elif addrtype == 4:  # ipv6
            addr = data_io.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        port = struct.unpack(b">H", data_io.read(2))[0]
        dgram = data_io.read()

        remote_ip = ipaddress.ip_address(addr)
        # send recieved dgram to relay
        async with self.lock:
            if not self.udp_relay:
                try:
                    await self.get_relay(remote_ip)
                except OSError as err:
                    self.logger.error(repr(err))
                    self.close()
                    raise

        await self.udp_relay.send(addr, port, dgram, data)

    async def get_relay(self, remote_ip):
        proxy = self.parent.conf.parentlist.get(self.parent.conf.udp_proxy)
        if proxy:
            proxy_list = [proxy, ]
        else:
            proxy_list = self.parent.conf.GET_PROXY.get_proxy(
                'udp', (str(remote_ip), 0), 'UDP_ASSOCIATE',
                remote_ip, self.parent.mode)
        for proxy in proxy_list:
            try:
                if proxy.scheme == '':
                    udp_relay = UDPRelayDirect(self)
                    await udp_relay.udp_associate()
                    self.udp_relay = udp_relay
                    self.proxy = proxy
                if proxy.scheme == 'ss':
                    udp_relay = UDPRelaySS(self, proxy)
                    await udp_relay.udp_associate()
                    self.udp_relay = udp_relay
                    self.proxy = proxy
                if proxy.scheme == 'hxs2':
                    from .hxsocks2 import hxs2_get_connection
                    conn = await hxs2_get_connection(proxy, timeout=8, tcp_nodelay=True)
                    self.udp_relay = await conn.udp_associate(self)
                    self.proxy = proxy
                if proxy.scheme in ('hxs3', 'hxs3s'):
                    from .hxsocks3 import hxs3_get_connection
                    conn = await hxs3_get_connection(proxy, timeout=8, tcp_nodelay=True)
                    self.udp_relay = await conn.udp_associate(self)
                    self.proxy = proxy
            except OSError:
                proxy.log('udp', 20)
        if not self.udp_relay:
            raise OSError(0, 'get_relay failed.')
        self.logger.debug(repr(self.udp_relay))
        self.init_time = time.monotonic()

    async def on_remote_recv(self, data):
        ''' data recieved from remote.
            if data, it is shadowsocks style.
        '''
        if not self.log_sent:
            self.log_sent = True
            rtime = time.monotonic() - self.init_time
            self.proxy.log('udp', rtime)
        self.last_active = time.monotonic()
        try:
            await self.client_stream.send(b'\x00\x00\x00' + data, self.client_addr)
        except OSError:
            self.close(True)

    def close(self, close_relay=False):
        self._closed = True
        if not self.log_sent:
            if self.proxy:
                self.proxy.log('udp', 20)
        if close_relay:
            if self.udp_relay:
                self.udp_relay.close()


class UDPRelayInterface:
    def __init__(self, udp_server):
        self.udp_server = udp_server
        self.logger = self.udp_server.logger
        self.on_remote_recv = self.udp_server.on_remote_recv
        self._close = False

    async def send(self, addr, port, dgram, data):
        # datagram recieved from client, relay to server
        raise NotImplementedError

    def close(self):
        # close this relay
        self._close = True
        self.udp_server.close()


class UDPRelayDirect(UDPRelayInterface):
    def __init__(self, udp_server):
        super().__init__(udp_server)
        self.write_lock = asyncio.Lock()
        self.remote_stream = None
        self.recv_from_remote_task = None

    async def send(self, addr, port, dgram, data):
        remote_addr = (addr, port)
        await self.remote_stream.send(dgram, remote_addr)

    async def recv_from_remote(self):
        while not self._close:
            try:
                fut = self.remote_stream.recv()
                dgram, remote_addr = await asyncio.wait_for(fut, timeout=6)
                data = self.recv_from_remote_process(dgram, remote_addr)
            except asyncio.TimeoutError:
                continue
            except (IVError, InvalidTag):
                continue
            except OSError:
                break

            await self.on_remote_recv(data)
        self.remote_stream.close()
        self.close()

    async def udp_associate(self):
        self.remote_stream = await asyncio_dgram.bind(('0.0.0.0', 0))
        self.recv_from_remote_task = asyncio.ensure_future(self.recv_from_remote())

    def recv_from_remote_process(self, dgram, remote_addr):
        remote_ip = ipaddress.ip_address(remote_addr[0])
        data = b'\x01' if remote_ip.version == 4 else b'\x04'
        data += remote_ip.packed
        data += struct.pack(b'>H', remote_addr[1])
        data += dgram
        return data


class UDPRelaySS(UDPRelayDirect):
    def __init__(self, parent, proxy):
        self.proxy = proxy
        self.remote_addr = None
        ssmethod, sspassword = self.proxy.username, self.proxy.password
        if sspassword is None:
            ssmethod, sspassword = base64.b64decode(ssmethod).decode().split(':', 1)
        self.ssmethod, self.sspassword = ssmethod, sspassword
        try:
            ipaddress.ip_address(self.proxy.hostname)
        except ValueError:
            pass
        super().__init__(parent)

    async def udp_associate(self):
        self.remote_stream = await asyncio_dgram.connect((self.proxy.hostname, self.proxy.port))
        self.recv_from_remote_task = asyncio.ensure_future(self.recv_from_remote())

    def get_cipher(self):
        cipher = Encryptor(self.sspassword, self.ssmethod)
        return cipher

    async def send(self, addr, port, dgram, data):
        buf = self.get_cipher().encrypt_once(data)
        await self.remote_stream.send(buf)

    def recv_from_remote_process(self, dgram, remote_addr):
        return self.get_cipher().decrypt(dgram)
