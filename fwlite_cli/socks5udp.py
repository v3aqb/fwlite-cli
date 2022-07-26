
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
    def __init__(self, socks5_handler, timeout=300):
        self.socks5_handler = socks5_handler
        self.client_addr = None
        self.client_stream = None
        self.running = False
        self.timeout = timeout
        self.logger = logger

        self.lock = asyncio.Lock()
        self.init_time = time.monotonic()
        self.last_send = 0
        self.last_recv = 0

        self.udp_relay_holder = {}

        self.client_recv_task = None

    async def bind(self):
        # can be called multiple times
        if self.running:
            self.logger.info('reuse udp server, %s', self.client_stream.sockname)
        else:
            client_ip = self.socks5_handler.client_address[0]
            stream = await asyncio_dgram.connect((client_ip, 53))
            interface = stream.sockname[0]
            stream.close()
            self.running = True
            self.client_stream = await asyncio_dgram.bind((interface, 0))
            self.logger.info('start udp server, %s', self.client_stream.sockname)
            self.client_recv_task = asyncio.ensure_future(self.recv_from_client())
        # tell client the port number
        return self.client_stream.sockname

    async def recv_from_client(self):
        # start reading... until timeout
        while self.running:
            try:
                fut = self.client_stream.recv()
                data, client_addr = await asyncio.wait_for(fut, timeout=6)
            except asyncio.TimeoutError:
                self.close_inactive_relay()
                inactive_time = time.monotonic() - max(self.last_recv, self.last_send, self.init_time)
                if inactive_time > self.timeout * 2:
                    if not self.last_send:
                        self.logger.warning('udp_server no send')
                    elif not self.last_recv:
                        self.logger.warning('udp_server no recv')
                    else:
                        self.logger.warning('udp_server idle')
                    break
                continue
            except OSError:
                self.logger.warning('udp_server recv OSError')
                break

            frag = data[2]
            if frag:
                self.logger.warning('frag set, drop')
                continue
            # get relay, send
            try:
                self.last_send = time.monotonic()
                await self.on_client_recv(data[3:], client_addr)
            except OSError:
                self.logger.warning('udp_server send OSError')
        self.logger.info('udp server finish, %ds, running: %s',
                         time.monotonic() - self.init_time, self.running)
        self.close()
        self.client_stream.close()
        self.client_stream = None

    async def on_client_recv(self, data, client_addr):
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
            if client_addr not in self.udp_relay_holder:
                try:
                    await self.get_relay(client_addr, remote_ip)
                except OSError as err:
                    self.logger.error('get_relay fail: %r', err)
                    return
        relay = self.udp_relay_holder[client_addr]
        await relay.send(addr, port, dgram, data)

    async def get_relay(self, client_addr, remote_ip):
        proxy = self.socks5_handler.conf.parentlist.get(self.socks5_handler.conf.udp_proxy)
        if proxy:
            proxy_list = [proxy, ]
        else:
            proxy_list = self.socks5_handler.conf.GET_PROXY.get_proxy(
                'udp', (str(remote_ip), 0), 'UDP_ASSOCIATE',
                remote_ip, self.socks5_handler.mode)
        for proxy in proxy_list:
            try:
                if proxy.scheme == '':
                    udp_relay = UDPRelayDirect(self, proxy, client_addr)
                    await udp_relay.udp_associate()
                    self.udp_relay_holder[client_addr] = udp_relay
                if proxy.scheme == 'ss':
                    udp_relay = UDPRelaySS(self, proxy, client_addr)
                    await udp_relay.udp_associate()
                    self.udp_relay_holder[client_addr] = udp_relay
                if proxy.scheme == 'hxs2':
                    from .hxsocks2 import hxs2_get_connection
                    conn = await hxs2_get_connection(proxy, timeout=8, tcp_nodelay=True)
                    self.udp_relay_holder[client_addr] = await conn.udp_associate(self, client_addr)
                if proxy.scheme in ('hxs3', 'hxs3s'):
                    from .hxsocks3 import hxs3_get_connection
                    conn = await hxs3_get_connection(proxy, timeout=8, tcp_nodelay=True)
                    self.udp_relay_holder[client_addr] = await conn.udp_associate(self, client_addr)
            except OSError:
                proxy.log('udp', 20)
        if not self.udp_relay_holder[client_addr]:
            raise OSError(0, 'get_relay failed.')
        self.logger.info(repr(self.udp_relay_holder[client_addr]))
        self.init_time = time.monotonic()

    async def on_remote_recv(self, data, client_addr):
        ''' data recieved from remote.
            if data, it is shadowsocks style.
        '''
        self.last_recv = time.monotonic()
        try:
            await self.client_stream.send(b'\x00\x00\x00' + data, client_addr)
        except OSError:
            self.close()

    def close_inactive_relay(self):
        close_list = []
        for client_addr, relay in self.udp_relay_holder.items():
            if relay.is_inactive():
                relay.close(close_server=False)
                close_list.append(client_addr)
        for client_addr in close_list:
            self.logger.info('close inactive relay, %s', client_addr)
            del self.udp_relay_holder[client_addr]

    def close(self, client_addr=None):
        self.running = False
        if not client_addr:
            # close all:
            for _, relay in self.udp_relay_holder.items():
                relay.close(close_server=False)
            self.udp_relay_holder = {}
            return
        if client_addr in self.udp_relay_holder:
            self.udp_relay_holder[client_addr].close()
            del self.udp_relay_holder[client_addr]


class UDPRelayInterface:
    def __init__(self, udp_server, proxy, client_addr):
        self.udp_server = udp_server
        self.logger = self.udp_server.logger
        self.proxy = proxy
        self.client_addr = client_addr
        self._close = False
        self.init_time = time.monotonic()
        self.last_recv = 0
        self.last_send = 0

    def is_inactive(self):
        inactive_time = time.monotonic() - max(self.last_recv, self.last_send, self.init_time)
        if not self.last_recv and inactive_time > 60:
            return True
        if inactive_time > self.udp_server.timeout:
            return True
        return False

    async def on_remote_recv(self, data):
        if not self.last_recv:
            rtime = time.monotonic() - self.init_time
            self.proxy.log('udp', rtime)
        self.last_recv = time.monotonic()
        await self.udp_server.on_remote_recv(data, self.client_addr)

    async def send(self, addr, port, dgram, data):
        self.last_send = time.monotonic()
        await self._send(addr, port, dgram, data)

    async def _send(self, addr, port, dgram, data):
        # datagram recieved from client, relay to server
        raise NotImplementedError

    def close(self, close_server=True):
        # close this relay
        self._close = True
        if not self.last_recv:
            self.proxy.log('udp', 20)
        if close_server:
            self.udp_server.close(client_addr=self.client_addr)


class UDPRelayDirect(UDPRelayInterface):
    def __init__(self, udp_server, proxy, client_addr):
        super().__init__(udp_server, proxy, client_addr)
        self.write_lock = asyncio.Lock()
        self.remote_stream = None
        self.recv_from_remote_task = None

    async def _send(self, addr, port, dgram, data):
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
    def __init__(self, parent, proxy, client_addr):
        super().__init__(parent, proxy, client_addr)
        self.remote_addr = None
        ssmethod, sspassword = self.proxy.username, self.proxy.password
        if sspassword is None:
            ssmethod, sspassword = base64.b64decode(ssmethod).decode().split(':', 1)
        self.ssmethod, self.sspassword = ssmethod, sspassword
        try:
            ipaddress.ip_address(self.proxy.hostname)
        except ValueError:
            pass

    async def udp_associate(self):
        self.remote_stream = await asyncio_dgram.connect((self.proxy.hostname, self.proxy.port))
        self.recv_from_remote_task = asyncio.ensure_future(self.recv_from_remote())

    def get_cipher(self):
        cipher = Encryptor(self.sspassword, self.ssmethod)
        return cipher

    async def _send(self, addr, port, dgram, data):
        buf = self.get_cipher().encrypt_once(data)
        await self.remote_stream.send(buf)

    def recv_from_remote_process(self, dgram, remote_addr):
        return self.get_cipher().decrypt(dgram)
