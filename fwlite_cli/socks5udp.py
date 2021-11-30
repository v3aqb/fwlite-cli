
import io
import ipaddress
import socket
import struct
import time
import logging

import base64

import asyncio
import asyncio_dgram

from hxcrypto import Encryptor, InvalidTag, IVError


class Socks5UDPServer:
    '''
    created after recieving UDP_ASSOCIATE request
    '''
    def __init__(self, parent, proxy, timeout=180):
        self.parent = parent
        self.client_addr = None
        self.client_stream = None
        self.proxy = proxy
        self.timeout = timeout
        self.lock = asyncio.Lock()

        self.close_event = asyncio.Event()
        self.init_time = time.monotonic()
        self.log_sent = False
        self.last_active = time.monotonic()

        self.udp_relay = None

        self.logger = logging.getLogger('socks5udp_%d' % self.parent.server_addr[1])
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self._close = False
        self.client_recv_task = asyncio.ensure_future(self.recv_from_client())

    async def recv_from_client(self):
        self.logger.debug('start udp forward, %s', self.proxy)
        # find a free port and bind
        self.client_stream = await asyncio_dgram.bind((self.parent.server_addr[0], 0))
        # tell client the port number
        self.parent.write_udp_reply(self.client_stream.sockname[1])
        # start reading... until timeout
        while not self._close:
            try:
                fut = self.client_stream.recv()
                data, client_addr = await asyncio.wait_for(fut, timeout=6)
                self.last_active = time.monotonic()
            except asyncio.TimeoutError:
                if time.monotonic() - self.last_active > self.timeout:
                    break
                if not self.log_sent and time.monotonic() - self.init_time > 16:
                    # relay not working?
                    self.log_sent = True
                    self.proxy.log('udp', 20)
                continue
            # source check
            if not self.client_addr:
                self.client_addr = client_addr
            if client_addr != self.client_addr:
                self.logger.warning('client_addr not match, drop')
                continue
            frag = data[2]
            if frag:
                continue
            # get relay, send
            await self.on_client_recv(data[3:])
        self.close(True)

    async def on_client_recv(self, data):
        # send recieved dgram to relay
        async with self.lock:
            if not self.udp_relay:
                try:
                    await self.get_relay()
                except OSError:
                    self.close()
                    return

        await self.udp_relay.on_client_recv(data)

    async def get_relay(self):
        # if not self.parent.conf.GET_PROXY.ip_in_china(None, remote_addr[0]):
        if self.proxy and self.proxy.scheme == 'ss':
            self.udp_relay = UDPRelaySS(self, self.proxy)
        if not self.udp_relay:
            self.udp_relay = UDPRelayDirect(self, self.proxy)
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
        await self.client_stream.send(b'\x00\x00\x00' + data, self.client_addr)

    def close(self, close_relay=False):
        self._close = True
        if not self.log_sent:
            self.proxy.log('udp', 20)
        if close_relay:
            if self.udp_relay:
                self.udp_relay.close()
        # tell socks5 server to close connection
        self.close_event.set()


class UDPRelayInterface:
    def __init__(self, udp_server):
        self.udp_server = udp_server
        self.on_remote_recv = self.udp_server.on_remote_recv
        self._close = False

    async def on_client_recv(self, data):
        # datagram recieved from client, relay to server
        raise NotImplementedError

    def close(self):
        # close this relay
        self._close = True
        self.udp_server.close()


class UDPRelayDirect(UDPRelayInterface):
    def __init__(self, udp_server, proxy):
        super().__init__(udp_server)
        self.proxy = proxy
        self.write_lock = asyncio.Lock()
        self.remote_stream = None
        self.recv_from_remote_task = None

    async def on_client_recv(self, data):
        async with self.write_lock:
            if not self.remote_stream:
                await self.udp_associate()
        await self._send(data)

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

    async def _send(self, data):
        # if FRAG, drop
        data_io = io.BytesIO(data)
        addrtype = data_io.read(1)
        if addrtype == 1:  # ipv4
            addr = data_io.read(4)
            addr = socket.inet_ntoa(addr)
        elif addrtype == 3:  # hostname
            addrlen = data_io.read(1)
            addr = data_io.read(addrlen[0])
            addr = addr.decode()
        elif addrtype == 4:  # ipv6
            addr = data_io.read(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        port = struct.unpack(b">H", data_io.read(2))[0]
        remote_addr = (addr, port)
        dgram = data_io.read()

        await self.remote_stream.send(dgram, remote_addr)

    def recv_from_remote_process(self, dgram, remote_addr):
        remote_ip = ipaddress.ip_address(remote_addr[0])
        data = b'\x01' if remote_ip.version == 4 else b'\x04'
        data += remote_ip.packed
        data += struct.pack(b'>H', remote_addr[1])
        data += dgram
        return data


class UDPRelaySS(UDPRelayDirect):
    def __init__(self, parent, proxy):
        super().__init__(parent, proxy)
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

    async def _send(self, data):
        buf = self.get_cipher().encrypt_once(data)
        await self.remote_stream.send(buf)

    def recv_from_remote_process(self, dgram, remote_addr):
        return self.get_cipher().decrypt(dgram)
