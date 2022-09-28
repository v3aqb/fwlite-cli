

import os
import struct
import asyncio
import logging
from fwlite_cli.socks5udp import UDPRelayInterface

UDP_RELAY2_STORE = {}  # udp_sid, udp_relay
UDP_RELAY2_ADDR = {}   # client_addr, udp_sid
UDP_CLIENT_ID = os.urandom(8)

logger = logging.getLogger('hxs_udp2')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)


def get_hxs_udp_relay(udp_server, client_addr, hxs_list):
    if client_addr not in UDP_RELAY2_ADDR:
        relay = UDPRelayHxs2(udp_server, client_addr, hxs_list)
        UDP_RELAY2_ADDR[client_addr] = relay.sid
        UDP_RELAY2_STORE[relay.sid] = relay
    return UDP_RELAY2_STORE[UDP_RELAY2_ADDR[client_addr]]


class UDPRelayHxs2(UDPRelayInterface):
    next_sid = 1

    def __init__(self, udp_server, client_addr, hxs_list):
        super().__init__(udp_server, None, client_addr)
        self.client_addr = client_addr
        self.hxs_list = hxs_list
        self.sid = self.get_sid()

    @classmethod
    def get_sid(cls):
        sid = cls.next_sid
        cls.next_sid += 1
        if cls.next_sid > 2 ** 31:
            cls.next_sid = 1
        return sid

    async def _send(self, addr, port, dgram, data):
        # find a hxs_connection, send dgram
        conn = await self.get_connection()
        await conn.send_dgram2(UDP_CLIENT_ID, self.sid, data)

    async def get_connection(self):
        for proxy in self.hxs_list:
            if proxy.scheme == 'hxs2':
                from fwlite_cli.hxsocks2 import hxs2_get_connection
                get_connection = hxs2_get_connection
            elif proxy.scheme in ('hxs3', 'hxs3s'):
                from fwlite_cli.hxsocks3 import hxs3_get_connection
                get_connection = hxs3_get_connection
            conn = await get_connection(proxy, timeout=4, tcp_nodelay=True)
            self.proxy = conn.proxy
            return conn

    def close(self, close_server=True):
        super().close(close_server)
        del UDP_RELAY2_ADDR[self.client_addr]
        del UDP_RELAY2_STORE[self.sid]

    def __repr__(self):
        return '<UDPRelayHxs2> %d' % self.sid


def parse_dgram2(payload):
    client_id = payload.read(8)
    udp_sid, data_len = struct.unpack(b">LH", payload.read(6))
    data = payload.read(data_len)
    return client_id, udp_sid, data


def on_dgram_recv(payload):
    _, udp_sid, data = parse_dgram2(payload)
    if udp_sid in UDP_RELAY2_STORE:
        relay = UDP_RELAY2_STORE[udp_sid]
        asyncio.ensure_future(relay.on_remote_recv(data))
