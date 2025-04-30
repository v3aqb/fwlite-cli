
import json
import struct
import socket
import asyncio
import threading
import subprocess

from asyncio import get_running_loop, StreamReader, StreamReaderProtocol, StreamWriter

from .util import get_port
from .plugin_manager import PLUGIN_PATH

LISTEN_ADDR = ('', 0)


def start_utls_tunnel():
    if LISTEN_ADDR[0]:
        return

    port = get_port('127.0.0.1')

    addr = ('127.0.0.1', port)

    threading.Thread(target=run, args=(addr, ))


def run(addr):
    global LISTEN_ADDR
    with subprocess.Popen((PLUGIN_PATH['utls-tunnel'], '-l', f'{addr[0]}:{addr[1]}')) as proc:
        LISTEN_ADDR = addr
        proc.wait()
    LISTEN_ADDR = ('', 0)


def utls_connect(addr: str, server_name: str = '', client_hello_id: str = 'chrome', insecure: bool = False):
    start_utls_tunnel()

    sock = socket.create_connection(LISTEN_ADDR, timeout=2)

    req = {}
    req['RemoteAddr'] = addr
    req['ServerName'] = server_name or addr.rsplit(':', 1)[0]
    req['ClientHelloID'] = client_hello_id
    req['Insecure'] = insecure  # type: ignore[assignment]

    req_data = json.dumps(req).encode()

    req_data = struct.pack('>BH', 0, len(req_data)) + req_data

    sock.sendall(req_data)

    resph = sock.recv(3)
    resp_type, resp_len = struct.unpack('>BH', resph)

    resp = b''
    rlen = resp_len
    for _ in range(10):
        if rlen == 0:
            break
        resp += sock.recv(rlen)
        rlen -= len(resp)
    else:
        sock.close()
        raise IOError(0, f'utls_tunnel connect to {addr} failed!')

    if resp_type != 0:
        sock.close()
        raise IOError(0, f'utls_tunnel connect to {addr} failed!')

    return sock


async def utls_connect_async(
        addr: str,
        server_name: str,
        client_hello_id: str = 'chrome',
        insecure: bool = False):
    start_utls_tunnel()

    loop = get_running_loop()
    reader = StreamReader(loop=loop)
    protocol = StreamReaderProtocol(reader, loop=loop)

    transport = await asyncio.wait_for(create_utls_connection(
        protocol, addr, server_name,
        client_hello_id=client_hello_id,
        insecure=insecure), timeout=2)

    writer = StreamWriter(transport, protocol, reader, loop)
    return reader, writer


async def create_utls_connection(protocol, addr, server_name, client_hello_id='chrome', insecure=False):
    loop = get_running_loop()
    connected_cb = loop.create_future()
    utls_protocol = UtlsClientProtocol(protocol, connected_cb, addr, server_name, client_hello_id, insecure)

    laddr, lport = LISTEN_ADDR
    transport, _ = await asyncio.wait_for(loop.create_connection(lambda: utls_protocol, laddr, lport), timeout=2)

    await connected_cb

    return transport


class UtlsClientProtocol(asyncio.Protocol):
    '''forward recieved data from transport, write to peer_transport'''

    def __init__(self, next_protocol, connected_cb, addr,
                 server_name='', client_hello_id='chrome', insecure=False):
        self._next_protocol = next_protocol
        self._connected_cb = connected_cb
        self._addr = addr
        self._server_name = server_name
        self._client_hello_id = client_hello_id
        self._insecure = insecure
        self._transport = None

        self._connected = False
        self._send_buffer = bytearray()

    def connection_made(self, transport):
        self._transport = transport

        req = {}
        req['RemoteAddr'] = self._addr
        req['ServerName'] = self._server_name or self._addr.rsplit(':', 1)[0]
        req['ClientHelloID'] = self._client_hello_id
        req['Insecure'] = self._insecure

        req_data = json.dumps(req).encode()

        req_data = struct.pack('>BH', 0, len(req_data)) + req_data
        self._transport.write(req_data)

    def data_received(self, data):
        self._send_buffer.extend(data)
        resp_type, resp_len = struct.unpack('>BH', self._send_buffer[:3])
        if resp_type != 0:
            self._connected_cb.set_exception(ConnectionResetError)
            return
        resp = 3 + resp_len
        if len(self._send_buffer) >= resp:
            self._next_protocol.connection_made(self._transport)
            if self._send_buffer[resp:]:
                self._next_protocol.data_received(self._send_buffer[resp:])
            self._transport.set_protocol(self._next_protocol)
            self._next_protocol.connection_made(self._transport)
            self._connected_cb.set_result(None)

    def connection_lost(self, exc):
        self._connected_cb.set_exception(ConnectionResetError)

    def pause_writing(self):
        '''Called when the transport’s buffer goes over the high watermark.'''

    def resume_writing(self):
        '''Called when the transport’s buffer drains below the low watermark.'''

    def eof_received(self):
        self._connected_cb.set_exception(ConnectionResetError)

    def close(self):
        self._transport.close()


async def test():
    reader, writer = await utls_connect_async('www.baidu.com:443', 'www.baidu.com', False)
    writer.write(b"GET / HTTP/1.1\r\nHosts: www.baidu.com\r\n\r\n")
    data = await reader.read(1024)
    while data:
        print(data)
        data = await reader.read(1024)


if __name__ == '__main__':
    asyncio.run(test())
