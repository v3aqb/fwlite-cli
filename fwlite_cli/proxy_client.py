
import base64
import struct
import asyncio


class ProxyClient:
    def __init__(self, proxy, proxy_auth, addr):
        self._proxy = proxy
        self._proxy_auth = proxy_auth
        self._addr = addr
        self._stage = 0
        self._recv_buf = b''
        self.feed = self._feed_http if self._proxy == 'http' else self._feed_socks5

    def connect(self):
        if self._proxy == 'http':
            req = ['CONNECT %s:%s HTTP/1.1\r\n' % self._addr, ]
            if self._proxy_auth:
                auth = '%s:%s' % self._proxy_auth
                req.append('Proxy-Authorization: Basic %s\r\n' % base64.b64encode(auth.encode()).decode())
            req.append('Host: %s:%s\r\n\r\n' % self._addr)
            return ''.join(req).encode()

        elif self._proxy == 'socks5':
            self._stage = 1  # client auth pending
            return b"\x05\x02\x00\x02" if self._proxy_auth else b"\x05\x01\x00"

    def _feed_http(self, data):
        self._recv_buf += data
        try:
            index = self._recv_buf.index(b'\r\n\r\n')
        except ValueError:
            return None, b''
        if '200' in self._recv_buf:
            return True, self._recv_buf[index + 4:]
        return False, self._recv_buf

    def _feed_socks5(self, data):
        if self._stage == 1:
            if data[1] == 2:  # send basic auth
                return None, b''.join([b"\x01",
                                       bytes((len(self._proxy_auth[0].encode()), )),
                                       self._proxy_auth[0].encode(),
                                       bytes((len(self._proxy_auth[1].encode()), )),
                                       self._proxy_auth[1].encode()])
            if data[1] == 0:  # auth passed, send connection request
                self._stage = 2
                return None, b''.join([b"\x05\x01\x00\x03",
                                      bytes((len(self._addr[0].encode()), )),
                                      self._addr.encode(),
                                      struct.pack(b">H", self._addr[1])])
        if self._stage == 2:
            self._recv_buf += data
            # recv server response
            if data[1] != 0:
                return False, data
            resp_len = 4
            if data[3] == 1:
                resp_len += 4
            if data[3] == 3:
                resp_len += data[4] + 1
            if data[3] == 4:
                resp_len += 16
            resp_len += 2
            if len(self._recv_buf) >= resp_len:
                return True, self._recv_buf[resp_len:]
            return None, b''


class ProxyClientProtocol(asyncio.Protocol):
    '''forward recieved data from transport, write to peer_transport'''

    def __init__(self, next_protocol, connected_cb, addr, proxy='', proxy_auth=None):
        self._next_protocol = next_protocol
        self._connected_cb = connected_cb
        self._addr = addr  # (host, port)
        self._proxy = proxy
        self._proxy_auth = proxy_auth  # (username, password)
        self._transport = None
        self._proxy_client = None

        self._connected = False
        self._send_buffer = bytearray()

    def connection_made(self, transport):
        self._transport = transport
        if self._proxy:
            self._proxy_client = ProxyClient(self._proxy, self._proxy_auth, self._addr)
            connect_req = self._proxy_client.connect()
            self._transport.write(connect_req)
        else:
            self._connection_made()

    def data_received(self, data):
        connected, data = self._proxy_client.feed(data)
        if connected is False:
            self.close()
        if not connected and data:
            self._transport.write(data)
        if connected:
            self._connection_made(data)
            self._proxy_client = None

    def _connection_made(self, data=b''):
        self._next_protocol.connection_made(self._transport)
        if data:
            self._next_protocol.data_received(data)
        self._transport.set_protocol(self._next_protocol)
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
        self._connected_cb.set_exception(ConnectionResetError)
        self._transport.close()
