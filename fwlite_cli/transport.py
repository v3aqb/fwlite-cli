
import asyncio


class FWProtocol(asyncio.Protocol):
    '''act as transport provided for client, and protocol connecting to server transport'''
    def __init__(self, transport):
        self._t_transport = transport
        self._conn_lost = 0
        self._is_closing = False
        self._is_reading = True
        self._connected = False
        self._write_eof = False
        self._eof_received = False

        self._transport = None

    # BaseProtocol
    def connection_made(self, transport):
        '''Called when a connection is made.

        The transport argument is the transport representing the connection.
        The protocol is responsible for storing the reference to its transport.'''
        self._transport = transport

    def connection_lost(self, exc):
        '''Called when the connection is lost or closed.
           self._transport is already closed?'''
        self._t_transport.close()
        self._transport.close()

    # Flow Control Callbacks
    # Flow control callbacks can be called by transports to pause or resume writing performed by the protocol.
    def pause_writing(self):
        '''Called when the transport’s buffer goes over the high watermark.'''
        self._t_transport.pause_reading()

    def resume_writing(self):
        '''Called when the transport’s buffer drains below the low watermark.'''
        self._t_transport.resume_reading()

    def data_received(self, data):
        '''Called when some data is received. data is a non-empty bytes object containing the incoming data.

        Whether the data is buffered, chunked or reassembled depends on the transport.
        In general, you shouldn’t rely on specific semantics and instead make your parsing generic and flexible.
        However, data is always received in the correct order.

        The method can be called an arbitrary number of times while a connection is open.

        However, protocol.eof_received() is called at most once. Once eof_received() is called, data_received() is not called anymore.'''
        self._t_transport.write(data)

    def eof_received(self):
        '''Called when the other end signals it won’t send any more data
        (for example by calling transport.write_eof(), if the other end also uses asyncio).

        This method may return a false value (including None), in which case the transport will close itself.
        Conversely, if this method returns a true value, the protocol used determines whether to close the transport.
        Since the default implementation returns None, it implicitly closes the connection.

        Some transports, including SSL, don’t support half-closed connections,
        in which case returning true from this method will result in the connection being closed.'''
        if not self._eof_received:
            self._eof_received = True
            self._t_transport.write_eof()


async def transport_forward(transport_1, transport_2, ctx):
    protocol_1 = FWProtocol(transport_1)
    protocol_1.connection_made(transport_2)
    protocol_2 = FWProtocol(transport_2)
    protocol_2.connection_made(transport_1)
