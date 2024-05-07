
from asyncio import transports, constants, get_running_loop
from asyncio.log import logger


class FWTransport(transports.Transport):
    def __init__(self, protocol, peer=None, extra=None):
        super().__init__(extra)
        self._protocol = protocol  # reader protocol
        self._peer = peer
        self._protocol.connection_made(self)
        self._closing = False
        self._paused = False  # Reading
        self._conn_lost = 0
        self._eof = False            # eof from Endpoint, sent to Conn
        self._eof_from_conn = False  # eof from Conn, sent to Endpoint
        self._empty_waiter = None
        self._protocol_paused = False
        # self._set_write_buffer_limits()

    def get_peer(self, protocol):
        # set self._peer
        assert self._peer is None
        self._peer = FWTransport(protocol, self)
        return self._peer

    # BaseTransport
    def is_closing(self):
        """Return True if the transport is closing or closed."""
        return self._closing

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously.  No more data
        will be received.  After all buffered data is flushed, the
        protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        if self._closing:
            return
        self._closing = True
        self.write_eof()
        self._conn_lost += 1
        self._peer.close()
        loop = get_running_loop()
        loop.call_soon(self._call_connection_lost, None)

    def _call_connection_lost(self, exc):
        try:
            self._protocol.connection_lost(exc)
        finally:
            self.resume_reading()
            self._protocol = None

    def set_protocol(self, protocol):
        """Set a new protocol."""
        self._protocol = protocol
        self._protocol.connection_made(self)

    def get_protocol(self):
        """Return the current protocol."""
        return self._protocol

    # called by peer transport
    def pause_writing(self):
        self._protocol.pause_writing()

    def resume_writing(self):
        self._protocol.resume_writing()

    def data_received(self, data):
        self._protocol.data_received(data)

    def eof_received(self):
        self._protocol.eof_received()

    # called by self._protocol
    def is_reading(self):
        """Return True if the transport is receiving."""
        return not self._paused and not self._closing

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received()
        method until resume_reading() is called.
        """
        if self._closing or self._paused:
            return
        self._paused = True
        self._peer.pause_writing()

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        if self._closing or not self._paused:
            return
        self._paused = False
        self._peer.resume_writing()

    # called by Writer
    def write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'data argument must be a bytes-like object, '
                            f'not {type(data).__name__!r}')
        if self._eof:
            raise RuntimeError('Cannot call write() after write_eof()')
        if self._empty_waiter is not None:
            raise RuntimeError('unable to write; sendfile is in progress')
        if not data:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                logger.warning('FWTransport.write() raised exception.')
            self._conn_lost += 1
            return
        self._peer.data_received(data)

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return True

    def write_eof(self):
        """Close the write end after flushing buffered data.

        (This is like typing ^D into a UNIX program reading from stdin.)

        Data may still be received.
        """
        if self._eof:
            return
        self._eof = True
        self._peer.eof_received()

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._peer.close()
