
from asyncio import transports, constants, ensure_future
from asyncio.log import logger


class FWTransport(transports._FlowControlMixin):
    def __init__(self, loop, protocol, conn):
        super().__init__(loop=loop)
        self._loop = loop
        self._protocol = protocol  # reader protocol
        self._conn = conn
        self._stream_id = None
        self._closing = False
        self._server = None
        self._paused = False  # Reading
        self._protocol_paused = False
        self._conn_lost = 0
        self._eof = False            # eof from Endpoint, sent to Conn
        self._eof_from_conn = False  # eof from Conn, sent to Endpoint
        self._empty_waiter = None

    async def connect(self, addr, port, timeout, tcp_nodelay):
        # set self._stream_id
        self._stream_id = await self._conn.create_connection(
            addr, port, timeout, self, tcp_nodelay)
        self._protocol.connection_made(self)

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
        self.eof_from_conn()
        self._conn_lost += 1
        self._loop.call_soon(self._call_connection_lost, None)

    def _call_connection_lost(self, exc):
        try:
            self._protocol.connection_lost(exc)
        finally:
            self.resume_reading()
            self._conn.close_stream(self._stream_id)
            self._conn = None
            self._protocol = None
            self._loop = None
            server = self._server
            if server is not None:
                server._detach()
                self._server = None

    def set_protocol(self, protocol):
        """Set a new protocol."""
        self._protocol = protocol

    def get_protocol(self):
        """Return the current protocol."""
        return self._protocol

    # Called by Endpoint StreamReaderProtocol
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
        self._conn.pause_reading_stream(self._stream_id)

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        if self._closing or not self._paused:
            return
        self._paused = False
        self._conn.resume_reading_stream(self._stream_id)

    # Called by Conn, act as writer. feed data to Endpoint StreamReaderProtocol
    def data_from_conn(self, data):
        """called by conn, should await self.drain() next"""
        if not self._eof_from_conn:
            self._protocol.data_received(data)

    def eof_from_conn(self):
        self._eof_from_conn = True
        if self._protocol:
            self._protocol.eof_received()

    # called by Endpoint StreamWriter, send data to Conn
    def get_write_buffer_size(self):
        """Return the current size of the write buffer."""
        return self._conn.get_write_buffer_size(self._stream_id)

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
        self._conn.write_stream(data, self._stream_id)
        self._maybe_pause_protocol()

    def _maybe_pause_protocol(self):
        '''called after write to conn'''
        size = self.get_write_buffer_size()
        if size <= self._high_water:
            return
        if not self._protocol_paused:
            self._protocol_paused = True
            try:
                self._protocol.pause_writing()
                ensure_future(self.wait_resume_writing())
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler({
                    'message': 'protocol.pause_writing() failed',
                    'exception': exc,
                    'transport': self,
                    'protocol': self._protocol,
                })

    async def wait_resume_writing(self):
        try:
            await self._conn.drain_stream(self._stream_id)
        except OSError:
            self.close()
            return
        self._protocol.resume_writing()

    def write_eof(self):
        """Close the write end after flushing buffered data.

        (This is like typing ^D into a UNIX program reading from stdin.)

        Data may still be received.
        """
        if self._eof:
            return
        self._eof = True
        self._conn.write_eof_stream(self._stream_id)

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return True

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._conn.abort_stream(self._stream_id)
