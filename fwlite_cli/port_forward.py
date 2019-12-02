
import asyncio
import socket
import time
import logging
import traceback

logger = logging.getLogger('tunnel')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


BUFSIZE = 8196


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
        self.err = None


async def forward_from_client(read_from, write_to, context, timeout=60):
    while True:
        intv = 5
        try:
            fut = read_from.read(BUFSIZE)
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


async def forward_from_remote(read_from, write_to, context, timeout=60):
    count = 0
    while True:
        intv = 5
        try:
            fut = read_from.read(BUFSIZE)
            data = await asyncio.wait_for(fut, intv)
            count += 1
        except asyncio.TimeoutError:
            if time.time() - context.last_active > timeout or context.local_eof:
                data = b''
            else:
                continue
        except ConnectionResetError:
            data = b''

        if not data:
            break
        try:
            context.last_active = time.time()
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

    try:
        write_to.write_eof()
    except (ConnectionResetError, OSError):
        pass


class ForwardHandler:
    def __init__(self, target, proxy, ctimeout=3, timeout=120):
        self.addr, self.port = target
        self.proxy = proxy
        self.timeout = timeout
        self.ctimeout = ctimeout

    async def handle(self, client_reader, client_writer):
        remote_writer = None
        try:
            # connect to target
            from .connection import open_connection
            remote_reader, remote_writer, _ = await open_connection(self.addr,
                                                                    self.port,
                                                                    proxy=self.proxy,
                                                                    timeout=self.ctimeout,
                                                                    tunnel=True)

            # forward
            context = ForwardContext()

            tasks = [forward_from_client(client_reader, remote_writer, context, self.timeout),
                     forward_from_remote(remote_reader, client_writer, context, self.timeout),
                     ]
            await asyncio.wait(tasks)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            logger.error(repr(err))
            logger.error(traceback.format_exc())
        for writer in (remote_writer, client_writer):
            try:
                writer.close()
            except (OSError, AttributeError):
                pass


class ForwardManager:
    def __init__(self, conf):
        self.conf = conf
        self.server = {}
        self.server_info = {}

    def add(self, target, proxy, port=0):
        soc = None
        if port == 0:
            soc = socket.socket()
            soc.bind(('127.0.0.1', port))
            _, port = soc.getsockname()

        logger.info('add port_forward %s %s %s', target, proxy, port)
        asyncio.ensure_future(self.add_forward(target, proxy, port, soc))
        return port

    async def add_forward(self, target, proxy, port, soc=None):
        if isinstance(proxy, str):
            proxy = self.conf.parentlist.get(proxy)
        if soc:
            soc.close()
        # start server on port
        handler = ForwardHandler(target, proxy, timeout=120)
        loop = asyncio.get_event_loop()
        server = await asyncio.start_server(handler.handle, '127.0.0.1', port, loop=loop)
        self.server[port] = server
        self.server_info[port] = (target, proxy.name)
        self.conf.stdout('forward')

    def stop(self, port):
        asyncio.ensure_future(self.stop_w(port))

    async def stop_w(self, port):
        import sys
        if sys.platform == 'win32':
            if sys.version_info < (3, 7):
                return

        logger.info('removing forward %s', port)
        server = self.server[port]
        server.close()
        await server.wait_closed()
        del self.server[port]
        del self.server_info[port]
        self.conf.stdout('forward')

    def list(self):
        return [(target_proxy[0], target_proxy[1], port)
                for port, target_proxy in self.server_info.items()]
