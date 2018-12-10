
# Copyright (C) 2018 v3aqb

# This file is part of fwlite-cli.

# Fwlite-cli is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Fwlite-cli is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with fwlite-cli.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, division

import os
import sys
import logging
import argparse

import asyncio

from .config import Config
from .proxy_handler import handler_factory, http_handler
from . import __version__


def main():
    s = 'FWLite %s with asyncio, ' % __version__
    import platform
    s += 'python %s %s' % (platform.python_version(), platform.architecture()[0])

    logger = logging.getLogger('FW_Lite')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="path to config file")
    parser.add_argument('-gui', action='store_true')
    args = parser.parse_args()

    if args.gui:
        s += ' with GUI'

    logger.info(s)
    if not os.path.exists(args.c):
        sys.stderr.write('config file {} not exist!\n'.format(args.c))
        sys.exit()

    conf = Config(args.c, args.gui)

    for i, profile in enumerate(list(conf.userconf.dget('FWLite', 'profile', '13'))):
        server = handler_factory(conf.listen[0], conf.listen[1] + i, http_handler, int(profile), conf)
        loop = asyncio.get_event_loop()
        coro = asyncio.start_server(server.handle, server.addr, server.port, loop=loop)
        server = loop.run_until_complete(coro)

    loop.call_soon(conf.stdout)
    # loop.add_signal_handler(signal.SIGTERM, loop.stop)
    # loop.add_signal_handler(signal.SIGINT, sys.exit)
    try:
        loop.run_forever()
    finally:
        sys.exit()


if __name__ == '__main__':
    main()
