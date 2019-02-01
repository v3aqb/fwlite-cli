
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

import socket
import subprocess
import shlex
import atexit
import logging

logger = logging.getLogger('plugin_manager')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

plugin_args = {'kcptun': ['key value',    # pre-shared secret between client and server (default: "it's a secrect") [$KCPTUN_KEY]
                          'crypt',        # aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none (default: "aes")
                          'mode',         # profiles: fast3, fast2, fast, normal, manual (default: "fast")
                          'conn',         # set num of UDP connections to server (default: 1)
                          'autoexpire',   # set auto expiration time(in seconds) for a single UDP connection, 0 to disable (default: 0)
                          'scavengettl',  # set how long an expired connection can live(in sec), -1 to disable (default: 600)
                          'mtu',          # set maximum transmission unit for UDP packets (default: 1350)
                          'sndwnd',       # set send window size(num of packets) (default: 128)
                          'rcvwnd',       # set receive window size(num of packets) (default: 512)
                          'datashard',
                          'ds',           # set reed-solomon erasure coding - datashard (default: 10)
                          'parityshard',  # set reed-solomon erasure coding - parityshard (default: 3)
                          'ps',
                          'dscp',         # set DSCP(6bit) (default: 0)
                          'nocomp',       # disable compression
                          'sockbuf',      # (default: 4194304)
                          'keepalive',    # (default: 10)]}
                          ],
               'simple-obfs': ['obfs', 'obfs-host'],
               'goquiet': ['ServerName', 'key', 'TicketTimeHint'],
               }

plugin_path = {}


def is_udp(plugin_info):
    if plugin_info[0] == 'kcptun':
        return True
    return False


def plugin_register(plugin, path):
    if plugin in plugin_path:
        logger.error('%s already registered at %s' % (plugin, plugin_path[plugin]))
        return
    logger.info('register plugin: %s %s' % (plugin, path))
    plugin_path[plugin] = path


def plugin_command(host_port, plugin_info, port):
    '''
    host_port: plugin server address
    port: plugin client listening port
    '''
    plugin = plugin_info[0]
    plugin_args = plugin_info[1:]

    if plugin not in plugin_path:
        raise ValueError('plugin "%s" not registered!' % plugin)

    cmd = shlex.split(plugin_path[plugin])
    if 'kcptun' in plugin.lower():
        cmd.extend(['--localaddr', ':%d' % port])
        cmd.extend(['--remoteaddr', '%s:%d' % host_port])
        for args in plugin_args:
            if '=' in args:
                k, v = args.split('=')
                cmd.extend(['--' + k, v])
            else:
                cmd.append('--' + args)
        cmd.append('--quiet')
    elif 'simple-obfs' in plugin.lower():
        cmd.extend(['-s', '%s' % host_port[0]])
        cmd.extend(['-p', '%d' % host_port[1]])
        cmd.extend(['-l', '%d' % port])
        for args in plugin_args:
            cmd.extend(args.split('='))
    elif 'goquiet' in plugin.lower():
        #    gq-client -s 127.0.0.1 -l 1984 -c "ServerName=www.baidu.com;key=123456;TicketTimeHint=3600"
        # or gq-client -s 127.0.0.1 -l 1984 -c "<path-to-conf>"
        cmd.extend(['-s', '%s:%d' % host_port])
        cmd.extend(['-l', '%d' % port])
        args = ';'.join(plugin_args)
        cmd.extend(['-c', '%s' % args])
    return cmd


class PluginManager:

    def __init__(self, conf):
        self.conf = conf
        self.plugin_info = {}
        self.subprocess = {}
        self.plugin_port = {}
        atexit.register(self.cleanup)

    def add(self, host_port, plugin_info, proxy):
        # log plugin info
        key = '%s:%s' % host_port
        key += '-%s' % proxy.proxy
        if key in self.plugin_port:
            logger.warning('plugin registered!')
            return self.plugin_port[key]

        if proxy.proxy and is_udp(plugin_info):
            raise ValueError('cannot proxy UDP plugin')
        self.plugin_info[(host_port, proxy)] = plugin_info
        if proxy.proxy:
            # start tunnel
            tunnel_port = self.tunnel_manager.add(host_port, proxy)

            # adjust tunnel port
            new_host_port = ('127.0.0.1', tunnel_port)
            # assign free socket for plugin
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            _, port = s.getsockname()
            s.close()
            key = '%s:%s' % host_port
            key += '-%s' % proxy.proxy
            self.plugin_port[key] = port
            # start process
            self.start(new_host_port, proxy)
            return
        # assign free socket
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        _, port = s.getsockname()
        s.close()

        self.plugin_port[key] = port
        # start process
        self.start(host_port, proxy)
        return port

    def start(self, host_port, proxy):
        try:
            # construct command line
            key = '%s:%s' % host_port
            key += '-%s' % proxy.proxy
            args = plugin_command(host_port, self.plugin_info[(host_port, proxy)], self.plugin_port[key])
            logger.info(' '.join(args))
            # start subprocess
            process = subprocess.Popen(args)
            self.subprocess[host_port] = process
        except Exception as e:
            logger.error(repr(e))

    def restart(self, host_port, proxy):
        self.subprocess[(host_port, proxy)].kill()
        self.start(host_port, proxy)

    def cleanup(self):
        # kill all subprocess
        all_processes = [v for k, v in self.subprocess.items()]
        for p in all_processes:  # list of your processes
            p.kill()
