#!/usr/bin/env python

# Copyright (C) 2014-2019 v3aqb

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

import os
import sys
import socket
import json
import base64
import signal
import logging
import logging.handlers
import asyncio
import urllib.request
import urllib.parse
from collections import defaultdict, deque

from ipaddress import IPv4Address, ip_address

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

from .parent_proxy import ParentProxyList, ParentProxy
from .cic import CIC
from .hxscommon import HC
from .util import SConfigParser, parse_hostport
from .plugin_manager import plugin_register
from .port_forward import ForwardManager
from .plugin_manager import PluginManager


PAC = r'''
var wall_proxy = "__PROXY__";
var direct = "DIRECT;";

/*
 * Copyright (C) 2014 breakwa11
 * https://github.com/breakwa11/gfw_whitelist
 */

var subnetIpRangeList = [
0,1,
167772160,184549376,    //10.0.0.0/8
2886729728,2887778304,  //172.16.0.0/12
3232235520,3232301056,  //192.168.0.0/16
2130706432,2130706688   //127.0.0.0/24
];

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {
    // check if the ipv4 format (TODO: ipv6)
    //   http://home.deds.nl/~aeron/regex/
    var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
    if (re_ipv4.test(host)) {
        // in theory, we can add chnroutes test here.
        // but that is probably too much an overkill.
        return true;
    }
}
function convertAddress(ipchars) {
    var bytes = ipchars.split('.');
    var result = (bytes[0] << 24) |
    (bytes[1] << 16) |
    (bytes[2] << 8) |
    (bytes[3]);
    return result >>> 0;
}
function isInSubnetRange(ipRange, intIp) {
    for ( var i = 0; i < 10; i += 2 ) {
        if ( ipRange[i] <= intIp && intIp < ipRange[i+1] )
            return true;
    }
}
function getProxyFromDirectIP(strIp) {
    var intIp = convertAddress(strIp);
    if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
        return direct;
    }
    return wall_proxy;
}
function isInDomains(domain_dict, host) {
    var suffix;
    var pos1 = host.lastIndexOf('.');

    suffix = host.substring(pos1 + 1);
    if (suffix == "cn") {
        return true;
    }

    var domains = domain_dict[suffix];
    if ( domains === undefined ) {
        return false;
    }
    host = host.substring(0, pos1);
    var pos = host.lastIndexOf('.');

    while(1) {
        if (pos <= 0) {
            if (hasOwnProperty.call(domains, host)) {
                return true;
            } else {
                return false;
            }
        }
        suffix = host.substring(pos + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return true;
        }
        pos = host.lastIndexOf('.', pos - 1);
    }
}
function FindProxyForURL(url, host) {
    url=""+url;
    host=""+host;
    if ( isPlainHostName(host) === true ) {
        return direct;
    }
    if ( check_ipv4(host) === true ) {
        return getProxyFromDirectIP(host);
    }
    return wall_proxy;
}

'''


def url_retreive(url, path, proxy):
    if proxy.proxy:
        if proxy.scheme == 'http' and '|' not in proxy.proxy:
            proxy_handler = urllib.request.ProxyHandler(
                {'http': proxy.proxy,
                 'https': proxy.proxy})
        else:
            # proxy not supported
            with open(path, 'w') as localfile:
                localfile.write('\n')
            return
    else:
        proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler)
    urlopen = opener.open

    req = urlopen(url)
    data = req.read()
    if req.getcode() == 200 and data:
        with open(path, 'wb') as localfile:
            localfile.write(data)


class _stderr:
    # replace stderr
    def __init__(self, maxlen=100):
        self.store = deque(maxlen=maxlen)

    def write(self, data):
        sys.__stderr__.write(data)
        lines = data.strip().splitlines()
        self.store.extend(lines)

    def flush(self):
        sys.__stderr__.flush()

    def getvalue(self):
        data = '\r\n'.join(self.store)
        # self.store.clear()
        return data


class Config:
    def __init__(self, conf_path, gui):
        self.patch_stderr()

        self.logger = logging.getLogger('config')
        self.logger.setLevel(logging.INFO)
        hdr = logging.StreamHandler()
        format = '%(asctime)s %(name)s:%(levelname)s %(message)s'
        formatter = logging.Formatter(format, datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        ParentProxy.conf = self

        self._started = False
        self.GUI = gui
        self.loop = None
        self.conf_path = conf_path

        self.userconf = SConfigParser(interpolation=None)

        self.hello()

    def init(self):  # pylint: disable=W0201
        self.timeout = 6
        self.profile = '134'
        self.maxretry = 4
        self.rproxy = False
        self.remoteapi = False
        self.remotepass = ''
        self.tcp_nodelay = False
        self.tcp_timeout = 0
        self.udp_enable = False
        self.udp_proxy = ''
        self.udp_timeout = 600

        self.listen = ('127.0.0.1', 8118)

        self.gate = 5
        self.probation = 10

        self.plugin_manager = None  # PluginManager(self)
        self.port_forward = None  # ForwardManager(self)
        self.parentlist = None  # ParentProxyList(self)

        self.HOSTS = defaultdict(list)
        self.local_ip = '127.0.0.1'

        self.PAC = b''

        self.cic = None  # CIC(self)

    def addhost(self, host, ip):
        try:
            ipo = ip_address(ip)
            if isinstance(ipo, IPv4Address):
                self.HOSTS[host].append((2, ip))
            else:
                self.HOSTS[host].append((10, ip))
        except Exception:
            self.logger.error('unsupported host: %s', ip, exc_info=True)

    def reload(self, plugin_dir=None):  # pylint: disable=W0201
        self.init()
        self.conf_path = os.path.abspath(self.conf_path)
        self.conf_dir = os.path.dirname(self.conf_path)
        os.chdir(self.conf_dir)
        self.local_path = os.path.join(self.conf_dir, 'local.txt')
        self.gfwlist_path = os.path.join(self.conf_dir, 'gfwlist.txt')
        self.chinalist_path = os.path.join(self.conf_dir, 'chinalist.txt')
        self.china_ip_path = os.path.join(self.conf_dir, 'china_ip_list.txt')
        self.china_ipv6_path = os.path.join(self.conf_dir, 'china_ip_list_v6.txt')
        self.adblock_path = os.path.join(self.conf_dir, 'adblock.txt')
        self.porn_path = os.path.join(self.conf_dir, 'porn.txt')

        self.userconf.read(self.conf_path, encoding='utf8')

        self.timeout = self.userconf.dgetint('FWLite', 'timeout', self.timeout)
        self.profile = self.userconf.dget('FWLite', 'profile', self.profile)
        if '1' not in self.profile:
            self.profile += '1'
        if '3' not in self.profile:
            self.profile += '3'
        self.maxretry = self.userconf.dgetint('FWLite', 'maxretry', self.maxretry)
        self.rproxy = self.userconf.dgetbool('FWLite', 'rproxy', self.rproxy)
        self.remoteapi = self.userconf.dgetbool('FWLite', 'remoteapi', self.remoteapi)
        self.remotepass = self.userconf.dget('FWLite', 'remotepass', self.remotepass)
        if self.remoteapi and not self.remotepass:
            self.logger.warning('Remote API Enabled WITHOUT password protection!')
        self.tcp_nodelay = self.userconf.dgetbool('FWLite', 'tcp_nodelay', self.tcp_nodelay)
        self.tcp_timeout = self.userconf.dgetint('FWLite', 'tcp_timeout', self.tcp_timeout)

        if self.tcp_timeout == 0:
            self.tcp_timeout = float('+inf')
        else:
            HC.STREAM_TIMEOUT = self.tcp_timeout

        if self.userconf.dgetbool('FWLite', 'eco', False):
            self.tcp_timeout = 30
            HC.STREAM_TIMEOUT = 30
            HC.IDLE_TIMEOUT = 30

        listen = self.userconf.dget('FWLite', 'listen', '8118')
        if listen.isdigit():
            self.listen = ('127.0.0.1', int(listen))
        else:
            self.listen = (listen.rsplit(':', 1)[0], int(listen.rsplit(':', 1)[1]))

        self.gate = self.userconf.dgetint('FWLite', 'gate', self.gate)
        if self.gate < 0:
            self.logger.warning('gate < 0, set to 0')
            self.gate = 0
        self.probation = self.userconf.dgetint('FWLite', 'probation', self.probation)
        ParentProxy.DEFAULT_TIMEOUT = self.timeout
        ParentProxy.GATE = self.gate
        ParentProxy.PROBATION = self.probation

        self.udp_enable = self.userconf.dgetbool('udp', 'enable', self.udp_enable)
        self.udp_proxy = self.userconf.dget('udp', 'proxy', self.udp_proxy)
        self.udp_timeout = self.userconf.dgetint('udp', 'udp_timeout', self.udp_timeout)

        for key, val in self.userconf.items('plugin'):
            if plugin_dir:
                val = os.path.join(plugin_dir, val)
            plugin_register(key, val)

        self.plugin_manager = PluginManager(self)
        self.port_forward = ForwardManager(self)
        self.parentlist = ParentProxyList(self)

        self.HOSTS = defaultdict(list)

        for host, ip_ in self.userconf.items('hosts'):
            self.addhost(host, ip_)

        if not os.path.exists(self.local_path):
            self.logger.warning('"local.txt" not found! creating...')
            with open(self.local_path, 'w') as f:
                f.write('''\
! local gfwlist config
! rules: https://autoproxy.org/zh-CN/Rules
! /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1/
''')

        # prep PAC
        try:
            csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            csock.connect(('8.8.8.8', 53))
            (addr, _) = csock.getsockname()
            csock.close()
            self.local_ip = addr
        except socket.error:
            self.local_ip = '127.0.0.1'

        self.PAC = PAC.replace('__PROXY__', 'PROXY %s:%s' % (self.local_ip, self.listen[1]))
        if self.userconf.dget('FWLite', 'pac', ''):
            if os.path.isfile(self.userconf.dget('FWLite', 'pac', '')):
                with open(self.userconf.dget('FWLite', 'pac', '')) as f:
                    self.PAC = f.read()

        self.PAC = self.PAC.encode()

        self.cic = CIC(self)

    def confsave(self):
        with open(self.conf_path, 'w', encoding='utf8') as conf_file:
            self.userconf.write(conf_file)

    def register_proxy_n_forward(self):
        # add proxy created my fwlite self
        for i, profile in enumerate(self.profile):
            self.addparentproxy('FWLITE:%s' % profile, 'http://127.0.0.1:%d' % (self.listen[1] + i))

        if self.userconf.dget('FWLite', 'parentproxy', ''):
            self.addparentproxy('_D1R3CT_', '%s 0' % self.userconf.dget('FWLite', 'parentproxy'))
        else:
            self.addparentproxy('_D1R3CT_', 'direct 0')

        for key, val in self.userconf.items('parents'):
            if key in ('_D1R3CT_', '_L0C4L_'):
                self.logger.error('proxy name %s is protected!', key)
                continue
            try:
                self.add_proxy(key, val)
            except Exception as err:
                self.logger.error('add proxy failed! %r', err)

        subscription = self.userconf.dget('FWLite', 'subscription', '')
        if subscription:
            self.load_subscription(subscription)

        if not self.rproxy and not [parent for parent in self.parentlist.get_proxy_list() if parent.priority < 100]:
            self.logger.warning('No parent proxy available!')

        for port, target_proxy in self.userconf.items('port_forward'):
            # default using proxy FWLITE:1
            try:
                target, _, proxy = target_proxy.partition(' ')
                target = (target.rsplit(':', 1)[0], int(target.rsplit(':', 1)[1]))
                proxy = proxy or ('FWLITE:' + self.profile[0])
                port = int(port)
                self.port_forward.add(target, proxy, port)
            except Exception as err:
                self.logger.error('Bad port_forward rule, %r', err, exc_info=True)

    def load_subscription(self, subscription):
        proxy = self.parentlist.get('_D1R3CT_')
        if proxy.proxy:
            if proxy.scheme == 'http' and '|' not in proxy.proxy:
                proxy_handler = urllib.request.ProxyHandler(
                    {'http': proxy.proxy,
                     'https': proxy.proxy})
            else:
                # proxy not supported
                self.logger.error('proxy not supported.')
                return
        else:
            proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)
        urlopen = opener.open
        urlquote = urllib.parse.quote

        try:
            req = urlopen(subscription)
            data = req.read()
            if req.getcode() == 200 and data:
                data = json.loads(data)
                for ss_ in data:
                    userinfo = '%s:%s' % (ss_['method'], ss_['password'])
                    userinfo = base64.b64encode(userinfo.encode()).decode()
                    url = 'ss://%s@%s:%d/' % (userinfo, ss_['server'], ss_['server_port'])
                    if ss_.get('plugin', ''):
                        if ss_.get('plugin_opts', ''):
                            plugin_info = urlquote(ss_['plugin'] + ';' + ss_['plugin_opts'])
                        else:
                            plugin_info = urlquote(ss_['plugin'])
                        url += '?plugin=%s' % plugin_info
                    name = ss_['remarks']
                    self.add_proxy(name, url)
        except Exception as err:
            self.logger.error('load subscription failed. %r', err)

    def addparentproxy(self, name, proxy):
        self.parentlist.addstr(name, proxy)

    def stdout(self, text=''):
        if text == 'all':
            self._started = True
            sys.stdout.write('Fwlite port: %s\n' % self.listen[1])
            sys.stdout.flush()
        if not self._started:
            return
        if self.GUI:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()

    async def download(self):
        proxy = self.parentlist.get('FWLITE:3')

        file_list = {self.gfwlist_path: self.userconf.dget('FWLite', 'gfwlist_url', 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt'),
                     self.chinalist_path: self.userconf.dget('FWLite', 'chinalist_url', 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt'),
                     self.china_ip_path: self.userconf.dget('FWLite', 'china_ip_list', 'https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chnroute.txt'),
                     self.china_ipv6_path: self.userconf.dget('FWLite', 'china_ipv6_list', 'https://github.com/QiuSimons/Chnroute/raw/master/dist/chnroute/chnroute-v6.txt'),
                     self.adblock_path: self.userconf.dget('FWLite', 'adblock_url', 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt'),
                     self.porn_path: self.userconf.dget('FWLite', 'porn_url', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts'),
                     }

        def _dl(path, url, proxy):
            file_name = os.path.basename(path)
            self.logger.warning('"%s" not found! downloading...', file_name)
            try:
                url_retreive(url, path, proxy)
            except Exception as err:
                self.logger.warning('download "%s" failed! %r', file_name, err)
                open(path, 'a').close()
            else:
                if path == self.gfwlist_path:
                    with open(self.gfwlist_path) as f:
                        data = f.read()
                        if '.' not in data:
                            data = ''.join(data.split())
                            data = base64.b64decode(data).decode()
                    with open(self.gfwlist_path, 'w') as f:
                        f.write(data)

        task_list = []
        loop = asyncio.get_event_loop()

        def file_exist(path):
            if not os.path.exists(path):
                return False
            with open(path) as f:
                if not f.read().strip():
                    return False
            return True

        for path, url in file_list.items():
            if not file_exist(path):
                task = loop.run_in_executor(None, _dl, path, url, proxy)
                task_list.append(task)

        await asyncio.gather(*task_list)

    async def post_start(self):
        await self.download()
        self.cic.load()
        self.stdout('all')

    @property
    def adblock_enable(self):
        return self.userconf.dgetbool('FWLite', 'adblock', False)

    @adblock_enable.setter
    def adblock_enable(self, val):
        self.userconf.set('FWLite', 'adblock', '1' if val else '0')
        self.confsave()
        self.stdout('setting')

    @property
    def pornblock_enable(self):
        return self.userconf.dgetbool('FWLite', 'pornblock', False)

    @pornblock_enable.setter
    def pornblock_enable(self, val):
        self.userconf.set('FWLite', 'pornblock', '1' if val else '0')
        self.confsave()
        self.stdout('setting')

    @property
    def gfwlist_enable(self):
        return self.userconf.dgetbool('FWLite', 'gfwlist', True)

    @gfwlist_enable.setter
    def gfwlist_enable(self, val):
        self.userconf.set('FWLite', 'gfwlist', '1' if val else '0')
        self.confsave()
        self.stdout('setting')

    def patch_stderr(self):
        self.stderr = _stderr()
        sys.stderr = self.stderr

    def get_log(self):
        return self.stderr.getvalue()

    def list_proxy(self):
        data = [(p.name, p.short, p.priority, f'{p.get_avg_resp_time():.2f}')
                for _, p in self.parentlist.dict.items()]
        data = sorted(data, key=lambda item: item[0])
        data = sorted(data, key=lambda item: item[2])
        return data

    def add_proxy(self, name, proxy):
        if 'FWLITE:' in name:
            raise ValueError
        if name == '_L0C4L_':
            raise ValueError
        self.addparentproxy(name, proxy)
        if name not in ('_D1R3CT_', '_L0C4L_'):
            self.userconf.set('parents', name, proxy)
            self.confsave()

    def del_proxy(self, name):
        self.parentlist.remove(name)
        if self.userconf.has_option('parents', name):
            self.userconf.remove_option('parents', name)
            self.confsave()

    def get_proxy(self, name):
        proxy = self.parentlist.get(name)
        return proxy.proxy

    def proxy_log(self, proxy, host, rtime):
        proxy.log(host, rtime)
        if proxy.name not in ('_D1R3CT_', '_L0C4L_') and rtime < 5:
            self.parentlist.get('_D1R3CT_').log('', rtime)

    def list_forward(self):
        return [('%s:%s' % target, proxy, port)
                for target, proxy, port in self.port_forward.list()]

    def add_forward(self, target, proxy, port):
        target = parse_hostport(target)
        self.port_forward.add(target, proxy, port)

    def del_forward(self, port):
        self.port_forward.stop(port)

    def stop(self):
        self.logger.info('Stop')
        self.plugin_manager.cleanup()
        self.port_forward.stop_all()
        self.stop_fwlite()

    def stop_fwlite(self):
        for server in self.server_list:
            asyncio.ensure_future(server.stop())

    def start_server(self):
        from .proxy_handler import Server, http_handler
        addr, port = self.listen
        while port == 0:
            # find proper port
            from .util import get_port
            port_0 = get_port(addr)
            fail = False
            for i in range(len(self.profile) - 1):
                if get_port(addr, port_0 + 1 + i) == 0:
                    fail = True
            if not fail:
                port = port_0
                self.listen = (addr, port)
                break

        self.logger.info('Fwlite port: %s', port)

        if not self.userconf.dget('FWLite', 'pac', ''):
            self.PAC = PAC.replace('__PROXY__', 'PROXY %s:%s' % (self.local_ip, self.listen[1])).encode()

        self.server_list = []
        for i, profile in enumerate(self.profile):
            profile = int(profile)
            server = Server(addr, port + i, http_handler, profile, self)
            server.start()
            self.server_list.append(server)

        if os.path.exists(os.path.join(self.conf_dir, 'hxsocks.yaml')):
            try:
                from hxsocks.start_server import start_hxs_server
                server_list = start_hxs_server('hxsocks.yaml')
                if server_list:
                    self.server_list.extend(server_list)
            except Exception as err:
                self.logger.error(repr(err), exc_info=True)

    def set_loop(self):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.loop = loop

    async def shutdown(self, s):
        self.logger.info("Received exit signal %s...", s.name)
        self.plugin_manager.cleanup()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

        _ = [task.cancel() for task in tasks]

        self.logger.info("Cancelling %s outstanding tasks", len(tasks))
        await asyncio.gather(*tasks)
        self.loop.stop()

    def start(self):
        self.set_loop()
        self.start_server()
        self.register_proxy_n_forward()
        asyncio.ensure_future(self.post_start())
        try:
            signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
            for s in signals:
                self.loop.add_signal_handler(
                    s, lambda s=s: asyncio.create_task(self.shutdown(s)))
        except (AttributeError, NotImplementedError, RuntimeError):
            pass
        try:
            self.loop.run_forever()
        except (SystemExit, KeyboardInterrupt):
            self.logger.info('KeyboardInterrupt')
        finally:
            self.loop.close()
            self.plugin_manager.cleanup()
            self.logger.info('start() ended')
            sys.exit()

    def hello(self):
        from . import __version__
        hello = f'FWLite {__version__} with asyncio, '
        import platform
        hello += f'python {platform.python_version()} {platform.architecture()[0]}'

        if self.GUI:
            hello += ' with GUI'

        sys.stderr.write(hello + '\n')
