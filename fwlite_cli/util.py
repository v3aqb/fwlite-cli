#!/usr/bin/env python
# coding: UTF-8
#

# Copyright (C) 2012-2018 v3aqb

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

import sys
import re
import io
import struct
import socket
import configparser


configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')


class SConfigParser(configparser.ConfigParser):
    """docstring for SSafeConfigParser"""
    optionxform = str

    def dget(self, section, option, default=''):
        try:
            value = self.get(section, option)
            if not value:
                value = default
        except Exception:
            value = default
        return value

    def dgetfloat(self, section, option, default=0):
        try:
            return self.getfloat(section, option)
        except Exception:
            return float(default)

    def dgetint(self, section, option, default=0):
        try:
            return self.getint(section, option)
        except Exception:
            return int(default)

    def dgetbool(self, section, option, default=False):
        try:
            return self.getboolean(section, option)
        except Exception:
            return bool(default)

    def items(self, section):
        try:
            return configparser.ConfigParser.items(self, section)
        except Exception:
            return []

    def set(self, section, option, value):
        if not self.has_section(section):
            self.add_section(section)
        configparser.ConfigParser.set(self, section, option, value)


def parse_hostport(host, default_port=80):
    if isinstance(host, bytes):
        host = host.decode()
    match = re.match(r'(.+):(\d+)$', host)
    if match:
        return match.group(1).strip('[]'), int(match.group(2))
    return host.strip('[]'), default_port


def extract_tls_extension(packet):
    # modified from https://github.com/phuslu/sniproxy/blob/master/sniproxy_py3.py
    extensions = {}
    if packet.startswith(b'\x16\x03'):
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length + 2)
        struct.unpack('>h', stream.read(2))  # extensions_length
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            extensions[etype] = edata
    return extensions


def sizeof_fmt(num):
    if num < 1024:
        return "%dB" % num
    for x in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return "%.1f%s" % (num, x)
        num /= 1024.0
    return "%.1f%s" % (num, 'TB')


def get_port(addr, port=0):
    try:
        soc = socket.socket()
        soc.bind((addr, port))
        _, port = soc.getsockname()
        soc.close()
        return port
    except OSError:
        return 0


def set_keepalive(soc):
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if sys.platform.startswith('win32'):
        soc.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 15000, 5000))
    elif sys.platform.startswith('linux'):
        soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)
        soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    elif sys.platform.startswith('darwin'):
        tcp_keepintvl = 0x10
        soc.setsockopt(socket.IPPROTO_TCP, tcp_keepintvl, 5)


import time
from hxcrypto import AEncryptor


def test_one(method, block, repeat):
    data = b'\0' * block
    cipher = AEncryptor(b'123456', method, b"ctx", check_iv=False)
    cipher.encrypt(data)
    time_log = time.time()
    for _ in range(repeat):
        cipher.encrypt(data)
    return time.time() - time_log


def test_cipher():
    '''
    result_chacha20 on different CPU:
    Intel i3:   0.01
    Cortex-A7:  0.21
    Cortex-A76: 0.05
    on CPU with AES-NI, aes128 is 10% faster than chacha20
    without AES-NI, chacha20 is twice faster
    '''
    result_aes = test_one('aes-128-gcm', 10240, 512)
    result_chacha20 = test_one('chacha20-ietf-poly1305', 10240, 512)
    result = result_aes / result_chacha20
    return (result_aes, result_chacha20, result)


cipher_test = test_cipher()
