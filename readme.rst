fwlite-cli
===============

FWLite across the GreatFireWall, we can reach every corner of the world.

A intelligent HTTP/Socks5 proxy, detect and circumvent censorship automatically. (CLI part)

Support Python 3.8 and above.

Current Version: 0

2022.07.24: update hxsocks authentication method. before updating to this version, make sure your hxsocks server is updated.

Portable package for `Windows`_

`fwlite-gui`_

features
--------

- Detect blocked sites automatically

  - autoproxy-gfwlist
  - user-defined rules
  - connection reset
  - connect timeout
  - read timeout
- Multiple work profile

  - 0: direct
  - 1: auto (gfwlist)
  - 3: bypass ip in china
  - 4: bypass ip in china and LAN
  - 5: bypass localhost only
- Randomize listening port (when listening port is 0)
- Support Network requires a Proxy (`fwlite#39`_)
- Supported parent proxy

  - HTTP
  - socks5
  - shadowsocks
  - hxsocks2
  - hxsocks3
  - hxsocks4
- Support SIP003 plugin (`fwlite-cli#1`_)
- Support Shadowsocks Subscription (test pending)
- Supprot proxy chain
- Hosts based AdBlock
- Port Forwarding
- Prioritize proxy by response time
- User-defined redirector
- Simple PAC for WPAD

install
-------

You may want to turn on *tcp timestamps*.

For Linux(should be on by default):

::

    sysctl -w net.ipv4.tcp_timestamps=1

For Windows, start PowerShell with Administrator Privilege, run this command:

::

    netsh interface tcp set global timestamps=enabled

You may want to install ``python3-uvloop`` for better performance.

::

    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/fwlite-cli/archive/master.zip

update
------

using ``pip -U`` may cause problems, better uninstall and install.

::

    pip3 uninstall fwlite-cli
    pip3 uninstall hxcrypto
    pip3 install https://github.com/v3aqb/hxcrypto/archive/master.zip
    pip3 install https://github.com/v3aqb/fwlite-cli/archive/master.zip


Set parent proxy
----------------

Add your own parent proxy in the `parents` section of main configuration file `config.ini`.

It looks like this:

::

    [parents]
    shadowsocks = ss://aes-256-cfb:password@127.0.0.1:8388
    proxy1 = http://user:pass@127.0.0.1:8087
    proxy2 = socks5://127.0.0.1:1080

    # connect to 'http://server:8087' via 'socks5://127.0.0.1:1080'
    proxy3 = http://server:8087|socks5://127.0.0.1:1080

Set browser
-----------

Set system proxy setting to ``127.0.0.1:8118`` (default port, or as configured in ``config.ini``).

Run
---

::

    fwlite-cli -c <path_to_config_file>

.. _Windows: https://github.com/v3aqb/fwlite
.. _fwlite#39: https://github.com/v3aqb/fwlite/issues/39
.. _fwlite-gui: https://github.com/v3aqb/fwlite-gui
.. _fwlite-cli#1: https://github.com/v3aqb/fwlite-cli/issues/1
