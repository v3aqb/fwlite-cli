fwlite-cli
===============

A anti-censorship HTTP proxy with builtin shadowsocks support, CLI part only.

Support Python 3.5 and above.

Current Version: 0

features
--------

- Detect blocked sites automatically

  - autoproxy-gfwlist
  - user-defined rules
  - connect timeout
  - read timeout
  - connection reset
- Multiple work profile
- Support Network which require a Proxy ([issue #39](https://github.com/v3aqb/fwlite/issues/39))
- Supported parent proxy

  - HTTP
  - socks5
  - shadowsocks (with AEAD support)
  - hxsocks2
- Supported SIP003 plugin

  - simple-obfs
  - kcptun (https://github.com/xtaci/kcptun)
  - GoQuiet
- Prioritize parent proxies by response time
- Redirector
- Port Forward
- Simple PAC for WPAD

install
-------

::

    pip install https://github.com/v3aqb/fwlite-cli/archive/master.zip --process-dependency-links

update
------

using `pip -U` may cause problems, better uninstall and install.

::

    pip uninstall fwlite-cli
    pip uninstall hxcrypto
    pip install https://github.com/v3aqb/fwlite-cli/archive/master.zip --process-dependency-links


Set parent proxy
----------------

**NOTICE**: the config file is a little different than original fwlite.

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

Set proxy setting to `http://127.0.0.1:8118` (default, or as configured).

Run
---

::

    fwlite-cli -c <path_to_config_file>
