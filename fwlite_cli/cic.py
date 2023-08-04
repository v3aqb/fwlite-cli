
# cic.py
# this file is a part of fwlite_cli
# connection information center

from fwlite_cli.get_proxy import get_proxy
from fwlite_cli.redirector import redirector
from fwlite_cli.resolver import Resolver
import urllib.parse as urlparse


class CIC:
    def __init__(self, conf):
        self.conf = conf
        self.redir_o = redirector(self.conf)
        self.get_proxy_o = get_proxy(self)
        self.resolver = Resolver(self)

    def load(self):
        self.redir_o.load()
        self.get_proxy_o.load()

    def get_proxy(self, *args):
        return self.get_proxy_o.get_proxy(*args)

    def list_localrule(self):
        return [(rule, self.get_proxy_o.local.expire[rule]) for rule in self.get_proxy_o.local.rules]

    def add_localrule(self, rule, expire):
        self.get_proxy_o.add_temp(rule, expire)

    def del_localrule(self, rule):
        self.get_proxy_o.local.remove(rule)
        self.conf.stdout('local')

    def notify(self, *args):
        return self.get_proxy_o.notify(*args)

    def redirect(self, handler):
        return self.redir_o.redirect(handler)

    def add_redir(self, rule, dest):
        self.get_proxy_o.add_redirect(rule, dest)
        self.conf.stdout('redir')

    def list_redir(self):
        return self.redir_o.list()

    def del_redir(self, rule):
        self.redir_o.remove(rule)
        self.conf.stdout('redir')

    def inspect(self, url):
        ''' url: either url or host
            return: string
        '''
        result = f'url: {url}\n'
        if '//' in url:
            host = urlparse.urlparse(url).netloc
            host = parse_hostport(host, 80)[0]
        else:
            host = url
            url = f'https://{url}/'
        result += self.get_proxy_o.inspect(url, host)
        return result
