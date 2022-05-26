
import bisect
import ipaddress
import logging


logger = logging.getLogger('ipfilter')


def set_logger():
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


class NetFilter:
    def __init__(self):
        # keep this list sorted
        self.net_list_4 = []
        self.net_list_6 = []
        self.ip_set = set()

    def add(self, network):
        if not any([isinstance(network, ipaddress.IPv4Network),
                    isinstance(network, ipaddress.IPv6Network)]):
            network = ipaddress.ip_network(network)
            # raises ValueError

        if network.num_addresses == 1:
            self.ip_set.add(int(network.network_address))
            return

        network_list = self.net_list_4 if network.version == 4 else self.net_list_6

        # if network_list is empty
        if not network_list:
            network_list.append(network)
            return
        # check for overlap
        if self.contains(network.network_address):
            logger.error('%r already in this filter.', network)
            return
        if network.network_address > network_list[-1].network_address:
            network_list.append(network)
        else:
            # find proper location for this network to insert
            index = bisect.bisect(network_list, network)
            network_list.insert(index, network)

    def remove(self, network):
        if not any([isinstance(network, ipaddress.IPv4Network),
                    isinstance(network, ipaddress.IPv6Network)]):
            network = ipaddress.ip_network(network)
            # raises ValueError

        if network.num_addresses == 1:
            self.ip_set.discard(int(network.network_address))
            return

        network_list = self.net_list_4 if network.version == 4 else self.net_list_6

        if not network_list:
            return

        item = self.contains(network.network_address)
        if item:
            network_list.remove(item)
            return

    def contains(self, item):
        if not any([isinstance(item, ipaddress.IPv4Network),
                    isinstance(item, ipaddress.IPv6Network)]):
            try:
                item = ipaddress.ip_network(item)
            except ValueError:
                return False

        if item.num_addresses == 1 and int(item.network_address) in self.ip_set:
            return True

        network_list = self.net_list_4 if item.version == 4 else self.net_list_6

        if not network_list:
            return False

        index = bisect.bisect(network_list, item)

        if item.network_address in network_list[index - 1]:
            return network_list[index - 1]
        return False

    def __contains__(self, item):
        if self.contains(item):
            return True
        return False

    def __repr__(self):
        return "NetFilter v4: %d, v6: %d, ip: %d" % (len(self.net_list_4), len(self.net_list_6), len(self.ip_set))
