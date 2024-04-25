import ipaddress
from mininet.topo import Topo
from utils.utils_leo import extract_ip_mask, get_trailing_number, int_to_ip
from utils.utils_phill import mask_to_prefix_len


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch("s1")

        for i in range(1, n + 1):
            host = self.addHost(
                "h%d" % i, ip="10.0.0.%d" % i, mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)


class WrapperTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        self.router_info = {}

    def init_router(self, router_id, cpu_ip):
        # preprocess the ip address
        ip, network_mask = extract_ip_mask(cpu_ip)

        # initing the mininet instances
        cpu_name = "cpu%d" % router_id
        router_name = "r%d" % router_id

        router = self.addSwitch(router_name)
        cpu = self.addHost(cpu_name, ip=cpu_ip)

        self.addLink(cpu, router, port1=1, port2=1)

        self.router_info[router] = {
            "ports": set(),
            "cpu_name": cpu_name,
            "cpu_ip": ip,
            "netmask": network_mask,
        }
        return router

    def init_host(self, host_id, host_ip):
        return self.addHost("h%d" % host_id, ip=host_ip)

    def connect_router_host(self, router_name, host_name, router_port, host_port):
        assert router_port != 1  # reserved for cpu
        # host ip should be a subnetted one
        self.addLink(
            host_name,
            router_name,
            port1=host_port,
            port2=router_port,
        )
        self.router_info[router_name]["ports"].add(router_port)

    def connect_router_router(
        self, router1_name, router2_name, router1_port, router2_port
    ):
        assert (
            router1_port != 1 and router2_port != 1 and router1_name != router2_name
        )  # reserved for cpu
        # host ip should be a subnetted one
        self.addLink(
            router1_name,
            router2_name,
            port1=router1_port,
            port2=router2_port,
        )
        self.router_info[router1_name]["ports"].add(router1_port)
        self.router_info[router2_name]["ports"].add(router2_port)

    def connect_two_routers_here(self, router1, router2, port1, port2):

        id1 = get_trailing_number(router1)
        id2 = get_trailing_number(router2)

        self.connect_router_router(router1, router2, port1, port2)
        self.router_info[router1]["port_ips_macs"][port1] = {
            "ip": "10.0.%d.%d" % (id1, port1),
            "mac": "00:00:00:00:%02x:%02x" % (id1, port1),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        self.router_info[router2]["port_ips_macs"][port2] = {
            "ip": "10.0.%d.%d" % (id2, port2),
            "mac": "00:00:00:00:%02x:%02x" % (id2, port2),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

    def get_sw_intfs_info(self, sw_name):
        assert sw_name in self.router_info, "Invalid switch name"
        sw_port_ips_macs = self.router_info[sw_name]["port_ips_macs"]
        intfs_info = {}
        intfs_info[sw_name + "-eth1"] = self.router_info[sw_name]["cpu_ip"] + "/" + str(
            mask_to_prefix_len(int_to_ip(self.router_info[sw_name]["netmask"]))
        )
        for portn, port_info in sw_port_ips_macs.items():
            intf_name = "%s-eth%d" % (sw_name, portn)
            intfs_info[intf_name] = port_info['ip'] + '/' + str(mask_to_prefix_len(port_info['mask']))
        return intfs_info

class SingleRouterTopo(WrapperTopo):
    def __init__(self, n, **opts):
        WrapperTopo.__init__(self, **opts)

        router = self.init_router(1, "10.1.1.1/24")

        for i in range(2, n + 1):
            host = self.init_host(i, "10.0.0.%d" % i)
            self.connect_router_host(router, host, i, i)

        self.router_info[router]["port_ips_macs"] = {}
        for i in range(2, n + 1):
            self.router_info[router]["port_ips_macs"][i] = {
                "ip": "10.1.1.%d" % i,
                "mac": "00:00:00:00:11:%02x" % i,
                "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 24).netmask),
            }


class DoubleRouterTopo(WrapperTopo):
    def __init__(self, **opts):
        WrapperTopo.__init__(self, **opts)

        router1 = self.init_router(1, "10.1.1.1/24")
        router2 = self.init_router(2, "10.2.2.2/24")

        self.connect_router_router(router1, router2, 2, 3)

        self.router_info[router1]["port_ips_macs"] = {}
        self.router_info[router2]["port_ips_macs"] = {}

        self.router_info[router1]["port_ips_macs"][2] = {
            "ip": "10.1.1.2",
            "mac": "00:00:00:00:11:02",
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 24).netmask),
        }
        self.router_info[router2]["port_ips_macs"][3] = {
            "ip": "10.1.1.3",
            "mac": "00:00:00:00:22:03",
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 24).netmask),
        }

class LineTopo(WrapperTopo):
    def __init__(self, **opts):
        WrapperTopo.__init__(self, **opts)

        router1 = self.init_router(1, "10.0.1.0/16")
        router2 = self.init_router(2, "10.0.2.0/16")
        #router3 = self.init_router(3, "10.0.3.0/16")
        #router4 = self.init_router(4, "10.0.4.0/16")

        self.router_info[router1]["port_ips_macs"] = {}
        self.router_info[router2]["port_ips_macs"] = {}
        #self.router_info[router3]["port_ips_macs"] = {}
        #self.router_info[router4]["port_ips_macs"] = {}

        self.connect_two_routers_here(router1, router2, 12, 11)
        #self.connect_two_routers_here(router2, router3, 13, 12)
        #self.connect_two_routers_here(router3, router4, 14, 13)

        h1 = self.init_host(1, "10.0.1.201/16")
        self.connect_router_host(router1, h1, 101, 201)
        self.router_info[router1]["port_ips_macs"][101] = {
            "ip": "10.0.%d.%d" % (1, 101),
            "mac": "00:00:00:00:%02x:%02x" % (1, 101),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h2 = self.init_host(2, "10.0.1.202/16")
        self.connect_router_host(router1, h2, 102, 202)
        self.router_info[router1]["port_ips_macs"][102] = {
            "ip": "10.0.%d.%d" % (1, 102),
            "mac": "00:00:00:00:%02x:%02x" % (1, 102),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h3 = self.init_host(3, "10.0.1.203/16")
        self.connect_router_host(router1, h3, 103, 203)
        self.router_info[router1]["port_ips_macs"][103] = {
            "ip": "10.0.%d.%d" % (1, 103),
            "mac": "00:00:00:00:%02x:%02x" % (1, 103),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h4 = self.init_host(4, "10.0.2.204/16")
        self.connect_router_host(router1, h4, 104, 204)
        self.router_info[router1]["port_ips_macs"][104] = {
            "ip": "10.0.%d.%d" % (2, 104),
            "mac": "00:00:00:00:%02x:%02x" % (2, 104),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h5 = self.init_host(5, "10.0.2.205/16")
        self.connect_router_host(router1, h5, 105, 205)
        self.router_info[router1]["port_ips_macs"][105] = {
            "ip": "10.0.%d.%d" % (2, 105),
            "mac": "00:00:00:00:%02x:%02x" % (2, 105),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h6 = self.init_host(6, "10.0.2.206/16")
        self.connect_router_host(router1, h6, 106, 206)
        self.router_info[router1]["port_ips_macs"][106] = {
            "ip": "10.0.%d.%d" % (2, 106),
            "mac": "00:00:00:00:%02x:%02x" % (2, 106),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

# Massive Configuration Problem, yet to be resultved
class OSPFTopo(WrapperTopo):
    def __init__(self, **opts):
        WrapperTopo.__init__(self, **opts)

        router1 = self.init_router(1, "10.0.1.0/16")
        router2 = self.init_router(2, "10.0.2.0/16")
        router3 = self.init_router(3, "10.0.3.0/16")
        router4 = self.init_router(4, "10.0.4.0/16")

        self.router_info[router1]["port_ips_macs"] = {}
        self.router_info[router2]["port_ips_macs"] = {}
        self.router_info[router3]["port_ips_macs"] = {}
        self.router_info[router4]["port_ips_macs"] = {}

        self.connect_two_routers_here(router1, router2, 12, 11)
        self.connect_two_routers_here(router2, router3, 13, 12)
        self.connect_two_routers_here(router3, router4, 14, 13)
        self.connect_two_routers_here(router4, router1, 11, 14)


class OSPFTopoHard(WrapperTopo):
    def __init__(self, **opts):
        WrapperTopo.__init__(self, **opts)

        router1 = self.init_router(1, "10.0.1.0/16")
        router2 = self.init_router(2, "10.0.2.0/16")
        router3 = self.init_router(3, "10.0.3.0/16")
        router4 = self.init_router(4, "10.0.4.0/16")
        router5 = self.init_router(5, "10.0.5.0/16")
        router6 = self.init_router(6, "10.0.6.0/16")
        router7 = self.init_router(7, "10.0.7.0/16")
        router8 = self.init_router(8, "10.0.8.0/16")
        router9 = self.init_router(9, "10.0.9.0/16")

        self.router_info[router1]["port_ips_macs"] = {}
        self.router_info[router2]["port_ips_macs"] = {}
        self.router_info[router3]["port_ips_macs"] = {}
        self.router_info[router4]["port_ips_macs"] = {}
        self.router_info[router5]["port_ips_macs"] = {}
        self.router_info[router6]["port_ips_macs"] = {}
        self.router_info[router7]["port_ips_macs"] = {}
        self.router_info[router8]["port_ips_macs"] = {}
        self.router_info[router9]["port_ips_macs"] = {}

        self.connect_two_routers_here(router1, router2, 12, 11)
        self.connect_two_routers_here(router2, router3, 13, 12)
        self.connect_two_routers_here(router3, router4, 14, 13)
        self.connect_two_routers_here(router4, router1, 11, 14)
        self.connect_two_routers_here(router3, router5, 15, 13)
        self.connect_two_routers_here(router4, router5, 15, 14)
        self.connect_two_routers_here(router5, router9, 19, 15)
        self.connect_two_routers_here(router5, router6, 16, 15)
        self.connect_two_routers_here(router6, router7, 17, 16)
        self.connect_two_routers_here(router7, router8, 18, 17)
        self.connect_two_routers_here(router8, router9, 19, 18)


class ComprehensiveTopo(WrapperTopo):
    def __init__(self, **opts):
        WrapperTopo.__init__(self, **opts)

        router1 = self.init_router(1, "10.0.1.0/16")
        router2 = self.init_router(2, "10.0.2.0/16")
        router3 = self.init_router(3, "10.0.3.0/16")
        router4 = self.init_router(4, "10.0.4.0/16")
        router5 = self.init_router(5, "10.0.5.0/16")
        router6 = self.init_router(6, "10.0.6.0/16")
        router7 = self.init_router(7, "10.0.7.0/16")
        router8 = self.init_router(8, "10.0.8.0/16")
        router9 = self.init_router(9, "10.0.9.0/16")
        router10 = self.init_router(10, "10.1.10.0/16")
        router11 = self.init_router(11, "10.2.11.0/16")

        self.router_info[router1]["port_ips_macs"] = {}
        self.router_info[router2]["port_ips_macs"] = {}
        self.router_info[router3]["port_ips_macs"] = {}
        self.router_info[router4]["port_ips_macs"] = {}
        self.router_info[router5]["port_ips_macs"] = {}
        self.router_info[router6]["port_ips_macs"] = {}
        self.router_info[router7]["port_ips_macs"] = {}
        self.router_info[router8]["port_ips_macs"] = {}
        self.router_info[router9]["port_ips_macs"] = {}
        self.router_info[router10]["port_ips_macs"] = {}
        self.router_info[router11]["port_ips_macs"] = {}

        self.connect_two_routers_here(router1, router2, 12, 11)
        self.connect_two_routers_here(router2, router3, 13, 12)
        self.connect_two_routers_here(router3, router4, 14, 13)
        self.connect_two_routers_here(router4, router1, 11, 14)
        self.connect_two_routers_here(router3, router5, 15, 13)
        self.connect_two_routers_here(router4, router5, 15, 14)
        self.connect_two_routers_here(router5, router9, 19, 15)
        self.connect_two_routers_here(router5, router6, 16, 15)
        self.connect_two_routers_here(router6, router7, 17, 16)
        self.connect_two_routers_here(router7, router8, 18, 17)
        self.connect_two_routers_here(router8, router9, 19, 18)

        # connect 9 and 10, being in different subnets:
        self.connect_router_router(router9, router10, 20, 19)
        self.router_info[router9]["port_ips_macs"][20] = {
            "ip": "10.1.%d.%d" % (9, 20),
            "mac": "00:00:00:00:%02x:%02x" % (9, 20),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        self.router_info[router10]["port_ips_macs"][19] = {
            "ip": "10.0.%d.%d" % (10, 19),
            "mac": "00:00:00:00:%02x:%02x" % (10, 19),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        # connect 10 and 11, being in different subnets:
        self.connect_router_router(router10, router11, 21, 20)
        self.router_info[router10]["port_ips_macs"][21] = {
            "ip": "10.2.%d.%d" % (10, 21),
            "mac": "00:00:00:00:%02x:%02x" % (10, 21),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        self.router_info[router11]["port_ips_macs"][20] = {
            "ip": "10.1.%d.%d" % (11, 20),
            "mac": "00:00:00:00:%02x:%02x" % (11, 20),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        # connect 10 and 11, being in different subnets:
        self.connect_router_router(router9, router11, 21, 19)
        self.router_info[router9]["port_ips_macs"][21] = {
            "ip": "10.2.%d.%d" % (9, 21),
            "mac": "00:00:00:00:%02x:%02x" % (9, 21),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        self.router_info[router11]["port_ips_macs"][19] = {
            "ip": "10.0.%d.%d" % (11, 19),
            "mac": "00:00:00:00:%02x:%02x" % (11, 19),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        h1 = self.init_host(1, "10.0.1.222/16")
        self.connect_router_host(router1, h1, 111, 222)
        self.router_info[router1]["port_ips_macs"][111] = {
            "ip": "10.0.%d.%d" % (1, 111),
            "mac": "00:00:00:00:%02x:%02x" % (1, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h2 = self.init_host(2, "10.0.2.222/16")
        self.connect_router_host(router2, h2, 111, 222)
        self.router_info[router2]["port_ips_macs"][111] = {
            "ip": "10.0.%d.%d" % (2, 111),
            "mac": "00:00:00:00:%02x:%02x" % (2, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h3 = self.init_host(3, "10.0.3.222/16")
        self.connect_router_host(router3, h3, 111, 222)
        self.router_info[router3]["port_ips_macs"][111] = {
            "ip": "10.0.%d.%d" % (3, 111),
            "mac": "00:00:00:00:%02x:%02x" % (3, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }
        h4 = self.init_host(4, "10.0.4.222/16")
        self.connect_router_host(router4, h4, 111, 222)
        self.router_info[router4]["port_ips_macs"][111] = {
            "ip": "10.0.%d.%d" % (4, 111),
            "mac": "00:00:00:00:%02x:%02x" % (4, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        h9 = self.init_host(9, "10.0.9.222/16")
        self.connect_router_host(router9, h9, 111, 111)
        self.router_info[router9]["port_ips_macs"][111] = {
            "ip": "10.0.%d.%d" % (9, 111),
            "mac": "00:00:00:00:%02x:%02x" % (9, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        h10 = self.init_host(10, "10.1.10.222/16")
        self.connect_router_host(router10, h10, 111, 111)
        self.router_info[router10]["port_ips_macs"][111] = {
            "ip": "10.1.%d.%d" % (10, 111),
            "mac": "00:00:00:00:%02x:%02x" % (10, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }

        h11 = self.init_host(11, "10.2.11.222/16")
        self.connect_router_host(router11, h11, 111, 111)
        self.router_info[router11]["port_ips_macs"][111] = {
            "ip": "10.2.%d.%d" % (11, 111),
            "mac": "00:00:00:00:%02x:%02x" % (11, 111),
            "mask": str(ipaddress.IPv4Network("0.0.0.0/%d" % 16).netmask),
        }


class BadTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        h1 = self.addHost("h1", ip="10.0.0.1")
        # h2 = self.addHost("h2", ip="9.0.0.2")
        h3 = self.addHost("h3", ip="10.0.0.3")
        # self.addLink(h1, h2)
        self.addLink(h1, h3)
