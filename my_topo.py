from mininet.topo import Topo
from collections import defaultdict


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch("s1")

        for i in range(1, n + 1):
            host = self.addHost(
                "h%d" % i, ip="10.0.0.%d" % i, mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)

    def __str__(self):
        resp = "************ TOPOLOGY ************\n"
        for host in self.hosts():
            resp += "Host: %s\n" % host
        resp += "************ LINKS **************\n"
        for switch in self.switches():
            for link in self.links():
                if switch in link:
                    resp += "%s -- %s\n" % (link[0], link[1])
        resp += "*********************************\n"
        return resp


class DoubleSwitchTopo(Topo):
    # IP assignment:   1 -> CPU, 2-99 -> router interfaces, 102-... -> hosts
    # Port assignment: 1 -> CPU, router-to-host, router-to-router
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)
        self.n = n
        assert n < 15, "Too many hosts"

        switch1 = self.addSwitch("s1")
        switch2 = self.addSwitch("s2")

        cpu1 = self.addHost("cpu1", ip="10.0.1.1")
        self.addLink(cpu1, switch1, port2=1)
        cpu2 = self.addHost("cpu2", ip="10.0.2.1")
        self.addLink(cpu2, switch2, port2=1)

        for i in range(2, n+1):
            host = self.addHost(
                "h1-%d" % i, ip="10.0.1.%d" % (100+i)
            )
            self.addLink(host, switch1, port2=i)
        for i in range(2, n+1):
            host = self.addHost(
                "h2-%d" % i, ip="10.0.2.%d" % (100+i)
            )
            self.addLink(host, switch2, port2=i)
        self.addLink(switch1, switch2, port1=n+1, port2=n+1)


class RingTopo(Topo):
    def __init__(self, num_switch, num_host, extra_links=[], **opts):
        Topo.__init__(self, **opts)
        self.num_switch = num_switch
        self.num_host = num_host
        self.extra_links = extra_links
        self.sw_to_node_port = defaultdict(list)

        switches = [self.addSwitch("s%d" % i)
                    for i in range(1, num_switch + 1)]

        for sw_ind in range(1, num_switch + 1):
            sw = switches[sw_ind - 1]
            for host_ind in range(1, num_host + 1):
                host = self.addHost("h%d-%d" % (sw_ind, host_ind), ip="10.0.%d.%d" % (
                    100+host_ind, sw_ind), mac="00:00:00:00:%02x:%02x" % (sw_ind, host_ind))
                self.addLink(host, sw, port2=host_ind)
                self.sw_to_node_port[sw].append((host, host_ind))
        port = num_host + 1
        # handle special cases in Ring topology
        if num_switch == 1:
            return
        elif num_switch == 2:
            self.addLink(switches[0], switches[1], port1=port, port2=port)
            self.sw_to_node_port[switches[0]].append((switches[1], port))
            self.sw_to_node_port[switches[1]].append((switches[0], port))
            return
        for sw_ind in range(1, num_switch + 1):
            self.addLink(switches[sw_ind - 1], switches[sw_ind %
                         num_switch], port1=port, port2=port)
            self.sw_to_node_port[switches[sw_ind - 1]
                ].append((switches[sw_ind % num_switch], port))
            self.sw_to_node_port[switches[sw_ind % num_switch]
                ].append((switches[sw_ind - 1], port))
            port += 1

        for node1, node2 in extra_links:
            assert node1.startswith("s") and node2.startswith(
                "s"), "Extra links with hosts not supported"
            assert node1 in switches and node2 in switches, "Invalid switch names"
            if (node1, node2) not in self.links():
                self.addLink(node1, node2, port1=port, port2=port)
                self.sw_to_node_port[node1].append((node2, port))
                self.sw_to_node_port[node2].append((node1, port))

            port += 1

    def get_sw_intfs_info(self, sw_name):
        '''Get the interfaces info of a switch'''
        assert sw_name.startswith("s"), "Invalid switch name"
        sw_num = int(sw_name[1:])
        assert sw_num >= 1 and sw_num <= self.num_switch, "Invalid switch number"
        intfs_info = {}
        # portn = 1
        # while portn <= self.num_host + self.num_switch:
        #     intf_name = "%s-eth%d" % (sw_name, i)
        #     intfs_info[intf_name] = (
        #         self.get_ip_addr(intf_name), "255.255.0.0")
        #     portn += 1
        for _, portn in self.sw_to_node_port[sw_name]:
            intf_name = "%s-eth%d" % (sw_name, portn)
            intfs_info[intf_name] = (
                self.get_ip_addr(intf_name), "255.255.255.0")
        return intfs_info

    def get_ip_addr(self, intf_name):
        '''Should only be used to get the IP addr for interfaces'''
        sw_num=int(intf_name[1:].split("-")[0])
        intf_num=int(intf_name.split("eth")[-1])
        assert sw_num >= 0 and sw_num <= 255, "Invalid switch number"
        assert intf_num >= 0 and intf_num <= 255, "Invalid interface number"
        if intf_num == 1:
            ip_addr="10.0.101.{}".format(sw_num)
        else:
            ip_addr="10.0.{}.{}".format(intf_num, sw_num)
        return ip_addr

    def __str__(self):
        resp="************ TOPOLOGY ************\n"
        for host in self.hosts():
            resp += "Host: %s\t%s\n" % (host, self.nodeInfo(host))
        resp += "************ LINKS **************\n"
        for switch in self.switches():
            for link in self.links(withInfo=True):
                if switch in link and link[0].startswith("s") and link[1].startswith("s"):
                    portn = None
                    for sw_name, port in self.sw_to_node_port[link[0]]:
                        if sw_name == link[1]:
                            portn = port
                            break
                    assert portn is not None, "Invalid link"
                    intf0_name = "%s-eth%d" % (link[0], portn)
                    intf1_name = "%s-eth%d" % (link[1], portn)
                    resp += "%s (IP: %s)  -- %s (IP: %s)\n" % (link[0], self.get_ip_addr(intf0_name), link[1], self.get_ip_addr(intf1_name))
                elif switch in link:
                    resp += "%s -- %s\n" % (link[0], link[1])
        resp += "*********************************\n"
        return resp
