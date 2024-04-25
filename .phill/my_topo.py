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

class CommonTopo(Topo):
    def __init__(self, num_switch, num_host, extra_links=[], **opts):
        super(CommonTopo, self).__init__(**opts)
        self.num_switch = num_switch
        self.num_host = num_host
        self.extra_links = extra_links
        #self.link_order = defaultdict(set) # used to keep the order of links -> create unique network addr for links
        
        assert num_host > 1, "At least 2 hosts are required"

        self.switch_names = [self.addSwitch("s%d" % i)
                    for i in range(1, num_switch + 1)]
        
        self.host_names = []

        for sw_ind in range(1, num_switch + 1):
            sw = self.switch_names[sw_ind - 1]
            for host_ind in range(1, num_host + 1):
                host_name = "cpu%d" % (sw_ind) if host_ind == 1 else "h%d-%d" % (sw_ind, host_ind)
                host_id = 1 if host_ind == 1 else host_ind+100
                host = self.addHost(host_name, ip="10.0.%d.%d/24" % (
                    sw_ind, host_id), mac="00:00:00:00:%02x:%02x" % (sw_ind, host_ind), defaultRoute="via 10.0.%d.1" % sw_ind)
                self.addLink(host, sw, port2=host_ind)
                self.host_names.append(host_name)
    
    # def addLink(self, *args, **kwargs):
    #     port = max(self.link_order.values()) + 1
    #     super().addLink(*args, port1=port, port2=port, **kwargs)
    #     self.link_order[args[0]] = port

    def _setup_extra_links(self):
        for node1, node2 in self.extra_links:
            assert node1.startswith("s") and node2.startswith(
                "s"), "Extra links with hosts not supported"
            assert node1 in self.switch_names and node2 in self.switch_names, "Invalid switch names"
            if (node1, node2) not in self.links():
                self.addLink(node1, node2)

    # def addLink(self, *args, **kwargs):
    #     host = super().addLink(*args, **kwargs)
    #     if args[0].startwith('s') and "port1" in kwargs:
    #         intf_name = "%s-eth%d" % (args[0], kwargs["port1"])
    #         self.intf_info[args[0]].append((intf_name, self.get_ip_mask(intf_name)))
    #     if args[1].startwith('s') and "port2" in kwargs:
    #         intf_name = "%s-eth%d" % (args[1], kwargs["port2"])
    #         self.intf_info[args[1]].append((args[1], self.get_ip_mask(intf_name)))
    #     return host

    def get_ip_mask(self, intf_name):
        if intf_name.startswith('cpu') or intf_name.startswith('h'):
            return self.nodeInfo(intf_name)['ip']
        sw_num=int(intf_name[1:].split("-")[0])
        port_num=int(intf_name.split("eth")[-1])
        assert sw_num >= 0 and sw_num <= 255, "Invalid switch number"
        assert port_num >= 0 and port_num <= 255, "Invalid interface number"
        # ip for intfs with hosts and cpu
        if port_num <= self.num_host:
            ip_subnet="10.0.{}.{}/24".format(sw_num, port_num)
        # ip for intfs between routers
        else:
            ip_subnet="192.168.{}.{}/16".format(sw_num, port_num)
        return ip_subnet
    
    def get_ip_addr(self, intf_name):
        return self.get_ip_mask(intf_name).split("/")[0]

    def get_sw_intfs_info(self, sw_name):
        '''Get the interfaces info of a switch'''
        assert sw_name.startswith("s"), "Invalid switch name"
        sw_num = int(sw_name[1:])
        assert sw_num >= 1 and sw_num <= self.num_switch, "Invalid switch number"
        sw_ports = self.ports[sw_name]
        intfs_info = {}
        for portn, (_, _) in sw_ports.items():
            intf_name = "%s-eth%d" % (sw_name, portn)
            intfs_info[intf_name] = self.get_ip_mask(intf_name)
        return intfs_info
    
    def __str__(self):
        resp="************ TOPOLOGY ************\n"
        for host in self.hosts():
            resp += "Host: %s\t%s\n" % (host, self.nodeInfo(host))
        resp += "************ LINKS **************\n"
        for switch_name in self.switch_names:
            for port, (dst_name, dst_port) in self.ports[switch_name].items():
                intf0_name = "%s-eth%d" % (switch_name, port)
                intf1_name = "%s-eth%d" % (dst_name, dst_port) if dst_name in self.switch_names else dst_name
                resp += "%s (IP: %s port: %s)  -- %s (IP: %s port: %s)\n" % (switch_name, self.get_ip_mask(intf0_name), port, dst_name, self.get_ip_mask(intf1_name), dst_port)
        resp += "*********************************\n"
        return resp

class RingTopo(CommonTopo):
    def __init__(self, num_switch, num_host, extra_links=[], **opts):
        super(RingTopo, self).__init__(num_switch, num_host, extra_links, **opts)
        # handle special cases in Ring topology
        if num_switch == 1:
            return
        elif num_switch == 2:
            self.addLink(self.switch_names[0], self.switch_names[1])

            return
        for sw_ind in range(1, num_switch + 1):
            self.addLink(self.switch_names[sw_ind - 1], self.switch_names[sw_ind %
                         num_switch])
        self._setup_extra_links()

class LineTopo(CommonTopo):
    def __init__(self, num_switch, num_host, extra_links=[], **opts):
        super().__init__(num_switch, num_host, **opts)
        for sw_ind in range(1, num_switch):
            self.addLink(self.switch_names[sw_ind - 1], self.switch_names[sw_ind])
        self._setup_extra_links()
