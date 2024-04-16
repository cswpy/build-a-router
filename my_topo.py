from mininet.topo import Topo


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
    def __init__(self, num_switch, num_host, **opts):
        Topo.__init__(self, **opts)
        self.num_switch = num_switch
        self.num_host = num_host

        switches = [self.addSwitch("s%d" % i)
                    for i in range(1, num_switch + 1)]

        for sw_ind in range(1, num_switch + 1):
            sw = switches[sw_ind - 1]
            for host_ind in range(1, num_host + 1):
                host = self.addHost("h%d-%d" % (sw_ind, host_ind), ip="10.0.%d.%d" % (
                    sw_ind, 100+host_ind), mac="00:00:00:00:%02x:%02x" % (sw_ind, host_ind))
                self.addLink(host, sw, port2=host_ind)
        port = num_host + 1
        for sw_ind in range(1, num_switch + 1):
            self.addLink(switches[sw_ind - 1], switches[sw_ind %
                         num_switch], port1=port, port2=port)
            port += 1

    def get_sw_intfs_info(self, sw_name):
        '''Get the interfaces info of a switch'''
        assert sw_name.startswith("s"), "Invalid switch name"
        sw_num = int(sw_name[1:])
        assert sw_num >= 1 and sw_num <= self.num_switch, "Invalid switch number"
        intfs_info = {}
        for i in range(1, self.num_host + self.num_switch + 1):
            intf_name = "%s-eth%d" % (sw_name, i)
            intfs_info[intf_name] = (
                self.get_ip_addr(intf_name), "255.255.255.0")
        return intfs_info

    def get_ip_addr(self, intf_name):
        '''Should only be used to get the IP addr for interfaces'''
        sw_num = int(intf_name[1:].split("-")[0])
        intf_num = int(intf_name.split("eth")[-1])
        assert sw_num >= 0 and sw_num <= 255, "Invalid switch number"
        assert intf_num >= 0 and intf_num <= 255, "Invalid interface number"
        ip_addr = "10.0.{}.{}".format(sw_num, intf_num)
        return ip_addr

    def __str__(self):
        resp = "************ TOPOLOGY ************\n"
        for host in self.hosts():
            resp += "Host: %s\t%s\n" % (host, self.nodeInfo(host))
        resp += "************ LINKS **************\n"
        for switch in self.switches():
            for link in self.links(withInfo=True):
                if switch in link:
                    resp += "%s -- %s\n" % (link[0], link[1])
        resp += "*********************************\n"
        return resp
