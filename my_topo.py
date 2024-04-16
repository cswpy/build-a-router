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