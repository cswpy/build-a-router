# type: ignore

from p4app import P4Mininet

from controller import RouterController
from my_topo import *

import copy
import time

# basic + arp cache
# N = 3
# topo = SingleRouterTopo(N)

# basic PWOSPF
# topo = DoubleRouterTopo()


# topo = OSPFTopo()
# topo = OSPFTopoHard()
topo = ComprehensiveTopo()

net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

bcast_mgid = 1
router_info = copy.deepcopy(topo.router_info)

controllers = []
for router, info in topo.router_info.items():
    r = net.get(router)
    _cpu = net.get(info["cpu_name"])
    # Add a mcast group for all ports (except for the CPU port)
    r.addMulticastGroup(mgid=bcast_mgid, ports=info["ports"])

    r.insertTableEntry(
        table_name="MyIngress.local_ips",
        match_fields={"hdr.ipv4.dst_ip": _cpu.IP()},
        action_name="MyIngress.send_to_cpu",
    )

    for port_num, port_ip_mac in info["port_ips_macs"].items():
        r.insertTableEntry(
            table_name="MyIngress.local_ips",
            match_fields={"hdr.ipv4.dst_ip": port_ip_mac["ip"]},
            action_name="MyIngress.send_to_cpu",
        )

        # r.insertTableEntry(
        #     table_name="MyIngress.port_to_interface_mac",
        #     match_fields={"standard_metadata.egress_spec": port_num},
        #     action_name="MyIngress.get_interface_mac",
        #     action_params={"interface_mac": port_ip_mac["mac"]},
        # )

    r.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dst_mac": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

    cpu = RouterController(r, 1, lsuint=10, router_info=info, hello_int=3)
    # cpu = RouterController(r, 1, lsuint=3, arp_enabled=True, router_info=info)
    cpu.start()

    controllers.append(cpu)

    """ unreachable
    h2, h3 = net.get("h2"), net.get("h3")

    print(h3.cmd("ping -c1 %s" % "10.0.0.2"))

    print(h2.cmd("ping -c1 10.23.14.14"))
    """

    """
    Basic Functionality

    h2, h3 = net.get("h2"), net.get("h3")

    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("arping -c1 10.0.0.2"))

    print(h3.cmd("ping -c1 %s" % "10.1.1.1"))
    print(h3.cmd("ping -c1 %s" % "10.1.1.2"))
    print(h3.cmd("ping -c1 %s" % "10.1.1.3"))

    print(h2.cmd("ping -c1 %s" % "10.1.1.1"))
    print(h2.cmd("ping -c1 %s" % "10.1.1.2"))
    print(h2.cmd("ping -c1 %s" % "10.1.1.3"))

    print(h2.cmd("ping -c1 %s" % "10.0.0.3"))
    print(h3.cmd("ping -c1 %s" % "10.0.0.2"))
    """

    """ arp cache suites
    h2, h3 = net.get("h2"), net.get("h3")
    print(h2.cmd("arping -c1 10.0.0.3"))
    print(h3.cmd("arping -c1 10.0.0.2"))

    time.sleep(1)

    print("------ presleep ------")
    r.printTableEntries()
    print("------ presleep ------")

    time.sleep(10)
    print("------ should be removed now ------")
    r.printTableEntries()
    print("------ should be removed now ------")

    print(h2.cmd("ping -c2 %s" % "10.0.0.3"))
    print(h3.cmd("ping -c10 %s" % "10.0.0.2"))

    time.sleep(10)
    print(h2.cmd("ping -c2 %s" % "10.0.0.3"))
    print(h3.cmd("ping -c10 %s" % "10.0.0.2"))

    print(h3.cmd("ping -c1 %s" % "10.0.0.3"))
    print(h2.cmd("ping -c1 %s" % "10.0.0.2"))

    # print(h3.cmd('echo "Hello, UDP!" | socat - UDP-DATAGRAM:10.0.0.2:9999'))

    # These table entries were added by the CPU:
    r.printTableEntries()

    print(r.readCounter("ip_counter", 1)[0])
    print(r.readCounter("arp_counter", 1)[0])
    print(r.readCounter("cpu_counter", 1)[0])
    """

""" OSPF Hello + LSU Test suites 1
time.sleep(5)

r1 = net.get("r1")
r2 = net.get("r2")

r1.printTableEntries()
r2.printTableEntries()
"""

""" Counters
r1 = net.get("r1")
print(r1.readCounter("ip_counter", 1)[0])
print(r1.readCounter("arp_counter", 1)[0])
print(r1.readCounter("cpu_counter", 1)[0])
"""

# """ OSPF Hello + LSU Test suites 2
# time.sleep(90)

# r1 = net.get("r1")
# r2 = net.get("r2")
# r3 = net.get("r3")
# r4 = net.get("r4")
# r5 = net.get("r5")
# r6 = net.get("r6")
# r7 = net.get("r7")
# r8 = net.get("r8")
# r9 = net.get("r9")


# r1.printTableEntries()
# r2.printTableEntries()
# r3.printTableEntries()
# r4.printTableEntries()
# r5.printTableEntries()
# r6.printTableEntries()
# r7.printTableEntries()
# r8.printTableEntries()
# r9.printTableEntries()

# for cpu in controllers:
#     cpu.join()

# """

time.sleep(5)

r1 = net.get("r1")
r2 = net.get("r2")
r3 = net.get("r3")
r4 = net.get("r4")
r5 = net.get("r5")
r6 = net.get("r6")
r7 = net.get("r7")
r8 = net.get("r8")
r9 = net.get("r9")
r10 = net.get("r10")
r11 = net.get("r11")


r1.printTableEntries()
r2.printTableEntries()
r3.printTableEntries()
r4.printTableEntries()
r5.printTableEntries()
r6.printTableEntries()
r7.printTableEntries()
r8.printTableEntries()
r9.printTableEntries()
r10.printTableEntries()
r11.printTableEntries()

h1 = net.get("h1")
h2 = net.get("h2")
h3 = net.get("h3")
h4 = net.get("h4")
h9 = net.get("h9")
h10 = net.get("h10")
h11 = net.get("h11")


# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("arping -c1 10.0.1.222"))
# print(h9.cmd("sleep 10; ping -c1 10.0.1.111"))
# time.sleep(5)
# print(h9.cmd("arp -a"))

print(h1.cmd("route add default gw 10.0.9.0"))
print(h2.cmd("route add default gw 10.0.9.0"))
print(h10.cmd("route add default gw 10.1.10.0"))
print(h11.cmd("route add default gw 10.2.11.0"))

print(h1.cmd("ping -c1 10.0.4.222"))
print(h1.cmd("ping -c1 10.1.10.222"))
print(h1.cmd("ping -c1 10.2.11.222"))
print(h2.cmd("ping -c1 10.1.10.222"))

# print(h1.cmd("ping -c1 10.2.11.222"))
# print(h1.cmd("traceroute 10.2.11.222"))

# print(h1.cmd("ping -c1 10.0.4.13"))
# print(h1.cmd("ping -c1 10.0.5.0"))
# print(h1.cmd("ping -c1 10.1.10.0"))


# Unreachables
print(h1.cmd("ping -c1 10.0.4.223"))
print(h1.cmd("ping -c1 10.1.10.223"))

# while True:
#     pass
# time.sleep(3)
# print(h1.cmd("ping -c1 10.2.11.223"))
# print(h2.cmd("ping -c1 10.1.10.223"))
# print(h2.cmd("ping -c1 10.0.1.222"))
# print(h2.cmd("arp -a"))

# print(h3.cmd("arping -c1 10.0.1.222"))
# time.sleep(10)
# print(h3.cmd("arp -a"))

# print(h4.cmd("ping -c1 10.0.1.222"))
# print(h4.cmd("arp -a"))

print(h1.MAC())
print(h1.IP())

# time.sleep(5)


print(r1.readCounter("dummy_counter", 1)[0])
print(r1.readCounter("cpu_counter", 1)[0])
print(r1.readCounter("ip_counter", 1)[0])
print(r1.readCounter("arp_counter", 1)[0])


time.sleep(45)


# topo = BadTopo()

# net = P4Mininet(program="router.p4", topo=topo)
# net.start()

# h1 = net.get("h1")
# # h2 = net.get("h2")
# h3 = net.get("h3")

# # print(h2.cmd("ping -c1 10.0.0.1"))
# print(h3.cmd("ping -c1 10.0.0.1"))
