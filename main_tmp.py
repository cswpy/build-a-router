# type: ignore

from p4app import P4Mininet

from controller_leo import RouterController
from controller_phill import MacLearningController
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
# topo = SimpleRingTopo()
# topo = LineTopo()

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

    # cpu = MacLearningController(r, topo.get_sw_intfs_info(router))

    if router == "r8" or router == "r9" or router == "r10" or router == "r11":
        cpu = MacLearningController(r, topo.get_sw_intfs_info(router))
    else:
        cpu = RouterController(r, 1, lsuint=10, router_info=info, hello_int=5)
    # cpu = RouterController(r, 1, lsuint=3, arp_enabled=True, router_info=info)
    print(topo.get_sw_intfs_info(router))
    cpu.start()

    controllers.append(cpu)

time.sleep(45)

# r1 = net.get("r1")
# r2 = net.get("r2")
# r3 = net.get("r3")
# r4 = net.get("r4")
# r5 = net.get("r5")
# r6 = net.get("r6")
# r7 = net.get("r7")
# r8 = net.get("r8")
# r9 = net.get("r9")
# r10 = net.get("r10")
# r11 = net.get("r11")


# r1.printTableEntries()
# r2.printTableEntries()
# r3.printTableEntries()
# r4.printTableEntries()
# r5.printTableEntries()
# r6.printTableEntries()
# r7.printTableEntries()
# r8.printTableEntries()
# r9.printTableEntries()
# r10.printTableEntries()
# r11.printTableEntries()

h1 = net.get("h1")
h2 = net.get("h2")
h3 = net.get("h3")
h4 = net.get("h4")
h9 = net.get("h9")
h10 = net.get("h10")
h11 = net.get("h11")

# print(h1.cmd("route add default gw 10.0.1.0"))
# print(h2.cmd("route add default gw 10.0.1.0"))
# print(h3.cmd("route add default gw 10.0.1.0"))
# print(h4.cmd("route add default gw 10.1.2.0"))
# print(h5.cmd("route add default gw 10.1.2.0"))
# print(h6.cmd("route add default gw 10.1.2.0"))

# print(h4.cmd("ping -c1 10.1.2.106"))
# print(h1.cmd("ping -c1 10.0.1.102"))
# print(h1.cmd("ping -c1 10.1.2.106"))
# print(h5.cmd("ping -c1 10.0.1.101"))

# print(h1.cmd("ping -c1 10.0.1.202"))
# print(h5.cmd("ping -c1 10.1.2.204"))
# print(h2.cmd("ping -c1 10.1.2.206"))
# print(h4.cmd("ping -c1 10.0.1.203"))

# print(h1.cmd("ping -c1 10.0.3.222"))
# print(h1.cmd("ping -c1 10.0.4.222"))
# print(h2.cmd("ping -c1 10.0.5.222"))
# print(h6.cmd("ping -c1 10.0.3.222"))
# print(h11.cmd("ping -c1 10.0.1.222"))

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

print(h1.cmd("ping -c1 10.0.4.13"))
print(h1.cmd("ping -c1 10.0.5.0"))
print(h1.cmd("ping -c1 10.1.10.0"))


# Unreachables
print(h1.cmd("ping -c1 10.0.4.223"))
print(h1.cmd("ping -c1 10.1.10.223"))


for controller in controllers:
    controller.print_state()
    controller.join()
