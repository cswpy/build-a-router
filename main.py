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
# topo = ComprehensiveTopo()
topo = LineTopo()

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

    if router == "r1":
        cpu = RouterController(r, 1, lsuint=10, router_info=info, hello_int=3)
    else:
        cpu = MacLearningController(r, topo.get_sw_intfs_info(router))
    # cpu = RouterController(r, 1, lsuint=3, arp_enabled=True, router_info=info)
    print(topo.get_sw_intfs_info(router))
    cpu.start()

    controllers.append(cpu)

