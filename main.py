from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo, DoubleSwitchTopo
import time


def test_double_topo():
    # Add three hosts. Port 1 (h1) is reserved for the CPU.
    N = 3

    # topo = SingleSwitchTopo(N)
    topo = DoubleSwitchTopo(N)

    print(topo)

    net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
    net.start()

    # Add a mcast group for all ports (except for the CPU port)
    bcast_mgid = 1
    s1 = net.get("s1")
    s1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 1))

    s2 = net.get("s2")
    s2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 1))


    # Send MAC bcast packets to the bcast multicast group
    s1.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )
    s2.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

    # ipv4 static routing table
    s1.insertTableEntry(
        table_name="MyIngress.local_ip_table",
        match_fields={"hdr.ipv4.dstAddr": ["10.0.1.1"]},
        action_name="send_to_cpu",
        action_params={},
    )
    s2.insertTableEntry(
        table_name="MyIngress.local_ip_table",
        match_fields={"hdr.ipv4.dstAddr": ["10.0.2.1"]},
        action_name="send_to_cpu",
        action_params={},
    )


    # Start the MAC learning controller
    cpu1=MacLearningController(s1)
    cpu1.start()
    cpu2=MacLearningController(s2)
    cpu2.start()

    h1_2, h1_3=net.get("h1-2"), net.get("h1-3")

    # print(h1_2.cmd("arping -c1 10.0.1.103"))

    #print(h1_3.cmd("ping -c1 10.0.1.102"))

    # print(h3.cmd("ping -c1 10.0.0.1"))

    # These table entries were added by the CPU:
    s1.printTableEntries()
    s2.printTableEntries()

def test_single_topo():
    # Add three hosts. Port 1 (h1) is reserved for the CPU.
    N=3

    topo=SingleSwitchTopo(N)
    net=P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
    net.start()

    # Add a mcast group for all ports (except for the CPU port)
    bcast_mgid=1
    sw=net.get("s1")
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 1))

    # Send MAC bcast packets to the bcast multicast group
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )

    for intf in sw.intfList():
        print(intf.name, intf.IP(), intf.MAC())

    # Start the MAC learning controller
    cpu=MacLearningController(sw)
    cpu.start()

    h2, h3=net.get("h2"), net.get("h3")

    print(h2.cmd("arping -c1 10.0.0.3"))

    print(h3.cmd("ping -c1 10.0.0.2"))

    # These table entries were added by the CPU:
    sw.printTableEntries()

test_double_topo()
