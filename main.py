from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo, DoubleSwitchTopo, RingTopo
import time


def test_ring_topo(num_switch=2, num_host=3, extra_links=[]):

    topo = RingTopo(num_switch, num_host, extra_links)

    print(topo)

    net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
    net.start()
    switches = []
    # Add a mcast group for all ports (except for the CPU port)
    bcast_mgid = 1
    for sw_ind in range(1, topo.num_switch+1):
        sw_name = "s%d" % sw_ind
        sw = net.get(sw_name)
        sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, num_host + 1))

        # Send MAC bcast packets to the bcast multicast group
        sw.insertTableEntry(
            table_name="MyIngress.fwd_l2",
            match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
            action_name="MyIngress.set_mgid",
            action_params={"mgid": bcast_mgid},
        )

        # local ip table static entries
        for intf_name in sw.intfNames():
            if 'lo' in intf_name:
                continue
            sw.insertTableEntry(
                table_name="MyIngress.local_ip_table",
                match_fields={"hdr.ipv4.dstAddr": [topo.get_ip_addr(intf_name)]},
                action_name="send_to_cpu",
                action_params={},
            )
        switches.append(sw)
    controllers = []
    # Start the MAC learning controller
    for sw in switches:
        intfs_info = topo.get_sw_intfs_info(sw.name)
        cpu = MacLearningController(sw, intfs_info)
        cpu.start()
        controllers.append(cpu)

    return net, switches, controllers

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

extra_links = [('s2', 's4'), ('s4', 's6')]
net, switches, controllers = test_ring_topo(6, 3, extra_links)


#h1_2, h1_3=net.get("h1-2"), net.get("h1-3")

# print(h1_2.cmd("arping -c1 10.0.1.103"))

#print(h1_3.cmd("ping -c1 10.0.1.102"))

# print(h3.cmd("ping -c1 10.0.0.1"))

# These table entries were added by the CPU:
for sw in switches:
    sw.printTableEntries()


cnt = 0
while cnt < 5:
    print("Main thread sleeping for 5 seconds")
    time.sleep(5)
    print("Main thread resumes")
    controllers[1].print_state()
    cnt+=1


