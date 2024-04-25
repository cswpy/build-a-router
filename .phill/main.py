from p4app import P4Mininet

from controller import MacLearningController
from my_topo import SingleSwitchTopo, DoubleSwitchTopo, RingTopo, LineTopo
import time


def test_topo(TopoCls, num_switch=2, num_host=3, extra_links=[]):

    topo = TopoCls(num_switch, num_host, extra_links)

    print(topo)

    net = P4Mininet(program="router.p4app/router.p4", topo=topo, auto_arp=False)
    net.start()
    switches = []
    # Add a mcast group for all ports (except for the CPU port)
    bcast_mgid = 1
    for sw_ind in range(1, topo.num_switch+1):
        sw_name = "s%d" % sw_ind
        sw = net.get(sw_name)
        ports = [port for port in sw.ports.values() if port > 1]
        sw.addMulticastGroup(mgid=bcast_mgid, ports=ports)

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

    return topo, net, switches, controllers


extra_links = []
#extra_links = [('s2', 's4'), ('s4', 's6')]
topo, net, switches, controllers = test_topo(LineTopo, 5, 3, extra_links)

for host_name in topo.host_names:
    if 'cpu' not in host_name:
        host = net.get(host_name)
        host.cmd("ip route add default {}".format(topo.nodeInfo(host_name)['defaultRoute']))
h1_2 = net.get("h1-2")
h5_3 = net.get("h5-3")

time.sleep(10) # wait for routing to kick in

controllers[0].print_state()
controllers[4].print_state()
print(h1_2.cmd("ip route"))
print(h5_3.cmd("ip route"))
switches[0].printTableEntries()

print(h1_2.cmd("ping -c1 10.0.5.103"))

# s1-eth2-in -> s1-eth5-out -> s5-eth5-in -> s5-eth3-out
for controller in controllers:
    controller.join()