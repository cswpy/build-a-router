from p4app import P4Mininet
from my_topo import SingleSwitchTopo
from controller import MacLearningController

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SingleSwitchTopo(N)
net = P4Mininet(program='l2switch.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw = net.get('s1')
sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))

# Send MAC bcast packets to the bcast multicast group
sw.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

# Start the MAC learning controller
cpu = MacLearningController(sw)
cpu.start()

h2, h3 = net.get('h2'), net.get('h3')

print h2.cmd('arping -c1 10.0.0.3')

print h3.cmd('ping -c1 10.0.0.2')

# These table entries were added by the CPU:
sw.printTableEntries()
