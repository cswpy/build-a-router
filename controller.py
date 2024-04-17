from threading import Thread, Event, Lock
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from pwospf_proto import PWOSPF_Header, PWOSPF_Hello, PWOSPF_LSU, PWOSPF_LSA
from collections import defaultdict
from async_sniff import sniff
from utils import *
from cpu_metadata import CPUMetadata
import datetime
import time

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_PROTO = 0x59
PWOSPF_ALLSPFROUTERS = "224.0.0.5"

ICMP_PROT_NUM = 0x01
ICMP_ECHO_REPLY_TYPE = 0x00
ICMP_ECHO_REPLY_CODE = 0x00
ICMP_HOST_UNREACHABLE_REPLY_TYPE = 0x03
ICMP_HOST_UNREACHABLE_REPLY_CODE = 0x01


class PWOSPF_Interface():
    def __init__(self, ip_addr, subnet_mask, helloint, iface, mac, port):
        self.ip_addr = ip_addr
        self.subnet_mask = subnet_mask
        self.helloint = helloint
        self.iface = iface
        self.MAC = mac
        self.port = port
        self.neighbors = {}  # (router_id, neighbor_IP) -> last_recv_time

    def __str__(self):
        return "Interface Name: {}\nIP: {}, Subnet: {}, HelloInt: {}, MAC: {}, Port: {}\nneighbors: {}".format(self.iface, self.ip_addr, self.subnet_mask, self.helloint, self.MAC, self.port, self.neighbors)


class LSU_Daemon(Thread):
    def __init__(self, sw, router, lsuint, start_wait=.3, **kwargs):
        '''
        @router: PWOSPFRouter object
        
        self.topology: Dict[router_id] -> {checksum, seq, last_recv_time, subnet (obtained from LSA)}
        self.pending_subnet2nexthop: Dict[network addr] -> (next_hop_ip, port) next_hop_ip: IP of the receiving interface, port: port to reach the next hop, buffering for the routing table entries
        self.global_subnet2nexthop: same as above, but the actual table
        '''
        super(LSU_Daemon, self).__init__(**kwargs)
        self.sw = sw
        self.router = router
        self.lsuint = lsuint
        self.start_wait = start_wait
        self.seq = 0
        self.stop_event = Event()
        self.trigger_lsu_event = Event()
        self.adjacency_list = defaultdict(list)
        self.adjacency_list_lock = Lock()
        self.topology = defaultdict(
            lambda: {'checksum': None, 'seq': -1, 'last_recv_time': None, 'subnets': set()})
        self.global_subnet2nexthop = {}  # current rules 
        self.pending_subnet2nexthop = {}

    def flood_LSU(self):

        def craft_LSU_packet():
            LSA_list = []
            for intf in self.router.intfs:
                if intf.neighbors:
                    for router_id, _ in intf.neighbors.keys():
                        lsa_pkt = PWOSPF_LSA(subnet=calculate_subnet(
                            intf.ip_addr, intf.subnet_mask), mask=intf.subnet_mask, routerid=router_id)
                        LSA_list.append(lsa_pkt)
                else:
                    lsa_pkt = PWOSPF_LSA(subnet=calculate_subnet(
                        intf.ip_addr, intf.subnet_mask), mask=intf.subnet_mask, routerid="0.0.0.0")
                    LSA_list.append(lsa_pkt)
            lsu_pkt = PWOSPF_Header(type=4, routerid=self.router.router_id,
                                    areaid=self.router.area_id) / PWOSPF_LSU(sequence=self.seq, lsaList=LSA_list)
            return lsu_pkt

        lsu_pkt = craft_LSU_packet()
        for intf in self.router.intfs:
            for _, router_ip in intf.neighbors.keys():
                pkt = Ether() / CPUMetadata(origEtherType=0x0800, srcPort=1,
                                            dstPort=intf.port) / IP(src=intf.ip_addr, dst=router_ip, proto=PWOSPF_PROTO) / lsu_pkt
                self.router.send(pkt)
        # Updating adjacency information for the router itself
        with self.adjacency_list_lock:
            self.adjacency_list[self.router.router_id] = []
            for lsa in lsu_pkt[PWOSPF_LSU].lsaList:
                self.adjacency_list[self.router.router_id].append(
                    LSA_tuple(lsa.subnet, lsa.mask, lsa.routerid))
        self.seq += 1

    def handle_LSU(self, pkt):
        rid = pkt[PWOSPF_Header].routerid
        if rid == self.router.router_id:
            return
        if pkt[PWOSPF_LSU].sequence <= self.topology[rid]['seq']:
            return
        self.topology[rid]['seq'] = pkt[PWOSPF_LSU].sequence
        self.topology[rid]['last_recv_time'] = datetime.datetime.now()
        # if valid packet and topology has changed -> reset adjacency list for that router
        #is_chksum_same = self.topology[rid]['checksum'] == pkt[PWOSPF_Header].checksum
        
        # if is_chksum_same:
        #     print('LSU Updates detected')
        self.topology[rid]['checksum'] = pkt[PWOSPF_Header].checksum

        #if not is_chksum_same:
        with self.adjacency_list_lock:
            self.adjacency_list[rid] = []
            for lsa in pkt[PWOSPF_LSU].lsaList:
                self.adjacency_list[rid].append(
                    LSA_tuple(lsa.subnet, lsa.mask, lsa.routerid))
                self.topology[rid]['subnets'].add(lsa.subnet)
        # flood LSU packets
        pkt[PWOSPF_LSU].ttl -= 1
        if pkt[PWOSPF_LSU].ttl > 0:
            for intf in self.router.intfs:
                if intf.port == pkt[CPUMetadata].srcPort or not intf.neighbors:
                    continue
                for _, router_ip in intf.neighbors.keys():
                    pkt[IP].src = router_ip
                    pkt[CPUMetadata].dstPort = intf.port
                    self.router.send(pkt)
        # run dijkstra if topology has changed
        #if not is_chksum_same:
        graph = None
        with self.adjacency_list_lock:
            graph = build_graph(self.adjacency_list)
        next_hops, nhop = find_next_hop(graph, self.router.router_id)
        subnet_nhop = defaultdict(lambda: float('inf'))
        for dst, next_hop in next_hops.items():
            intf, neighbor_router_ip = self.router.nexthop_rid2intf[next_hop]
            next_hop_port = intf.port
            for dst_subnet in self.topology[dst]['subnets']:
                if (dst_subnet not in self.pending_subnet2nexthop) or (nhop[dst] < subnet_nhop[dst_subnet]):
                    self.pending_subnet2nexthop[dst_subnet] = (
                        neighbor_router_ip, next_hop_port)
                    subnet_nhop[dst_subnet] = nhop[dst]
        self.sync_routing_table()

    def sync_routing_table(self):
        #print("Syncing...\n{}\n{}".format(self.pending_subnet2nexthop, self.global_subnet2nexthop))
        for subnet, (next_hop_ip, port) in self.global_subnet2nexthop.items():
            if subnet in self.global_subnet2nexthop:
                if (next_hop_ip, port) != self.global_subnet2nexthop[subnet]:
                    self.sw.removeTableEntry(table_name='MyIngress.routing_table',
                                            match_fields={'hdr.ipv4.dstAddr': [subnet, 32]})
                else:
                    continue
            self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                                     match_fields={
                                         'hdr.ipv4.dstAddr': [subnet, 32]},
                                     action_name='MyIngress.ipv4_route',
                                     action_params={'next_hop': next_hop_ip, 'port': port})
        self.global_subnet2nexthop = self.pending_subnet2nexthop.copy()
        self.pending_subnet2nexthop = {}
        #print("Routing table synchronized to data plane")

    def run(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            has_neighbor_changed = self.trigger_lsu_event.wait(self.lsuint)
            if has_neighbor_changed:
                self.trigger_lsu_event.clear()
            self.flood_LSU()
        print('LSU Daemon stopped')

    def start(self):
        super(LSU_Daemon, self).start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        print('LSU_Daemon join called')
        self.stop_event.set()
        super(LSU_Daemon, self).join(*args, **kwargs)


class PWOSPF_Router(Thread):
    def __init__(self, sw, router_id, area_id, intfs_info, iface, helloint=5, lsuint=10, start_wait=0.3):
        super(PWOSPF_Router, self).__init__()
        self.sw = sw
        self.router_id = router_id
        self.area_id = area_id
        self.intfs = []
        self.iface = iface
        self.start_wait = start_wait
        self.lsuint = lsuint
        self.lsu_daemon = LSU_Daemon(sw, self, lsuint)
        self.MAC = self.sw.intfs[1].MAC()
        # rid -> (intf, neighbor_router_ip) intf: intf for next hop (immediate neighbor) through Hello packets, neighbor_router_ip: IP of the neighbor router
        self.nexthop_rid2intf = {}
        self.nexthop_rid2intf_lock = Lock()
        self.hello_threads = []
        self.stop_event = Event()

        for intf_name, intf in self.sw.nameToIntf.items():
            # skip the first interface, which is connected to the CPU
            if 'lo' in intf_name or intf_name.endswith('eth1'):
                continue
            iface, mac = intf_name, intf.MAC()
            port = self.sw.ports[intf]
            ip_addr, subnet_mask = intfs_info[iface][0], intfs_info[iface][1]
            intf = PWOSPF_Interface(
                ip_addr, subnet_mask, helloint, iface, mac, port)
            self.intfs.append(intf)

    def _hello(self, intf_id):
        # craft hello packet
        intf = self.intfs[intf_id]
        etherLayer = Ether(src=intf.MAC, dst="ff:ff:ff:ff:ff:ff")
        CPUlayer = CPUMetadata(
            origEtherType=0x0800, srcPort=1, dstPort=intf.port)
        IPLayer = IP(src=intf.ip_addr, dst=PWOSPF_ALLSPFROUTERS,
                     proto=PWOSPF_PROTO, ttl=1)
        PWOSPFHeader = PWOSPF_Header(
            type=1, routerid=self.router_id, areaid=self.area_id)
        PWOSPFHello = PWOSPF_Hello(
            netmask=intf.subnet_mask, helloint=intf.helloint)
        hello_pkt = etherLayer / CPUlayer / IPLayer / PWOSPFHeader / PWOSPFHello

        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            self.send(hello_pkt)
            with self.nexthop_rid2intf_lock:
                for neighbor, last_recv_time in list(intf.neighbors.items()):
                    if time.time() - last_recv_time > intf.helloint * 3:
                        del intf.neighbors[neighbor]
                        del self.nexthop_rid2intf[neighbor[0]]
                        # trigger LSU flood on change
                        if self.lsu_daemon:
                            self.lsu_daemon.trigger_lsu_event.set()
            time.sleep(intf.helloint)
        print('Hello thread on interface {} stopped'.format(intf.iface))

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def start(self, *args, **kwargs):
        super(PWOSPF_Router, self).start(*args, **kwargs)
        for intf_id in range(len(self.intfs)):
            t = Thread(target=self._hello, args=(intf_id,))
            self.hello_threads.append(t)
            t.start()
        self.lsu_daemon.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        print('PWOSPF_Router join called')
        self.stop_event.set()
        self.lsu_daemon.join()
        for thread in self.hello_threads:
            thread.join()
        super(PWOSPF_Router, self).join(*args, **kwargs)


class MacLearningController(Thread):
    '''
    intfs: [(ip_addr, subnet_mask, helloint, iface), ...] first intf should be the one connected to the CPU
    '''

    def __init__(self, sw, intfs_info, start_wait=0.3):
        super(MacLearningController, self).__init__()
        # assert intfs[0][3].endswith('eth1'), "First interface should be connected to the CPU"
        self.sw = sw
        self.start_wait = start_wait  # time to wait for the controller to be listenning
        self.intfs = self.sw.intfList()[1:]  # ignoring the loopback interface
        self.intfs_info = intfs_info
        self.controller_intf = self.intfs[0]
        self.iface = self.intfs[0].name
        self.port_for_mac = {}
        self.arp_table_lock = Lock()
        self.arp_table = {}
        self.local_ip_table = {}
        for intf in self.intfs:
            self.local_ip_table[intfs_info[intf.name][0]] = intf
        self.fwd_table = {}
        self.stop_event = Event()
        self.router = PWOSPF_Router(
            sw, intfs_info[self.iface][0], 1, intfs_info, self.iface)
        self.arp_daemon = ARP_Daemon(sw, self)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac:
            return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                                 match_fields={'hdr.ethernet.dstAddr': [mac]},
                                 action_name='MyIngress.set_egr',
                                 action_params={'port': port})
        self.port_for_mac[mac] = port

    def addArpEntry(self, ip, mac):
        if ip in self.arp_table:
            return
        with self.arp_table_lock:
            self.arp_table[ip] = (mac, time.time())
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                                 match_fields={'next_hop_ip_addr': [ip, 32]},
                                 action_name='MyIngress.arp_table_match',
                                 action_params={'mac': mac})

    def addIPV4FwdEntry(self, ip, mac, port):
        if ip in self.fwd_table:
            return
        self.fwd_table[ip] = {"mac": mac, "port": port}
        self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                                 match_fields={'hdr.ipv4.dstAddr': [ip, 32]},
                                 action_name='MyIngress.ipv4_fwd',
                                 action_params={'mac': mac, 'port': port})

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        self.addArpEntry(ip, mac)
        self.addIPV4FwdEntry(ip, mac, pkt[CPUMetadata].srcPort)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        self.addArpEntry(ip, mac)
        self.addIPV4FwdEntry(ip, mac, pkt[CPUMetadata].srcPort)
        print("Handling ARP Request")
        pkt.show2()
        # Send ARP reply for ARP requests to local IPs
        if pkt[ARP].pdst in self.local_ip_table:
            dstIP = pkt[ARP].pdst
            intf = self.local_ip_table[dstIP]
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = intf.MAC()
            pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
            pkt[CPUMetadata].srcPort = 1
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = intf.MAC()
            pkt[ARP].psrc = self.intfs_info[intf.name][0]

        self.send(pkt)

    def sendICMPEchoReply(self, pkt):
        print('Handling ICMP Echo Request')
        new_pkt = Ether(src=self.controller_intf.MAC(), dst=pkt[Ether].src) / CPUMetadata(origEtherType=0x0800, srcPort=1, dstPort=pkt[CPUMetadata].srcPort) / IP(
            src=self.intfs_info[self.controller_intf.name][0], dst=pkt[IP].src) / ICMP(type=ICMP_ECHO_REPLY_TYPE, code=ICMP_ECHO_REPLY_CODE, seq=pkt[ICMP].seq, id=pkt[ICMP].id) / pkt[ICMP].payload
        self.send(new_pkt)

    def handlePkt(self, pkt):
        # pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1:
            return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif ICMP in pkt:
            if pkt[ICMP].type == 8 and pkt[IP].dst in self.local_ip_table:
                self.sendICMPEchoReply(pkt)
                return
            else:
                pkt[CPUMetadata].dstPort = 0
                return

        
        if PWOSPF_Header in pkt:
            self.handlePWOSPFPkt(pkt)
        elif IP in pkt:
            # Not in routing table, host unreachable
            if pkt[IP].dst not in self.router.lsu_daemon.global_subnet2nexthop:
                new_pkt = Ether(src=self.controller_intf.MAC(), dst=pkt[Ether].src) / CPUMetadata(origEtherType=0x0800, srcPort=1, dstPort=pkt[CPUMetadata].srcPort) / IP(
                    src=self.intfs_info[self.controller_intf.name][0], dst=pkt[IP].src) / ICMP(type=ICMP_HOST_UNREACHABLE_REPLY_TYPE, code=ICMP_HOST_UNREACHABLE_REPLY_CODE)
                self.send(new_pkt)
            else:
                # Send ARP request
                pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                pkt[Ether].src = self.controller_intf.MAC()
                pkt[ARP].op = ARP_OP_REQ
                pkt[ARP].hwdst = "00:00:00:00:00:00"
                pkt[ARP].pdst = pkt[IP].dst
                pkt[ARP].hwsrc = self.controller_intf.MAC()
                pkt[ARP].psrc = self.intfs_info[self.controller_intf.name][0]
                self.send(pkt)

    def handlePWOSPFPkt(self, pkt):

        def handleHelloPkt(pkt, intf):
            if pkt[PWOSPF_Hello].netmask != intf.subnet_mask:
                return
            if pkt[PWOSPF_Hello].helloint != intf.helloint:
                return
            router_id = pkt[PWOSPF_Header].routerid
            neighbor_router_ip = pkt[IP].src
            intf.neighbors[(router_id, neighbor_router_ip)] = time.time()
            with self.router.nexthop_rid2intf_lock:
                self.router.nexthop_rid2intf[router_id] = (
                    intf, neighbor_router_ip)
            # trigger LSU flood on change
            if self.router.lsu_daemon:
                self.router.lsu_daemon.trigger_lsu_event.set()

        if pkt[PWOSPF_Header].version != 2:
            return
        if pkt[PWOSPF_Header].type != 1 and pkt[PWOSPF_Header].type != 4:
            return
        if pkt[PWOSPF_Header].areaid != self.router.area_id:
            return
        if pkt[PWOSPF_Header].autype != 0:
            return

        if PWOSPF_LSU in pkt:
            self.router.lsu_daemon.handle_LSU(pkt)
            return

        intf = None
        for i in range(len(self.router.intfs)):
            if pkt[CPUMetadata].srcPort == self.router.intfs[i].port:
                intf = self.router.intfs[i]
                break

        if intf and PWOSPF_Hello in pkt:
            handleHelloPkt(pkt, intf)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        self.router.start()
        self.arp_daemon.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        print('MacLearningController join called')
        self.stop_event.set()
        self.router.join()
        self.arp_daemon.join()
        super(MacLearningController, self).join(*args, **kwargs)

    def print_state(self):
        '''
        It should print the ARP table, the PWOSPF's adjacency list, and the routing table
        '''
        print("*************** ARP Table ******************")
        with self.arp_table_lock:
            for ip, mac in self.arp_table.items():
                print("IP: {}, MAC: {}".format(ip, mac))
        print("********* PWOSPF Interface States **********")
        for intf in self.router.intfs:
            print(intf)
        print("********* PWOSPF Adjacency List ***********")
        with self.router.lsu_daemon.adjacency_list_lock:
            for rid, neighbors in self.router.lsu_daemon.adjacency_list.items():
                print("Router ID: {}, Neighbor links: {}".format(rid, neighbors))
        print("************* Routing Table ***************")
        for subnet, (next_hop_ip, port) in self.router.lsu_daemon.global_subnet2nexthop.items():
            print("Subnet: {}, Next Hop: IP {} Port {}".format(subnet, next_hop_ip, port))
        print("*******************************************")

class ARP_Daemon(Thread):
    def __init__(self, sw, router, arp_timeout=60, start_wait=0.3):
        super(ARP_Daemon, self).__init__()
        self.sw = sw
        self.arp_timeout = arp_timeout
        self.router = router
        self.start_wait = start_wait
        self.stop_event = Event()

    def run(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            with self.router.arp_table_lock:
                for ip, (_, entry_time) in list(self.router.arp_table.items()):
                    if time.time() - entry_time > self.arp_timeout:
                        del self.router.arp_table[ip]
                        self.sw.removeTableEntry(table_name='MyIngress.arp_table',
                                                match_fields={'next_hop_ip_addr': [ip, 32]})
            time.sleep(2)
    
    def start(self, *args, **kwargs):
        super(ARP_Daemon, self).start(*args, **kwargs)
        time.sleep(self.start_wait)
    
    def join(self, *args, **kwargs):
        print('ARPManager join called')
        self.stop_event.set()
        super(ARP_Daemon, self).join(*args, **kwargs)