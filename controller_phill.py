from threading import Thread, Event, Lock
from queue import Queue
import threading
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP # type: ignore
#from utils.pwospf_proto_phill import PWOSPF_Header, PWOSPF_Hello, PWOSPF_LSU, PWOSPF_LSA
from utils.pwospf_leo import PWOSPF, HELLO, LSU, LSA
from collections import defaultdict, Counter
from utils.async_sniff import sniff
from utils.utils_phill import *
from utils.cpu_metadata import CPUMetadata
import time
from controller_leo import ArpReqLimitRefresher
from utils.utils_leo import locking

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_PROTO = 0x59
PWOSPF_ALLSPFROUTERS = "224.0.0.5"

ICMP_PROT_NUM = 0x01
ICMP_ECHO_REPLY_TYPE = 0x00
ICMP_ECHO_REPLY_CODE = 0x00
ICMP_DEST_UNREACHABLE_REPLY_TYPE = 0x03
ICMP_NET_UNREACHABLE_REPLY_CODE = 0x00
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


class Queueing_Packet_Daemon(Thread):
    def __init__(self, router, start_wait=0.3, queue_timeout=0.618, **kwargs):
        super(Queueing_Packet_Daemon, self).__init__(**kwargs)
        self.router = router
        self.start_wait = start_wait
        self.queue_timeout = queue_timeout
        self.stop_event = Event()
        self.queue = Queue()

    def run(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            if not self.queue.empty():
                pkt, next_hop_ip, sent_time = self.queue.get()
                if next_hop_ip in self.router.arp_table:
                    pkt[CPUMetadata].dstPort = self.router.port_for_mac[self.router.arp_table[next_hop_ip][0]]
                    pkt[Ether].dst = self.router.arp_table[next_hop_ip][0]
                    self.router.send(pkt)
                else:
                    if time.time() - sent_time > self.queue_timeout:
                        print("ARP request timed out for IP: {}".format(next_hop_ip))
                        new_pkt = Ether(src=self.router.controller_intf.MAC(), dst=pkt[Ether].src) / CPUMetadata(origEtherType=0x0800, srcPort=1, dstPort=pkt[CPUMetadata].srcPort) / IP(
                            src=self.router.controller_ip, dst=pkt[IP].src) / ICMP(type=ICMP_DEST_UNREACHABLE_REPLY_TYPE, code=ICMP_HOST_UNREACHABLE_REPLY_CODE)
                        self.router.send(new_pkt)
                    else:
                        self.queue.put((pkt, next_hop_ip, sent_time))

    def start(self):
        super(Queueing_Packet_Daemon, self).start()
        time.sleep(self.start_wait)

    def join(self):
        self.stop_event.set()
        super(Queueing_Packet_Daemon, self).join()


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
        self.topology = defaultdict(
            lambda: {'counter': Counter(), 'seq': -1, 'last_recv_time': None, 'subnets': set()})
        self.global_subnet2nexthop = {}  # current rules
        self.pending_subnet2nexthop = {}

    def flood_LSU(self):

        def craft_LSU_packet():
            LSA_list = []
            # if a PWOSPF_Interface does not have any neighbors, we assume it has a local subnet, and we add a dummy LSA with router_id only once
            has_local_subnet = False
            for intf in self.router.intfs:
                if intf.neighbors:
                    for router_id, _ in intf.neighbors.keys():
                        lsa_pkt = LSA(subnet=calculate_subnet(
                            intf.ip_addr, intf.subnet_mask), mask=intf.subnet_mask, router_id=router_id)
                        LSA_list.append(lsa_pkt)
                else:
                    # if not has_local_subnet:
                    #     lsa_pkt = LSA(subnet=calculate_subnet(
                    #         intf.ip_addr, intf.subnet_mask), mask=intf.subnet_mask, router_id="0.0.0.0")
                    #     LSA_list.append(lsa_pkt)
                    # has_local_subnet = True
                    pass
            lsu_pkt = PWOSPF(type=4, router_id=self.router.router_id,
                                    area_id=self.router.area_id) / LSU(sequence=self.seq, lsaList=LSA_list)
            return lsu_pkt

        lsu_pkt = craft_LSU_packet()
        for intf in self.router.intfs:
            for _, router_ip in intf.neighbors.keys():
                pkt = Ether() / CPUMetadata(origEtherType=0x0800, srcPort=1,
                                            dstPort=intf.port) / IP(src=intf.ip_addr, dst=router_ip, proto=PWOSPF_PROTO) / lsu_pkt
                self.router.send(pkt)
        # Updating adjacency information for the router itself
        self.adjacency_list[self.router.router_id] = []
        for lsa in lsu_pkt[LSU].lsaList:
            self.adjacency_list[self.router.router_id].append(
                LSA_tuple(lsa.subnet, lsa.mask, lsa.router_id))
        self.seq += 1

    def handle_LSU(self, pkt):
        rid = pkt[PWOSPF].router_id
        if rid == self.router.router_id:
            return
        if pkt[LSU].sequence <= self.topology[rid]['seq']:
            return
        self.topology[rid]['seq'] = pkt[LSU].sequence
        self.topology[rid]['last_recv_time'] = time.time() # type: ignore
        # if valid packet and topology has changed -> reset adjacency list for that router

        new_lsa_list = Counter([(lsa.subnet, lsa.mask, lsa.router_id)
                                for lsa in pkt[LSU].lsaList])

        is_chksum_same = len(self.topology[rid]['counter']) == len( # type: ignore
            new_lsa_list) and self.topology[rid]['counter'] == new_lsa_list 

        # if is_chksum_same:
        #     print('LSU update received but checksum is same')
        # else:
        #     print('LSU update detected, flooding...')
        self.topology[rid]['checksum'] = pkt[PWOSPF].cksum

        if not is_chksum_same:
            self.adjacency_list[rid] = []
            for lsa in pkt[LSU].lsaList:
                self.adjacency_list[rid].append(
                    LSA_tuple(lsa.subnet, lsa.mask, lsa.router_id))
                self.topology[rid]['subnets'].add(lsa.subnet) # type: ignore
            # flood LSU packets
            pkt[LSU].ttl -= 1
            if pkt[LSU].ttl > 0:
                for intf in self.router.intfs:
                    if intf.port == pkt[CPUMetadata].srcPort or not intf.neighbors:
                        continue
                    for _, router_ip in intf.neighbors.keys():
                        pkt[IP].src = router_ip
                        pkt[CPUMetadata].dstPort = intf.port
                        self.router.send(pkt)
            # run dijkstra if topology has changed
            graph = None
            graph = build_graph(self.adjacency_list)
            next_hops, nhop = find_next_hop(graph, self.router.router_id)
            subnet_nhop = defaultdict(lambda: float('inf'))
            for dst, next_hop in next_hops.items():
                intf, neighbor_router_ip = self.router.nexthop_rid2intf[next_hop]
                next_hop_port = intf.port
                for dst_subnet in self.topology[dst]['subnets']: # type: ignore
                    if (dst_subnet not in self.pending_subnet2nexthop) or (nhop[dst] < subnet_nhop[dst_subnet]):
                        self.pending_subnet2nexthop[dst_subnet] = (
                            neighbor_router_ip, next_hop_port)
                        subnet_nhop[dst_subnet] = nhop[dst]
            self.sync_routing_table()

    def sync_routing_table(self):
        # print("{} Syncing...\n{}\n{}".format(self.router.router_id, self.pending_subnet2nexthop, self.global_subnet2nexthop))
        for subnet, (next_hop_ip, port) in self.pending_subnet2nexthop.items():
            if subnet in self.global_subnet2nexthop:
                if (next_hop_ip, port) != self.global_subnet2nexthop[subnet]:
                    self.sw.removeTableEntry(table_name='MyIngress.routing_table',
                                             match_fields={'ip_to_match': [subnet, 16]})
                else:
                    continue
            self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                                     match_fields={
                                         'ip_to_match': [subnet, 16]},
                                     action_name='MyIngress.ipv4_route',
                                     action_params={'dst_ip': next_hop_ip, 'egress_port': port})
        self.global_subnet2nexthop = self.pending_subnet2nexthop.copy()
        self.pending_subnet2nexthop = {}
        # print("Router {} Routing table synchronized to data plane".format(self.router.router_id))

    def run(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            has_neighbor_changed = self.trigger_lsu_event.wait(self.lsuint)
            if has_neighbor_changed:
                self.trigger_lsu_event.clear()
            self.flood_LSU()

    def start(self):
        super(LSU_Daemon, self).start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
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
        self.hello_threads = []
        self.stop_event = Event()

        # print('Initializing PWOSPF Router...\nrouter_id: {}\narea_id: {}\nintfs_info: {}\niface: {}\nhelloint: {}\n'.format(
        #     self.router_id, self.area_id, intfs_info, self.iface, helloint))

        for intf_name, intf in self.sw.nameToIntf.items():
            # skip the first interface, which is connected to the CPU
            if 'lo' in intf_name or intf_name.endswith('eth1'):
                continue
            iface, mac = intf_name, intf.MAC()
            port = self.sw.ports[intf]
            ip_addr, subnet_mask = get_ip_from_ip_subnet(intfs_info[intf_name]), get_mask_from_ip_subnet(
                intfs_info[intf_name])
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
        PWOSPFHeader = PWOSPF(
            type=1, router_id=self.router_id, area_id=self.area_id)
        PWOSPFHello = HELLO(
            netmask=intf.subnet_mask, helloint=intf.helloint)
        hello_pkt = etherLayer / CPUlayer / IPLayer / PWOSPFHeader / PWOSPFHello

        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            self.send(hello_pkt)
            for neighbor, last_recv_time in list(intf.neighbors.items()):
                if time.time() - last_recv_time > intf.helloint * 3:
                    del intf.neighbors[neighbor]
                    del self.nexthop_rid2intf[neighbor[0]]
                    # trigger LSU flood on change
                    if self.lsu_daemon:
                        self.lsu_daemon.trigger_lsu_event.set()
            self.stop_event.wait(intf.helloint)

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
        self.lsu_daemon.join()
        self.stop_event.set()
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
        self.controller_ip = get_ip_from_ip_subnet(
            intfs_info[self.controller_intf.name])
        self.controller_mask = get_mask_from_ip_subnet(
            intfs_info[self.controller_intf.name])
        self.controller_subnet = calculate_subnet(
            self.controller_ip, self.controller_mask)
        self.iface = self.intfs[0].name
        self.port_for_mac = {}
        self.arp_table = {}
        self.local_ip_table = {}
        for intf in self.intfs:
            self.local_ip_table[get_ip_from_ip_subnet(
                intfs_info[intf.name])] = intf
        self.fwd_table = {}
        self.stop_event = Event()
        self.router = PWOSPF_Router(
            sw, get_ip_from_ip_subnet(intfs_info[self.iface]), 1, intfs_info, self.iface)
        self.arp_timeout = 60
        #self.arp_thread = Thread(target=self.arp_thread)
        self.queueing_pkt_daemon = Queueing_Packet_Daemon(self)

        self.arpReq_from_mac_seen = set()
        self.afms_lock = threading.Lock()
        self.arp_req_limit_refresher_thread = ArpReqLimitRefresher(self)

    def arp_thread(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break
            for ip, (_, entry_time) in list(self.arp_table.items()):
                if time.time() - entry_time > self.arp_timeout:
                    del self.arp_table[ip]
                    self.sw.removeTableEntry(table_name='MyIngress.arp_table',
                                             match_fields={'next_hop_ip': [ip, 32]})
            self.stop_event.wait(self.arp_timeout)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac:
            return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                                 match_fields={'hdr.ethernet.dst_mac': [mac]},
                                 action_name='MyIngress.set_egr',
                                 action_params={'port': port})
        self.port_for_mac[mac] = port

    def addArpEntry(self, ip, mac):
        # print('DEBUG: Adding ARP entry for IP: {}, MAC: {}'.format(ip, mac))
        # # print types of ip and mac
        # print(type(ip))
        # print(type(mac))

        if ip in self.arp_table:
            return
        self.arp_table[ip] = (mac, time.time())
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                                 match_fields={'next_hop_ip': ip},
                                 action_name='MyIngress.arp_lookup',
                                 action_params={'dst_mac': mac})

    # def addIPV4FwdEntry(self, ip, mac, port):
    #     if ip in self.fwd_table:
    #         return
    #     self.fwd_table[ip] = {"mac": mac, "port": port}
    #     self.sw.insertTableEntry(table_name='MyIngress.routing_table',
    #                              match_fields={'hdr.ipv4.dstAddr': [ip, 32]},
    #                              action_name='MyIngress.ipv4_fwd',
    #                              action_params={'mac': mac, 'port': port})

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        self.addArpEntry(ip, mac)
        # self.addIPV4FwdEntry(ip, mac, pkt[CPUMetadata].srcPort)
        if pkt[ARP].pdst not in self.local_ip_table:
            if pkt[Ether].dst in self.port_for_mac:
                pkt[CPUMetadata].dstPort = self.port_for_mac[pkt[Ether].dst]
                self.send(pkt)
            else:
                print('[ALERT] ARP reply destined to unknown MAC address, dropping...')

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        self.addArpEntry(ip, mac)
        # self.addIPV4FwdEntry(ip, mac, pkt[CPUMetadata].srcPort)
        # pkt.show2()

        with locking(self.afms_lock):
            if (
                (pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].pdst)
            ) in self.arpReq_from_mac_seen:
                print("dropped the same arp")
                return

            target_subnet = calculate_subnet(pkt[ARP].pdst, self.controller_mask)
            # Send ARP reply for ARP requests to local IPs
            if pkt[ARP].pdst in self.local_ip_table:
                print('ARP destined to local IP {}'.format(pkt[ARP].pdst))
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
                pkt[ARP].psrc = get_ip_from_ip_subnet(self.intfs_info[intf.name])
                self.send(pkt)
            # only forward ARP requests within the same subnet
            elif target_subnet == self.controller_subnet:
                print('ARP request in the same subnet {}, forwarding...'.format(target_subnet))
                for intf in self.intfs:
                    intf_name = intf.name
                    if intf_name != self.controller_intf.name:
                        pkt[CPUMetadata].dstPort = self.sw.ports[intf]
                        if pkt[CPUMetadata].srcPort == pkt[CPUMetadata].dstPort:
                            continue
                        # pkt.show2()
                        print(pkt[CPUMetadata].dstPort, pkt[CPUMetadata].srcPort)
                        self.send(pkt)
                self.arpReq_from_mac_seen.add((pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].pdst))
            else:
                print('Dropped arp request because not in the same subnet, target subnet {}, controller subnet {}'.format(target_subnet, self.controller_subnet))

    def sendICMPEchoReply(self, pkt):
        new_pkt = Ether(src=self.controller_intf.MAC(), dst=pkt[Ether].src) / CPUMetadata(origEtherType=0x0800, srcPort=1, dstPort=pkt[CPUMetadata].srcPort) / IP(
            src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=ICMP_ECHO_REPLY_TYPE, code=ICMP_ECHO_REPLY_CODE, seq=pkt[ICMP].seq, id=pkt[ICMP].id) / pkt[ICMP].payload
        self.send(new_pkt)

    def handlePkt(self, pkt):
        if not CPUMetadata in pkt:
            print('Invalid CPUMetadata packet detected')
            pkt.show2()
            print('------------------------------------')
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        # if PWOSPF not in pkt:
        #     pkt.show2()
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

        if PWOSPF in pkt:
            self.handlePWOSPFPkt(pkt)
        elif IP in pkt:
            # Send ARP request
            # print('Next hop ip not in ARP table, sending ARP request to {}'.format(
            #     pkt[IP].dst))
            target_subnet = calculate_subnet(pkt[IP].dst, self.controller_mask)
            if target_subnet not in self.router.lsu_daemon.global_subnet2nexthop and target_subnet != self.controller_subnet:
                print('Destination subnet {} not in routing table, dropping...'.format(
                    target_subnet))
                pkt.show2()
                # new_pkt = Ether(src=self.controller_intf.MAC(), dst=pkt[Ether].src) / CPUMetadata(origEtherType=0x0800, srcPort=1, dstPort=pkt[CPUMetadata].srcPort) / IP(
                #     src=get_ip_from_ip_subnet(self.intfs_info[self.controller_intf.name]), dst=pkt[IP].src) / ICMP(type=ICMP_DEST_UNREACHABLE_REPLY_TYPE, code=ICMP_NET_UNREACHABLE_REPLY_CODE)
                # self.send(new_pkt)
            else:
                new_pkt = Ether() / CPUMetadata(origEtherType=0x0806, srcPort=1) / ARP()
                new_pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                new_pkt[Ether].src = self.controller_intf.MAC()
                new_pkt[ARP].op = ARP_OP_REQ
                new_pkt[ARP].hwdst = "00:00:00:00:00:00"
                new_pkt[ARP].pdst = pkt[IP].dst
                new_pkt[ARP].hwsrc = self.controller_intf.MAC()
                new_pkt[ARP].psrc = self.controller_ip
                for intf in self.intfs:
                    intf_name = intf.name
                    target_subnet = calculate_subnet(pkt[IP].dst, self.controller_mask)
                    if intf_name != self.controller_intf.name and calculate_subnet(get_ip_from_ip_subnet(self.intfs_info[intf_name]), get_mask_from_ip_subnet(self.intfs_info[intf_name])) == target_subnet:
                        new_pkt[CPUMetadata].dstPort = self.sw.ports[intf]
                        if pkt[CPUMetadata].srcPort == pkt[CPUMetadata].dstPort:
                            continue
                        # new_pkt.show2()
                        self.send(new_pkt)
                # queue the packet
                self.queueing_pkt_daemon.queue.put((pkt, pkt[IP].dst, time.time()))

    def handlePWOSPFPkt(self, pkt):

        def handleHelloPkt(pkt, intf):
            if pkt[HELLO].netmask != intf.subnet_mask:
                return
            if pkt[HELLO].helloint != intf.helloint:
                return
            router_id = pkt[PWOSPF].router_id
            neighbor_router_ip = pkt[IP].src
            intf.neighbors[(router_id, neighbor_router_ip)] = time.time()
            self.router.nexthop_rid2intf[router_id] = (
                intf, neighbor_router_ip)
            # learns the MAC address of the neighbor
            self.addMacAddr(pkt[Ether].src, pkt[CPUMetadata].srcPort)
            # trigger LSU flood on change
            if self.router.lsu_daemon:
                self.router.lsu_daemon.trigger_lsu_event.set()

        if pkt[PWOSPF].version != 2:
            return
        if pkt[PWOSPF].type != 1 and pkt[PWOSPF].type != 4:
            return
        if pkt[PWOSPF].area_id != self.router.area_id:
            return
        if pkt[PWOSPF].au_type != 0:
            return

        if LSU in pkt:
            self.router.lsu_daemon.handle_LSU(pkt)
            return

        intf = None
        for i in range(len(self.router.intfs)):
            if pkt[CPUMetadata].srcPort == self.router.intfs[i].port:
                intf = self.router.intfs[i]
                break

        if intf and HELLO in pkt:
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
        #self.arp_thread.start()
        self.queueing_pkt_daemon.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.router.join()
        self.stop_event.set()
        #self.arp_thread.join()
        self.queueing_pkt_daemon.join()
        super(MacLearningController, self).join(*args, **kwargs)

    def print_state(self):
        '''
        It should print the ARP table, the PWOSPF's adjacency list, and the routing table
        '''
        print("*************** ARP Table ******************")
        for ip, mac in self.arp_table.items():
            print("IP: {}, MAC: {}".format(ip, mac))
        print("********* PWOSPF Interface States **********")
        for intf in self.router.intfs:
            print(intf)
        print("********* PWOSPF Adjacency List ***********")
        for rid, neighbors in self.router.lsu_daemon.adjacency_list.items():
            print("Router ID: {}, Neighbor links: {}".format(rid, neighbors))
        print("************* Routing Table ***************")
        for subnet, (next_hop_ip, port) in self.router.lsu_daemon.global_subnet2nexthop.items():
            print("Subnet: {}, Next Hop: IP {} Port {}".format(
                subnet, next_hop_ip, port))
        print("************* Router State ***************")
        print("-------------------------------------------")
        self.sw.printTableEntries()
        print("-------------------------------------------")
        print("*******************************************")
