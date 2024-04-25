import copy
import time
import threading

from collections import Counter, defaultdict
from scapy.all import Ether, IP, ARP, ICMP, sendp, Raw  # type: ignore
from threading import Thread, Event

from async_sniff import sniff
from cpu_metadata import CPUMetadata
from utils import *
from pwospf import *

# constants
ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002
TYPE_ARP = 0x0806
TYPE_ETHER = 0x0800
PWOSPF_HELLO_DST = "224.0.0.5"
CPU_PORT = 1


class RouterController(Thread):
    def __init__(
        self,
        rt,
        area_id,
        lsuint=30,
        start_wait=0.3,
        router_info={},
        arp_enabled=False,
        hello_int=10,
    ):
        super(RouterController, self).__init__()
        self.rt = rt  # the data plane of the router, in the other word, the swtich
        self.start_wait = start_wait  # time to wait for the controller to be listenning

        self.cpu_iface = self.rt.intfs[
            1
        ].name  # the interface that the router uses to connect to the controller
        self.cpu_ip = router_info["cpu_ip"]  # the ip of the router, I gave
        self.cpu_mac = self.rt.intfs[
            1
        ].MAC()  # Don't worry about this now, this is the still a mac from the router per se
        self.router_id = router_info["cpu_ip"]  # string
        self.router_mask = router_info["netmask"]  # integer
        self.area_id = area_id
        self.subnet = calculate_subnet_id(self.router_id, self.router_mask)

        self.ifaces = {}
        self.arp_cache = ArpCache(rt, enabled=arp_enabled)

        self.port_for_mac = {}

        self.ospf_lock = threading.Lock()

        # OSPF HELLO
        self.last_lsu_from_routers = {}
        self.last_lsu_times = {}
        self.hello_outs = []  # outgoing ospf hello threads

        # OSPF LSU
        self.routing_table = (
            {}
        )  # ip -> (next_hop_ip, port); port can be gotten from ip -> arp -> port?
        self.adj_list = defaultdict(set)  # router_id -> set of adjacent routers
        self.lsuint = lsuint
        self.lsu_seq = defaultdict(lambda: 0)
        self.next_lsu_flood = 0

        # populating the interfaces
        for port, info in router_info["port_ips_macs"].items():
            self.ifaces[port] = RouterInterface(
                info["ip"], info["mask"], info["mac"], port, helloint=hello_int
            )
        for port, iface in self.ifaces.items():
            self.hello_outs.append(HelloThread(iface, self))

        self.lsu_thread = LSUThread(self)

        self.stop_event = Event()

        self.arp_request_packets_seen = defaultdict(lambda: 0)

        self.arpReq_from_mac_seen = set()
        self.afms_lock = threading.Lock()
        self.arp_req_limit_refresher_thread = ArpReqLimitRefresher(self)

        self.dummy_counter = 0

        self.cv = threading.Condition()

        self.router_subnets = set()

    def addArp(self, ip, mac):
        self.arp_cache.add_entry(ip, mac)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        # if mac in self.port_for_mac and self.port_for_mac[mac] == port:
        if mac in self.port_for_mac:
            return

        # if mac in self.port_for_mac:
        #     if self.port_for_mac[mac] != port:  # TODO: add update later
        #         self.rt.removeTableEntry(
        #             table_name="MyIngress.fwd_l2",
        #             match_fields={"hdr.ethernet.dst_mac": [mac]},
        #         )

        # print("add 2")
        self.rt.insertTableEntry(
            table_name="MyIngress.fwd_l2",
            match_fields={"hdr.ethernet.dst_mac": [mac]},
            action_name="MyIngress.set_egr",
            action_params={"port": port},
        )
        # print("add 2 done")

        self.port_for_mac[mac] = port

    def handleArpReply(self, pkt):

        arp_layer = pkt[ARP]

        if arp_layer.hwdst == self.cpu_mac:
            # this is for me
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.addArp(pkt[ARP].psrc, pkt[ARP].hwsrc)
            # print("received!")
            with self.cv:
                self.cv.notify()
            return

        if arp_layer.hwsrc == self.cpu_mac:
            # print("received my own arp, dropping")
            assert arp_layer.psrc == self.cpu_ip
            return

        for _, iface in self.ifaces.items():
            if arp_layer.hwsrc == iface.mac:
                # print("received my own arp, dropping")
                assert arp_layer.psrc == iface.ip
                return

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArp(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.addArp(pkt[ARP].pdst, pkt[ARP].hwdst)

        if (pkt[ARP].hwdst) == self.cpu_mac:
            # print("this is an arp for me, dropping")
            assert arp_layer.pdst == self.cpu_ip
            return

        for _, iface in self.ifaces.items():
            if arp_layer.hwdst == iface.mac:
                # print("this is an arp for me, dropping")
                assert arp_layer.pdst == iface.ip
                return

        # valid forward case, let hardware do it

        if pkt[ARP].hwdst in self.port_for_mac:
            pkt[CPUMetadata].dstPort = self.port_for_mac[pkt[ARP].hwdst]
            # print("done")
            self.send(pkt)
            return

        print("shouldn't not know how to reach the mac address")

        assert False

        # if pkt[ARP].hwdst in self.port_for_mac:
        # pkt[CPUMetadata].dstPort = 0
        # print("set port: ", self.port_for_mac[pkt[ARP].hwdst])
        # print("port_for_mac: ", self.port_for_mac)
        # else:
        #     best_match, next_port = longest_prefix_match(
        #         ip_to_int(pkt[ARP].pdst), self.routing_table
        #     )
        #     print("ip:", pkt[ARP].pdst, "dst port:", next_port)
        #     pkt[CPUMetadata].dstPort = next_port
        #     print("relayed arp response to", next_port)
        #     # pkt.show2()
        # print("invoked 4")
        # self.send(pkt)

    def handleArpRequest(self, pkt):

        ether_layer = pkt[Ether]
        arp_layer = pkt[ARP]

        if arp_layer.hwsrc == self.cpu_mac:
            # print("received my own arp, dropping")
            assert arp_layer.psrc == self.cpu_ip
            return

        for _, iface in self.ifaces.items():
            if arp_layer.hwsrc == iface.mac:
                # print("received my own arp, dropping")
                assert arp_layer.psrc == iface.ip
                return

        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArp(pkt[ARP].psrc, pkt[ARP].hwsrc)

        with locking(self.afms_lock):
            if (
                (pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].pdst)
            ) in self.arpReq_from_mac_seen:
                # print("dropped the same arp")
                return

            if arp_layer.pdst == self.cpu_ip:
                # These are done also by the hardware
                # send the packet back to sender
                ether_layer.dst = ether_layer.src
                ether_layer.src = self.cpu_mac

                arp_layer.hwdst = arp_layer.hwsrc
                arp_layer.hwsrc = self.cpu_mac
                arp_layer.pdst = arp_layer.psrc
                arp_layer.psrc = self.cpu_ip

                arp_layer.op = ARP_OP_REPLY
                pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
                pkt[CPUMetadata].fromCpu = 1

                self.send(pkt)
                # print("invoked 1")
                return

            for _, iface in self.ifaces.items():
                if iface.ip == arp_layer.pdst:
                    # These are done also by the hardware
                    # send the packet back to sender
                    ether_layer.dst = ether_layer.src
                    ether_layer.src = iface.mac

                    arp_layer.hwdst = arp_layer.hwsrc
                    arp_layer.hwsrc = iface.mac
                    arp_layer.pdst = arp_layer.psrc
                    arp_layer.psrc = iface.ip

                    arp_layer.op = ARP_OP_REPLY
                    pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
                    pkt[CPUMetadata].fromCpu = 1

                    # print("invoked 2")
                    self.send(pkt)
                    return

            # The case that I am just a rely

            src_port = pkt[CPUMetadata].srcPort
            if not pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                # print("dropped arp req forwarded by host")
                # pkt.show2()
                return
            # assert pkt[Ether].dst == "ff:ff:ff:ff:ff:ff"
            for port, iface in self.ifaces.items():
                if port == src_port:
                    continue
                pkt[CPUMetadata].dstPort = port
                # print("invoked 3")
                self.send(pkt)

            self.arpReq_from_mac_seen.add(
                (pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].pdst)
            )

    def handleIcmpRequest(self, pkt):
        ip_layer = pkt[IP]
        icmp_layer = pkt[ICMP]
        ether_layer = pkt[Ether]

        # Find the interface for the destination IP
        if ip_layer.dst not in [iface.ip for iface in self.ifaces.values()] + [
            self.cpu_ip
        ]:
            # TODO: send arp?

            if not self.arp_cache.has_entry(pkt[IP].dst):
                cpu_meta = CPUMetadata(
                    fromCpu=1,
                    origEtherType=TYPE_ARP,
                    srcPort=1,
                )

                arp_data = ARP(
                    op=ARP_OP_REQ,
                    hwsrc=self.cpu_mac,
                    hwdst="00:00:00:00:00:00",
                    psrc=self.cpu_ip,
                    pdst=pkt[IP].dst,
                )

                # Construct Ethernet frame
                response_frame = (
                    Ether(
                        dst="ff:ff:ff:ff:ff:ff",
                        src=self.cpu_mac,
                    )
                    / cpu_meta
                    / arp_data
                )

                for port, iface in self.ifaces.items():
                    if iface.subnet == calculate_subnet_id(
                        ip_to_int(pkt[IP].dst), ip_to_int(iface.mask)
                    ):
                        response_frame[CPUMetadata].dstPort = port

                        self.send(response_frame)

                threading.Thread(
                    target=self.waitAndSendArpRequest,
                    args=(pkt),
                ).start()
                return

            print("here?")

            target_mac = self.arp_cache.get_mac(pkt[IP].dst)

            if target_mac is not None:
                # print("got it, nice")
                # pkt.show2()
                # forward the packet
                pkt[CPUMetadata].dstPort = self.port_for_mac[target_mac]
                pkt[Ether].dst = target_mac
                pkt[Ether].src = self.cpu_mac
                self.send(pkt)

                return
            else:
                print("generate bad response")
                # Modify Ethernet Layer
                pkt[Ether].dst = pkt[Ether].src
                pkt[Ether].src = self.cpu_mac

                pkt[IP].chksum = None
                pkt[IP].ttl = 64

                # Extract the original IP header and the first 8 bytes of the payload
                original_ip_header = pkt[IP].copy()
                original_ip_header.len = None  # Let Scapy recalculate
                payload_start = bytes(pkt[IP].payload)[:8]
                icmp_payload = original_ip_header / Raw(load=payload_start)

                # Create ICMP Host Unreachable message
                icmp = ICMP(type=3, code=1)
                icmp.chksum = None  # Start with no checksum

                # Full ICMP message as bytes for checksum calculation
                full_icmp_message = bytes(icmp) + bytes(icmp_payload)
                full_icmp_message = (
                    full_icmp_message[:2] + b"\x00\x00" + full_icmp_message[4:]
                )  # Zero checksum field for calculation

                # Calculate and set ICMP checksum
                # computed_checksum = checksum(full_icmp_message)
                # icmp.chksum = computed_checksum  # Update checksum field

                # Update the packet's ICMP layer
                pkt[ICMP] = icmp / icmp_payload

                # Metadata and sending (if used in your setup)
                pkt[CPUMetadata].fromCpu = 1
                pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
                pkt[CPUMetadata].srcPort = 1

                pkt[IP].dst = pkt[IP].src
                pkt[IP].src = self.cpu_ip

                pkt[ICMP].chksum = None
                pkt[ICMP].chksum = 0x3D4D

                # print("whole packet: \n", bytes(pkt))
                # print("icmp: \n", bytes(pkt[ICMP]))
                # print("icmp data: \n", pkt[ICMP])
                # print("hex: \n", bytes(pkt[ICMP]).hex())

                # Display and send the packet
                # pkt.show2()
                self.send(pkt)
                return

        # Recevied ICMP destined for me
        # assert False

        # print("here")

        # # Create ICMP Echo Reply
        echo_reply = (
            IP(src=ip_layer.dst, dst=ip_layer.src)
            / ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)
            / icmp_layer[Raw].load
        )

        cpu_meta = CPUMetadata(
            fromCpu=1,
            origEtherType=pkt[Ether].origEtherType,
            srcPort=pkt[CPUMetadata].srcPort,
            dstPort=pkt[CPUMetadata].dstPort,
        )

        # Construct Ethernet frame
        response_frame = (
            Ether(
                dst=self.ifaces[
                    pkt[CPUMetadata].srcPort
                ].mac,  # Swap source and destination MAC addresses
                src=self.cpu_mac,
            )
            / cpu_meta
            / echo_reply
        )
        # Send the reply packet
        self.send(response_frame)

    def handlePkt(self, pkt):

        assert (
            CPUMetadata in pkt
        ), "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1:
            # Question: why am I receiving them from the first place
            return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
                return
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
                return

        if IP in pkt:
            if PWOSPF in pkt:  # and src_port != 1
                with locking(self.ospf_lock):
                    if not self.valid_ospf_packet(pkt):
                        return

                    if HELLO in pkt:
                        self.handle_ospf_hello(pkt)
                        return

                    if LSU in pkt:
                        self.handle_ospf_lsu(pkt)
                        return
                return

            if ICMP in pkt:
                # pkt.show2()
                # Check if it's an ICMP Echo Request
                if pkt[ICMP].type == 8 and pkt[ICMP].code == 0:
                    # print("Handling ICMP Echo Request")
                    self.handleIcmpRequest(pkt)

                if pkt[ICMP].type == 0 and pkt[ICMP].code == 0:
                    #
                    print("here..........")

                # return

                # else, no idea what to do, drop

            # TODO: think
            # case that ARP timed out
            if not self.arp_cache.has_entry(pkt[IP].dst):
                cpu_meta = CPUMetadata(
                    fromCpu=1,
                    origEtherType=TYPE_ARP,
                    srcPort=pkt[CPUMetadata].srcPort,
                    dstPort=pkt[CPUMetadata].dstPort,
                )

                arp_data = ARP(
                    op=ARP_OP_REQ,
                    hwsrc=self.cpu_mac,
                    hwdst="00:00:00:00:00:00",
                    psrc=self.cpu_ip,
                    pdst=pkt[IP].dst,
                )

                # Construct Ethernet frame
                response_frame = (
                    Ether(
                        dst="ff:ff:ff:ff:ff:ff",
                        src=self.cpu_mac,
                    )
                    / cpu_meta
                    / arp_data
                )

                self.send(response_frame)

                time.sleep(0.3)

            # Then you can do what ever you want

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.cpu_iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.cpu_iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        self.lsu_thread.start()
        for h_thread in self.hello_outs:
            h_thread.start()
        self.arp_req_limit_refresher_thread.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        for hells in self.hello_outs:
            hells.join()
        self.lsu_thread.join()
        self.arp_req_limit_refresher_thread.join()
        super(RouterController, self).join(*args, **kwargs)

    def lsuFlood(self):
        "initiate the lsuflood process, creating a new LSU packet that initiates from myself"
        lsa_lists = defaultdict(set)
        for _, iface in self.ifaces.items():
            for id, neighbor in iface.neighbors.items():
                subnet = calculate_subnet_id(neighbor[0], neighbor[1])
                lsa_lists[subnet].add(
                    LSA(subnet=subnet, mask=neighbor[1], router_id=id)
                )

        for subnet, lsa_list in lsa_lists.items():
            ether_data = Ether(src=self.cpu_mac, dst="ff:ff:ff:ff:ff:ff")
            cpu_metadata = CPUMetadata(
                fromCpu=1,
                origEtherType=TYPE_ETHER,
                srcPort=1,
            )
            ip_data = IP(
                src=self.cpu_ip,
                proto=OSPF_PROTO_NUM,
                ttl=1,
            )
            pwospf_data = PWOSPF(
                version=2,
                type=TYPE_LSU,
                len=0,
                router_id=self.router_id,
                area_id=self.area_id,
            )
            lsu_data = LSU(
                sequence=self.lsu_seq[subnet],
                numLsa=len(lsa_list),
                lsaList=list(lsa_list),
            )
            pkt = ether_data / cpu_metadata / ip_data / pwospf_data / lsu_data

            self.lsu_seq[subnet] += 1
            self.next_lsu_flood = time.time() + self.lsuint
            self.lsuFloodPkt(pkt, subnet)

    def lsuFloodPkt(self, pkt, subnet):
        "flooding the given packet through all my interfaces that have the same subnet\n\
         also used for forwarding LSU packets"

        pkt[LSU].ttl -= 1
        if pkt[LSU].ttl > 0:
            for port, iface in self.ifaces.items():
                if pkt[CPUMetadata].srcPort == port:
                    continue

                for _, (ip, _) in iface.neighbors.items():
                    # TODO: more checks

                    pkt[CPUMetadata].dstPort = port
                    pkt[IP].dst = ip
                    if pkt[IP].dst == pkt[IP].src:
                        continue

                    pkt[IP].chksum = None
                    self.send(pkt)

    def sync_routing_table(self):
        "syncing the routing table with the most up-to-date adj_list"

        graph = defaultdict(set)
        for id_a, id_bs in self.adj_list.items():
            for id_b in id_bs:
                graph[id_a].add((id_b, 1))
                graph[id_b].add((id_a, 1))

        _distances, predecessors = dijkstra(graph, self.router_id)

        shortest_paths = {}
        for node in graph:
            if node == self.router_id:
                # note: this should hanld the later `len(path) == 0` case, investigate later
                continue
            shortest_paths[node] = reconstruct_path(predecessors, self.router_id, node)

        finished = True
        for router_id, path in shortest_paths.items():
            if len(path) == 0:
                # maybe investigate later
                continue
            next_hop_ip, next_hop_port = self.get_interface_ip_from_router_id(path[0])

            if next_hop_ip is None:
                # not enough information yet
                finished = False
                continue

            if router_id in self.routing_table:
                if next_hop_ip != self.routing_table[router_id][0]:
                    # item changed
                    # self.rt.removeTableEntry(
                    #     table_name="MyIngress.routing_table",
                    #     match_fields={"ip_to_match": [router_id, 32]},
                    # )

                    # self.rt.insertTableEntry(
                    #     table_name="MyIngress.routing_table",
                    #     match_fields={"ip_to_match": [router_id, 32]},
                    #     action_name="MyIngress.ipv4_route",
                    #     action_params={
                    #         "dst_ip": next_hop_ip,
                    #         "egress_port": next_hop_port,
                    #     },
                    # )
                    self.routing_table[router_id] = (next_hop_ip, next_hop_port)
                else:
                    # In and previous Same, do nothing
                    pass
            else:
                # TODO: fix this for remove case
                router_subnet = calculate_subnet_id(
                    ip_to_int(router_id), self.router_mask
                )
                if router_subnet != self.subnet and (
                    router_subnet not in self.router_subnets
                ):
                    # print("add 3")
                    self.rt.insertTableEntry(
                        table_name="MyIngress.routing_table",
                        match_fields={"ip_to_match": [router_subnet, 16]},  # change
                        action_name="MyIngress.ipv4_route",
                        action_params={
                            "dst_ip": next_hop_ip,
                            "egress_port": next_hop_port,
                        },
                    )
                    # print("add 3 don3")

                    self.router_subnets.add(router_subnet)

                # self.rt.insertTableEntry(
                #     table_name="MyIngress.routing_table",
                #     match_fields={"ip_to_match": [router_id, 32]},
                #     action_name="MyIngress.ipv4_route",
                #     action_params={"dst_ip": next_hop_ip, "egress_port": next_hop_port},
                # )
                self.routing_table[router_id] = (next_hop_ip, next_hop_port)

        return finished

    def get_interface_ip_from_router_id(self, router_id):
        for port_num, iface in self.ifaces.items():
            for r_id, neighbor in iface.neighbors.items():
                if r_id == router_id:
                    return neighbor[0], port_num

        return None, None

    def valid_ospf_packet(self, pkt):
        pw = pkt[PWOSPF]
        if (not (pw.version == 2)) or (
            pw.router_id == self.router_id and pw.area_id == self.area_id
        ):
            # print("dropped1")
            return False

        if not (pw.type == TYPE_HELLO or pw.type == TYPE_LSU):
            # print("dropped2")
            return False

        if not (pw.auth == 0 and pw.au_type == 0):
            # print("dropped3")
            return False

        return True

    def handle_ospf_hello(self, pkt):
        pw = pkt[PWOSPF]
        src_port = pkt[CPUMetadata].srcPort
        intf = self.ifaces[src_port]
        hell = pkt[HELLO]

        self.addArp(pkt[IP].src, pkt[Ether].src)

        if not ((intf.helloint == hell.helloint) and (intf.mask == hell.netmask)):
            # print("dropped4")
            return

        # print("received HELLO")
        if pw.router_id == self.router_id:
            print("really shouldn't be here... received PWOSPF HELLO from myself...")
            return

        if pw.router_id not in intf.neighbors:
            # note: the `removed` case is interesting, not hit again...
            # This is a new neighbor, adding to both neighbors and adj_list
            intf.neighbors[pw.router_id] = (pkt[IP].src, hell.netmask)

            intf.neighbor_update_times[pw.router_id] = time.time()
            self.adj_list[self.router_id].add(pw.router_id)
            self.adj_list[pw.router_id].add(self.router_id)

            self.sync_routing_table()
            self.lsuFlood()

            return

        if intf.neighbors[pw.router_id] != (pkt[IP].src, hell.netmask):
            print("this is probably unlikely to happen...")
            # neighbor updated
            old_src, _ = intf.neighbors[pw.router_id]

            # remove relevant entry from adj_list
            self.adj_list[pw.router_id].remove(old_src)
            self.adj_list[old_src].remove(pw.router_id)

            # updates
            intf.neighbors[pw.router_id] = (pkt[IP].src, hell.netmask)
            intf.neighbor_update_times[pw.router_id] = time.time()
            self.adj_list[self.router_id].add(pw.router_id)
            self.adj_list[pw.router_id].add(self.router_id)

            self.sync_routing_table()
            self.lsuFlood()

            return

        # the case that nothing is updated, merely update the timer
        intf.neighbor_update_times[pw.router_id] = time.time()

    def handle_ospf_lsu(self, pkt):
        pw = pkt[PWOSPF]

        diff = False
        if pw.router_id not in self.last_lsu_from_routers:
            diff = True
        else:
            last_ospf_pkt = self.last_lsu_from_routers[pw.router_id]

            if pkt[PWOSPF].sequence <= last_ospf_pkt.sequence:
                return
            diff = Counter(last_ospf_pkt[LSU].lsaList) == Counter(pkt[LSU])

        self.last_lsu_from_routers[pw.router_id] = copy.deepcopy(pkt)
        self.last_lsu_times[pw.router_id] = time.time()

        if diff:
            # remove everything and insert all things new, TODO: optimize for later
            for adj_router in self.adj_list[pw.router_id]:
                self.adj_list[adj_router].remove(pw.router_id)
            del self.adj_list[pw.router_id]

            # re-enter everything
            for lsa in pkt[LSU].lsaList:
                self.adj_list[pw.router_id].add(lsa.router_id)
                self.adj_list[lsa.router_id].add(pw.router_id)

            if not self.sync_routing_table():
                # case that doesn't have enough information, needs to do this again later
                del self.last_lsu_from_routers[pw.router_id]
                del self.last_lsu_times[pw.router_id]

            # TODO:s checksum
            # if valid packet and topology has changed -> reset adjacency list for that router
            pkt[Ether].src = self.cpu_mac

        self.lsuFloodPkt(pkt, ip_to_int(pkt[LSU].lsaList[0].subnet))
        return

    def waitAndSendArpRequest(self, pkt):

        # We could also simply just wait here

        with self.cv:
            self.cv.wait(1.0)
        # print("we are here", time.time())

        target_mac = self.arp_cache.get_mac(pkt[IP].dst)
        icmp_layer = pkt[ICMP]

        if target_mac is not None:
            # print("got it, nice")
            # pkt.show2()
            # forward the packet
            pkt[CPUMetadata].dstPort = self.port_for_mac[target_mac]
            pkt[Ether].dst = target_mac
            pkt[Ether].src = self.cpu_mac
            self.send(pkt)
        else:
            print("generate bad response")
            # Modify Ethernet Layer
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.cpu_mac

            pkt[IP].chksum = None
            pkt[IP].ttl = 64

            # Extract the original IP header and the first 8 bytes of the payload
            original_ip_header = pkt[IP].copy()
            original_ip_header.len = None  # Let Scapy recalculate
            payload_start = bytes(pkt[IP].payload)[:8]
            icmp_payload = original_ip_header / Raw(load=payload_start)

            # Create ICMP Host Unreachable message
            icmp = ICMP(type=3, code=1)
            icmp.chksum = None  # Start with no checksum

            # Full ICMP message as bytes for checksum calculation
            full_icmp_message = bytes(icmp) + bytes(icmp_payload)
            full_icmp_message = (
                full_icmp_message[:2] + b"\x00\x00" + full_icmp_message[4:]
            )  # Zero checksum field for calculation

            # Calculate and set ICMP checksum
            # computed_checksum = checksum(full_icmp_message)
            # icmp.chksum = computed_checksum  # Update checksum field

            # Update the packet's ICMP layer
            pkt[ICMP] = icmp / icmp_payload

            # Metadata and sending (if used in your setup)
            pkt[CPUMetadata].fromCpu = 1
            pkt[CPUMetadata].dstPort = pkt[CPUMetadata].srcPort
            pkt[CPUMetadata].srcPort = 1

            pkt[IP].dst = pkt[IP].src
            pkt[IP].src = self.cpu_ip

            pkt[ICMP].chksum = None
            pkt[ICMP].chksum = 0x3D4D

            # print("whole packet: \n", bytes(pkt))
            # print("icmp: \n", bytes(pkt[ICMP]))
            # print("icmp data: \n", pkt[ICMP])
            # print("hex: \n", bytes(pkt[ICMP]).hex())

            # Display and send the packet
            # pkt.show2()
            self.send(pkt)
            return


class RouterInterface:
    def __init__(self, ip, mask, mac, port, helloint=10):
        # default
        self.ip = ip
        self.mask = mask
        self.subnet = calculate_subnet_id(ip, mask)
        self.mac = mac
        self.port = port
        self.neighbors = {}  # router_id -> (ip, mask)
        self.helloint = helloint
        self.neighbor_update_times = {}


class ArpCache:
    def __init__(self, rt, timeout_interval=3, cleanup_interval=1, enabled=False):
        self.cache = {}
        self.lock = threading.Lock()
        self.timeout_interval = timeout_interval
        self.cleanup_interval = cleanup_interval
        self.cleanup_thread = None
        self.active = (
            threading.Event()
        )  # Controls the active state of the cleanup thread
        self.rt = rt
        self.enabled = enabled

    def add_entry(self, ip, mac):
        with locking(self.lock):
            # Start the cleanup thread if it's not active
            if self.enabled and not self.active.is_set():
                self.active.set()
                self.start_cleanup_thread()

            need_remove = ip in self.cache

            if ip in self.cache and self.cache[ip][0] == mac:
                # refresh only
                self.cache[ip] = (mac, time.time() + self.timeout_interval)
                return

            # Update the cache
            self.cache[ip] = (mac, time.time() + self.timeout_interval)

            # Insert or update entry in the routing table
            if need_remove:
                self.rt.removeTableEntry(
                    table_name="MyIngress.arp_table",
                    match_fields={"next_hop_ip": ip},
                )

            # print("add 1")
            self.rt.insertTableEntry(
                table_name="MyIngress.arp_table",
                match_fields={"next_hop_ip": ip},
                action_name="MyIngress.arp_lookup",
                action_params={"dst_mac": mac},
            )
            # print("add 1 done")

    def start_cleanup_thread(self):
        if (self.enabled) and (
            self.cleanup_thread is None or not self.cleanup_thread.is_alive()
        ):
            self.cleanup_thread = threading.Thread(target=self.clean_up)
            self.cleanup_thread.start()

    def clean_up(self):
        while self.enabled and not self.active.wait(self.cleanup_interval):
            with locking(self.lock):
                current_time = time.time()
                keys_to_delete = [
                    ip
                    for ip, (_, timestamp) in self.cache.items()
                    if current_time > timestamp
                ]
                for key in keys_to_delete:
                    self.rt.removeTableEntry(
                        table_name="MyIngress.arp_table",
                        match_fields={"next_hop_ip": key},
                    )
                    del self.cache[key]

                if not self.cache:
                    # Stop the thread if the cache is empty
                    self.active.clear()

    def has_entry(self, ip):
        with locking(self.lock):
            return ip in self.cache

    def get_mac(self, ip):
        with locking(self.lock):
            if ip not in self.cache:
                return None
            return self.cache[ip][0]


class HelloThread(Thread):
    def __init__(self, intf, controller):
        super(HelloThread, self).__init__()
        self.interface = intf
        self.controller = controller
        # self.daemon = True
        self.stop_event = Event()

    def run(self):
        while not self.stop_event.wait(self.interface.helloint):
            # Send Hello packet
            ether_data = Ether(
                src=self.controller.cpu_mac,
                dst="ff:ff:ff:ff:ff:ff",
            )
            cpu_metadata = CPUMetadata(
                fromCpu=1,
                origEtherType=TYPE_ETHER,
                srcPort=1,
                dstPort=self.interface.port,
            )
            ip_data = IP(
                src=self.interface.ip,
                dst=PWOSPF_HELLO_DST,
                proto=OSPF_PROTO_NUM,
                ttl=1,
            )
            pwospf_data = PWOSPF(
                version=2,
                type=TYPE_HELLO,
                len=0,
                router_id=self.controller.router_id,
                area_id=self.controller.area_id,
            )
            hello_data = HELLO(
                netmask=self.interface.mask, helloint=self.interface.helloint
            )
            pkt = ether_data / cpu_metadata / ip_data / pwospf_data / hello_data

            self.controller.send(pkt)

            # # Remove timed-out neighbors
            curr_time = time.time()
            # List to hold the keys to be removed
            keys_to_remove = []

            with locking(self.controller.ospf_lock):
                # Iterate over the dictionary to identify keys that should be removed
                for router_id, _ in self.interface.neighbors.items():
                    updated_times = self.interface.neighbor_update_times[router_id]
                    if (curr_time - updated_times) > (self.interface.helloint * 3):
                        # print("removed")
                        # TODO: care here, somehow when things are removed, they aren't added back...
                        keys_to_remove.append(router_id)

                # Remove the identified keys from the dictionaries
                for router_id in keys_to_remove:
                    del self.interface.neighbors[router_id]
                    del self.interface.neighbor_update_times[router_id]
                    try:
                        del self.controller.last_lsu_from_routers[router_id]
                    except:
                        pass
                    try:
                        del self.controller.last_lsu_times[router_id]
                    except:
                        pass
                    try:
                        for adj_router in self.controller.adj_list[router_id]:
                            self.controller.adj_list[adj_router].remove(router_id)
                        del self.controller.adj_list[router_id]
                    except:
                        pass

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(HelloThread, self).join(*args, **kwargs)


class LSUThread(Thread):
    def __init__(self, controller):
        super(LSUThread, self).__init__()
        self.controller = controller
        self.stop_event = Event()

    def run(self):

        while True:
            if self.stop_event and self.stop_event.is_set():
                break

            with locking(self.controller.ospf_lock):
                # if another lsu has been triggered before
                cur_time = time.time()
                if self.controller.next_lsu_flood > cur_time:
                    # print("sleeping ", self.controller.next_lsu_flood - cur_time)
                    self.stop_event.wait(self.controller.next_lsu_flood - cur_time)
                    continue

                self.controller.lsuFlood()

            self.stop_event.wait(self.controller.lsuint)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(LSUThread, self).join(*args, **kwargs)


class ArpReqLimitRefresher(Thread):
    def __init__(self, controller):
        super(ArpReqLimitRefresher, self).__init__()
        self.controller = controller
        self.stop_event = Event()

    def run(self):
        while True:
            if self.stop_event and self.stop_event.is_set():
                break

            with self.controller.afms_lock:
                # if another lsu has been triggered before
                self.controller.arpReq_from_mac_seen.clear()
                pass

            self.stop_event.wait(0.618)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(ArpReqLimitRefresher, self).join(*args, **kwargs)
