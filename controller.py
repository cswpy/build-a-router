from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from pwospf_proto import PWOSPF_Header, PWOSPF_Hello
from async_sniff import sniff
from utils import *
from cpu_metadata import CPUMetadata
import time

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_PROTO = 0x59  # follow OSPFv2
PWOSPF_ALLSPFRouters = "224.0.0.5"


class PWOSPF_Interface():
    def __init__(self, ip_addr, subnet_mask, helloint, iface, mac, port):
        self.ip_addr = ip_addr
        self.subnet_mask = subnet_mask
        self.helloint = helloint
        self.iface = iface
        self.MAC = mac
        self.port = port
        self.neighbors = {}  # (neighbor_id, IP) -> last_recv_time

    # def start(self):
    #     self.thread = Thread(target=self._hello)
    #     self.thread.start()

    # def stop(self):
    #     self.stop_event.set()
    #     self.thread.join()

    # def _hello(self):
    #     while True:
    #         if self.stop_event and self.stop_event.is_set():
    #             break
    #         self.router.send(self.hello_pkt, iface=self.iface)
    #         time.sleep(self.helloint)


class PWOSPF_Router(Thread):
    def __init__(self, sw, router_id, area_id, intfs, iface, helloint=5, lsuint=10, start_wait=0.3):
        super(PWOSPF_Router, self).__init__()
        self.sw = sw
        self.router_id = router_id
        self.area_id = area_id
        self.intfs = []
        self.iface = iface
        self.start_wait = start_wait
        self.lsu_interval = lsuint
        self.MAC = self.sw.intfs[1].MAC()
        self.hello_threads = []
        self.stop_event = Event()

        for i in range(1, len(intfs)):
            # skip the first interface, which is connected to the CPU
            ip_addr, subnet_mask, iface, mac, port = intfs[i].ip, prefix_len_to_mask(
                int(intfs[i].prefixLen)), intfs[i].name, intfs[i].MAC(), self.sw.ports[intfs[i]]
            intf = PWOSPF_Interface(
                ip_addr, subnet_mask, helloint, iface, mac, port)
            self.intfs.append(intf)

    def _hello(self, intf_id):
        # craft hello packet
        intf = self.intfs[intf_id]
        etherLayer = Ether(src=intf.MAC, dst="ff:ff:ff:ff:ff:ff")
        CPUlayer = CPUMetadata(
            fromCpu=1, origEtherType=0x0800, srcPort=1, dstPort=intf.port)
        IPLayer = IP(src=intf.ip_addr, dst=PWOSPF_ALLSPFRouters,
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
            time.sleep(intf.helloint)

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
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        for thread in self.hello_threads:
            thread.join()
        super(PWOSPF_Router, self).join(*args, **kwargs)


class MacLearningController(Thread):
    '''
    intfs: [(ip_addr, subnet_mask, helloint, iface), ...] first intf should be the one connected to the CPU
    '''

    def __init__(self, sw, start_wait=0.3):
        super(MacLearningController, self).__init__()
        # assert intfs[0][3].endswith('eth1'), "First interface should be connected to the CPU"
        self.sw = sw
        self.start_wait = start_wait  # time to wait for the controller to be listenning
        self.intfs = self.sw.intfList()[1:]  # ignoring the loopback interface
        self.iface = self.intfs[0].name
        self.port_for_mac = {}
        self.arp_table = {}
        self.routing_table = {}
        self.fwd_table = {}
        self.stop_event = Event()
        self.router = PWOSPF_Router(
            sw, self.intfs[0].ip, 1, self.intfs, self.iface)

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
        self.arp_table[ip] = mac
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                                 match_fields={'next_hop_ip_addr': [ip, 32]},
                                 action_name='MyIngress.arp_table_match',
                                 action_params={'mac': mac})

    def addIPV4RouteEntry(self, ip, next_hop_ip, port):
        if ip in self.routing_table:
            return
        self.routing_table[ip] = {"next_hop": next_hop_ip, "port": port}
        self.sw.insertTableEntry(table_name='MyIngress.routing_table',
                                 match_fields={'hdr.ipv4.dstAddr': [ip, 32]},
                                 action_name='MyIngress.ipv4_route',
                                 action_params={'next_hop': next_hop_ip, 'port': port})

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
        self.send(pkt)

    def handlePkt(self, pkt):
        pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1:
            return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

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
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        self.router.join()
        super(MacLearningController, self).join(*args, **kwargs)

# class ARPManager(Thread):
#     def __init__(self, sw):
#         super(MacLearningController, self).__init__()
#         self.sw = sw
#         self.arp_table = dict()

#     def add_ARP_entry(self, ip, mac):
#         self.arp_table[ip] = mac
#         self.sw.insertTableEntry(   table_name='MyIngress.arp_table',
#                                     match_fields={'next_hop_ip_addr': ip},
#                                     action_name='MyIngress.arp_table_match',
#                                     action_params={'mac': mac}
#                                 )
