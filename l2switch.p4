/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<8> TYPE_PWOSPF        = 0x59;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
// 5 bytes
header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}
// 28 bytes
header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ipv4Addr_t srcIP;
    macAddr_t dstEth;
    ipv4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header pwospf_t {
    bit<8>  version;
    bit<8>  type;
    bit<16> length_;
    bit<32> routerID;
    bit<32> areaID;
    bit<16> checksum;
    bit<16> auType;
    bit<64> authentication;
}

header hello_t {
    ipv4Addr_t netMask;
    bit<16>   helloint;
    bit<16>   padding;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    pwospf_t          pwospf;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_pwospf {
        packet.extract(hdr.pwospf);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_PWOSPF: parse_pwospf;
            default: accept;
        }
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    ipv4Addr_t next_hop_ip_addr = 32w0;
    port_t dstPort = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        // if (hdr.cpu_metadata.dstPort != 0){
        //     set_egr((bit<9>) hdr.cpu_metadata.dstPort);
        // }
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_route(ipv4Addr_t next_hop, port_t port) {
        standard_metadata.egress_spec = port;
        next_hop_ip_addr = next_hop;
    }

    action ipv4_fwd(macAddr_t mac, port_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac;
        standard_metadata.egress_spec = port;
    }

    action arp_table_match(macAddr_t mac) {
        hdr.ethernet.dstAddr = mac;
    }

    // locate the next-hop IP address and port based on IP dest addr
    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_route;
            ipv4_fwd;
            drop;
            send_to_cpu;
            NoAction;
        }
        size = 1024;
        default_action = send_to_cpu();
    }
    // find the mac addr based on next-hop addr
    table arp_table {
        key = {
            next_hop_ip_addr: lpm;
        }
        actions = {
            arp_table_match;
            send_to_cpu;
            drop;
            NoAction;
        }   
        size = 64;
        default_action = NoAction;
    }

    // forward any packets with matching ip addr to CPU
    table local_ip_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
            drop;
        }
        size = 64;
        default_action = NoAction;
    }

    // set the outgoing port and multicast based on ethernet dst addr
    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    apply {

        if (standard_metadata.ingress_port == CPU_PORT){
            cpu_meta_decap();
        }

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
            return;
        }
        else if (hdr.ipv4.isValid() && !hdr.pwospf.isValid()) {
            if (hdr.ipv4.ttl < 1) {
                drop();
                // ICMP timeout
            } else {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            }
            
            // if it is destined for cpu, forward to cpu
            local_ip_table.apply();
            if(hdr.cpu_metadata.isValid()){
                return;
            }

            // attempts to find next-hop ip and port
            routing_table.apply();
            arp_table.apply();
            return;
        }
        if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { 
         update_checksum(
            hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                  hdr.ipv4.ihl,
                  hdr.ipv4.tos,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
                  hdr.ipv4.hdrChecksum,
                  HashAlgorithm.csum16);
     }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.pwospf);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
