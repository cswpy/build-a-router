/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* typedefs for data structures */
typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

/* Protocol Related Constants */
const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_RESERVED     = 0xffff;

const bit<8> OSPF_PROTO_NUM = 0x59;
const ip4Addr_t ALLSPFROUTERS_ADDR = 0xe0000005;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> ARP_HWTYPE_ETHER  = 0x0001;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
header ethernet_t {
    macAddr_t dst_mac;
    // ARP: ff:ff:ff:ff:ff:ff - broadcast
    macAddr_t src_mac;
    // ARP: requester's MAC
    bit<16>   ether_type;
    // ARP: TYPE_ARP
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}

header arp_t {
    // assumes hardware type is ethernet and protocol is IP
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // ARP_OP_REQ           |           ARP_OP_REPLY
    macAddr_t sender_mac;
    // requestor's mac      |           target's mac
    ip4Addr_t sender_ip;
    // requestor's ip       |           target's ip
    macAddr_t target_mac;
    // 00:00:00:00:00:00    |           requestor's mac
    ip4Addr_t target_ip;
    // target's ip          |           requestor's ip
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t src_ip;
    ip4Addr_t dst_ip;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t          ethernet;
    cpu_metadata_t      cpu_metadata;
    arp_t               arp;
    ipv4_t              ipv4;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    // todo 
    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }    
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {
	verify_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_ip,
              hdr.ipv4.dst_ip },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bool ipv4_route_hit = false;
    ip4Addr_t next_hop_ip = (bit<32>) 0;
    bool both_tables_miss = false;
    bool unfinished = false;
    bool unfinished_pwospf = false;
    port_t e_port = (bit<9>) 0;
    ip4Addr_t ip_to_match = (bit<32>) 0;

    counter(64, CounterType.packets) ip_counter;
    counter(64, CounterType.packets) arp_counter;
    counter(64, CounterType.packets) cpu_counter;
    counter(64, CounterType.packets) dummy_counter;
    counter(64, CounterType.packets) error_counter;

    /* provided actions */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    // cpu meta data manipulations
    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.ether_type;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.dstPort = (bit<16>) 0;
        hdr.ethernet.ether_type = TYPE_CPU_METADATA;
    }
    action cpu_meta_decap() {
        hdr.ethernet.ether_type = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }
    action send_to_cpu() {
        cpu_counter.count((bit<32>) 1);
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    /* new actions */
    // taking care of all incoming arp packets that are destined to me
    // action handle_arps(macAddr_t src_mac, port_t egress_port) {
    //     /* arp request case, and it is destined to the current router */
    //     if (hdr.arp.opcode == ARP_OP_REQ) {
    //         // send the packet back to sender
    //         hdr.ethernet.dst_mac = hdr.ethernet.src_mac;
    //         // fill in the src addr as my mac
    //         hdr.ethernet.src_mac = src_mac;
    //         // output port
    //         standard_metadata.egress_spec = standard_metadata.ingress_port;

    //         // change this to reply
    //         /*
    //             don't set this for discerning which is a request
    //             hdr.arp.opcode = ARP_OP_REPLY;
    //         */
    //         hdr.arp.target_mac = hdr.arp.sender_mac;
    //         hdr.arp.sender_mac = src_mac;
    //         ip4Addr_t temp = hdr.arp.target_ip;
    //         hdr.arp.target_ip = hdr.arp.sender_ip;
    //         hdr.arp.sender_ip = temp; // target_ip
    //     }
    //     // else handled outside, since not do-able in here
    //         /* arp reply case, forwarded to cpu */
    //         /* or this is a malformed/wrong request */
    //         // send_to_cpu();
    // }

    table fwd_l2 {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    action arp_lookup(macAddr_t dst_mac) {
        hdr.ethernet.dst_mac = dst_mac;
    }

    table arp_table {
        key = {
            next_hop_ip: exact;
        }
        actions = {
            arp_lookup;
            NoAction;
        }

        size = 1024;
        default_action = NoAction;
    }
    
    // action ipv4_forward(macAddr_t dst_mac) {
    //     // dst_mac being the next-hop address
    //     // port being the egress port
    //     hdr.ethernet.dst_mac = dst_mac;
    // }

    action ipv4_route(ip4Addr_t dst_ip, port_t egress_port) {
        next_hop_ip = dst_ip;
        standard_metadata.egress_spec = egress_port;
        ipv4_route_hit = true;
    }


    /* required tables */
    // forwarding rules installed by the control-plane pwospf routing table
    table routing_table {
        key = {
            ip_to_match: lpm;
        }
        actions = {
            // ipv4_forward;
            ipv4_route;
            NoAction; // construct icmp unreachable there?
        }
        size = 1024;
        // if not found, want to forward to cpu
        default_action = NoAction;
    }

    // static forwarding table
    table static_routing_table {
        key = {
            ip_to_match: lpm;
        }
        actions = {
            // ipv4_forward;
            ipv4_route;
            NoAction;
        }
        size = 1024;
        // if not found, want to go to the pwospf_forwarding_table
        // this is first queried because the high-priority comes with static configuration
        default_action = NoAction;
    }

    

    // for handling ip request dedicated for self router (all there needed is to forward to CPU), the CPU then have all the information
    // the slow path
    table local_ips {
        key = {
            hdr.ipv4.dst_ip: exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    action get_interface_mac(macAddr_t interface_mac) {
        hdr.ethernet.src_mac = interface_mac;
    }

    table port_to_interface_mac {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            get_interface_mac;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    apply {
        if (!hdr.cpu_metadata.isValid()) {
            if (hdr.arp.isValid()) {
                arp_counter.count((bit<32>) 1);
                // all incoming arp sent to cpu for caching
                send_to_cpu();
                return;
            }
            if (hdr.ipv4.isValid()) {
                ip_counter.count((bit<32>) 1);
                if (hdr.ipv4.protocol == OSPF_PROTO_NUM) {
                    // all incoming ospf packets go to cpu
                    send_to_cpu();
                    return;
                }
            }
        }


        if (hdr.cpu_metadata.isValid() && 
                hdr.ipv4.isValid() && 
                hdr.ipv4.protocol == OSPF_PROTO_NUM) {
            // all ospf packets from cpu go out directly
            e_port = (bit<9>) hdr.cpu_metadata.dstPort;
            set_egr(e_port);
            cpu_meta_decap();
            return;
        }


        if (hdr.arp.isValid() && hdr.arp.opcode == ARP_OP_REQ) {
            // must have valid cpu_meta_data
            // would have set the source correctly
            e_port = (bit<9>) hdr.cpu_metadata.dstPort;
            // if (e_port == (bit<9>) 511) {
            //     set_mgid((bit<16>) 1);
            // } else {
            //     if (e_port == (bit<9>) 0) {
            //         error_counter.count((bit<32>) 1);
            //     }
            //     set_egr(e_port);
            // }
            cpu_meta_decap();
            set_egr(e_port);
            return;
        }

        if (hdr.arp.isValid() && hdr.arp.opcode == ARP_OP_REPLY) {
            e_port = (bit<9>) hdr.cpu_metadata.dstPort;
            cpu_meta_decap();
            set_egr(e_port);
            return;
        }

        dummy_counter.count((bit<32>) 1);
        
        // arp handling should be done here

        if (hdr.cpu_metadata.isValid()) {
            cpu_meta_decap();
        }
        
        // e_port = (bit<9>)hdr.cpu_metadata.dstPort;
        //         cpu_meta_decap();
        //         set_egr(e_port);
        //         return;
        
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.checksum_error == 1) {
                drop();
                return;
            }
            // to me
            if (local_ips.apply().hit) {
                return;
            }
            if (hdr.ipv4.ttl == 1) {
                drop();
                return;
            }

            ip_to_match = hdr.ipv4.dst_ip;

            if (!static_routing_table.apply().hit) {
                if (!routing_table.apply().hit) {
                    next_hop_ip = hdr.ipv4.dst_ip;
                }
                // if (!routing_table.apply().hit) {
                //     // no hit, go to cpu
                //     send_to_cpu();
                //     return;
                // }
                // now the next_hop ip is stored in next_hop_ip
            }

            if (!arp_table.apply().hit) {
                send_to_cpu();
                return;
            }

            fwd_l2.apply();

            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

            return;
        }

        send_to_cpu();
        return;
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
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_ip,
              hdr.ipv4.dst_ip },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
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
