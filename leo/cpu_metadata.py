from scapy.fields import BitField, ByteField, ShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080A


class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        ByteField("fromCpu", 0),
        ShortField("origEtherType", None),
        ShortField("srcPort", None),
        ShortField("dstPort", None),
    ]

    def __hash__(self):
        # Include all fields that define the packet's identity for hashing
        return hash((self.fromCpu, self.origEtherType, self.srcPort, self.dstPort))

    def __eq__(self, other):
        if isinstance(other, CPUMetadata):
            return (
                self.fromCpu == other.fromCpu
                and self.origEtherType == other.origEtherType
                and self.srcPort == other.srcPort
                and self.dstPort == other.dstPort
            )
        return False


bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
