import struct
from copy import deepcopy

from scapy.fields import ByteField, ByteEnumField, LenField, IPField, \
    XShortField, ShortField, LongField, PadField, FieldLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP, DestIPField
from scapy.layers.l2 import Ether
from scapy.utils import checksum


class PWOSPF_Header(Packet):
    '''
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version #   |     Type      |         Packet length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Router ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Area ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |             Autype            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Authentication                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    name = "PWOSPF header"

    fields_desc = [
        ByteField('version', 2),
        ByteField('type', None),
        LenField('len', None, adjust=lambda x: x+24), # payload + PWOSFP header
        IPField('routerid', '0.0.0.0'),
        IPField('areaid', None),
        ShortField('checksum', None),
        ShortField('autype', 0),
        LongField('authentication', 0)
    ]

    def post_build(self, p, pay):
        # calculate checksum, see https://scapy.readthedocs.io/en/latest/build_dissect.html#handling-default-values-post-build
        # The standard IP checksum of the entire contents of the packet,
        # excluding the 64-bit authentication field.  This checksum is
        # calculated as the 16-bit one's complement of the one's complement
        # sum of all the 16-bit words in the packet, excepting the
        # authentication field.  If the packet's length is not an integral
        # number of 16-bit words, the packet is padded with a byte of zero
        # before checksumming.
        # 0-16: PWOSPF header (12-14: checksum); 16-24: authentication; 24-: payload
        p += pay
        if self.checksum is None:
            chksm = checksum(p[:16]+p[24:])
            p = p[:12] + chksm.to_bytes(2, 'big') + p[14:]
        return p

class PWOSPF_Hello(Packet):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Network Mask                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         HelloInt              |           padding             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    name = "PWOSPF Hello"

    fields_desc = [
        IPField('netmask', None),
        ShortField('helloint', None),
        ShortField('padding', 0)
    ]

class PWOSPF_LSA(Packet):
    """
    12 bytes
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Subnet                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Mask                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Router ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    name = "PWOSPF LSA"

    fields_desc = [
        IPField('subnet', '0.0.0.0'),
        IPField('mask', None),
        IPField('routerid', '0.0.0.0')
    ]

    def extract_padding(self, p):
        return '', p

class PWOSPF_LSU(Packet):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Version #   |       4       |         Packet length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Router ID                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Area ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |             Autype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Authentication                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Sequence                |          TTL                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      # advertisements                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-                                                            +-+
    |                  Link state advertisements                    |
    +-                                                            +-+
    |                              ...                              |
    """
    name = "PWOSPF LSU"

    fields_desc = [
        ShortField('sequence', 0),
        ShortField('ttl', 32),
        FieldLenField('numlsa', None, fmt='!I', count_of='lsalist'),
        PacketListField('lsaList', None, PWOSPF_LSA,
                        count_from=lambda pkt: pkt.numlsa,
                        length_from=lambda pkt: 12 * pkt.lsacount)
    ]

    def extract_padding(self, p):
        return '', p

bind_layers(IP, PWOSPF_Header, proto=89) # using OSPF protocol number
bind_layers(PWOSPF_Header, PWOSPF_Hello, type=1)
bind_layers(PWOSPF_Header, PWOSPF_LSU, type=4)
