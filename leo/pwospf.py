from scapy.fields import (
    ByteField,
    IntField,
    LenField,
    IPField,
    ShortField,
    LongField,
    FieldLenField,
    PacketListField,
)
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.utils import checksum

OSPF_PROTO_NUM = 0x59

TYPE_HELLO = 0x01
TYPE_LSU = 0x04


class PWOSPF(Packet):
    """
    24 bytes
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
    """

    name = "PWOSPF"

    fields_desc = [
        ByteField("version", 2),
        ByteField("type", None),
        # payload + PWOSFP header
        LenField("len", None, adjust=lambda x: x + 24),
        IPField("router_id", "0.0.0.0"),
        IntField("area_id", None),
        ShortField("cksum", None),
        ShortField("au_type", 0),
        LongField("auth", 0),
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
        if self.cksum is None:
            chksm = checksum(p[:16] + p[24:])
            p = p[:12] + chksm.to_bytes(2, "big") + p[14:]
        return p


class HELLO(Packet):
    """
    8 bytes
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Network Mask                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         HelloInt              |           padding             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    name = "HELLO"

    fields_desc = [
        IPField("netmask", None),
        ShortField("helloint", None),
        ShortField("padding", 0),
    ]


class LSA(Packet):
    """
    12 bytes
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Subnet                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Mask                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Router ID                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    name = "LSA"

    fields_desc = [
        IPField("subnet", "0.0.0.0"),
        IPField(
            "mask", "255.255.255.0"
        ),  # Assume a default mask if None is not acceptable
        IPField("router_id", "0.0.0.0"),
    ]

    def __eq__(self, other):
        if isinstance(other, LSA):
            return (self.subnet, self.mask, self.router_id) == (
                other.subnet,
                other.mask,
                other.router_id,
            )
        return False

    def __hash__(self):
        return hash((self.subnet, self.mask, self.router_id))

    def extract_padding(self, p):
        return "", p


class LSU(Packet):
    """
    8 + n * 12 bytes
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Sequence            |              TTL                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      # advertisements                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-                                                            +-+
    |                  Link state advertisements                    |
    +-                                                            +-+
    |                              ...                              |
    """

    name = "LSU"

    fields_desc = [
        ShortField("sequence", 0),
        ShortField("ttl", 32),
        FieldLenField("numLsa", None, fmt="!I", count_of="lsaList"),
        PacketListField("lsaList", None, LSA, count_from=lambda pkt: pkt.numLsa),
    ]

    def __eq__(self, other):
        if not isinstance(other, LSU):
            return False
        return (self.sequence, self.ttl, self.numLsa, tuple(self.lsaList)) == (
            other.sequence,
            other.ttl,
            other.numLsa,
            tuple(other.lsaList),
        )

    def __hash__(self):
        return hash((self.sequence, self.ttl, self.numLsa, tuple(self.lsaList)))

    def extract_padding(self, p):
        return "", p


bind_layers(IP, PWOSPF, proto=OSPF_PROTO_NUM)  # using OSPF protocol number
bind_layers(PWOSPF, HELLO, type=TYPE_HELLO)
bind_layers(PWOSPF, LSU, type=TYPE_LSU)
