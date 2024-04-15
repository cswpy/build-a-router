-- Define the PWOSPF protocol
local p_pwospf = Proto("PWOSPF", "Pee Wee OSPF Protocol")

-- Common Header Fields
local f_version = ProtoField.uint8("pwospf.version", "Version", base.DEC)
local f_type = ProtoField.uint8("pwospf.type", "Type", base.DEC)
local f_packet_length = ProtoField.uint16("pwospf.packet_length", "Packet Length", base.DEC)
local f_router_id = ProtoField.ipv4("pwospf.router_id", "Router ID")
local f_area_id = ProtoField.ipv4("pwospf.area_id", "Area ID")
local f_checksum = ProtoField.uint16("pwospf.checksum", "Checksum", base.HEX)
local f_autype = ProtoField.uint16("pwospf.autype", "Authentication Type", base.DEC)
local f_authentication = ProtoField.uint64("pwospf.authentication", "Authentication", base.HEX)

-- Hello Packet Fields
local f_netmask = ProtoField.ipv4("pwospf.hello.netmask", "Network Mask")
local f_helloint = ProtoField.uint16("pwospf.hello.helloint", "Hello Interval", base.DEC)
local f_padding = ProtoField.uint16("pwospf.hello.padding", "Padding", base.DEC)

-- LSU Packet Fields
local f_sequence = ProtoField.uint16("pwospf.lsu.sequence", "Sequence Number", base.DEC)
local f_ttl = ProtoField.uint16("pwospf.lsu.ttl", "TTL", base.DEC)
local f_numlsa = ProtoField.uint32("pwospf.lsu.numlsa", "Number of LSAs", base.DEC)

-- LSA Fields
local f_subnet = ProtoField.ipv4("pwospf.lsu.lsa.subnet", "Subnet")
local f_mask = ProtoField.ipv4("pwospf.lsu.lsa.mask", "Mask")
local f_lsa_router_id = ProtoField.ipv4("pwospf.lsu.lsa.router_id", "Router ID")

-- Adding fields to the protocol
p_pwospf.fields = {f_version, f_type, f_packet_length, f_router_id, f_area_id, f_checksum, f_autype, f_authentication,
                   f_netmask, f_helloint, f_padding, f_sequence, f_ttl, f_numlsa, f_subnet, f_mask, f_lsa_router_id}

-- Create dissect function
function p_pwospf.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    pinfo.cols.protocol = "PWOSPF"
    local subtree = tree:add(p_pwospf, buffer(), "PWOSPF Protocol Data")
    local packet_length = buffer(2,2):uint()

    if packet_length > buffer:len() then
        pinfo.desegment_len = packet_length - buffer:len()
        pinfo.desegment_offset = 0
        return
    end

    subtree:add(f_version, buffer(0,1))
    local type = buffer(1,1):uint()
    subtree:add(f_type, buffer(1,1))
    subtree:add(f_packet_length, buffer(2,2))
    subtree:add(f_router_id, buffer(4,4))
    subtree:add(f_area_id, buffer(8,4))
    subtree:add(f_checksum, buffer(12,2))
    subtree:add(f_autype, buffer(14,2))
    subtree:add(f_authentication, buffer(16,8))

    local payload_offset = 24
    if buffer:len() > payload_offset then
        local payload_tree = subtree:add(buffer(payload_offset), "Payload")

        -- Handling different types based on type field
        if type == 1 then
            -- PWOSPF Hello packet
            pinfo.cols.info:set("PWOSPF Hello")
            subtree:add(f_netmask, buffer(payload_offset, 4))
            subtree:add(f_helloint, buffer(payload_offset + 4, 2))
            subtree:add(f_padding, buffer(payload_offset + 6, 2))
        elseif type == 4 then
            -- PWOSPF LSU packet
            pinfo.cols.info:set("PWOSPF LSU")
            subtree:add(f_sequence, buffer(payload_offset, 2))
            subtree:add(f_ttl, buffer(payload_offset + 2, 2))
            local numlsa = buffer(payload_offset + 4, 4):uint()
            subtree:add(f_numlsa, buffer(payload_offset + 4, 4))
            local lsa_offset = payload_offset + 8
            for i = 1, numlsa do
                local lsa_tree = subtree:add(p_pwospf, buffer(lsa_offset, 12), "Link State Advertisement "..i)
                lsa_tree:add(f_subnet, buffer(lsa_offset, 4))
                lsa_tree:add(f_mask, buffer(lsa_offset + 4, 4))
                lsa_tree:add(f_lsa_router_id, buffer(lsa_offset + 8, 4))
                lsa_offset = lsa_offset + 12 -- move to the next LSA
            end
        else
            pinfo.cols.info:set("Unknown PWOSPF Type")
        end
    end
end

-- Register dissector to IP protocol, using the OSPF protocol number
local ip_proto = DissectorTable.get("ip.proto")
ip_proto:add(89, p_pwospf)  -- Protocol number for OSPF
