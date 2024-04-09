-- Define the custom and ARP protocols
local p_cpu_metadata = Proto("CPU_Metadata", "CPU Metadata Protocol")
local ethertype_arp = 0x0806 -- EtherType for ARP
local ethertype_cpu_metadata = 0x080a

-- Define the fields in the custom header
local f_fromCpu = ProtoField.uint8("cpu_metadata.fromCpu", "From CPU", base.HEX)
local f_origEtherType = ProtoField.uint16("cpu_metadata.origEtherType", "Original EtherType", base.HEX)
local f_srcPort = ProtoField.uint16("cpu_metadata.srcPort", "Source Port", base.DEC)

p_cpu_metadata.fields = {f_fromCpu, f_origEtherType, f_srcPort}

-- Dissector function for CPU Metadata
function p_cpu_metadata.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = p_cpu_metadata.name
    local subtree = tree:add(p_cpu_metadata, buffer(), "CPU Metadata Header")

    subtree:add(f_fromCpu, buffer(0,1))
    local origEtherTypeField = subtree:add(f_origEtherType, buffer(1,2))
    subtree:add(f_srcPort, buffer(3,2))

    local origEtherType = buffer(1,2):uint()

    -- Depending on the original EtherType, call appropriate dissector
    if origEtherType == ethertype_arp then
        -- Call the ARP dissector for the rest of the packet
        local arp_dissector = Dissector.get("arp")
        if arp_dissector then
            arp_dissector:call(buffer(5):tvb(), pinfo, tree)
        end
    end
    -- If origEtherType is not ARP, we do not further dissect the packet here.
end

-- Register the protocol dissector to Ethernet type.
-- Replace 0xXXXX with the actual EtherType value your custom protocol uses.
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(ethertype_cpu_metadata, p_cpu_metadata)


