import ipaddress
import heapq
import re

from scapy.all import Ether, ARP  # type: ignore
from cpu_metadata import CPUMetadata
from contextlib import contextmanager


def prefix_len_to_netmask(prefix_len):
    prefix_len = int(prefix_len)
    # Ensure the prefix length is within the valid range for IPv4
    if not 0 <= prefix_len <= 32:
        raise ValueError("Prefix length must be between 0 and 32")

    # Calculate the subnet mask as an integer
    # If prefix_len is 0, mask should be 0; otherwise, it starts with prefix_len bits set to 1
    if prefix_len == 0:
        return 0
    mask = (2**prefix_len - 1) << (32 - prefix_len)
    return mask


def extract_ip_mask(full_ip):
    assert "/" in full_ip
    ip, prefix_len = full_ip.split("/")
    network_mask = prefix_len_to_netmask(prefix_len)
    return ip, network_mask


def calculate_host_id(ip_int, netmask_int):
    ip_int = int(ipaddress.ip_address(ip_int))
    netmask_int = int(ipaddress.ip_address(netmask_int))

    # Invert the netmask to isolate the host portion of the IP address
    inverted_netmask = ~netmask_int & 0xFFFFFFFF  # Ensure it stays within 32-bit limits

    # Calculate the host ID by ANDing the IP address with the inverted netmask
    host_id = ip_int & inverted_netmask

    return host_id


def calculate_subnet_id(ip_int, netmask_int):
    ip_int = int(ipaddress.ip_address(ip_int))
    netmask_int = int(ipaddress.ip_address(netmask_int))

    # Calculate the subnet ID by ANDing the IP address with the subnet mask
    subnet_id = ip_int & netmask_int

    return subnet_id


def ip_to_int(ip):
    return int(ipaddress.ip_address(ip))


def dijkstra(graph, start):
    """
    Some Reference From
    https://github.com/ryanmcdermott/algorithms/blob/master/djikstra/djikstra.py
    """
    distances = {node: float("inf") for node in graph}
    distances[start] = 0
    predecessors = {node: None for node in graph}
    pq = [(0, start)]

    while pq:
        current_distance, current_node = heapq.heappop(pq)

        # Check if the current node is still in the graph (avoiding failures)
        if current_node not in graph:
            continue

        if current_distance > distances[current_node]:
            continue

        for neighbor, weight in graph.get(current_node, []):
            distance = current_distance + weight
            if distance < distances[neighbor]:
                distances[neighbor] = distance
                predecessors[neighbor] = current_node
                heapq.heappush(pq, (distance, neighbor))

    return distances, predecessors


def reconstruct_path(predecessors, start, end):
    path = []
    step = end
    while step != start:
        if step is None:
            return []  # If step is None, there's no path to start
        path.append(step)
        step = predecessors[step]
    path.append(start)
    # print(path)
    return path[::-1][1:]


def get_trailing_number(s):
    match = re.search(r"\d+$", s)
    return int(match.group()) if match else None


# def hash_arp_packet(pkt):
#     # Extract layers and compute a composite hash
#     layers = []
#     layers.append(HashableEther(pkt[Ether]))
#     # layers.append(pkt[CPUMetadata])
#     layers.append(HashableARP(pkt[ARP]))
#     # Compute a hash of the tuple of all layers
#     return hash(tuple(layers))


# def hash_arp_packet(pkt):
#     # Print packet for debugging
#     print("hashing")
#     pkt.show2()

#     layers = []

#     # Check for Ether layer and process it
#     if Ether in pkt:
#         ether_layer = pkt[Ether]
#         ether_layer.show2()  # To confirm the layer is correct
#         # Create a HashableEther instance by copying the Ether layer
#         hashable_ether = HashableEther(raw(ether_layer))
#         hashable_ether.show2()
#         layers.append(hashable_ether)

#     # Check for ARP layer and process it
#     if ARP in pkt:
#         arp_layer = pkt[ARP]
#         hashable_arp = HashableARP(
#             psrc=arp_layer.psrc,
#             pdst=arp_layer.pdst,
#             hwsrc=arp_layer.hwsrc,
#             hwdst=arp_layer.hwdst,
#             ptype=arp_layer.ptype,
#             op=arp_layer.op,
#         )
#         layers.append(hashable_arp)

#     # Compute a hash of the tuple of all layers
#     return hash(tuple(layers))


def longest_prefix_match(ip_address, routing_table):
    max_prefix = 0
    best_match = None

    for ip, (_, next_hop_port) in routing_table.items():
        # TODO: Optimize Later
        print("origin: ", ip)
        ip = ip_to_int(ip)
        # Determine the number of matching prefix bits
        for i in range(32, -1, -1):
            mask = (0xFFFFFFFF << (32 - i)) & 0xFFFFFFFF  # Mask for the first i bits
            if (ip_address & mask) == (ip & mask):
                if i > max_prefix:
                    max_prefix = i
                    best_match = ip
                break

    return best_match, next_hop_port


@contextmanager
def locking(lock):
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


import socket
import struct


def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def checksum(data):
    """Creates the ICMP checksum as in RFC 1071

    :param data: Data to calculate the checksum ofs
    :type data: bytes
    :return: Calculated checksum
    :rtype: int

    Divides the data in 16-bits chunks, then make their 1's complement sum"""
    subtotal = 0
    for i in range(0, len(data) - 1, 2):
        subtotal += (data[i] << 8) + data[i + 1]  # Sum 16 bits chunks together
    if len(data) % 2:  # If length is odd
        subtotal += (
            data[len(data) - 1] << 8
        )  # Sum the last byte plus one empty byte of padding
    while subtotal >> 16:  # Add carry on the right until fits in 16 bits
        subtotal = (subtotal & 0xFFFF) + (subtotal >> 16)
    check = ~subtotal  # Performs the one complement
    return ((check << 8) & 0xFF00) | ((check >> 8) & 0x00FF)  # Swap bytes
