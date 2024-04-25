import heapq
from collections import defaultdict, namedtuple

LSA_tuple = namedtuple('LSA_tuple', ['subnet', 'mask', 'neighbor_rid'])

def get_ip_from_ip_subnet(ip_subnet):
    return ip_subnet.split("/")[0]

def get_mask_from_ip_subnet(ip_subnet):
    '''turns prefix length to mask'''
    prefix_len = int(ip_subnet.split("/")[1])
    return prefix_len_to_mask(prefix_len)

def prefix_len_to_mask(prefix_len):
    '''turns prefix length to mask'''
    mask = [0, 0, 0, 0]
    for i in range(prefix_len):
        mask[i // 8] |= 1 << (7 - i % 8)
    return '.'.join(map(str, mask))

def mask_to_prefix_len(mask):
    '''turns mask to prefix length'''
    mask = mask.split(".")
    prefix_len = 0
    for i in range(4):
        byte = int(mask[i])
        while byte:
            prefix_len += byte & 1
            byte >>= 1
    return prefix_len

def calculate_subnet(ip_addr, mask):
    # assume both ip_addr and mask are strings in the form of IP addresses
    ip_addr = ip_addr.split(".")
    mask = mask.split(".")
    subnet = []
    for i in range(4):
        subnet.append(str(int(ip_addr[i]) & int(mask[i])))
    return '.'.join(subnet)

def build_graph(adjacency_list):
    '''build graph from adjacency list, only add validated edges
    @param adjacency_list: dict, rid -> (subnet, mask, neighbor_rid)
    '''
    graph = defaultdict(set)
    for rid, lsa_tuple_list in adjacency_list.items():
        # check if the link is valid in another direction
        for tuple in lsa_tuple_list:
            if tuple.neighbor_rid in adjacency_list and LSA_tuple(tuple.subnet, tuple.mask, rid) in adjacency_list[tuple.neighbor_rid]:
                graph[rid].add(tuple.neighbor_rid)
    return graph

def find_next_hop(graph, start):
    '''dijkstra algorithm to find shortest path and then find the next hop for each node, weightes are omitted'''
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    pq = [(0, start)]
    parent = {}

    while len(pq) > 0:
        distance, node = heapq.heappop(pq)

        if distance > distances[node]:
            continue

        for neighbor in graph[node]:
            new_dist = distance + 1
            if new_dist < distances[neighbor]:
                parent[neighbor] = node
                distances[neighbor] = new_dist
                heapq.heappush(pq, (new_dist, neighbor)) # type: ignore

    next_hop ={}

    for node in parent:
        curr = node
        while curr in parent:
            prev = curr
            curr = parent[curr]
        next_hop[node] = prev
    return next_hop, distances

if __name__ == "__main__":
    graph = {
                'U': ['V', 'W', 'X'],
                'V': ['U', 'X', 'W'],
                'W': ['V', 'U', 'X', 'Y', 'Z'],
                'X': ['U', 'V', 'W', 'Y'],
                'Y': ['X', 'W', 'Z'],
                'Z': ['W', 'Y'],
            }

    print(find_next_hop(graph, 'U'))