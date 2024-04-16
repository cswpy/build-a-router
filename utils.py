import heapq
from collections import defaultdict, namedtuple

LSA_tuple = namedtuple('LSA_tuple', ['subnet', 'mask', 'neighbor_rid'])

def get_ip_addr(intf_name):
    sw_num = int(intf_name[1:].split("-")[0])
    intf_num = int(intf_name.split("eth")[-1])
    assert sw_num >= 0 and sw_num <= 255, "Invalid switch number"
    assert intf_num >= 0 and intf_num <= 255, "Invalid interface number"
    ip_addr = "10.0.{}.{}".format(sw_num, intf_num)
    return ip_addr

def get_subnet(ip_addr, mask):
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
    '''djikstra algorithm to find shortest path and then find the next hop for each node, weightes are omitted'''
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
                heapq.heappush(pq, (new_dist, neighbor))

    next_hop ={}

    for node in parent:
        curr = node
        while curr in parent:
            prev = curr
            curr = parent[curr]
        next_hop[node] = prev
    return next_hop

graph = {
            'U': ['V', 'W', 'X'],
            'V': ['U', 'X', 'W'],
            'W': ['V', 'U', 'X', 'Y', 'Z'],
            'X': ['U', 'V', 'W', 'Y'],
            'Y': ['X', 'W', 'Z'],
            'Z': ['W', 'Y'],
        }

print(find_next_hop(graph, 'U'))