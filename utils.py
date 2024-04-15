def prefix_len_to_mask(prefix_len):
    """Convert a prefix length (CIDR notation) to a subnet mask."""
    # Start with a mask of 0 bits
    mask = 0
    
    # Set 'prefix_len' number of bits to 1 (from left to right)
    for i in range(prefix_len):
        mask = mask | (1 << (31 - i))
    
    # Convert the integer mask into a dotted-decimal format
    return "{0}.{1}.{2}.{3}".format((mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF)