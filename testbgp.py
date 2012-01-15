#!/usr/bin/python

import testttl
import sys
import random
import socket
import struct

'''
Input: "1.2.3.0/24"
Output: "1.2.3.87"
'''
def get_random_host_in_network(network):
    # parse 1.2.3.0/24 into prefix (0x01020304) and netmask (0xffffff00)
    prefix_str, prefix_len = network.split('/')
    prefix, = struct.unpack('!I', socket.inet_aton(prefix_str))
    netmask = ~(2**(32 - int(prefix_len)) - 1)

    # pick a random host
    return socket.inet_ntoa(struct.pack('!I', 
                    prefix | (~netmask & random.randint(0, 0xffffffff))))

def get_hops(prefixes_file=sys.stdin, num_routers=5):
    hosts = [] 
    # For each network, pick a random host in it
    lines = prefixes_file.readlines()
    best_hops = {}
    while len(best_hops.keys()) < num_routers:
    
        index = random.randint(0, len(lines))
         
        rand_host = get_random_host_in_network(lines[index])
     
        hops = testttl.test_dest(rand_host) 
    
        print '-----'
        print '%s' % rand_host
        testttl.print_hops(hops)
        
        payload_len_hop, payload_len = testttl.get_max_payload_len(hops)
        if (payload_len >= 64):
            best_hops[(rand_host, payload_len_hop)] = payload_len
    
    #print '-----'
    #print 'Using:'    
    using_hops = []
    for host, hop in best_hops.keys():
        real_mtu = testttl.confirm_max_mtu(host, hop)
        if real_mtu > 64:
            using_hops.append( (host, hop, real_mtu) )
    return using_hops



if __name__ == "__main__":
    for host, hop, real_mtu in get_hops():
        print '%s hop %d (MTU %d)' % (host, hop, real_mtu)
