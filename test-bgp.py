#!/usr/bin/python

import testttl
import sys
import random
import socket
import struct

# TODO: don't read through a 385k line file only to pull out 100 random lines
hosts = [] 
# For each network, pick a random host in it
for line in sys.stdin.readlines():
    # parse 1.2.3.0/24 into prefix (0x01020304) and netmask (0xffffff00)
    prefix_str, prefix_len = line.split('/')
    prefix, = struct.unpack('!I', socket.inet_aton(prefix_str))
    netmask = ~(2**(32 - int(prefix_len)) - 1)

    # pick a random host
    rand_host = socket.inet_ntoa(struct.pack('!I', 
                    prefix | (~netmask & random.randint(0, 0xffffffff))))

    # add it to our list
    hosts.append(rand_host)

    #print '%s -> %s' % (line[0:-1], socket.inet_ntoa(rand_host))
    
    

# pick 100 hosts at random, and traceroute them to get their payload lengths
for i in range(0, 100):
    index = random.randint(0, len(hosts)) 

    print '-----'
    print '%s' % hosts[index]
    hops = testttl.test_dest(hosts[index])
    
    testttl.print_hops(hops)
