#!/usr/bin/python

import testttl
import sys
import random

hosts = [] 
for ip in sys.stdin.readlines():
    network = [int(c) for c in ip[0:ip.index('/')].split('.')]
    network[3] += 1
    host = '.'.join([str(c) for c in network])
    hosts.append(host)
    
    

for i in range(0, 100):
    index = random.randint(0, len(hosts)) 

    print '-----'
    print '%s' % hosts[index]
    hops = testttl.test_dest(hosts[index])

    testttl.print_hops(hops)
