#!/usr/bin/python

import sys
import socket
import time

UDP_PORT = 1234
MAX_MTU = 1500

if len(sys.argv) == 1:
    print 'Usage:'
    print ''
    print '%s host [port]' % (sys.argv[0])
    sys.exit(1)

host = sys.argv[1]

if len(sys.argv) > 2:
    UDP_PORT = int(sys.argv[2])

# set up icmp socket
icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)


# send a large UDP to the host
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto( 'A'*MAX_MTU, (host, UDP_PORT))


timeout = time.time() + 1.5  # you have 1.5 seconds to respond
icmp_sock.settimeout(1.5)

# see if we get an icmp message back
while time.time() < timeout:
    try:
        data, addr = icmp_sock.recvfrom(1508)
    except:
        print 'timed out'
        sys.exit(1)
    if addr[0] == host:
        try:
            start_seq = data.index('AAAAAAAA') # if we don't have at least 8 bytes, whatever
            payload_len = len(data) - start_seq
        except:
            payload_len = 0

        print 'max payload size: %d' % (payload_len)
        sys.exit(0)


