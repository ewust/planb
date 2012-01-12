#!/usr/bin/python

# iptables -N planb
# iptables -A planb -d 5.5.5.5 -j NFQUEUE --queue-num 1
# iptables -A OUTPUT -j planb

from netfilterqueue import NetfilterQueue
import socket
import dpkt
import dnet
import time
import random

RELAY = socket.inet_aton('68.40.51.184')
PROXY = socket.inet_aton('141.212.109.239')
MTU = 496 # must be divisible by 8

out = dnet.ip()

def print_and_accept(pkt):
    bytes = pkt.get_payload()
    print pkt, len(bytes)

    inner_ip_hdr = dpkt.ip.IP(bytes) # us -> proxy
                                     # (outer will be "proxy" -> relay)
    payload_bytes = str(inner_ip_hdr.data)
    
    # IP ( UDP ( real_IP(...) ) ) 
    # if fragments, also send
    # IP ( UDP ( real_IP_frag1(...) ) ) 
    # IP ( UDP ( real_IP_frag2(...) ) ) .. etc
    for pos in range(0,len(payload_bytes), MTU):
        
        # make an inner ip fragment
        frag = payload_bytes[pos:pos+MTU]
        cur_inner_ip_hdr = dpkt.ip.IP(str(inner_ip_hdr))
        cur_inner_ip_hdr.sum = 0
        cur_inner_ip_hdr.data = frag
        cur_inner_ip_hdr.off = pos/8
        if pos+len(frag) < len(payload_bytes):
            cur_inner_ip_hdr.off |= dpkt.ip.IP_MF

        udp = dpkt.udp.UDP(sport=random.randint(0, 0xffff), dport=random.randint(1000,2000), data=str(cur_inner_ip_hdr))
        udp.ulen += len(udp.data)
        p = dpkt.ip.IP(src=PROXY, dst=RELAY, p=0x11, data=udp)
        p.len += len(p.data)
        pkt_out = str(p)
        print "sending %d bytes..." % len(pkt_out)
        #time.sleep(0.5)
        print out.send(pkt_out)

    pkt.drop()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
