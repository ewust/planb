#!/usr/bin/python


import dpkt
import dnet
import socket
import time
import sys

SRC_IP = socket.gethostbyname_ex(socket.gethostname())[2][0]
TIMEOUT = 1.2 #seconds
MIN_TTL = 1
MAX_TTL = 20
icmp_sock = None


def get_icmp_sock(timeout=TIMEOUT):
    global icmp_sock
    if icmp_sock == None:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        icmp_sock.settimeout(timeout)
    elif icmp_sock.gettimeout() != timeout:
        icmp_sock.settimeout(timeout)
    return icmp_sock

def test_dest(dest, min_ttl=MIN_TTL, src_ip=SRC_IP):
    icmp_sock = get_icmp_sock()
    
    ip = dnet.ip()
    
    for ttl in range(min_ttl, MAX_TTL):
        udp = dpkt.udp.UDP(sport=ttl, dport=2222)
        udp.data = "pkt %d " % ttl
        udp.data += 'A'*250
        udp.ulen += len(udp.data)
        pkt = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dest), ttl=ttl, id=ttl, p=0x11)
        pkt.data = udp 
        pkt.len += len(str(pkt.data))
        ip.send(str(pkt))
        time.sleep(.001)
        
    
    timeout = time.time() + TIMEOUT  # give a few seconds for all routers to respond
    
    hops = {}

    while time.time() < timeout:
        try:
            data, addr = icmp_sock.recvfrom(1508)
        except socket.timeout:
            return hops
         
        ip_pkt = dpkt.ip.IP(data) 
        icmp_pkt = ip_pkt.data
        inner_ip_pkt = icmp_pkt.data.data
        payload_data = inner_ip_pkt.data
        #print '%s (hop %d) sent %d bytes' % (addr[0], inner_ip_pkt.id, len(payload_data))
        hops[payload_data.sport] = (addr[0], len(payload_data))

        if (addr[0] == dest):
            return hops

    return hops
   
'''
Some destinations append garbage data to your payload - this function
attempts to confirm the actual length by sending a payload of 'AAAAAAA...'
and seeing just how many AAAA's we get back
'''
def confirm_max_mtu(host, hop, reported_payload_len=1024, src_ip=SRC_IP):
    icmp_sock = get_icmp_sock()
    
    ip = dnet.ip()
    
    udp = dpkt.udp.UDP(sport=hop, dport=2222)
    udp.data = 'A'*reported_payload_len
    udp.ulen += len(udp.data)
    pkt = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(host), ttl=hop, id=hop, p=0x11)
    pkt.data = udp 
    pkt.len += len(str(pkt.data))
    ip.send(str(pkt))

    timeout = time.time() + TIMEOUT  # give a few seconds for all routers to respond
    
    while time.time() < timeout:
        try:
            data, addr = icmp_sock.recvfrom(1508)
        except socket.timeout:
            return -1
         
        ip_pkt = dpkt.ip.IP(data) 
        icmp_pkt = ip_pkt.data
        inner_ip_pkt = icmp_pkt.data.data
        udp_pkt = inner_ip_pkt.data
        payload = udp_pkt.data
        return len(payload) - len(payload.replace('A'*8, ''))
    return -1 
    


def print_hops(hops, min_ttl=MIN_TTL):
    if len(hops.keys()) == 0:
        return 0
    for ttl in range(min_ttl, max(hops.keys())+1):
        if ttl in hops:
            addr, payload_len = hops[ttl]
        else:
            addr = '*'
            payload_len = 0
        print '% 3d  % 15s  % 4d bytes' % (ttl, addr, payload_len)

def get_max_payload_len(hops, min_ttl=MIN_TTL):
    if len(hops.keys()) == 0:
        return (0, 0, 0)

    max_payload_len = 0
    max_payload_len_ttl = 0
    for ttl in range(min_ttl, max(hops.keys())+1):
        if ttl in hops:
            addr, payload_len = hops[ttl]
            if payload_len > max_payload_len:
                max_payload_len = payload_len
                max_payload_len_ttl = ttl

    return (max_payload_len_ttl, max_payload_len)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print 'Usage'
        print ''
        print '%s dest_ip [min_ttl=1]' % (sys.argv[0])
        print '    Finds the MTUs of TTL exceeded messages for routers'
        print '    between here and dest_ip (starting at hop min_ttl)'
        sys.exit(1)
    
    min_ttl = 1
    
    if len(sys.argv) > 1:
        dest = sys.argv[1]
    
    if len(sys.argv) > 2:
        min_ttl = sys.argv[2]

    hops = test_dest(dest, min_ttl) 

    print_hops(hops, min_ttl)    
