#!/usr/bin/python

# iptables -N pb_in
# iptables -A pb_in -p icmp -j NFQUEUE --queue-num 2
# iptables -A INPUT -j pb_in

from netfilterqueue import NetfilterQueue
import socket
import dpkt
import dnet

out = dnet.ip()

class PacketError(Exception):
    pass

def unnest_payload(bytes):
    ip = dpkt.ip.IP(bytes)
    if not isinstance(ip.data, dpkt.icmp.ICMP):
        raise PacketError
    icmp = ip.data
    if not isinstance(icmp.data, dpkt.icmp.ICMP.Unreach):
        raise PacketError
    unreach = icmp.data
    if not isinstance(unreach.data, dpkt.ip.IP):
        raise PacketError
    ip2 = unreach.data
    if not isinstance(ip2.data, dpkt.udp.UDP):
        raise PacketError
    udp = ip2.data
    ip3 = dpkt.ip.IP(str(udp.data))
    return ip3

def handle_packet(pkt):
    print pkt
    data = pkt.get_payload()
    print data.encode('hex')
    try:
        ip = unnest_payload(data)
        #print str(ip).encode('hex')
        print ip.__repr__()
        out.send(str(ip))
        print 'drop'
        pkt.drop()
    except PacketError:
        print 'accept'
        pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(2, handle_packet)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print
