#!/usr/bin/python

# iptables -N planb
# iptables -A planb -d 5.5.5.5 -j NFQUEUE --queue-num 1
# iptables -A OUTPUT -j planb

#from netfilterqueue import NetfilterQueue
import socket
import dpkt
import dnet
import time
import random
import sys
import select

RELAY = socket.inet_aton('68.40.51.184')
PROXY = socket.inet_aton('141.212.109.239')
MTU = 496 # must be divisible by 8
IFACE = "eth0"

out = dnet.ip()

routers = None
router_index = None

'''
Returns a (dest, ttl_hop, mtu) tuple that we know to be a 
router that will support TTL exceeded
'''
def get_router():
    global routers, router_index
    if routers == None:
        print 'Initializing routers...'
        import testbgp
        f = open("bgp-prefixes", "r")
        routers = testbgp.get_hops(f, 2)
        f.close()
        print 'Done, using:'
        for host, hop, real_mtu in routers:
            print '  %s hop %d (MTU %d)' % (host, hop, real_mtu)
        router_index = -1
    router_index += 1
    router_index %= len(routers)
    return routers[router_index]

'''
Given a payload (such as an IP (fragment) packet) that you'd LIKE to send 
(but can't because its blocked), this will wrap your payload in a IP/UDP
packet and send it toward your specified router. 

It is the CALLERS responsibility to make sure they have the right MTU
for this router
'''
def send_out_payload(payload, dest, hop):
    udp = dpkt.udp.UDP(sport=random.randint(0, 0xffff), dport=random.randint(0,0xffff), 
                    data=str(payload))
    udp.ulen += len(udp.data)

    p = dpkt.ip.IP(src=PROXY, dst=dest, ttl=hop, p=0x11, data=udp)
    p.len += len(p.data)
    pkt_out = str(p)
    #print "sending %d bytes" % len(pkt_out
    out.send(pkt_out)



def handle_pkt(bytes):
    #print pkt, len(bytes)

    inner_ip_hdr = dpkt.ip.IP(bytes) # us -> proxy
                                     # (outer will be "proxy" -> relay)
    payload_bytes = str(inner_ip_hdr.data)
    
    # choose a router per packet, because if one router is down, then
    # only a few packets don't get through, rather than always a fragment
    # for each packet (i.e. no packets get through)
    host, hop, mtu = get_router()

    mtu -= 20 # for IP header?
    mtu -= 4 # still has to be divisible by 8!!

    # construct a packet like:
    # IP ( UDP ( real_IP(...) ) ) 
    # if fragments, send:
    # IP ( UDP ( real_IP_frag1(...) ) ) 
    # IP ( UDP ( real_IP_frag2(...) ) ) .. etc
    for pos in range(0,len(payload_bytes), mtu):
        
        # make an inner ip fragment
        frag = payload_bytes[pos:pos+mtu]
        cur_inner_ip_hdr = dpkt.ip.IP(str(inner_ip_hdr))
        cur_inner_ip_hdr.sum = 0
        cur_inner_ip_hdr.data = frag
        cur_inner_ip_hdr.off = pos/8

        if pos+len(frag) < len(payload_bytes):
            cur_inner_ip_hdr.off |= dpkt.ip.IP_MF

        send_out_payload(cur_inner_ip_hdr, socket.inet_aton(host), hop)



if __name__ == "__main__":

    if len(sys.argv) != 2:
        print 'Usage:'
        print
        print '%s blocked_ip' % sys.argv[0]
        sys.exit(1)

    blocked_dest = sys.argv[1]
    my_real_addr = socket.gethostbyname_ex(socket.gethostname())[2][0]
    my_addr = "10.78.0.2"

    get_router() 
    
    tun = dnet.tun(dnet.addr(my_addr), dnet.addr(blocked_dest))

    raw_sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    raw_sock.bind((IFACE, 0x0003))
    
    
    try:
        while 1:
            ready_list,_,_ = select.select([tun, raw_sock], [], [])
            for sock in ready_list:
                if sock == raw_sock:
                    # forward packet to tun device if from the proxy 
                    e = dpkt.ethernet.Ethernet(raw_sock.recv(0xffff))
                    if isinstance(e.data, dpkt.ip.IP):
                        if e.data.src == socket.inet_aton(blocked_dest) and \
                           e.data.dst == socket.inet_aton(my_real_addr):
                            e.data.dst = socket.inet_aton(my_addr)
                            e.data.sum = 0
                            if (e.data.p == 0x11 or e.data.p == 0x06):
                                e.data.data.sum = 0

                            # you would think this is tun.send, but it's not! sigh, linux
                            out.send(str(e.data))
                     
                elif sock == tun:
                    pkt = dpkt.ip.IP(tun.recv())
                    pkt.src = socket.inet_aton(my_real_addr)
                    if pkt.p == 0x11 or pkt.p == 0x07:
                        pkt.sum = 0
                        pkt.data.sum = 0
                    
                    handle_pkt(str(pkt))
    
    except KeyboardInterrupt:
        print
