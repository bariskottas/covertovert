from scapy.all import sniff, ICMP, IP

def recv_packet(packet):
    if packet.haslayer(ICMP):
        if packet[IP].ttl==1:
            packet.show()
            exit(0)

#sniff(prn=recv_packet)