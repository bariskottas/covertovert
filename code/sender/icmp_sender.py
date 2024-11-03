from scapy.all import IP, ICMP, send

ip = IP()
ip.ttl = 1
ip.dst = "receiver"
icmp = ICMP()
packet = ip/icmp
send(packet)