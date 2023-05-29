import scapy.all as scapy
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6
from defines import *

def reroute_tcp(packet: scapy.Packet, new_dest_port):
    tcp_packet = packet.copy()
    tcp_packet.dport = new_dest_port
    tcp_packet.sport = get_self_port()
    return tcp_packet
