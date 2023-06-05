from scapy.all import *
import time
import argparse

def copy_and_reroute(packet, new_dest_port):
    if TCP in packet:

        new_packet = packet.copy()
        new_packet.dport = new_dest_port
        new_packet.sport = get_self_port

    elif UDP in packet:
        new_packet = packet.copy()
        new_packet.dport = new_dest_port
    
    else: # currently only support TCP and UDP
        return None

    return new_packet


def sniffer_and_filter(packet,lora_IP, lora_port):
    # print(packet)
    if TCP in packet:
        if IP in packet:
            src_IP = packet[IP].src 
            dst_IP = packet[IP].dst
        elif IPv6 in packet:
            src_IP = packet[IPv6].src 
            dst_IP = packet[IPv6].dst
            
        src_port = packet[TCP].sport 
        dst_port = packet[TCP].dport 
        data = packet[TCP].payload
        print("Source IP: {} | Destination IP: {}".format(str(src_IP), str(dst_IP)))
        print("Source Port: {} | Destination port: {}".format(str(src_port), str(dst_port)))
        print(packet)  # Print TCP packet summary


        # inspect packet content for security


        # send here
        packet_to_send = copy_and_reroute(packet, lora_port)
        packet_to_send[IP].dst = lora_IP
        send(packet_to_send)

    # let's say we focus on TCP packets for now.

    elif UDP in packet:
        pass
        # print(packet.summary())  # Print UDP packet summary

    else: # ARP and more
        # print(packet.summary())  # Print summary of other packet types
        pass
    



if __name__ == '__main__':

    source_port, lora_port, lora_ip = 0,0, ""

    # init parser
    parser = argparse.ArgumentParser(
                    prog='sniff_and_forward.py',
                    description='A sniff-forwarder that sniffs network traffic and forwards it to LoRa IoT if a set of security rules apply',
                    epilog='^_^')

    parser.add_argument('-sport ','--srcport', dest='src_port', action='store',
                    default = 79,
                    help='specify the source port (Middle box) to listen on')

    parser.add_argument('-dport ','--dstport', dest='dst_port', action='store',
                default = 1700,
                help='specify the destination (LoRa) port to forward to')

    parser.add_argument('-dip ','--dstIP', dest='dst_IP', action='store',
                default = "192.168.1.100",
                help='specify the destination (LoRa) IP  to forward to')

    args = parser.parse_args()

    source_port = args.src_port
    lora_port = args.dst_port
    lora_ip = args.dst_IP
    # end parsing


    print(f"src port: {source_port}, dst port: {lora_port}, dst ip: {lora_ip}")

    # sniff for UL traffic

    # filter on port
    sniff(filter = f'src port {source_port}', prn=lambda pkt: sniffer_and_filter(pkt, lora_ip, lora_port))
    # sniff(prn=sniffer_and_filter)

