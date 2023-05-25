from scapy.all import *
import time
import argparse


def sniffer_and_filter(packet):
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



    # let's say we focus on TCP packets for now.

    elif UDP in packet:
        pass
        # print(packet.summary())  # Print UDP packet summary

    else: # ARP and more
        # print(packet.summary())  # Print summary of other packet types
        pass
    



if __name__ == '__main__':

    source_port, destination_port, destination_ip = 0,0, ""

    # init parser
    parser = argparse.ArgumentParser(
                    prog='sniff_and_forward.py',
                    description='A sniff-forwarder that sniffs network traffic and forwards it to LoRa IoT if a set of security rules apply',
                    epilog='^_^')

    parser.add_argument('-sport ','--srcport', dest='src_port', action='store',
                    default = 79,
                    help='specify the source port to listen on')

    parser.add_argument('-dport ','--dstport', dest='dst_port', action='store',
                default = 1700,
                help='specify the destination port to forward to')

    parser.add_argument('-dip ','--dstIP', dest='dst_IP', action='store',
                default = "192.168.1.100",
                help='specify the destination IP to forward to')

    args = parser.parse_args()

    source_port = args.src_port
    destination_port = args.dst_port
    destination_ip = args.dst_IP
    # end parsing


    print(f"src port: {source_port}, dst port: {destination_port}, dst ip: {destination_ip}")

    # sniff for UL traffic

    # filter on port
    sniff(filter = f'src port {source_port}', prn=sniffer_and_filter)
    # sniff(prn=sniffer_and_filter)

