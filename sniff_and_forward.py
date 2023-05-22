from scapy.all import *
import time




def sniffer_and_filter(packet):
    print(packet)
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
        # print(packet)  # Print TCP packet summary
        # time.sleep(1)


    elif UDP in packet:
        pass
        # print(packet)  # Print UDP packet summary

    else: # ARP and more
        # print(packet.summary())  # Print summary of other packet types
        pass


    





# # Usage example
if __name__ == '__main__':
    source_port = 80  # Port where the forwarder listens for incoming packets
    destination_ip = '192.168.1.100'  # IP address of the destination server
    destination_port = 80  # Port of the destination server
    
    sniff(prn=sniffer_and_filter)
