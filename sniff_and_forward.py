from scapy.all import *
import argparse
# import netifaces

def print_interfaces():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_addresses = addresses[netifaces.AF_INET]
            for entry in ipv4_addresses:
                ip = entry['addr']
                print(f"Interface: {interface}")
                print(f"   IP: {ip}")
                print()


# def print_payload(packet):
#     if TCP in packet:
#         payload = packet[TCP].payload
#     elif UDP in packet:
#         payload = packet[UDP].payload
        
#     payload_hexdump = hexdump(payload, dump=True)
#     print("Payload: ")
#     print(payload_hexdump.decode())

def copy_and_reroute(packet, lora_IP, new_dest_port):
    if TCP in packet:

        new_packet = packet.copy()
        new_packet.dport = int(new_dest_port)
        new_packet.sport = 5000
        del(new_packet.chksum) 
        del(new_packet[TCP].chksum) 
    

    elif UDP in packet:
        new_packet = IP(bytes(packet[IP])) 
        new_packet[IP].dst = lora_IP
        new_packet.sport = 54916
        new_packet.dport = int(new_dest_port)
        del(new_packet.chksum) 
        del(new_packet[UDP].chksum) 
        del(new_packet[IP].chksum)
    
    else: # currently only support TCP and UDP
        return None

    return new_packet


def sniff_and_filter(packet,lora_IP, lora_port):
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
        send(packet_to_send)


    elif UDP in packet:
        print(packet.summary())
        udp_packet = packet[UDP]
        payload = udp_packet.load

        # Find the starting position of the JSON content
        start_position = payload.find(b'{')

        # Extract the JSON portion
        json_payload = payload[start_position:]
        try:
        # Decode the payload as JSON
            decoded_payload = json.loads(json_payload.decode('utf-8'))
            # print(json.dumps(decoded_payload, indent=4))
            print("rxpk has length: " + str(len(decoded_payload)))
            for i in range(len(decoded_payload)):
                raw_data = decoded_payload["rxpk"][i]["data"]
                base_64_decoded_data = base64.b64decode(raw_data).decode('utf-8')
                print(base_64_decoded_data)
                data_buffer.append(base_64_decoded_data)
        except:
            print("Decode failed for: " + repr(json_payload))


        print(f"Sending to {lora_IP} : {lora_port}")
        packet_to_send = copy_and_reroute(packet, lora_IP, lora_port)
        send(packet_to_send)

    else: # ARP and more
        # print(packet.summary())  # Print summary of other packet types
        pass
    



if __name__ == '__main__':

    listen_on_port, lora_port, lora_IP = 0,0, ""
    all_ports_flag = False

    # print("A List of available interfaces: ")
    # print_interfaces()

    # print(f"Currently sniffing on interface: {conf.iface}")
    # print()
    # init parser
    parser = argparse.ArgumentParser(
                    prog='sniff_and_forward.py',
                    description='A sniff-forwarder that sniffs network traffic and forwards it to LoRa IoT if a set of security rules apply',
                    epilog='^_^')

    parser.add_argument('-sport ','--srcport', dest='src_port', action='store',
                    default = 10079,
                    help='specify the source port (Middle box) to listen on')

    parser.add_argument('-dport ','--dstport', dest='dst_port', action='store',
                default = 17000,
                help='specify the destination (LoRa) port to forward to')

    parser.add_argument('-dip ','--dstIP', dest='dst_IP', action='store',
                default = "192.168.1.100",
                help='specify the destination (LoRa) IP  to forward to')

    parser.add_argument('-a','--all', dest='all_ports', action='store_true',
                    default = False,
                    help='Listen on all ports')
            

    args = parser.parse_args()

    all_ports_flag = args.all_ports
    listen_on_port = args.src_port
    lora_port = args.dst_port
    lora_IP = args.dst_IP
    # end parsing



    # sniff for UL traffic

   
    if not all_ports_flag: # filter on port
        print(f"Listening on port: {listen_on_port}, dst port: {lora_port}, dst ip: {lora_IP}")
        sniff(filter = f'dst port {listen_on_port}', prn=lambda pkt: sniff_and_filter(pkt, lora_IP, lora_port))
    
    else: #sniff all traffic
        sniff(prn=lambda pkt: sniff_and_filter(pkt, lora_IP, lora_port))

