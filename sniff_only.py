from scapy.all import *
import argparse
import json

def sniff_on_port(packet):
    if UDP in packet:
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
            print(json.dumps(decoded_payload, indent=4))

        except:
            pass
    else:
        pass


if __name__ == '__main__':

    source_port = 0
    all_ports_flag = False

    # init parser
    parser = argparse.ArgumentParser(
                    prog='sniffonly.py',
                    description='A simple sniffer on port specified',
                    epilog='^_^')

    parser.add_argument('-p','--port', dest='dst_port', action='store',
                    default = 79,
                    help='Specify the port on middle box to listen on')

    parser.add_argument('-a','--all', dest='all_ports', action='store_true',
                    default = False,
                    help='Listen on all ports')


    args = parser.parse_args()

    source_port = args.src_port
    all_ports_flag = args.all_ports
    print(f"Sniffing on port: {source_port}")

    if not all_ports_flag:
    # filter on port
        sniff(filter = f'dst port {source_port}', prn=sniff_on_port)
    
    else:
        sniff(prn=sniff_on_port)