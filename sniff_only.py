from scapy.all import *
import argparse
import json
import base64

# List of encodings to test
encodings = ['utf-8', 'latin-1', 'utf-16', 'utf-16le', 'utf-16be']

data_buffer = list()

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
            # print(json.dumps(decoded_payload, indent=4))
            print("rxpk has length: " + str(len(decoded_payload)))
            for i in range(len(decoded_payload)):
                raw_data = decoded_payload["rxpk"][i]["data"]
                base_64_decoded_data = base64.b64decode(raw_data).decode('utf-8')
                print(base_64_decoded_data)
                data_buffer.append(base_64_decoded_data)

        except:
            print(repr(json_payload))

    else:
        pass


if __name__ == '__main__':

    dst_port = 0
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

    dst_port = args.dst_port
    all_ports_flag = args.all_ports
    print(f"Sniffing on port: {dst_port}")

    if not all_ports_flag:
    # filter on port
        sniff(filter = f'dst port {dst_port}', prn=sniff_on_port)
    
    else:
        sniff(prn=sniff_on_port)