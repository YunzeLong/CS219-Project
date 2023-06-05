from scapy.all import *
import argparse


def sniff_on_port(packet):
    print(packet.summary())


if __name__ == '__main__':

    source_port = 0
    all_ports_flag = False

    # init parser
    parser = argparse.ArgumentParser(
                    prog='sniffonly.py',
                    description='A simple sniffer on port specified',
                    epilog='^_^')

    parser.add_argument('-p','--port', dest='src_port', action='store',
                    default = 79,
                    help='Specify the source port (Middle box) to listen on')

    parser.add_argument('-a','--all', dest='all_ports', action='store_true',
                    default = False,
                    help='Listen on all ports')


    args = parser.parse_args()

    source_port = args.src_port
    all_ports_flag = args.all_ports
    print(f"Sniffing on src port: {source_port}")

    if not all_ports_flag:
    # filter on port
        sniff(filter = f'src port {source_port}', prn=sniff_on_port)
    
    else:
        sniff(prn=sniff_on_port)