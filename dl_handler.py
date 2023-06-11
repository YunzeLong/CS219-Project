import argparse
import json
import socket
import decode
import base64
import random
import socket_utils


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="dl_handler.py",
        description="Handles DL Traffic",
        epilog="^_^",
    )

    parser.add_argument(
        "-lp",
        "--local-port",
        dest="dst_port",
        action="store",
        default=1700,
        help="Port this middle box is listening to",
    )

    parser.add_argument(
        "-la",
        "--local-address",
        dest="dst_ip",
        action="store",
        default="131.179.26.123",
        help="IP address of this middle box.",
    )

    parser.add_argument(
        "-oa",
        "--outbound-address",
        dest="bs_domain",
        action="store",
        default="",
        help="IP address of this middle box.",
    )

    parser.add_argument(
        "-op",
        "--outbound-port",
        dest="bs_port",
        action="store",
        type=int,
        default=1701,
        help="Port this middle box is listening to",
    )

    args = parser.parse_args()
    UDP_IP = args.dst_ip
    UDP_PORT = args.dst_port

    outbound_IP = socket.gethostbyname(args.bs_domain)
    outbound_PORT = args.bs_port

    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet  # UDP
    recv_socket.bind((UDP_IP, UDP_PORT))

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 

    while True:
        payload, addr = recv_socket.recvfrom(1024)  # buffer size is 1024 bytes

        try:
            send_socket = socket_utils.get_randomized_socket(outbound_IP)
            send_socket.sendto(payload, (outbound_IP, outbound_PORT))
            send_socket.close()
            print('end packet')
        except:
            print("Failed sending packet")
