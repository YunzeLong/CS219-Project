import argparse
import json
import socket
import decode
import base64
import random
import send_mail

broken_devices = set()


def first_responder(packet: bytes):
    # TODO: respond to the foul join request here
    sender = "lora.cs219@gmail.com"
    sender_pswd = "rnppboitedgdxgbk"
    receiver = "lora.cs219@gmail.com"
    send_mail.send_mail(sender, sender_pswd, receiver)
    


def examine_packet(packet: bytes) -> bool:
    # look for json start point
    start_position = packet.find(b"{")
    json_payload = packet[start_position:]

    # chain of conditions: isJson -> isJoinReq -> isLeaked
    try:
        json_payload = json.loads(json_payload.decode("utf-8"))
        if "rxpk" not in json_payload:
            return False

        for rxpk_field in json_payload["rxpk"]:
            if "data" not in rxpk_field:
                continue

            raw_data = rxpk_field["data"]
            decoded_data = base64.b64decode(raw_data)
            if not decode.filter_join_req(decoded_data):
                continue
            
            print('[join-request]')
            
            dev_eui = decode.extract_dev_eui(decoded_data)
            if dev_eui in broken_devices:
                print(f'[known-leaked-device] {dev_eui.hex()}')
                return True

            if decode.key_collision_check(decoded_data):
                broken_devices.add(dev_eui)
                print(f'[new-leaked-device] {dev_eui.hex()}')
                first_responder(decoded_data)
                return True
    except:
        return False
    finally:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="socket_forwarder.py",
        description="A simple sniffer on port specified",
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
        "-ca",
        "--cloud-address",
        dest="cld_domain",
        action="store",
        default="symrec.nam1.cloud.thethings.industries",
        help="IP address of this middle box.",
    )

    parser.add_argument(
        "-cp",
        "--cloud-port",
        dest="cld_port",
        action="store",
        type=int,
        default=1700,
        help="Port this middle box is listening to",
    )

    args = parser.parse_args()
    UDP_IP = args.dst_ip
    UDP_PORT = args.dst_port

    CLOUD_IP = socket.gethostbyname(args.cld_domain)
    CLOUD_PORT = args.cld_port

    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet  # UDP
    recv_socket.bind((UDP_IP, UDP_PORT))

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 

    while True:
        payload, addr = recv_socket.recvfrom(1024)  # buffer size is 1024 bytes
        print(f'begin packet: {addr}')
        print(payload)

        if (examine_packet(payload)): # type: ignore
            print('[skipped]')
        else:
            send_socket.sendto(payload, (CLOUD_IP, CLOUD_PORT))
            send_socket.close()
            print('[forwarded]')
        print('end packet')
