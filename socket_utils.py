import random
import socket


def get_randomized_socket(ip) -> socket:
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    success = False
    while not success:
        try:
            rand_int = random.randint(49152, 65536)
            send_socket.bind((ip, rand_int))
            success = True
        except:
            success = False
    return send_socket
