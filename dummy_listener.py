import socket

if __name__ == "__main__":
    UDP_IP = "127.0.0.1"
    UDP_PORT = 9910

    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet  # UDP
    recv_socket.bind((UDP_IP, UDP_PORT))

    while True:
        payload, addr = recv_socket.recvfrom(1024)  # buffer size is 1024 bytes
        print(f'begin packet: {addr}')
        print(payload)
        print('end packet')
