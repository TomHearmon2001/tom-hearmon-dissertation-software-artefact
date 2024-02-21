##Imports
import socket


#functions
def udp_send(destination_ip, destination_port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (destination_ip, destination_port))

def udp_receive(source_ip, source_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, source_port))

    while True:
        data, addr = sock.recvfrom(1024) #1024 buffer size
        print("received message %s" % data)

## udp_send and udp receive are from https://wiki.python.org/moin/UdpCommunication