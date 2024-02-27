# Imports
import socket
import time
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# functions
def udp_send(destination_ip, destination_port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (destination_ip, destination_port))


def udp_receive(source_ip, source_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, source_port))

    while True:
        data, addr = sock.recvfrom(1024)  # 1024 buffer size
        print("received message %s" % data)


# udp_send and udp_receive are from https://wiki.python.org/moin/UdpCommunication

def aes_enc(plaintext, iv, key):
    iv = bytes.fromhex(iv)
    key = bytes.fromhex(key)
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    cipher_text = b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))).decode("utf-8")
    return cipher_text


def aes_dec(cipher_text, key, iv):
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    decoded_text = unpad(cipher.decrypt(b64decode(cipher_text)), AES.block_size).decode("utf-8")
    return decoded_text

# aes_enc and aes_dec are from Thomas Gross Week 3 Work Sheet


def dummy_time_stego():
    message = "Dummy message"
    enc_message = aes_enc(message, "123456", "banana")
    print(enc_message)
    stego_time = input("What delay in messages do you want in seconds?")
    # Dummy for now in full will send packets via udp
    print(enc_message)
    time.sleep(stego_time)
    print(enc_message)


dummy_time_stego()