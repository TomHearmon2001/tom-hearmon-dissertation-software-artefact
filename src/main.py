# Imports
import os
import getpass
import socket
import time
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

# Global Variables
passwordDict = {}   # Dictionary to Store User Account Information in


# functions
def sha256_hash(text_to_hash):  # Function to hash text
    return sha256(text_to_hash.encode('utf-8')).hexdigest()


def init_admin():   # Function to initialise the admin details (temporary)
    hashed_pw = sha256_hash("ADMIN")
    passwordDict['ADMIN'] = hashed_pw


def login():    # Login function, allows user to be authenticated to use the program
    getpass.GetPassWarning()
    username = input("Enter your username: ")
    print("Hello ", username)
    hashed_pw = sha256_hash(getpass.getpass("Enter your Password : "))
    for i in passwordDict.keys():
        if username == i:
            while hashed_pw != passwordDict.get(i):
                hashed_pw = sha256_hash(getpass.getpass("Incorrect Password, Please try again : "))
            break
    print("Login Successful")
    user_menu()


def udp_send(destination_ip, destination_port, message):    # Function to create and send udp packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (destination_ip, destination_port))


def udp_receive(source_ip, source_port):    # Function to receive and read udp packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, source_port))

    while True:
        data, addr = sock.recvfrom(1024)  # 1024 buffer size
        print("received message %s" % data)
# udp_send and udp_receive are from https://wiki.python.org/moin/UdpCommunication


def aes_enc(plaintext, iv, key):    # Function implementing aes-128 encryption in Chain Block Cipher Mode
    iv = bytes.fromhex(iv)
    key = bytes.fromhex(key)
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    cipher_text = b64encode(cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))).decode("utf-8")
    return cipher_text


def aes_dec(cipher_text, key, iv):  # Function implementing aes-128 decryption in Chain Block Cipher Mode
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    decoded_text = unpad(cipher.decrypt(b64decode(cipher_text)), AES.block_size).decode("utf-8")
    return decoded_text
# aes_enc and aes_dec are from Thomas Gross Week 3 Work Sheet


def integer_validation(message):    # Function to validate if the user has entered an integer
    while True:
        try:
            user_input = int(input(message))
        except ValueError:
            print("stego key must be an integer")
            continue
        else:
            return user_input


# How to make sure the user enters a number (integer) - www.101computing.net


def dummy_time_stego():    # function implementing time based steganography with dummy packets
    message = "Dummy message"
    enc_message = aes_enc(message, "ffeeddccbbaa99887766554433221100", "00112233445566778899aabbccddeeff")
    print(enc_message)
    stego_time_key = integer_validation("What delay in messages do you want in seconds?")
    # Dummy for now in full will send packets via udp
    print("dummy packet 1 sent")
    time.sleep(int(stego_time_key))
    print("dummy packet 2 sent")
    print("Program Complete returning to main menu in 5 seconds")
    time.sleep(5)
    user_menu()


def login_menu():   # Function for the login menu
    while True:
        os.system('cls')
        print("Welcome to the stegotime chat client menu.")
        print("Press 1 to Log In")
        print("Press 2 if you are a new user")
        print("Press 3 to exit")
        x = int(input())
        if x == 1:
            os.system('cls')
            login()
        elif x == 2:
            os.system('cls')
            print("Nothing Here Yet!")
        elif x == 3:
            os.system('cls')
            exit("User Closed the Program")


def user_menu():    # Function for the user menu
    while True:
        os.system('cls')
        print("Press 1 for dummy time stego")
        print("Press 2 to Log Out")
        print("Press 3 to close the program")

        x = int(input())
        if x == 1:
            os.system('cls')
            dummy_time_stego()
        if x == 2:
            os.system('cls')
            login_menu()
        if x == 3:
            os.system('cls')
            exit("User Closed the Program")


# main program here
def main():
    init_admin()    # Initialise Admin Credentials for Login (temporary)
    login_menu()    # Run Login Function


if __name__ == "__main__":
    main()
