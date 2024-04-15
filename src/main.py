# Imports
import getpass
from scapy.all import *
from scapy.layers.inet import IP, TCP
from sys import executable
if os.name == 'nt':
    from subprocess import Popen, CREATE_NEW_CONSOLE
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

# Global Variables
passwordDict = {}  # Dictionary to Store User Account Information in
stego = False


# functions
def clear_line():  # clears the line of the terminal on any OS
    os.system('cls' if os.name == 'nt' else 'clear')
    # https://discuss.codecademy.com/t/how-to-clear-the-screen-in-command-line-mode-on-python/403250


def sha256_hash(text_to_hash):  # Function to hash text
    return sha256(text_to_hash.encode("utf-8")).hexdigest()


def init_admin():  # Function to initialise the admin details (temporary)
    hashed_pw = sha256_hash("ADMIN")
    passwordDict['ADMIN'] = hashed_pw


def login():  # Login function, allows user to be authenticated to use the program
    login_attempts = 0
    getpass.GetPassWarning()
    username = input("Enter your username: ")
    for i in passwordDict.keys():
        if username == i:
            print("Hello ", username)
            hashed_pw = sha256_hash(getpass.getpass("Enter your Password : "))
            for j in passwordDict.keys():
                if username == j:
                    while hashed_pw != passwordDict.get(j):
                        if login_attempts == 4:
                            exit("Too many attempts closing program")
                        else:
                            login_attempts += 1
                            hashed_pw = sha256_hash(getpass.getpass("Incorrect Password, Please try again : "))
                    break
            print("Login Successful")
            user_menu()
        else:
            clear_line()
            print("Username not found!")
            login_menu()


def tcp_send(message, host):
    enc_message = aes_enc(message, b'hgfedcba87654321', b'00112233445566778899aabbccddeeff')
    port = 4001  # The port used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((host, port))
        s.sendall(enc_message.encode("utf-8"))
    s.close()


def tcp_send_forever(message, host):
    while True:
        time.sleep(1)
        tcp_send(message, host)


def tcp_receive(host):
    print(f"Server set up at {host}")
    port = 4001  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                data = decode_from_bytes(data)
                if len(data) == 0:
                    break
                else:
                    data = aes_dec(data, b'hgfedcba87654321', b'00112233445566778899aabbccddeeff')
                    print(decode_from_bytes(data))
    # https://realpython.com/python-sockets/#background


def tcp_receive_single(host):
    tcp_receive(host)
    time.sleep(5)


def tcp_receive_forever(host):
    while True:
        tcp_receive(host)


def data_print(data):
    print(decode_from_bytes(data))
    print("Message received Returning to menu in 10 seconds")
    time.sleep(10)


def decode_from_bytes(data):
    return data.decode().strip()


def aes_enc(plaintext, iv, key):  # Function implementing aes-128 encryption in Chain Block Cipher Mode
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    cipher_text = b64encode(cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size)))
    return decode_from_bytes(cipher_text)


def aes_dec(cipher_text, iv, key):  # Function implementing aes-128 decryption in Chain Block Cipher Mode
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    decoded_text = unpad(cipher.decrypt(b64decode(cipher_text)), AES.block_size)
    return decoded_text
    # aes_enc and aes_dec are from Thomas Gross Week 3 Work Sheet


def integer_validation(message):  # Function to validate if the user has entered an integer
    while True:
        try:
            user_input = int(input(message))
        except ValueError:
            print("stego key must be an integer")
            continue
        else:
            return user_input
    # How to make sure the user enters a number (integer) - www.101computing.net


def dummy_time_stego(host):  # function implementing time based steganography with dummy packets
    message = "Dummy message"
    stego_time_key = integer_validation("What delay in messages do you want in seconds?")
    tcp_send(message, host)
    print("Message 1 sent successfully")
    time.sleep(int(stego_time_key))
    tcp_send(message, host)
    print("Message 2 sent successfully")
    print("Program Complete returning to main menu in 5 seconds")
    time.sleep(5)
    user_menu()


def receive_time_stego_message():
    global stego
    stego = True
    host = find_user_ip()
    print("Waiting to receive stego message")
    tcp_receive(host)
    time1 = time.perf_counter()
    tcp_receive(host)
    time2 = time.perf_counter()
    print(f"The stego message received was {time2 - time1:0.4f}")
    print("Program will return to main menu in 10 seconds")
    stego = False
    time.sleep(10)


def packet_handler(packet):
    while True:
        if IP in packet and TCP in packet:
            content = packet[TCP].payload
            if len(content) == 0:
                break
            else:
                print(bytes(content))
                break


def net_info():  # Function to get network info
    ip = find_user_ip()
    clear_line()
    print("IP address is: ", ip)
    print("Program will return to main menu in 10 seconds")
    time.sleep(10)


def create_user():  # Function for new user creation
    getpass.GetPassWarning()
    print("This account will only be kept while the program is running.")  # Temporary
    username = input("Enter a username: ")
    pw = getpass.getpass("Enter your password: ")
    pw2 = getpass.getpass("Enter your password again: ")
    if pw == pw2:
        hashed_pw = sha256_hash(pw)
        passwordDict[username] = hashed_pw
        clear_line()
        print("Account Successfully Created!")
        login_menu()
    else:
        clear_line()
        print("Passwords did not match please start again")
        create_user()


def login_menu():  # Function for the login menu
    while True:
        print("Welcome to the stego-time chat client login.")
        print("Press 1 to login")
        print("Press 2 if you are a new user")
        print("Press 3 to exit")
        x = int(input())
        if x == 1:
            clear_line()
            login()
        if x == 2:
            clear_line()
            create_user()
        if x == 3:
            clear_line()
            exit("User Closed the Program")
        else:
            clear_line()
            print("Invalid Input Returning to menu in 5 seconds")
            time.sleep(5)
            login_menu()


def user_menu():  # Function for the user menu
    while True:
        clear_line()
        print("Press 1 for Network information")
        print("Press 2 to send a message via TCP")
        print("Press 3 to receive a message via TCP")
        print("Press 4 to send stego message with dummy packets")
        print("Press 5 to receive stego message")
        print("Press 6 to for Packet Information")
        print("Press 7 to Log Out")
        print("Press 8 to close the program")

        x = int(input())
        if x == 1:
            clear_line()
            net_info()
        if x == 2:
            clear_line()
            host = input("Destination IP Address ")
            message = input("What is your message? ")
            tcp_send(message, host)
        if x == 3:
            clear_line()
            host = find_user_ip()
            tcp_receive_single(host)
        if x == 4:
            clear_line()
            host = input("Destination IP Address ")
            dummy_time_stego(host)
        if x == 5:
            clear_line()
            receive_time_stego_message()
        if x == 6:
            sniff(prn=packet_handler, count=10)
        if x == 7:
            clear_line()
            login_menu()
        if x == 8:
            clear_line()
            exit("User Closed the Program")
        else:
            clear_line()
            print("Invalid Input Returning to menu in 5 seconds")
            time.sleep(5)
            user_menu()


def find_user_ip():
    if os.name == 'nt':
        print("This program cannot get your windows IP automatically.")
        print("Please select it from the information below:")
        os.system("ipconfig")
        return input("IP you wish to use: ")
    else:
        ip_addr = subprocess.check_output("hostname -I", shell=True)
        return decode_from_bytes(ip_addr)


def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
    # https://pynative.com/python-generate-random-string/#h-how-to-create-a-random-string-in-python


def new_console(script):
    if os.name == 'nt':
        Popen([executable, script], creationflags=CREATE_NEW_CONSOLE)  # Windows
        # https://stackoverflow.com/questions/6469655/how-can-i-spawn-new-shells-to-run-python-scripts-from-a-base-python-script
    else:  # Linux
        subprocess.call(['gnome-terminal', '-e', f'python3 {script}'])


# main program here
def main():
    new_console('auto-message-receive.py')
    init_admin()  # Initialise Admin Credentials for Login (temporary)
    new_console('auto-message-gen.py')
    login_menu()  # Run Login Function


if __name__ == "__main__":
    main()
