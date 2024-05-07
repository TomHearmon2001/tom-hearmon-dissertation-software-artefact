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
addition = ""
num_non_stego = 0


# functions
def clear_line():  # clears the line of the terminal on any OS
    os.system('cls' if os.name == 'nt' else 'clear')
    # https://discuss.codecademy.com/t/how-to-clear-the-screen-in-command-line-mode-on-python/403250


def sha256_hash(text_to_hash):  # Function to hash text with sha256
    return sha256(text_to_hash.encode("utf-8")).hexdigest()


def init_admin():  # Function to initialise the admin details
    hashed_pw = sha256_hash("ADMIN")
    passwordDict['ADMIN'] = hashed_pw


def login():  # Login function, allows user to be authenticated to use the program
    login_attempts = 0
    getpass.GetPassWarning()  # Warns user if password will not be hidden
    username = input("Enter your username: ")
    for i in passwordDict.keys():
        if username == i:  # Check username is in dictionary
            print("Hello ", username)
            hashed_pw = sha256_hash(getpass.getpass("Enter your Password : "))
            for j in passwordDict.keys():  # Check password is in dictionary and relates to inputted username
                if username == j:
                    while hashed_pw != passwordDict.get(j):
                        if login_attempts == 4:  # To many attempts closing program
                            exit("Too many attempts closing program")
                        else:
                            login_attempts += 1  # Add attempt
                            hashed_pw = sha256_hash(getpass.getpass("Incorrect Password, Please try again : "))
                    break
            print("Login Successful")
            user_menu()  # Move to user menu
        else:
            clear_line()
            print("Username not found!")
            login_menu()  # Reset login progress


def tcp_send(message, host):
    enc_message = aes_enc(message, b'hgfedcba87654321', b'00112233445566778899aabbccddeeff')  # Call encryption
    port = 4001  # The port used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Open socket to send message
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Close socket immediately after use
        s.connect((host, port))  # Make connection
        s.sendall(enc_message.encode("utf-8"))  # Send message
    s.close()  # Close socket


def tcp_receive(host):
    print("Server set up at {0}".format(host))
    port = 4001  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # Close socket immediately after use
        s.bind((host, port))
        s.listen()  # Listen for incoming traffic
        conn, addr = s.accept()  # Accept connection
        with conn:
            print("Connected by {0}".format(addr))
            while True:
                data = conn.recv(1024)
                data = decode_from_bytes(data)  # Decode data to string
                if len(data) == 0:  # Discard packets where payload has a length of 0
                    break
                else:
                    stego_receive(data)  # Check for stego messages
                    data = aes_dec(data, b'hgfedcba87654321', b'00112233445566778899aabbccddeeff') # Decrypt message
                    print(decode_from_bytes(data))
    # https://realpython.com/python-sockets/#background


def decode_from_bytes(data):
    return data.decode().strip()  # Decode from bytes and remove null bits from end


def aes_enc(plaintext, iv, key):  # Function implementing aes-128 encryption in Chain Block Cipher Mode
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)  # Generate Cipher
    cipher_text = b64encode(cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size)))  # Encryption process
    return decode_from_bytes(cipher_text)


def aes_dec(cipher_text, iv, key):  # Function implementing aes-128 decryption in Chain Block Cipher Mode
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)  # Generate Cipher
    decoded_text = unpad(cipher.decrypt(b64decode(cipher_text)), AES.block_size)  # Decryption Process
    return decoded_text
    # aes_enc and aes_dec are from Thomas Gross Week 3 Work Sheet


def integer_validation(message):  # Function to validate if the user has entered an integer
    while True:
        try:
            user_input = int(input(message))  # Check input is integer
        except ValueError:
            print("stego key must be an integer")
            continue
        else:
            return user_input
    # How to make sure the user enters a number (integer) - www.101computing.net


def dummy_time_stego(host):  # function implementing time based steganography with dummy packets
    message = "Dummy message"
    stego_time_key = integer_validation("What delay in messages do you want in seconds?")  # Get requested delay
    tcp_send(message, host)  # Send message 1
    print("Message 1 sent successfully")
    time.sleep(int(stego_time_key))  # Wait for amount of time as per stego key
    tcp_send(message, host)  # Send message 2
    print("Message 2 sent successfully")
    print("Program Complete returning to main menu in 5 seconds")
    time.sleep(5)
    user_menu()  # Return to user menu


def receive_time_stego_message():
    host = find_user_ip()  # Get IP of current device
    print("Waiting to receive stego message")
    tcp_receive(host)  # Receive first message
    time1 = time.perf_counter()  # Take time after first message
    tcp_receive(host)  # Receive second message
    time2 = time.perf_counter()  # Take time after second message
    print(f"The stego message received was {time2 - time1:0.4f}")  # Calculate difference between two times to generate stego time message
    print("Program will return to main menu in 10 seconds")
    time.sleep(10)


def packet_handler(packet):
    global addition  # Import the addition from outside the function scope
    while True:
        if IP in packet and TCP in packet:  # Check packet is valid
            content = packet[TCP].payload  # Extract payload
            if len(content) == 0:  # Remove 0 length packets to avoid error
                break
            else:
                content = bytes(content)  # extract message
                content_string = decode_from_bytes(content)  # Convert content to string
                content_string = f"{content_string}{addition}"  # Add stenographic symbol
                content = bytes(content_string, "utf-8")  # Re-encode into bytes
                packet[TCP].remove_payload()  # Remove old payload
                packet[TCP].set_payload(content)  # Add new payload
                sendp(packet)  # Resend packet with manipulated packet
                break


def check(x):  # Function to check that user input was a binary message
    b = set(x)  # Turn into set so includes no repeats
    s = {'0', '1'}  # Ground truth to check against
    if s == b or b == {'0'} or b == {'1'}:  # Check input set against ground truth set
        return  # Ok return to parent function
    else:
        print("Invalid Input! Returning to User Menu")  # Error Invalid
        time.sleep(2)
        user_menu()
# https://www.studytonight.com/python-programs/python-program-to-check-if-a-given-string-is-a-binary-string-or-not


def secret_stego(bin_in):
    global addition  # Import addition from outside
    stego_list = []
    check(bin_in)  # Check input is binary
    bin_list = [int(d) for d in str(bin_in)]
    for i in range(0, len(bin_list)):
        if bin_list[i] == 0: # If entry is a 0
            for j in range(0, 4):
                stego_list.append("-")  # Add four - for redundancy
        elif bin_list[i] == 1:  # If entry is a 1
            for j in range(0, 4):
                stego_list.append("+")  # Add four + for redundancy
        else:
            print("Error in input Array")  # Error catching
            time.sleep(2)
            user_menu()
    for j in range(0, len(stego_list)):  # For each item in the stego list do:
        addition = stego_list[j]  # set addition to the stego
        sniff(prn=packet_handler)  # Use scapy sniff function in addition with my packet handler function


def stego_receive(payload):
    global num_non_stego  # Import number of non stego messages received
    N = 1
    last_char = ''
    stego_message = []  # Empty list for stego message
    while N > 0:
        last_char = payload[-N]  # Select last character of message
        N = N - 1
    if last_char == '+' or last_char == '-':  # filter out packets that don't have stegonagraphic sysmbol in the payload
        num_non_stego = 0
        if last_char == '+':  # add 1 to message if + is present
            stego_message.append("1")
        elif last_char == '-':  # add 0 to message if - is present
            stego_message.append("0")
    else:
        num_non_stego += 1  # Implement number of non stego messages
        if num_non_stego > 5:
            print(stego_message)  # Print stego message once no more occur
        return


def net_info():  # Function to get network info
    ip = find_user_ip()  # Find current device ip
    clear_line()
    print("IP address is: ", ip)
    print("Program will return to main menu in 10 seconds")
    time.sleep(10)


def create_user():  # Function for new user creation
    getpass.GetPassWarning()  # Warn user if the password will not be hidden
    print("This account will only be kept while the program is running.")
    username = input("Enter a username: ")
    pw = getpass.getpass("Enter your password: ")  # hidden password input
    pw2 = getpass.getpass("Enter your password again: ")  # hidden password input
    if pw == pw2:  # if passwords match
        hashed_pw = sha256_hash(pw)  # hash password
        passwordDict[username] = hashed_pw  # add to password dictionary
        clear_line()
        print("Account Successfully Created!")
        login_menu()  # open login menu
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
        if x == 1:  # if input == 1 go to login function
            clear_line()
            login()
        if x == 2:  # if input == 2 go to create user function
            clear_line()
            create_user()
        if x == 3:  # if input == 3 close program
            clear_line()
            exit("User Closed the Program")
        else:
            clear_line()
            print("Invalid Input Returning to menu in 5 seconds")  # Invalid input catching
            time.sleep(5)
            login_menu()


def user_menu():  # Function for the user menu
    while True:
        clear_line()
        print("Press 1 for network information")
        print("Press 2 to send a message via TCP")
        print("Press 3 to receive a message via TCP")
        print("Press 4 to send time based steganography message")
        print("Press 5 to receive time based steganography message")
        print("Press 6 to to send a stegonagraphic message via packet manipulation")
        print("Press 7 to log out")
        print("Press 8 to close the program")

        x = int(input())
        if x == 1:  # if input == 1 run network information function
            clear_line()
            net_info()
        if x == 2:  # if input == 2 send a message via TCP
            clear_line()
            host = input("Destination IP Address ")
            message = input("What is your message? ")
            tcp_send(message, host)
        if x == 3:  # if input == 3 receive a message via tcp
            clear_line()
            host = find_user_ip()
            tcp_receive(host)
        if x == 4:  # if input == 4 send a time based stegonaography message
            clear_line()
            host = input("Destination IP Address ")
            dummy_time_stego(host)
        if x == 5:  # if input == 5 open to receive time based stegonagraphic message
            clear_line()
            receive_time_stego_message()
        if x == 6:  # if input == 6 send stegonagrapic message via packet manipulation
            clear_line()
            bin_in = str(input("Enter the binary message you want to send:"))
            secret_stego(bin_in)
        if x == 7:  # if input == 7 log out
            clear_line()
            login_menu()
        if x == 8:  # if input == 8 close program
            clear_line()
            exit("User Closed the Program")
        else:
            clear_line()
            print("Invalid Input Returning to menu in 5 seconds")  # input validation
            time.sleep(5)
            user_menu()


def find_user_ip():  # function to get user ip (only automatic on linux)
    if os.name == 'nt':  # check os
        print("This program cannot get your windows IP automatically.")
        print("Please select it from the information below:")
        os.system("ipconfig")  # can print info but needs user to input ip
        return input("IP you wish to use: ")
    else:
        ip_addr = subprocess.check_output("hostname -I", shell=True) # auto get ip with linux
        return decode_from_bytes(ip_addr)


def get_random_string(length):  # code for generating random string
    # choose from all lowercase letter
    letters = string.ascii_lowercase  # only lowercase ascii characters
    result_str = ''.join(random.choice(letters) for i in range(length))  # join together to create string
    return result_str
    # https://pynative.com/python-generate-random-string/#h-how-to-create-a-random-string-in-python


def new_console(script):  # code for opening new terminal
    if os.name == 'nt':  # check os is windows
        Popen([executable, script], creationflags=CREATE_NEW_CONSOLE)  # Windows
        # https://stackoverflow.com/questions/6469655/how-can-i-spawn-new-shells-to-run-python-scripts-from-a-base-python-script
    else:  # else os is linux
        subprocess.call(['gnome-terminal', '-e', 'python3 {0}'.format(script)])  # Linux


def print_stego_dino():
    print((r"""

                                      .       .
                                     / `.   .' \
                             .---.  <    > <    >  .---.
                             |    \  \ - ~ ~ - /  /    |
                              ~-..-~             ~-..-~
                          \~~~\.'                    `./~~~/
                           \__/                        \__/
                            /                  .-    .  \
                     _._ _.-    .-~ ~-.       /       }   \/~~~/
                 _.-'q  }~     /       }     {        ;    \__/
                {'__,  /      (       /      {       /      `. ,~~|   .     .
                 `''''='~~-.__(      /_      |      /- _      `..-'   \\   //
                             / \   =/  ~~--~~{    ./|    ~-.     `-..__\\_//_.-'
                            {   \  +\         \  =\ (        ~ - . _ _ _..---~
                            |  | {   }         \   \_\
                           '---.o___,'       .o___,'

                 """))
    print("Credit: https://ascii.co.uk/art/dinos")


# main program here
def main():
    while True:
        print("Welcome to the stego-time chat client setup.")
        print("Press 1 to run with Automatic message generation")
        print("Press 2 if run without automatic message generation")
        print("Press 3 to exit")
        x = int(input())
        if x == 1:  # if input == 1 run with automatic message generation
            clear_line()
            new_console('auto-message-receive.py')  # Open terminal for auto message receive
            init_admin()  # Initialise Admin Credentials for Login
            new_console('auto-message-gen.py')  # Open terminal for auto message send
            print_stego_dino()
            login_menu()  # Run Login Function
        if x == 2:  # if input == 2 go to create user function
            clear_line()
            init_admin()  # Initialise Admin Credentials for Login
            print_stego_dino()
            login_menu()  # Run Login Function
        if x == 3:  # if input == 3 close program
            clear_line()
            exit("User Closed the Program")
        else:
            clear_line()
            print("Invalid Input Returning to menu in 5 seconds")  # Invalid input catching
            time.sleep(5)
            login_menu()


if __name__ == "__main__":
    main()
