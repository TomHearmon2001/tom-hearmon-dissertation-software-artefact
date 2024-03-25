# Import
import random
import string
from main import tcp_send


# Functions
def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
    # https://pynative.com/python-generate-random-string/#h-how-to-create-a-random-string-in-python


def auto_message_gen(dest):
    message = get_random_string(random.randint(5, 10))
    tcp_send(message, dest)


# main
destination = input("Enter destination for automatic messages: ")
while True:
    auto_message_gen(destination)


