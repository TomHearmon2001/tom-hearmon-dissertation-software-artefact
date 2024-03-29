# Import
import random
from main import tcp_send_forever, get_random_string


# main
destination = input("Enter destination for automatic messages: ")
while True:
    message = get_random_string(random.randint(5, 10))
    tcp_send_forever(message, destination)
