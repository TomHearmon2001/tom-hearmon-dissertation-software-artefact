# Import
import random
import time
from main import tcp_send_forever, get_random_string


# main
destination = input("Enter destination for automatic messages: ")
while True:
    try:
        message = get_random_string(random.randint(5, 10))
        tcp_send_forever(message, destination)
    except Exception as e:
        print(e)
        time.sleep(20)
