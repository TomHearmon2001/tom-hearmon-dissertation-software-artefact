# Import
import random
import time
from main import tcp_send, get_random_string


# Variables
packet_loss_rate = 0.1
delay = 0
delay_likelyhood = 0.1


def update_delay(delay):
    delay = random.uniform(0.1, 0.2)
    delay = round(delay, 1)
    return delay


# main
destination = input("Enter destination for automatic messages: ")
while True:
    try:
        update_delay(delay)
        delay_chance = random.uniform(0, 1)
        delay_chance = round(delay_chance, 1)
        packet_loss_chance = random.uniform(0, 1)
        packet_loss_chance = round(packet_loss_chance, 1)
        message = get_random_string(random.randint(5, 10))
        if packet_loss_chance == packet_loss_rate:
            print("packet lost!")
        elif delay_chance == delay_likelyhood:
            time.sleep(delay)
            tcp_send(message, destination)
            time.sleep(1)
        else:
            tcp_send(message, destination)
            time.sleep(1)
    except Exception as e:
        print(e)
        time.sleep(20)
