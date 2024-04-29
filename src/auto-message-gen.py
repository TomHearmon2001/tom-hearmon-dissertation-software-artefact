# Import
import random
import time
from main import tcp_send, get_random_string


# Variables
packet_loss_rate = 0.1
delay = 0
delay_likelyhood = 0.1


def update_delay(delay):
    delay = random.uniform(0.1, 0.2)  # Randomly choose a delay between 100ms and 200ms
    delay = round(delay, 1)  # Remove additional float values past 1 decimal place
    return delay


# main
destination = input("Enter destination for automatic messages: ")
while True:
    try:
        update_delay(delay)  # Run function to update delay
        delay_chance = random.uniform(0, 1)  # Chance of delay occurring
        delay_chance = round(delay_chance, 1)
        packet_loss_chance = random.uniform(0, 1)  # Chance of packet loss occurring
        packet_loss_chance = round(packet_loss_chance, 1)
        message = get_random_string(random.randint(5, 10))  # Generate random string
        if packet_loss_chance == packet_loss_rate:
            print("packet lost!")
        elif delay_chance == delay_likelyhood:
            time.sleep(delay)
            tcp_send(message, destination)  # Send random message
            time.sleep(1)
        else:
            tcp_send(message, destination)  # Send random message
            time.sleep(1)
    except Exception as e:
        print(e)  # Print error if occurs
        time.sleep(20)
