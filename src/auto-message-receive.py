# Imports
import time
from main import tcp_receive, find_user_ip

# main
host = find_user_ip()  # Find current devices ip
while True:
    try:
        tcp_receive(host)  # Open sever for messages
    except Exception as e:
        print(e)  # Print error if occurs
        time.sleep(20)
