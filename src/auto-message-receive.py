# Imports
import time
from main import tcp_receive, find_user_ip

# main
host = find_user_ip()
while True:
    try:
        tcp_receive(host)
    except Exception as e:
        print(e)
        time.sleep(20)
