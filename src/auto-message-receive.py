# Imports
import time
from main import tcp_receive_forever, find_user_ip

# main
host = find_user_ip()
while True:
    try:
        tcp_receive_forever(host)
    except Exception as e:
        print(e)
        time.sleep(20)
