# Imports
from main import tcp_receive_forever, find_user_ip

# main
host = find_user_ip()
while True:
    tcp_receive_forever(host)
