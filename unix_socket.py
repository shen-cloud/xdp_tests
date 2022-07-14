#!/usr/bin/python3

import socket
import sys
import os
import time

filename = '/tmp/container1/uds'

fd = os.open("host.txt", os.O_RDONLY)
print(f" opened file with fd {fd}")

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

sock.bind(filename)
print(f"made a socket at {filename} with fd number {sock.fileno()}")

sock.listen(1)

connection, client_address = sock.accept()
print(f"got a connection from {client_address}")

socket.send_fds(connection, [b'foo'], [fd])

time.sleep(100)

