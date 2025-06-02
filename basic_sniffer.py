"""
basic_sniffer.py

A simple raw socket packet sniffer for Windows platforms.

This script captures incoming IP packets on the local machine,
displays the first 20 bytes of each packet,
and runs in promiscuous mode to capture all network traffic.

Usage:
    Run the script with administrator privileges.
    Press Ctrl+C to stop packet capture.

Note:
    This code works on Windows due to the use of SIO_RCVALL ioctl for promiscuous mode.
"""

import socket

def main():
    # Create a raw socket to capture IP packets
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("Error: You need to run this script with administrator privileges.")
        return

    # Get the local machine's IP address
    host = socket.gethostbyname(socket.gethostname())

    # Bind the socket to the local IP address
    s.bind((host, 0))

    # Include IP headers in captured packets
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode to capture all packets (Windows only)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Starting packet capture on {host}... Press Ctrl+C to stop.")

    try:
        while True:
            # Receive packets
            data, addr = s.recvfrom(65565)
            print(f"Packet from {addr}: {data[:20]}...")  # Display first 20 bytes
    except KeyboardInterrupt:
        # Disable promiscuous mode when stopping
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    main()
