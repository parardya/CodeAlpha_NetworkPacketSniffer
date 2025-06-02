"""
enhanced_sniffer.py

A simple raw socket packet sniffer for Windows that captures IP packets,
parses the IP header, and displays key information such as IP version,
header length, TTL, protocol, source, and destination addresses.

Usage:
    Run with administrator privileges.
    Press Ctrl+C to stop capturing.

Note:
    Uses Windows-specific ioctl calls for promiscuous mode.
"""

import socket
import struct

def parse_ip_header(data):
    """
    Parse the IP header from raw packet data.

    Parameters:
        data (bytes): Raw packet data starting with the IP header.

    Returns:
        tuple: (version, ihl, ttl, protocol, src_addr, dst_addr)
    """
    # Unpack first 20 bytes of IP header
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4            # IP version
    ihl = (version_ihl & 0xF) * 4         # Header length in bytes

    ttl = iph[5]                          # Time To Live
    protocol = iph[6]                     # Protocol number
    src_addr = socket.inet_ntoa(iph[8])  # Source IP
    dst_addr = socket.inet_ntoa(iph[9])  # Destination IP

    return version, ihl, ttl, protocol, src_addr, dst_addr

def protocol_name(proto_num):
    """
    Map protocol numbers to human-readable protocol names.

    Parameters:
        proto_num (int): Protocol number from IP header.

    Returns:
        str: Protocol name or the number if unknown.
    """
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    return protocols.get(proto_num, str(proto_num))

def main():
    # Change this to your actual local IP address if needed
    host = '172.20.10.2'

    try:
        # Create raw socket to capture IP packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("Error: Please run this script as Administrator.")
        return

    # Bind socket to the host IP and all ports (0)
    s.bind((host, 0))

    # Include IP headers in captured packets
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode to capture all packets (Windows only)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Starting packet capture on {host}... Press Ctrl+C to stop.")

    try:
        while True:
            data, addr = s.recvfrom(65565)
            version, ihl, ttl, protocol, src, dst = parse_ip_header(data)
            proto_name = protocol_name(protocol)

            print(f"IP Version: {version}, Header Length: {ihl} bytes, TTL: {ttl}")
            print(f"Protocol: {proto_name}, Source: {src}, Destination: {dst}\n")

    except KeyboardInterrupt:
        # Disable promiscuous mode before exiting
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    main()
