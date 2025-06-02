# Basic Network Sniffer — CodeAlpha Cyber Security Internship Task 1

## Overview
This Python script captures and analyzes IPv4 network packets on a specified local IP address using raw sockets. It extracts key details from the IP header, including IP version, header length, TTL (Time To Live), protocol type (TCP, UDP, ICMP), and source and destination IP addresses. This project demonstrates fundamental network packet capturing and parsing techniques useful in cybersecurity for network monitoring and traffic analysis.

## Features
- Captures raw network packets on Windows using raw sockets
- Parses IP headers to provide human-readable output
- Displays protocol type, TTL, source IP, and destination IP
- Runs continuously until interrupted by the user (Ctrl+C)
- Enables promiscuous mode to capture all packets on the network interface

## Requirements
- Python 3.x installed
- Run the script as Administrator (required for raw socket operations on Windows)
- Tested on Windows 10 with IP address `172.20.10.2`

## Usage
1. Open Command Prompt as Administrator.
2. Navigate to the folder containing `basic_sniffer.py`:
    ```bash
    cd C:\Users\parar\Downloads
    ```
3. Run the script:
    ```bash
    python basic_sniffer.py
    ```
4. Observe the live packet capture output showing decoded IP header information.
5. To stop capturing, press `Ctrl+C`.

## Sample Output
Starting packet capture on 172.20.10.2... Press Ctrl+C to stop.

IP Version: 4, Header Length: 20 bytes, TTL: 128
Protocol: TCP, Source: 172.20.10.2, Destination: 172.64.155.209

