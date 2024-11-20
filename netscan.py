#!/usr/bin/env python
from scapy.all import ARP, Ether, srp
import sys

def scan_network(ip_range):
    # Create an ARP request with the given IP range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture responses
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    try:
        # Get IP range from the user
        ip_range = input("Please enter the IP address range you would like to scan for (e.g., 192.168.1.1/24): ")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)

    if not ip_range:
        print("No IP address range provided. Exiting.")
        sys.exit(1)

    # Scan the network
    devices = scan_network(ip_range)

    # Display results
    print("\nAvailable devices in the network:")
    print("IP" + " " * 18 + "MAC")
    print("-" * 40)
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))
