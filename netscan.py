#!/usr/bin/env python
from scapy.all import ARP, Ether, srp
import pandas as pd
import matplotlib.pyplot as plt
import sys

def scan_network(ip_range):
    # Create an ARP request with the given IP range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def analyze_devices(devices):
    df = pd.DataFrame(devices)
    
    device_count = df.shape[0]
    print(f"\nTotal number of devices found: {device_count}")
    
    # Extract and analyze MAC address prefixes (first 8 characters for vendor analysis)
    df['vendor_prefix'] = df['mac'].str[:8]
    vendor_counts = df['vendor_prefix'].value_counts()
    
    print("\nMAC Address Prefix Distribution:")
    print(vendor_counts)
    
    vendor_counts.plot(kind='bar', figsize=(10, 6), title="MAC Address Prefix Distribution")
    plt.xlabel("MAC Address Prefix")
    plt.ylabel("Count")
    plt.show()

    #Adding dataframe to newly created CSV file
    df.to_csv("network_devices.csv", index=False)
    print("\nDevice data saved to 'network_devices.csv'.")

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

    devices = scan_network(ip_range)

    print("\nAvailable devices in the network:")
    print("IP" + " " * 18 + "MAC")
    print("-" * 40)
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))
    #if there are any devices to analyze 
    if devices:
        analyze_devices(devices)
    else:
        print("No devices found.")
