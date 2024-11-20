from scapy.all import ARP, Ether, srp
import sys

def scan_network(ip_range):
    # Create an ARP request with the given IP range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and capture responses
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Get IP range from the user
    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <IP_RANGE>")
        print("Example: python network_scanner.py 192.168.1.0/24")
        sys.exit(1)

    ip_range = sys.argv[1]
    devices = scan_network(ip_range)

    # Display results
    print("Available devices in the network:")
    print("IP" + " "*18 + "MAC")
    print("-"*40)
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))
