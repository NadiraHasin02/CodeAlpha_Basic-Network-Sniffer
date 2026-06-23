from scapy.all import *
from scapy.layers.inet6 import IPv6

def process_packet(packet):
    print("\n" + "=" * 60)

    if IP in packet:
    print("IPv4 Packet")
    print(f"Source IP      : {packet[IP].src}")
    print(f"Destination IP : {packet[IP].dst}")

elif IPv6 in packet:
    print("IPv6 Packet")
    print(f"Source IP      : {packet[IPv6].src}")
    print(f"Destination IP : {packet[IPv6].dst}")

        if TCP in packet:
            print("Protocol       : TCP")

        elif UDP in packet:
            print("Protocol       : UDP")

        elif ICMP in packet:
            print("Protocol       : ICMP")

        print(f"Packet Length  : {len(packet)} bytes")

        print("Summary:")
        print(packet.summary())

    else:
        print("Non-IP Packet")
        print(packet.summary())

print("=== NETWORK SNIFFER STARTED ===")
print("Listening for packets...\n")

sniff(prn=process_packet, store=False)