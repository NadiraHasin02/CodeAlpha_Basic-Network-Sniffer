from scapy.all import *

def process_packet(packet):
    print("\n" + "=" * 60)

    if IP in packet:
        print("Packet Captured")
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

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