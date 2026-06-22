from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):

    print("\n" + "=" * 50)

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        print(f"Packet Length  : {len(packet)} bytes")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("Payload Data:")
            print(payload[:100])

print("Starting Network Sniffer...")
print("Press CTRL+C to stop.\n")

sniff(prn=process_packet, store=False)