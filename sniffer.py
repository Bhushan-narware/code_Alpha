from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        protocol = ""
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = ip_layer.proto

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        print(f"    Protocol       : {protocol}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload        : {payload[:50]}...")  # first 50 bytes
    else:
        print("\n[!] Non-IP packet captured")

print("[*] Starting packet capture... (Press Ctrl+C to stop)\n")
sniff(prn=process_packet, store=False)
