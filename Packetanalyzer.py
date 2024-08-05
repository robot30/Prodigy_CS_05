from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Source: {ip_src} --> IP Destination: {ip_dst}")

        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Source Port: {tcp_sport} --> TCP Destination Port: {tcp_dport}")
            
            if packet.haslayer(Raw):
                data = packet[Raw].load
                print(f"Data: {data}")

# Sniff packets on the network with a limit of 100 packets or 10 seconds
sniff(prn=packet_callback, store=0, count=100)  # For a fixed number of packets
# sniff(prn=packet_callback, store=0, timeout=10)  # For a fixed duration
