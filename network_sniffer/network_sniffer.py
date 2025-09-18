# network_sniffer.py
# kai pokrandt

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# map protocol numbers to names
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

def packet_callback(packet, selected_protocols):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
        if "all" in selected_protocols or proto_name.lower() in selected_protocols:
            print(f"IP {ip_src} -> {ip_dst} | Protocol: {proto_name} | Length: {length}")
        
def main():
    print("Starting packet sniffer... Ctrl+C to stop.")
    
    # ask user for protocols to monitor
    user_input = input("Enter protocols to monitor (tcp, udp, icmp, all): ").lower()
    selected_protocols = [p.strip() for p in user_input.split(",")]
    
    # BPF filter for scapy sniff
    bpf_filter = ""
    if "all" not in selected_protocols:
        bpf_filter = " or ".join(selected_protocols)
        
    sniff(prn=lambda pkt: packet_callback(pkt, selected_protocols),
          store=False,
          filter=bpf_filter)

if __name__ == "__main__":
    main()

# To run this script, you may need to execute it with admin privileges.
# cd to project directory and run:
# python3 -m venv venv
# source venv/bin/activate
# pip install --upgrade pip
# pip install scapy
# sudo python3 network_sniffer.py
# ctrl+c to stop, deactivate to exit venv
# Note: Running a packet sniffer may require administrative privileges.
# Also, be aware of legal and ethical considerations when sniffing network traffic.
# This script captures packets on the network interface and prints basic information about each packet.