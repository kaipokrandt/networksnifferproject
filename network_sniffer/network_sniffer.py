# network_sniffer.py
# kai pokrandt

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from collections import defaultdict
import threading
import signal

# globals
protocol_counts = defaultdict(int)
top_talkers = defaultdict(int)
lock = threading.Lock()
running = True

# map protocol numbers to names
PROTO_MAP = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}

# callback function for each captured packet
def packet_callback(packet, selected_protocols):
    if IP in packet:
        proto = packet[IP].proto
        proto_name = PROTO_MAP.get(proto, f"OTHER({proto})")
        ip_src = packet[IP].src
        
        with lock:
            if "all" in selected_protocols or proto_name.lower() in selected_protocols:
                protocol_counts[proto_name] += 1
                top_talkers[ip_src] += 1
                print(f"IP {ip_src} -> {packet[IP].dst} | Protocol: {proto_name} | Length: {len(packet)}")

# start sniffing in a separate thread
def start_sniffer(selected_protocols, bpf_filter):
    global running
    sniff(prn=lambda pkt: packet_callback(pkt, selected_protocols),
          store=False,
          filter=bpf_filter,
          stop_filter=lambda x: not running)
            
def main():
    print("Starting packet sniffer... Ctrl+C to stop.")
    global running
    # ask user for protocols to monitor
    user_input = input("Enter protocols to monitor (tcp, udp, icmp, all): ").lower()
    selected_protocols = [p.strip() for p in user_input.split(",")]
    
    # BPF filter for scapy sniff
    bpf_filter = ""
    if "all" not in selected_protocols:
        bpf_filter = " or ".join(selected_protocols)
        
    # start sniffer thread
    sniff_thread = threading.Thread(target=start_sniffer, args=(selected_protocols, bpf_filter))
    sniff_thread.start()
    
    # GUI plot in main thread
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10,8))
    
    def signal_handler(sig, frame):
        global running
        print("Stopping...")
        running = False
        sniff_thread.join()
        plt.close(fig)
        exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    
    while True:
        with lock:
            ax1.clear()
            ax2.clear()

            # protocol counts bar chart
            ax1.bar(protocol_counts.keys(), protocol_counts.values(), color=['blue','red','green'])
            ax1.set_title("Packet Counts by Protocol")
            ax1.set_ylabel("Count")

            # top talkers bar chart
            sorted_talkers = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]
            ips = [ip for ip, count in sorted_talkers]
            counts = [count for ip, count in sorted_talkers]
            ax2.bar(ips, counts, color='purple')
            ax2.set_title("Top 5 Source IPs")
            ax2.set_ylabel("Packet Count")
            ax2.set_xticks(range(len(ips)))
            ax2.set_xticklabels(ips, rotation=45)
        plt.pause(1)
    
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