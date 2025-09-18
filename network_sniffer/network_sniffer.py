# network_sniffer.py
# kai pokrandt

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
import matplotlib.patheffects as path_effects
from matplotlib.animation import FuncAnimation
from collections import defaultdict, deque
from itertools import islice
import tkinter as tk
import threading
import signal
import time

# globals
protocol_counts = defaultdict(int)
top_talkers = defaultdict(int)
lock = threading.Lock()
running = True

# throughput tracking
packets_per_second = deque(maxlen=60)
bytes_per_second = deque(maxlen=60)
time_stamps = deque(maxlen=60)
packet_count = 0
byte_count = 0
last_update = time.time()

# map protocol numbers to names
PROTO_MAP = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}

# callback function for each captured packet
def packet_callback(packet, selected_protocols):
    global packet_count, byte_count
    
    if IP in packet:
        proto = packet[IP].proto
        proto_name = PROTO_MAP.get(proto, f"OTHER({proto})")
        ip_src = packet[IP].src
        
        with lock:
            if "all" in selected_protocols or proto_name.lower() in selected_protocols:
                protocol_counts[proto_name] += 1
                top_talkers[ip_src] += 1
                packet_count += 1
                byte_count += len(packet)
                print(f"IP {ip_src} -> {packet[IP].dst} | Protocol: {proto_name} | Length: {len(packet)}")

# start sniffing in a separate thread
def start_sniffer(selected_protocols, bpf_filter):
    global running, packet_count, byte_count, last_update
    sniff(prn=lambda pkt: packet_callback(pkt, selected_protocols),
          store=False,
          filter=bpf_filter,
          stop_filter=lambda x: not running)
            
def main():
    # start GUI
    print("Starting packet sniffer... Ctrl+C to stop.")
    global running, packet_count, byte_count, last_update
    
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
    # plt.ion()

    dpi = 100
    fig_width = min(10, 1920*0.8/dpi)
    fig_height = min(8, 1080*0.8/dpi)
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(fig_width, fig_height))
    
    # handle graceful exit
    def signal_handler(sig, frame):
        global running
        print("Stopping...")
        running = False
        sniff_thread.join()
        plt.close(fig)
        exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    # update function to avoid GUI freezing (thanks macOS)
    def update(frame):
        global packet_count, byte_count, last_update
        now = time.time()
        with lock:
            # update throughput stats every second
            if now - last_update >= 1:
                packets_per_second.append(packet_count)
                bytes_per_second.append(byte_count)
                time_stamps.append(int(now))
                packet_count = 0
                byte_count = 0
                last_update = now
            
            # ----- plot protocol counts bar chart -----
            ax1.clear()
            colors = {
                "TCP": "steelblue",
                "UDP": "darkorange",
                "ICMP": "seagreen",
                "IGMP": "purple",
                "OTHER": "grey"
            }
            proto_labels = list(protocol_counts.keys())
            proto_values = list(protocol_counts.values())
            proto_colors = [colors.get(label, "grey") for label in proto_labels]
            bars = ax1.bar(proto_labels, proto_values, color=proto_colors)
            ax1.set_title("Packet Counts by Protocol", fontsize=14, fontweight='bold')
            ax1.set_ylabel("Count")
            ax1.grid(axis='y', linestyle='--', alpha=0.6)
            bar_labels = [f"{label}\n{value}" for label, value in zip(proto_labels, proto_values)]
            ax1.bar_label(bars, labels=bar_labels, label_type='center', color='white', fontsize=8)
            ax1.set_xticks([])
            
            # ----- plot top talkers bar chart ------
            ax2.clear()
            sorted_talkers = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]
            ips = [ip for ip, count in sorted_talkers]
            counts = [count for ip, count in sorted_talkers]
            
            colors = plt.cm.viridis([0.3 + 0.1*i for i in range(len(ips))])
            bars = ax2.bar(ips, counts, color=colors)
            
            ax2.set_title("Top 5 Source IPs", fontsize=14, fontweight='bold')
            ax2.set_ylabel("Packet Count")
            ax2.grid(axis='y', linestyle='--', alpha=0.6)
            
            # bar label outlines for clarity
            for bar, label in zip(bars, ips):
                txt = ax2.text(
                    bar.get_x() + bar.get_width()/2,
                    bar.get_height()/2,
                    label,
                    ha='center', va='center', color='white', fontsize=8
                )
                txt.set_path_effects([
                    path_effects.Stroke(linewidth=1.5, foreground='black'),
                    path_effects.Normal()
                ])
            #ax2.bar_label(bars, labels=ips, label_type='center', color='lightgray', fontsize=8)
            ax2.set_xticks([])
            
            # ----- plot throughput line chart -----
            ax3.clear()
            if time_stamps:
                t = [ts - time_stamps[0] for ts in time_stamps]
                ax3.plot(t, packets_per_second, "-o", color='orange', label="Packets/s")
                ax3.plot(t, [b/1024 for b in bytes_per_second], "-o", color='cyan', label="KB/s")
                
                if len(packets_per_second) > 5:
                    avg = [
                        sum(islice(packets_per_second, max(0, i-4), i+1)) / min(i+1, 5)
                           for i in range(len(packets_per_second))
                    ]
                    ax3.plot(t, avg, "--", color='black', label="5s Avg Packets/s")
                ax3.set_title("Throughput Over Time (1m)", fontsize=14, fontweight='bold')
                ax3.set_xlabel("Time (s)")
                ax3.set_ylabel("Rate")
                ax3.grid(True, linestyle='--', alpha=0.6)
                ax3.legend()
    global ani
    ani = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
    plt.show(block=True)
    
if __name__ == "__main__":
    main()

# To run :
# cd to project directory
# python3 -m venv venv
# source venv/bin/activate
# pip install --upgrade pip
# pip install scapy matplotlib
# sudo python3 network_sniffer.py
# ctrl+c to stop, deactivate to exit venv
# Note: Running a packet sniffer may require administrative privileges.
# Also, be aware of legal and ethical considerations when sniffing network traffic.
# This script captures packets on the network interface and prints basic information about each packet.