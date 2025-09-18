Network Sniffer GUI

A real-time network sniffer and analyzer with a GUI that tracks packet counts by protocol, top source IPs, and network throughput. Works on TCP, UDP, ICMP, or all protocols.

Features :
    Real Time packet capture using Scapy
    Live Visualization of Packet Counts by Protocol, Top 5 Source IPs, Network Throughput(packets/s, KB/s)
    Configurable protocol filter
    Runs on macOS, Linux, Windows with python
    
Manual setup : 

# Clone the repo
git clone https://github.com/kaipokrandt/networksnifferproject.git

cd network-sniffer

# (Optional) Create a virtual environment
python3 -m venv venv

source venv/bin/activate  # macOS/Linux

venv\Scripts\activate     # Windows

# Install dependencies
pip install --upgrade pip

pip install -r requirements.txt

sudo python3 network_sniffer.py # macOS/Linux

python network_sniffer.py       # Windows



MIT License. See LICENSE file for details.

Use this tool responsibly. Capturing packets on networks you do not own or have permission to monitor may be illegal.

