from scapy.all import sniff, IP, TCP, UDP, Ether
from datetime import datetime
import csv
import os
import netifaces

CSV_FILE = "traffic_log.csv"

# 🧠 Step 1: Get local IP to detect packet direction
def get_local_ip():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                ip = link.get('addr')
                if ip and not ip.startswith("127."):
                    return ip
    return None

LOCAL_IP = get_local_ip()
print(f"Using local IP: {LOCAL_IP}")

# 🧾 Step 2: Define CSV columns
FIELDNAMES = [
    "timestamp", "direction", "src_mac", "dst_mac",
    "src_ip", "dst_ip", "protocol", "ttl", "ip_len",
    "src_port", "dst_port", "tcp_flags", "seq_num",
    "ack_num", "payload_len"
]

# 🗃️ Step 3: Create CSV if not exists
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()

# 🧪 Step 4: Process each packet
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        direction = "outbound" if src_ip == LOCAL_IP else "inbound" if dst_ip == LOCAL_IP else "unknown"

        data = {
            "timestamp": datetime.now().isoformat(),
            "direction": direction,
            "src_mac": packet[Ether].src if Ether in packet else None,
            "dst_mac": packet[Ether].dst if Ether in packet else None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": packet[IP].proto,
            "ttl": packet[IP].ttl,
            "ip_len": packet[IP].len,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "seq_num": None,
            "ack_num": None,
            "payload_len": len(packet[IP].payload)
        }

        if TCP in packet:
            data["src_port"] = packet[TCP].sport
            data["dst_port"] = packet[TCP].dport
            data["tcp_flags"] = str(packet[TCP].flags)
            data["seq_num"] = packet[TCP].seq
            data["ack_num"] = packet[TCP].ack

        elif UDP in packet:
            data["src_port"] = packet[UDP].sport
            data["dst_port"] = packet[UDP].dport

        # Log to CSV
        with open(CSV_FILE, mode='a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writerow(data)

        print(data)

# 🛠️ Step 5: Start sniffing on active interface (update to correct one if needed)
sniff(prn=process_packet, store=0, filter="ip", iface="en0")
