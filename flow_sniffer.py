from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv
import os
import netifaces
import atexit

FLOW_TIMEOUT = 60 # seconds
FLOW_LOG = "flow_log.csv"

# Detect local IP for direction
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

# CSV Header
FIELDNAMES = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "direction", "start_time", "end_time", "duration",
    "packet_count", "byte_count"
]

# Create log file if needed
if not os.path.exists(FLOW_LOG):
    with open(FLOW_LOG, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()

# Flow table
active_flows = {}

def get_direction(src_ip, dst_ip):
    if src_ip == LOCAL_IP:
        return "outbound"
    elif dst_ip == LOCAL_IP:
        return "inbound"
    else:
        return "unknown"

def write_flow_to_csv(flow):
    flow_data = {
        "flow_id": flow["id"],
        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],
        "protocol": flow["protocol"],
        "direction": flow["direction"],
        "start_time": flow["start_time"].isoformat(),
        "end_time": flow["last_seen"].isoformat(),
        "duration": (flow["last_seen"] - flow["start_time"]).total_seconds(),
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"]
    }

    with open(FLOW_LOG, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow(flow_data)

    print(f"💾 Flow logged: {flow_data}")

def flush_expired_flows():
    now = datetime.now()
    expired_keys = []

    for key, flow in active_flows.items():
        if (now - flow["last_seen"]).total_seconds() > FLOW_TIMEOUT:
            write_flow_to_csv(flow)
            expired_keys.append(key)

    for key in expired_keys:
        del active_flows[key]

def process_packet(pkt):
    if IP in pkt:
        proto = pkt[IP].proto
        l4 = None

        if TCP in pkt:
            l4 = pkt[TCP]
        elif UDP in pkt:
            l4 = pkt[UDP]
        else:
            return  # Skip non-TCP/UDP

        try:
            key = (
                pkt[IP].src,
                l4.sport,
                pkt[IP].dst,
                l4.dport,
                proto
            )
        except Exception as e:
            print(f"⚠️ Skipping malformed packet: {e}")
            return

        now = datetime.now()
        direction = get_direction(pkt[IP].src, pkt[IP].dst)
        byte_len = len(pkt)

        if key not in active_flows:
            active_flows[key] = {
                "id": f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}/{proto}",
                "src_ip": key[0],
                "dst_ip": key[2],
                "src_port": key[1],
                "dst_port": key[3],
                "protocol": proto,
                "direction": direction,
                "start_time": now,
                "last_seen": now,
                "packet_count": 1,
                "byte_count": byte_len
            }
        else:
            flow = active_flows[key]
            flow["last_seen"] = now
            flow["packet_count"] += 1
            flow["byte_count"] += byte_len

        print(f"✔️ Flow packet detected: {pkt.summary()}")

        if len(active_flows) % 50 == 0:
            flush_expired_flows()

# Start sniffing on correct interface
print(f"📡 Listening on interface: en0 (Local IP: {LOCAL_IP})")
sniff(prn=process_packet, store=0, filter="tcp or udp", iface="en0")

@atexit.register
def flush_all_on_exit():
    print("⚠️ Exiting: flushing all active flows...")
    for flow in active_flows.values():
        write_flow_to_csv(flow)

