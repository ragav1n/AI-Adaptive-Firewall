from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from ipwhois import IPWhois
import csv
import os
import netifaces
import ipaddress

FLOW_TIMEOUT = 60
LARGE_FLOW_THRESHOLD = 1000000
FLOW_LOG = "flow_log.csv"

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

FIELDNAMES = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "direction",
    "start_time", "end_time", "duration", "packet_count", "byte_count",
    "avg_packet_size", "pps", "bps",
    "syn_count", "fin_count", "rst_count", "ack_count",
    "is_large_flow", "dst_country", "dst_org", "dst_asn"
]

if not os.path.exists(FLOW_LOG):
    with open(FLOW_LOG, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()

active_flows = {}

def get_direction(src_ip, dst_ip):
    if src_ip == LOCAL_IP:
        return "outbound"
    elif dst_ip == LOCAL_IP:
        return "inbound"
    else:
        return "unknown"

def enrich_ip_whois(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return "Private", "Private Network", "N/A"
        whois = IPWhois(ip).lookup_rdap()
        asn = whois.get("asn", "N/A")
        org = whois.get("network", {}).get("name", "N/A")
        country = whois.get("network", {}).get("country", "N/A")
        return country, org, asn
    except Exception as e:
        print(f"⚠️ WHOIS failed for {ip}: {e}")
        return "N/A", "N/A", "N/A"


def write_flow_to_csv(flow):
    duration = (flow["last_seen"] - flow["start_time"]).total_seconds() or 1
    avg_packet_size = flow["byte_count"] / flow["packet_count"]
    pps = flow["packet_count"] / duration
    bps = flow["byte_count"] / duration

    dst_country, dst_org, dst_asn = enrich_ip_whois(flow["dst_ip"])

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
        "duration": duration,
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"],
        "avg_packet_size": avg_packet_size,
        "pps": pps,
        "bps": bps,
        "syn_count": flow["syn_count"],
        "fin_count": flow["fin_count"],
        "rst_count": flow["rst_count"],
        "ack_count": flow["ack_count"],
        "is_large_flow": int(flow["byte_count"] >= LARGE_FLOW_THRESHOLD),
        "dst_country": dst_country,
        "dst_org": dst_org,
        "dst_asn": dst_asn
    }

    with open(FLOW_LOG, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow(flow_data)

    print(f"💾 Logged: {flow_data['flow_id']} to {dst_org}, {dst_country} ({dst_asn})")

def flush_expired_flows():
    now = datetime.now()
    expired = []
    for key, flow in active_flows.items():
        if (now - flow["last_seen"]).total_seconds() > FLOW_TIMEOUT:
            write_flow_to_csv(flow)
            expired.append(key)
    for key in expired:
        del active_flows[key]

def process_packet(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        proto = pkt[IP].proto
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP]

        try:
            key = (pkt[IP].src, l4.sport, pkt[IP].dst, l4.dport, proto)
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
                "byte_count": byte_len,
                "syn_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "ack_count": 0,
            }
        else:
            flow = active_flows[key]
            flow["last_seen"] = now
            flow["packet_count"] += 1
            flow["byte_count"] += byte_len

        if TCP in pkt:
            flags = pkt[TCP].flags
            flow = active_flows[key]
            if flags & 0x02:
                flow["syn_count"] += 1
            if flags & 0x01:
                flow["fin_count"] += 1
            if flags & 0x04:
                flow["rst_count"] += 1
            if flags & 0x10:
                flow["ack_count"] += 1

        if len(active_flows) % 50 == 0:
            flush_expired_flows()

import atexit
@atexit.register
def flush_remaining():
    for flow in active_flows.values():
        write_flow_to_csv(flow)

print(f"📡 Sniffing interface: en0 (Local IP: {LOCAL_IP})")
sniff(prn=process_packet, store=0, filter="tcp or udp", iface="en0")
