# AI-Adaptive-Firewall

This project aims to build an intelligent, adaptive firewall that can:
- Analyze live network traffic in real-time
- Detect anomalies using ML models
- Dynamically update firewall rules to protect the system
- Log, visualize, and learn from evolving traffic behavior
  

# Packet Capture Scripts

1. ```sniffer.py```
      – Packet-Level Live Traffic Logger
      - Captures every IP packet and logs detailed metadata into traffic_log.csv.
      
      ### Features:
      - Logs source/destination IP and port
      - MAC addresses (Ethernet layer)
      - Protocol, TTL, length
      - TCP flags, sequence/ack numbers
      - Packet direction (inbound/outbound)
      - Payload size
      - Real-time printout and CSV output
      
      ### Use for:
      - Low-level inspection
      - Forensics
      - Building a packet-based dataset



2. ```flow_sniffer.py```
      – Session-Based Flow Tracker
      - Groups packets into session-level flows and enriches each flow with features and metadata for anomaly detection, ML training, and threat analysis.
      
      ### Features:
   
     ### ✅ Flow Tracking
      - Groups packets into flows using 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`
      - Tracks:
        - Packet count
        - Byte count
        - Duration
        - TCP flags (SYN, FIN, RST, ACK)
        - Direction (inbound/outbound)
       
      ### ✅ ML-Ready Features Enrichment
      - `avg_packet_size`  
      - `pps` (packets/sec)  
      - `bps` (bytes/sec)  
      - `is_large_flow` flag based on byte threshold

      ### ✅ External Intelligence Enrichment
      - WHOIS-based ASN lookup using `ipwhois`
      - Adds:
        - `dst_country`
        - `dst_org`
        - `dst_asn`
      - Automatically detects and tags private IP addresses

# Installation
Run this command to install dependencies:

```bash
pip install -r requirements.txt
```

```⚠️ Both `sniffer.py` and `flow_sniffer.py` must be run with `sudo` to enable raw packet capture on macOS and Linux.```
