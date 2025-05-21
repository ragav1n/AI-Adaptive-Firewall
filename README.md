# AI-Adaptive-Firewall

This project aims to build an intelligent, adaptive firewall that can:
- Analyze live network traffic in real-time
- Detect anomalies using ML models
- Dynamically update firewall rules to protect the system
- Log, visualize, and learn from evolving traffic behavior
  

# Packet Capture Scripts

1. ```sniffer.py```
      – Packet-Level Live Traffic Logger
      Captures every IP packet and logs detailed metadata into traffic_log.csv.
      
      Features:
      - Logs source/destination IP and port
      - MAC addresses (Ethernet layer)
      - Protocol, TTL, length
      - TCP flags, sequence/ack numbers
      - Packet direction (inbound/outbound)
      - Payload size
      - Real-time printout and CSV output
      
      Use for:
      - Low-level inspection
      - Forensics
      - Building a packet-based dataset



2. ```flow_sniffer.py```
      – Session-Based Flow Tracker
      Groups packets into connection flows and logs flow-level stats to flow_log.csv.
      
      Features:
      - Tracks TCP/UDP flows using 5-tuple
      - Logs:
        - Total packets
        - Total bytes
        - Flow duration
        - Direction (inbound/outbound)
        - Auto-expires idle flows after FLOW_TIMEOUT seconds
        - Flushes active flows on exit
      
      Use for:
      - Behavioral anomaly detection
      - ML model training
      - Summary analytics

# Installation
Run this command to install dependencies:

```bash
pip install -r requirements.txt
```

```⚠️ Both `sniffer.py` and `flow_sniffer.py` must be run with `sudo` to enable raw packet capture on macOS and Linux.```
