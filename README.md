# 🐺 NetHound v1.0 — Advanced Network Packet Sniffer

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)

**NetHound** is a lightweight, high-performance CLI network packet sniffer written in Python using Scapy. Designed for network engineers, SOC analysts, and security researchers, NetHound delivers real-time Layer 3 and Layer 4 protocol parsing, TCP flag analysis, service labeling, and custom Berkeley Packet Filtering (BPF) capabilities.

---

## ⚡ Features & Capabilities

* **Live Traffic Sniffing:** Captures live packets across system interfaces with zero memory leaks (`store=0`).
* **Layer 3 / Layer 4 Extraction:** Real-time decoding of IP source/destination addresses, TTLs, and transport protocols (`TCP`, `UDP`, `ICMP`).
* **TCP Flag Inspector:** Extracts and parses connection state flags (`SYN`, `ACK`, `PSH`, `FIN`, `RST`).
* **Service Labeling:** Automatic mapping of destination ports to common application services (`HTTPS`, `HTTP`, `DNS`, `SSH`, `RDP`).
* **Dynamic BPF Filtering:** CLI flags for targeted traffic analysis by protocol (`-p`) or port (`--port`).
* **Sleek CLI Output:** Color-coded terminal display for rapid visibility during active security analysis.

---

## 🛠️ Installation & Prerequisites

### Prerequisites
* **Python 3.8+** installed on your system.
* **Npcap** (Windows) or **libpcap** (Linux) installed for promiscuous mode socket access.

### 1. Clone the Repository
```bash
git clone [https://github.com/Arif-PySec/NetHound.git](https://github.com/Arif-PySec/NetHound.git)
cd NetHound
