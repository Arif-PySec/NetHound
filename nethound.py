import sys
import datetime
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Terminal Color Codes
BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def get_tcp_flags(tcp_layer):
    """Extract and format TCP flags into human-readable strings."""
    flags = []
    if tcp_layer.flags.S:
        flags.append("SYN")
    if tcp_layer.flags.A:
        flags.append("ACK")
    if tcp_layer.flags.F:
        flags.append("FIN")
    if tcp_layer.flags.R:
        flags.append("RST")
    if tcp_layer.flags.P:
        flags.append("PSH")
    return "-".join(flags) if flags else "NONE"

def get_service_name(port):
    """Identify common well-known port numbers."""
    services = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        3389: "RDP"
    }
    return services.get(port, "")

def process_packet(packet):
    """Callback function to parse and display packet details."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = get_tcp_flags(packet[TCP])
            
            # Check for well-known service on source or destination port
            service = get_service_name(dport) or get_service_name(sport)
            service_str = f" ({service})" if service else ""
            
            print(f"[{timestamp}] {BLUE}🔵 TCP [{flags}]{RESET}\t│ {src_ip}:{sport} -> {dst_ip}:{dport}{service_str}")
            
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            service = get_service_name(dport) or get_service_name(sport)
            service_str = f" ({service})" if service else ""
            
            print(f"[{timestamp}] {GREEN}🟢 UDP{RESET}\t\t│ {src_ip}:{sport} -> {dst_ip}:{dport}{service_str}")
            
        elif packet.haslayer(ICMP):
            print(f"[{timestamp}] {RED}🚨 ICMP{RESET}\t\t│ {src_ip} -> {dst_ip} [Ping Control]")

def parse_arguments():
    """Parse command line flags for live filtering."""
    parser = argparse.ArgumentParser(description="PacketHound v2.0 - Advanced Live Packet Sniffer")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp"], help="Filter traffic by protocol (tcp, udp, icmp)")
    parser.add_argument("--port", type=int, help="Filter traffic by specific port number (e.g. 80, 443)")
    return parser.parse_args()

def build_bpf_filter(args):
    """Construct a Berkeley Packet Filter string from user CLI inputs."""
    filters = []
    if args.protocol:
        filters.append(args.protocol)
    if args.port:
        filters.append(f"port {args.port}")
    return " and ".join(filters) if filters else None

def main():
    args = parse_arguments()
    bpf_filter = build_bpf_filter(args)

   
    
   # Terminal ANSI Color Codes
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    print(f"{CYAN}┌──────────────────────────────────────────────────────────────────────┐")
    print(fr"│ {BLUE}{BOLD}   _  _     _   _  _                  _  {RESET}{CYAN}                            │")
    print(fr"│ {BLUE}{BOLD}  | \| |___| |_| || |___ _  _ _ _  __| | {RESET}{CYAN}   🐺 NETHOUND v1.0         │")
    print(fr"│ {BLUE}{BOLD}  | .` / -_)  _| __ / _ \ || | ' \/ _` | {RESET}{CYAN}   Network Packet Sniffer   │")
    print(fr"│ {BLUE}{BOLD}  |_|\_\___|\__|_||_\___/\_,_|_||_\__,_| {RESET}{CYAN}   github.com/Arif-PySec    │")
    print(f"│                                                                      │")
    print(f"{CYAN}└──────────────────────────────────────────────────────────────────────┘{RESET}")
    if bpf_filter:
        print(f"[*] Applied Filter: '{bpf_filter}'")
    else:
        print("[*] No filters applied. Capturing ALL traffic...")
    print("Initializing promiscuous mode... Press Ctrl+C to stop.\n")

    # Wrap sniff() here so Ctrl+C exits cleanly without a traceback error
    try:
        sniff(filter=bpf_filter, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print(f"\n{RED}[*] Stopping PacketHound v1.0... Sniffer shut down cleanly.{RESET}")
        sys.exit(0)
if __name__ == "__main__":
    main()