#!/usr/bin/env python3
"""Generate synthetic PCAP file for testing."""

import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest


def generate_synthetic_pcap(output_file: str = "data/sample.pcap", duration_minutes: int = 10):
    """Generate synthetic PCAP with normal and suspicious traffic.
    
    Args:
        output_file: Output PCAP file path
        duration_minutes: Duration of capture to simulate
    """
    print(f"Generating synthetic PCAP file: {output_file}")
    
    # Ensure output directory exists
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    packets = []
    start_time = time.time()
    current_time = start_time
    
    # Device definitions
    devices = {
        'laptop': {
            'mac': '00:11:22:33:44:55',
            'ip': '192.168.1.100',
            'type': 'normal',
            'vendor': 'Dell'
        },
        'phone': {
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ip': '192.168.1.101',
            'type': 'normal',
            'vendor': 'Apple'
        },
        'iot_camera': {
            'mac': '64:16:66:12:34:56',
            'ip': '192.168.1.102',
            'type': 'suspicious',
            'vendor': 'Amazon Ring'
        },
        'smart_tv': {
            'mac': 'b0:72:bf:78:90:12',
            'ip': '192.168.1.103',
            'type': 'normal',
            'vendor': 'Roku'
        },
        'router': {
            'mac': '84:16:f9:00:00:01',
            'ip': '192.168.1.1',
            'type': 'infrastructure',
            'vendor': 'TP-Link'
        }
    }
    
    # Common destination servers
    servers = {
        'google_dns': '8.8.8.8',
        'cloudflare_dns': '1.1.1.1',
        'google': '142.250.80.46',
        'facebook': '31.13.64.35',
        'netflix': '52.84.228.25',
        'amazon': '52.94.236.248',
        'suspicious_c2': '185.220.101.45',  # Simulated C2 server
        'malware_host': '192.241.164.123'  # Simulated malware host
    }
    
    # Generate normal traffic patterns
    print("Generating normal traffic...")
    
    for minute in range(duration_minutes):
        # Adjust time for this minute
        minute_offset = minute * 60
        
        # Normal web browsing from laptop
        for _ in range(random.randint(5, 15)):
            src = devices['laptop']
            dst_ip = random.choice([servers['google'], servers['facebook'], servers['amazon']])
            
            # HTTP request
            pkt = Ether(src=src['mac'], dst=devices['router']['mac']) / \
                  IP(src=src['ip'], dst=dst_ip) / \
                  TCP(sport=random.randint(49152, 65535), dport=443, flags='S')
            pkt.time = current_time + minute_offset + random.random() * 60
            packets.append(pkt)
        
        # DNS queries from all devices
        for device_name, device in devices.items():
            if device['type'] != 'infrastructure':
                for _ in range(random.randint(1, 5)):
                    dns_server = random.choice([servers['google_dns'], servers['cloudflare_dns']])
                    domain = random.choice([
                        'www.google.com',
                        'www.facebook.com',
                        'www.netflix.com',
                        'api.amazon.com',
                        'cdn.cloudflare.com'
                    ])
                    
                    pkt = Ether(src=device['mac'], dst=devices['router']['mac']) / \
                          IP(src=device['ip'], dst=dns_server) / \
                          UDP(sport=random.randint(49152, 65535), dport=53) / \
                          DNS(qd=DNSQR(qname=domain))
                    pkt.time = current_time + minute_offset + random.random() * 60
                    packets.append(pkt)
        
        # Streaming traffic from Smart TV
        if minute % 2 == 0:  # Every other minute
            for _ in range(random.randint(50, 100)):
                src = devices['smart_tv']
                
                pkt = Ether(src=src['mac'], dst=devices['router']['mac']) / \
                      IP(src=src['ip'], dst=servers['netflix']) / \
                      TCP(sport=random.randint(49152, 65535), dport=443) / \
                      Raw(load=b'\x00' * random.randint(1000, 1500))
                pkt.time = current_time + minute_offset + random.random() * 60
                packets.append(pkt)
        
        # Mobile device traffic
        for _ in range(random.randint(3, 8)):
            src = devices['phone']
            dst_ip = random.choice([servers['google'], servers['facebook']])
            
            pkt = Ether(src=src['mac'], dst=devices['router']['mac']) / \
                  IP(src=src['ip'], dst=dst_ip) / \
                  TCP(sport=random.randint(49152, 65535), dport=443)
            pkt.time = current_time + minute_offset + random.random() * 60
            packets.append(pkt)
    
    print("Generating suspicious traffic...")
    
    # Suspicious IoT camera behavior
    suspicious_device = devices['iot_camera']
    
    # 1. DNS tunneling attempt (many DNS queries to random subdomains)
    for minute in range(duration_minutes):
        if minute >= 3:  # Start after 3 minutes
            for _ in range(random.randint(20, 40)):  # High DNS query rate
                subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
                domain = f"{subdomain}.tunnel-dns.com"
                
                pkt = Ether(src=suspicious_device['mac'], dst=devices['router']['mac']) / \
                      IP(src=suspicious_device['ip'], dst=servers['google_dns']) / \
                      UDP(sport=random.randint(49152, 65535), dport=53) / \
                      DNS(qd=DNSQR(qname=domain))
                pkt.time = current_time + (minute * 60) + random.random() * 60
                packets.append(pkt)
    
    # 2. Port scanning behavior
    for minute in [4, 5, 6]:  # Scan during minutes 4-6
        target_ip = f"192.168.1.{random.randint(50, 150)}"
        for port in [23, 22, 445, 3389, 8080]:  # Common ports
            pkt = Ether(src=suspicious_device['mac'], dst=devices['router']['mac']) / \
                  IP(src=suspicious_device['ip'], dst=target_ip) / \
                  TCP(sport=random.randint(49152, 65535), dport=port, flags='S')
            pkt.time = current_time + (minute * 60) + random.random() * 10
            packets.append(pkt)
    
    # 3. C2 communication (beaconing)
    for minute in range(2, duration_minutes):
        # Regular beacon every minute
        pkt = Ether(src=suspicious_device['mac'], dst=devices['router']['mac']) / \
              IP(src=suspicious_device['ip'], dst=servers['suspicious_c2']) / \
              TCP(sport=random.randint(49152, 65535), dport=443) / \
              Raw(load=b'BEACON')
        pkt.time = current_time + (minute * 60) + 30  # Beacon at 30 seconds into each minute
        packets.append(pkt)
    
    # 4. Telnet connection attempts
    for minute in [7, 8]:
        for _ in range(5):
            target_ip = f"192.168.1.{random.randint(100, 200)}"
            
            pkt = Ether(src=suspicious_device['mac'], dst=devices['router']['mac']) / \
                  IP(src=suspicious_device['ip'], dst=target_ip) / \
                  TCP(sport=random.randint(49152, 65535), dport=23, flags='S')
            pkt.time = current_time + (minute * 60) + random.random() * 60
            packets.append(pkt)
    
    # 5. Data exfiltration attempt (large upload)
    if duration_minutes > 8:
        for i in range(100):  # Send 100 large packets
            pkt = Ether(src=suspicious_device['mac'], dst=devices['router']['mac']) / \
                  IP(src=suspicious_device['ip'], dst=servers['malware_host']) / \
                  TCP(sport=random.randint(49152, 65535), dport=8888) / \
                  Raw(load=b'EXFIL_DATA' * 100)
            pkt.time = current_time + (9 * 60) + (i * 0.1)
            packets.append(pkt)
    
    # Sort packets by time
    packets.sort(key=lambda x: x.time)
    
    # Write PCAP file
    print(f"Writing {len(packets)} packets to {output_file}")
    wrpcap(output_file, packets)
    
    print(f"Synthetic PCAP generated successfully!")
    print(f"  - Duration: {duration_minutes} minutes")
    print(f"  - Packets: {len(packets)}")
    print(f"  - Devices: {len(devices)}")
    print(f"  - Suspicious device: {suspicious_device['ip']} ({suspicious_device['mac']})")
    
    return output_file


def generate_oui_sample():
    """Generate sample OUI database file."""
    oui_file = "data/oui_sample.csv"
    Path(oui_file).parent.mkdir(parents=True, exist_ok=True)
    
    oui_data = """# OUI Sample Database
# Format: MAC_PREFIX<tab>VENDOR_NAME
00:11:22	Dell Inc.
aa:bb:cc	Apple Inc.
64:16:66	Amazon Technologies Inc.
b0:72:bf	Roku, Inc.
84:16:f9	TP-Link Technologies Co.
00:00:5e	IANA
00:50:56	VMware, Inc.
08:00:27	Oracle VirtualBox
b8:27:eb	Raspberry Pi Foundation
dc:a6:32	Raspberry Pi Trading Ltd
28:d2:44	Google Inc.
f4:f5:d8	Google Inc.
3c:37:86	Amazon Technologies Inc.
68:54:f5	Amazon Technologies Inc.
a4:b1:c1	Amazon Technologies Inc.
d0:03:4b	Apple Inc.
f0:18:98	Apple Inc.
00:24:9b	Action Star Enterprise
18:03:73	Dell Inc.
34:17:eb	Dell Inc.
48:4d:7e	Dell Inc.
ec:f4:bb	Dell Technologies
30:9c:23	Micro-Star International
4c:ed:fb	ASUSTek Computer Inc.
5c:cf:7f	Espressif Inc.
60:01:94	Espressif Inc.
c0:06:c3	TP-Link Technologies
c0:25:e9	TP-Link Technologies
ac:84:c6	TP-Link Technologies
b0:a7:b9	TP-Link Technologies
e8:9f:80	Belkin International Inc.
ec:71:db	Ring LLC
bc:14:01	Google Nest
d8:bb:c1	Google Inc.
"""
    
    with open(oui_file, 'w') as f:
        f.write(oui_data)
    
    print(f"OUI sample database created: {oui_file}")
    return oui_file


def generate_suspicious_domains():
    """Generate list of suspicious domains."""
    domains_file = "data/suspicious_domains.txt"
    Path(domains_file).parent.mkdir(parents=True, exist_ok=True)
    
    suspicious_domains = """# Suspicious Domains List
# Known malware C2 domains (simulated)
malware-c2.com
evil-botnet.net
cryptominer-pool.org
ransomware-payment.com
phishing-site.tk
data-exfil.ml
command-control.ga
tunnel-dns.com
backdoor-server.cf
trojan-downloader.click

# DGA-like domains
xkj2h4k5j6h.com
qwe123rty456.net
zxc789vbn012.org

# Suspicious TLDs
suspicious.tk
malicious.ml
dangerous.ga
harmful.cf
"""
    
    with open(domains_file, 'w') as f:
        f.write(suspicious_domains)
    
    print(f"Suspicious domains list created: {domains_file}")
    return domains_file


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate synthetic network data")
    parser.add_argument("--output", default="data/sample.pcap", help="Output PCAP file")
    parser.add_argument("--duration", type=int, default=10, help="Duration in minutes")
    parser.add_argument("--oui", action="store_true", help="Also generate OUI database")
    parser.add_argument("--domains", action="store_true", help="Also generate suspicious domains")
    
    args = parser.parse_args()
    
    # Generate all data files
    generate_synthetic_pcap(args.output, args.duration)
    
    if args.oui or True:  # Always generate for completeness
        generate_oui_sample()
    
    if args.domains or True:  # Always generate for completeness
        generate_suspicious_domains()
    
    print("\nAll sample data generated successfully!")
