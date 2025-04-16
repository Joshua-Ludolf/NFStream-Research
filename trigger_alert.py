#!/usr/bin/env python3

"""
Alert Trigger Script for Network Monitor (LOCAL IP VERSION)

This script triggers alerts in the Network Monitor application (gui.py) by:
1. Sending suspicious network traffic with patterns matching the monitor's detection rules
2. Using packets with known malicious signatures
3. Generating traffic to/from IPs that are in the blacklist

This version ONLY sends traffic to your local IP address for safety.

Usage:
    python trigger_alert_local.py [options]
"""

import argparse
import socket
import time
import random
import requests
import threading
import scapy.all as scapy
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR


# Known malicious IPs from Network Monitor's built-in threats
# These match the IPs defined in _load_builtin_threats() method
MALICIOUS_IPS = [
    "192.168.1.100",  # Example malicious IP
    "10.0.0.99",      # Example malicious IP
    "203.0.113.0",    # Example from TEST-NET-3 block
    "198.51.100.0",   # Example from TEST-NET-2 block
    "192.0.2.0"       # Example from TEST-NET-1 block
]

# Known malicious domains from Network Monitor's built-in threats
MALICIOUS_DOMAINS = [
    "malware.example.com",
    "phishing.test",
    "evil.local"
]

# Suspicious patterns that match the regex patterns in Network Monitor
SUSPICIOUS_PAYLOADS = [
    # SQL injection patterns
    "' OR 1=1 --", 
    "1'; DROP TABLE users; --",
    # XSS patterns
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    # Command injection
    "| cat /etc/passwd",
    "; powershell.exe -Command 'Get-Process'",
    # Common malware signatures
    "zgrab scanner detected",
    "nikto scan in progress",
    # Hash-like strings that might trigger exfiltration detection
    "44d88612fea8a8f36de82e1278abb02f275a021bbfb6489e54d471899f7db9d1"
]

# Moderate severity suspicious patterns - will trigger medium-level alerts
MODERATE_SUSPICIOUS_PAYLOADS = [
    # Unusual but not definitely malicious user inputs
    "admin' --",
    "SELECT * FROM users",
    "<img src=x onerror=console.log(1)>",
    # Potential reconnaissance patterns
    "default_password",
    "system32\\drivers",
    # Port scanning signature
    "port scan detected",
    # Less dangerous but still suspicious file extensions
    ".bat.txt",
    ".ps1.jpg",
    # Non-malicious but suspicious commands
    "net user administrator",
    "ipconfig /all"
]

# Suspicious user agents
SUSPICIOUS_USER_AGENTS = [
    "zgrab/0.x",
    "sqlmap/1.3.10",
    "Nikto/2.1.5",
    "masscan/1.0",
    "gobuster/3.1.0",
    "Nmap Scripting Engine"
]

def get_local_ip():
    """Get the local IP address of this machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def send_malicious_http_request(target_ip, user_agent=None, payload=None):
    """Send HTTP request with malicious content to trigger alerts"""
    try:
        headers = {}
        if user_agent:
            headers['User-Agent'] = user_agent
        
        url = f"http://{target_ip}"
        if payload:
            url += f"/?id={payload}"
        
        print(f"Sending HTTP request to {url} with headers: {headers}")
        response = requests.get(url, headers=headers, timeout=2)
        print(f"Response: {response.status_code}")
        return True
    except Exception as e:
        print(f"HTTP request failed: {e}")
        return False

def send_tcp_packet_with_scapy(src_ip, dst_ip, dst_port, payload):
    """Send TCP packet with custom payload using Scapy"""
    try:
        print(f"Sending TCP packet from {src_ip} to {dst_ip}:{dst_port} with payload: {payload}")
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port) / payload
        scapy.send(packet, verbose=0)
        return True
    except Exception as e:
        print(f"Failed to send packet with Scapy: {e}")
        return False

def send_udp_packet_with_scapy(src_ip, dst_ip, dst_port, payload):
    """Send UDP packet with custom payload using Scapy"""
    try:
        print(f"Sending UDP packet from {src_ip} to {dst_ip}:{dst_port} with payload: {payload}")
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=dst_port) / payload
        scapy.send(packet, verbose=0)
        return True
    except Exception as e:
        print(f"Failed to send packet with Scapy: {e}")
        return False

def send_dns_query_with_scapy(src_ip, dst_ip, domain):
    """Send DNS query for potentially malicious domain"""
    try:
        print(f"Sending DNS query from {src_ip} to {dst_ip} for domain: {domain}")
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        scapy.send(packet, verbose=0)
        return True
    except Exception as e:
        print(f"Failed to send DNS query with Scapy: {e}")
        return False

def generate_high_packet_rate(target_ip, packet_count=1500, duration=5):
    """Generate abnormally high packet rate to trigger traffic anomaly detection"""
    print(f"Generating high packet rate ({packet_count} packets over {duration} seconds)...")
    
    local_ip = get_local_ip()
    packets_per_thread = packet_count // 10
    
    def send_packets_batch(count):
        for _ in range(count):
            if random.choice([True, False]):
                # TCP packets
                send_tcp_packet_with_scapy(
                    local_ip, 
                    target_ip, 
                    random.randint(1, 65535),
                    f"High packet rate test payload {random.randint(1000, 9999)}"
                )
            else:
                # UDP packets
                send_udp_packet_with_scapy(
                    local_ip, 
                    target_ip, 
                    random.randint(1, 65535),
                    f"High packet rate test payload {random.randint(1000, 9999)}"
                )
    
    # Create 10 threads to send packets simultaneously
    threads = []
    for _ in range(10):
        t = threading.Thread(target=send_packets_batch, args=(packets_per_thread,))
        threads.append(t)
        t.start()
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    print(f"Finished sending high packet rate ({packet_count} packets)")

def spoof_malicious_ip(target_ip):
    """Spoof traffic from a known malicious IP to trigger alerts"""
    malicious_ip = random.choice(MALICIOUS_IPS)
    payload = random.choice(SUSPICIOUS_PAYLOADS)
    
    print(f"Spoofing packet from malicious IP {malicious_ip} to {target_ip}")
    send_tcp_packet_with_scapy(malicious_ip, target_ip, 80, payload)

def query_malicious_domain(dns_server):
    """Send DNS queries for known malicious domains"""
    local_ip = get_local_ip()
    domain = random.choice(MALICIOUS_DOMAINS)
    
    print(f"Querying malicious domain {domain} via DNS server {dns_server}")
    send_dns_query_with_scapy(local_ip, dns_server, domain)

def send_suspicious_user_agent(target_ip):
    """Send HTTP request with suspicious user agent to trigger alerts"""
    user_agent = random.choice(SUSPICIOUS_USER_AGENTS)
    send_malicious_http_request(target_ip, user_agent=user_agent)

def send_moderate_alert_traffic(target_ip):
    """Generate traffic that should trigger moderate severity alerts"""
    local_ip = get_local_ip()
    payload = random.choice(MODERATE_SUSPICIOUS_PAYLOADS)
    
    print(f"Sending moderate severity traffic to {target_ip}")
    
    # Choose a random port that might look like a service (but not well-known)
    dst_port = random.randint(1025, 9000)
    
    # Either use HTTP request or direct TCP packet
    if random.choice([True, False]):
        # HTTP with moderate payload
        send_malicious_http_request(target_ip, payload=payload)
    else:
        # TCP with moderate payload
        send_tcp_packet_with_scapy(local_ip, target_ip, dst_port, payload)
    
    return True

def run_all_triggers(target_ip, dns_server, intensity=1):
    """Run all alert triggers with specified intensity (1-10)"""
    print(f"Running all alert triggers with intensity {intensity}...")
    
    # Scale operations based on intensity
    operations = max(1, intensity // 2)
    
    for _ in range(operations):
        # HTTP request with suspicious user agent
        send_suspicious_user_agent(target_ip)
        time.sleep(1)
        
        # HTTP request with malicious payload
        send_malicious_http_request(target_ip, payload=random.choice(SUSPICIOUS_PAYLOADS))
        time.sleep(1)
        
        # Send moderate severity alert traffic
        send_moderate_alert_traffic(target_ip)
        time.sleep(1)
        
        # Spoofed packet from malicious IP
        spoof_malicious_ip(target_ip)
        time.sleep(1)
        
        # DNS query for malicious domain
        query_malicious_domain(dns_server)
        time.sleep(1)
    
    # Generate high traffic volume if intensity is high enough
    if intensity >= 5:
        generate_high_packet_rate(target_ip, packet_count=intensity * 300, duration=5)
    
    print("Alert triggering complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trigger alerts in Network Monitor by generating suspicious traffic ONLY to local IP")
    parser.add_argument("--target", type=str, help="Target IP address (IGNORED - local IP is always used for safety)")
    parser.add_argument("--dns", type=str, help="DNS server IP (IGNORED - local IP is always used for safety)")
    parser.add_argument("--intensity", type=int, default=5, help="Intensity of traffic generation (1-10, default: 5)")
    parser.add_argument("--high-traffic", action="store_true", help="Generate high traffic volume to trigger anomaly detection")
    parser.add_argument("--malicious-ip", action="store_true", help="Spoof traffic from known malicious IPs")
    parser.add_argument("--malicious-domain", action="store_true", help="Send DNS queries for known malicious domains")
    parser.add_argument("--suspicious-agent", action="store_true", help="Send HTTP requests with suspicious user agents")
    parser.add_argument("--all", action="store_true", help="Run all alert triggers")
    
    args = parser.parse_args()
    
    # ALWAYS use local IP as target and DNS server for safety
    local_ip = get_local_ip()
    target_ip = local_ip
    dns_server = local_ip
    
    # Show warning if user tried to provide target or DNS server
    if args.target:
        print(f"WARNING: Ignoring provided target IP {args.target} - using local IP {local_ip} for safety")
    if args.dns:
        print(f"WARNING: Ignoring provided DNS server {args.dns} - using local IP {local_ip} for safety")
        
    print(f"Alert Trigger Script (LOCAL IP VERSION)")
    print(f"====================================")
    print(f"Target IP: {target_ip} (using local IP for safety)")
    print(f"DNS Server: {dns_server} (using local IP for safety)")
    print(f"Intensity: {args.intensity}")
    print(f"====================================")
    
    # Execute selected operations
    if args.all:
        run_all_triggers(target_ip, dns_server, args.intensity)
    else:
        if args.high_traffic:
            generate_high_packet_rate(target_ip, packet_count=args.intensity * 300)
        if args.malicious_ip:
            for _ in range(args.intensity):
                spoof_malicious_ip(target_ip)
                time.sleep(0.5)
        if args.malicious_domain:
            for _ in range(args.intensity):
                query_malicious_domain(dns_server)
                time.sleep(0.5)
        if args.suspicious_agent:
            for _ in range(args.intensity):
                send_suspicious_user_agent(target_ip)
                time.sleep(0.5)
        
        # If no specific operation was selected, run all with low intensity
        if not any([args.high_traffic, args.malicious_ip, args.malicious_domain, args.suspicious_agent]):
            print("No specific operation selected. Running all triggers with low intensity...")
            run_all_triggers(target_ip, dns_server, max(1, args.intensity // 2))
