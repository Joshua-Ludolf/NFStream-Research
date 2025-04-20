# filepath: c:\Users\Joshu\Downloads\Computer Security\NFStream-Research\GUI\threat_intelligence.py
import os
import re

def load_threat_intelligence():
    """Load known malicious IPs, domains, file hashes and patterns from multiple sources"""
    # Initialize threat collections
    threat_data = {
        "threat_ips": set([
            "192.168.1.100",  # Example malicious IP
            "10.0.0.99",      # Example malicious IP
            "203.0.113.0",    # Example from TEST-NET-3 block
            "198.51.100.0",   # Example from TEST-NET-2 block
            "192.0.2.0"       # Example from TEST-NET-1 block
        ]),
        
        "threat_domains": set([
            "malware.example.com",
            "phishing.test",
            "evil.local"
        ]),
        
        "threat_file_hashes": set(),
        
        "suspicious_patterns": [
            "' OR 1=1 --", 
            "1'; DROP TABLE users; --",
            "<script>alert\\('XSS'\\)</script>",
            "javascript:alert\\('XSS'\\)",
            "\\| cat /etc/passwd",
            "; powershell\\.exe -Command 'Get-Process'",
            "zgrab scanner detected",
            "nikto scan in progress",
            "[a-f0-9]{64}"  # Match for hash-like strings
        ],
        
        "suspicious_user_agents": [
            "zgrab/0.x",
            "sqlmap/1.3.10",
            "Nikto/2.1.5",
            "masscan/1.0",
            "gobuster/3.1.0",
            "Nmap Scripting Engine"
        ],
        
        "moderate_suspicious_payloads": [
            "admin' --",
            "SELECT * FROM users",
            "<img src=x onerror=console.log(1)>",
            "default_password",
            "system32\\drivers",
            "port scan detected",
            ".bat.txt",
            ".ps1.jpg",
            "net user administrator",
            "ipconfig /all"
        ]
    }
    
    # Try to load additional threat data from files
    load_threat_files(threat_data)
    
    print(f"Loaded {len(threat_data['threat_ips'])} malicious IPs")
    print(f"Loaded {len(threat_data['threat_domains'])} malicious domains")
    print(f"Loaded {len(threat_data['threat_file_hashes'])} malicious file hashes")
    print(f"Loaded {len(threat_data['suspicious_patterns'])} suspicious patterns")
    
    return threat_data

def load_threat_files(threat_data):
    """Load threat intelligence from local files"""
    # Define paths to look for threat files
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    threat_dirs = [
        os.path.join(base_dir, "threat_intel"),
        os.path.join(base_dir, "data", "threats"),
        os.path.join(base_dir)
    ]
    
    # Look for common threat files
    for threat_dir in threat_dirs:
        if not os.path.exists(threat_dir):
            continue
            
        # Try to load IP blocklists
        ip_files = ["malicious_ips.txt", "blocklist.txt", "ip_blacklist.txt"]
        for ip_file in ip_files:
            file_path = os.path.join(threat_dir, ip_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            threat_data["threat_ips"].add(line)
                except Exception as e:
                    print(f"Error loading IP file {file_path}: {e}")
        
        # Try to load domain blocklists
        domain_files = ["malicious_domains.txt", "domain_blacklist.txt"]
        for domain_file in domain_files:
            file_path = os.path.join(threat_dir, domain_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            threat_data["threat_domains"].add(line)
                except Exception as e:
                    print(f"Error loading domain file {file_path}: {e}")
        
        # Try to load file hash blocklists
        hash_files = ["malicious_hashes.txt", "hash_blacklist.txt"]
        for hash_file in hash_files:
            file_path = os.path.join(threat_dir, hash_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            threat_data["threat_file_hashes"].add(line)
                except Exception as e:
                    print(f"Error loading hash file {file_path}: {e}")
                    
        # Try to load regex patterns
        pattern_files = ["suspicious_patterns.txt", "regex_patterns.txt"]
        for pattern_file in pattern_files:
            file_path = os.path.join(threat_dir, pattern_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if not line or line.startswith('#'):
                                continue
                            # Validate regex
                            try:
                                re.compile(line)
                                threat_data["suspicious_patterns"].append(line)
                            except re.error:
                                print(f"Invalid regex pattern: {line}")
                except Exception as e:
                    print(f"Error loading pattern file {file_path}: {e}")
    
    return threat_data
