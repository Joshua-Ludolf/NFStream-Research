def load_threat_intelligence():
    """Load known malicious IPs, domains, and patterns"""
    threat_data = {
        "ips": [
            "192.168.1.100", "10.0.0.99", "203.0.113.0", "198.51.100.0", "192.0.2.0"
        ],
        "domains": [
            "malware.example.com", "phishing.test", "evil.local"
        ],
        "patterns": [
            "' OR 1=1 --", "1'; DROP TABLE users; --", "<script>alert('XSS')</script>",
            "javascript:alert('XSS')", "| cat /etc/passwd", "; powershell.exe -Command 'Get-Process'",
            "zgrab scanner detected", "nikto scan in progress"
        ]
    }
    return threat_data
