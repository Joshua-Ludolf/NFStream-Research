import tkinter as tk
from tkinter import Tk, ttk, messagebox
import threading
import os
import sys
from GUI.tabs.flows_tab import FlowsTab
from GUI.tabs.packets_tab import PacketsTab
from GUI.tabs.alerts_tab import AlertsTab
from GUI.tabs.config_tab import ConfigTab
from GUI.threat_intelligence import load_threat_intelligence
from GUI.monitoring import start_monitoring, stop_monitoring, set_app_reference
from GUI.responses import block_ip, unblock_ip

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-time Network Detection and Response System")
        self.root.geometry("1200x800")

        # Initialize variables
        self.is_monitoring = False
        self.blocked_ips = set()  # Track blocked IPs
        self.malicious_ips = set()  # Track malicious IPs
        self.threat_data = load_threat_intelligence()
        self.monitor_thread = None
        
        # Setup the hardcoded network interface
        self.setup_interface()
        
        # Add from threat data to threat sets if available
        if 'threat_ips' in self.threat_data:
            self.threat_ips = self.threat_data['threat_ips']
        else:
            self.threat_ips = set()
            
        if 'threat_domains' in self.threat_data:
            self.threat_domains = self.threat_data['threat_domains']
        else:
            self.threat_domains = set()
        
        # Initialize suspicious patterns
        self.suspicious_user_agents = [
            "zgrab/0.x",
            "sqlmap/1.3.10",
            "Nikto/2.1.5",
            "masscan/1.0",
            "gobuster/3.1.0",
            "Nmap Scripting Engine"
        ]
        
        self.moderate_suspicious_payloads = [
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
        
        self.suspicious_patterns = [
            "' OR 1=1 --", 
            "1'; DROP TABLE users; --",
            "<script>alert\\('XSS'\\)</script>",
            "javascript:alert\\('XSS'\\)",
            "\\| cat /etc/passwd",
            "; powershell\\.exe -Command 'Get-Process'",
            "zgrab scanner detected",
            "nikto scan in progress",
            "[a-f0-9]{64}"
        ]
            
        # Traffic anomaly thresholds
        self.thresholds = {
            "max_packets_per_second": 1000,
            "max_connections_per_minute": 100,
            "max_dns_queries_per_minute": 50,
            "max_failed_connections": 10
        }
        
        # Setup UI
        self.setup_ui()
        
        # Set up protocol handlers
        self.protocol_map = {
            0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 
            5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 
            17: "UDP", 58: "ICMPv6", 47: "GRE", 
            50: "ESP", 51: "AH", 
            # Add more as needed
        }
        
        # Provide a reference to this app to the monitoring module
        set_app_reference(self)

    def setup_interface(self):
        """Set up the fixed interface config using the hardcoded values"""
        # Use specific hardcoded interface from original gui.py
        self.interface = {
            'nfstream_name': "Intel(R) Wi-Fi 6 AX201 160MHz",
            'pyshark_name': "Wi-Fi",
            'scapy_name': "Intel(R) Wi-Fi 6 AX201 160MHz",
            'friendly_name': "Wi-Fi Interface"
        }
        
        # For backward compatibility with existing code
        self.interface_info = {"Wi-Fi": self.interface['friendly_name']}
        
        print(f"Using hardcoded interface: {self.interface['friendly_name']}")
        print(f"  NFStream name: {self.interface['nfstream_name']}")
        print(f"  PyShark name: {self.interface['pyshark_name']}")
        print(f"  Scapy name: {self.interface['scapy_name']}")

    def setup_ui(self):
        """Set up the user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tab instances with the class-based approach
        self.flows_tab = FlowsTab(self.notebook, self.root, self)
        self.packets_tab = PacketsTab(self.notebook, self.root, self)
        self.alerts_tab = AlertsTab(self.notebook, self.root, self)
        self.config_tab = ConfigTab(self.notebook, self.root, self)

        # Add tab frames to the notebook
        self.notebook.add(self.flows_tab.flows_tab, text="Network Flows")
        self.notebook.add(self.packets_tab.packets_tab, text="Packet Analysis")
        self.notebook.add(self.alerts_tab.alerts_tab, text="Alerts & Response")
        self.notebook.add(self.config_tab.config_tab, text="Configuration")
        
        # Create control panel at the bottom
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Display the fixed interface info
        ttk.Label(control_frame, text=f"Interface: {self.interface['friendly_name']}").pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.start_stop_button = ttk.Button(control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_stop_button.pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.status_var = tk.StringVar(master=self.root, value="Ready")
        ttk.Label(control_frame, textvariable=self.status_var).pack(side=tk.RIGHT, padx=5)

    def toggle_monitoring(self):
        """Start or stop the monitoring process"""
        if self.is_monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start the monitoring process"""
        interface = "Wi-Fi"  # Use the hardcoded interface key
        
        # Update UI
        self.is_monitoring = True
        self.start_stop_button.config(text="Stop Monitoring")
        self.status_var.set("Monitoring Active")
        
        # Call the monitoring module's start function in a separate thread
        self.monitor_thread = threading.Thread(
            target=start_monitoring,
            args=(interface,)
        )
        self.monitor_thread.daemon = True  # Thread will exit when main app exits
        self.monitor_thread.start()
        
        print(f"Started monitoring on interface {interface}")
        
    def stop_monitoring(self):
        """Stop the monitoring process"""
        # Update UI
        self.is_monitoring = False
        self.start_stop_button.config(text="Start Monitoring")
        self.status_var.set("Ready")
        
        # Call the monitoring module's stop function
        stop_monitoring()
        
        # Wait for monitoring thread to finish if it exists
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)  # Wait up to 2 seconds
            
        print("Stopped monitoring")

    def add_alert(self, alert_details):
        """Add an alert to the alerts tab"""
        if hasattr(self.alerts_tab, 'add_alert'):
            self.alerts_tab.add_alert(alert_details)
    
    def update_flow_ui(self, flow, risk_score):
        """Update the flow UI with new flow data"""
        if hasattr(self.flows_tab, 'update_flow_ui'):
            self.flows_tab.update_flow_ui(flow, risk_score)
    
    def add_packet_to_ui(self, packet, packet_data, packet_id):
        """Add a packet to the packets UI"""
        if hasattr(self.packets_tab, 'add_packet_to_ui'):
            self.packets_tab.add_packet_to_ui(packet, packet_data, packet_id)
    
    def block_ip(self, ip, reason):
        """Block an IP address"""
        if hasattr(self.alerts_tab, 'block_ip'):
            return self.alerts_tab.block_ip(ip, reason)
        return False
        
    def check_threat_indicators(self, ip=None, domain=None, file_hash=None, content=None):
        """Check if indicators match known threats"""
        results = []
        
        # Check IP
        if ip and ip in self.threat_ips:
            results.append({
                "type": "IP",
                "value": ip,
                "threat_level": "High", 
                "source": "Threat Intelligence"
            })
        
        # Check domain
        if domain and domain in self.threat_domains:
            results.append({
                "type": "Domain",
                "value": domain,
                "threat_level": "High", 
                "source": "Threat Intelligence"
            })
        
        # Check file hash
        if file_hash and hasattr(self, 'threat_file_hashes') and file_hash in self.threat_file_hashes:
            results.append({
                "type": "File Hash",
                "value": file_hash,
                "threat_level": "High", 
                "source": "Threat Database"
            })
        
        # Check content against patterns
        if content:
            import re
            for pattern in self.suspicious_patterns:
                try:
                    if re.search(pattern, content):
                        results.append({
                            "type": "Content",
                            "value": pattern,
                            "threat_level": "Medium", 
                            "source": "Pattern Matching"
                        })
                except:
                    pass  # Skip invalid regex patterns
        
        return results

if __name__ == "__main__":
    root = Tk()
    app = NetworkMonitor(root)
    root.mainloop()
