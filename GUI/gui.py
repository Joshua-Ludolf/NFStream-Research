from GUI.__init__ import *

class NetworkMonitor:
    """
    A real-time network detection and response system using NFStream, Pyshark, and Scapy.
    - NFStream: Flow processing and basic detection
    - Pyshark: Detailed packet analysis
    - Scapy: Response mechanism for malicious traffic
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Real-time Network Detection and Response System")
        self.root.geometry("1200x800")
        
        # Initialize variables
        self.is_monitoring = False
        self.monitor_thread = None
        self.interface = None
        self.interface_info = {}  # Will store mapping between friendly names and technical identifiers
        self.malicious_ips = set()
        self.blocked_ips = set()
        
        # Load threat intelligence
        self.load_threat_intelligence()
        
        self.setup_ui()
    
    def load_threat_intelligence(self):
        """Load known malicious IPs and patterns from multiple sources"""
        # Initialize threat collections
        self.threat_ips = set()
        self.threat_domains = set()
        self.threat_file_hashes = set()
        self.suspicious_patterns = []
        
        # Load built-in threat data (fallback)
        self._load_builtin_threats()
        
        # Try to load from local files
        try:
            self._load_threat_files()
        except Exception as e:
            print(f"Warning: Could not load threat files: {e}")
        
        # Set traffic anomaly thresholds
        self.thresholds = {
            "max_packets_per_second": 1000,
            "max_connections_per_minute": 100,
            "max_dns_queries_per_minute": 50,
            "max_failed_connections": 10
        }
        
        print(f"Loaded {len(self.threat_ips)} malicious IPs")
        print(f"Loaded {len(self.threat_domains)} malicious domains")
        print(f"Loaded {len(self.threat_file_hashes)} malicious file hashes")
        print(f"Loaded {len(self.suspicious_patterns)} suspicious patterns")
    
    def _load_builtin_threats(self):
        """Load built-in threat data as a fallback"""
        # Example malicious IPs (for demo purposes)
        builtin_ips = {
            "192.168.1.100",  # Example malicious IP
            "10.0.0.99",      # Example malicious IP
            "203.0.113.0",    # Example from TEST-NET-3 block
            "198.51.100.0",   # Example from TEST-NET-2 block
            "192.0.2.0"       # Example from TEST-NET-1 block
        }
        self.threat_ips.update(builtin_ips)
        
        # Example malicious domains (for demo purposes)
        builtin_domains = {
            "malware.example.com",
            "phishing.test",
            "evil.local"
        }
        self.threat_domains.update(builtin_domains)
        
        # Example malicious file hashes (for demo purposes)
        builtin_hashes = {
            "44d88612fea8a8f36de82e1278abb02f",  # Example MD5
            "3395856ce81f2b7382dee72602f798b642f14140",  # Example SHA1
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # Example SHA256
        }
        self.threat_file_hashes.update(builtin_hashes)
        
        # Common suspicious patterns (regex)
        builtin_patterns = [
            # Command and control patterns
            r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",  # Possible exfil or C2 beaconing
            # SQL injection patterns
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            # XSS patterns
            r"<script>|javascript:|onerror=|onload=",
            # Common malware user agents
            r"(zgrab)|(Nmap Scripting Engine)|(sqlmap)|(nikto)|(masscan)|(gobuster)",
            # Common shell commands in URLs
            r"(\/bin\/bash)|(\/bin\/sh)|(cmd\.exe)|(powershell\.exe)",
            # Common malware file extensions
            r"\.(exe|dll|bat|cmd|ps1|vbs|js)$"
        ]
        self.suspicious_patterns.extend(builtin_patterns)
    
    def _load_threat_files(self):
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
                                # Try to validate as IP
                                try:
                                    ipaddress.ip_address(line)
                                    self.threat_ips.add(line)
                                except ValueError:
                                    pass  # Not a valid IP
                    except Exception as e:
                        print(f"Error loading IP file {file_path}: {e}")
            
            # Try to load domain blocklists
            domain_files = ["malicious_domains.txt", "domain_blocklist.txt"]
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
                                self.threat_domains.add(line)
                    except Exception as e:
                        print(f"Error loading domain file {file_path}: {e}")
            
            # Try to load regex pattern files
            pattern_files = ["regex_patterns.txt", "detection_patterns.txt"]
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
                                    self.suspicious_patterns.append(line)
                                except re.error:
                                    print(f"Invalid regex pattern: {line}")
                    except Exception as e:
                        print(f"Error loading pattern file {file_path}: {e}")
    
    def check_threat_indicators(self, ip=None, domain=None, file_hash=None, content=None):
        """Check if indicators match known threats"""
        results = []
        
        # Check IP
        if ip and ip in self.threat_ips:
            results.append(("high", f"Known malicious IP: {ip}"))
        
        # Check domain
        if domain and domain in self.threat_domains:
            results.append(("high", f"Known malicious domain: {domain}"))
        
        # Check file hash
        if file_hash and file_hash in self.threat_file_hashes:
            results.append(("high", f"Known malicious file hash: {file_hash}"))
        
        # Check content against patterns
        if content:
            for pattern in self.suspicious_patterns:
                try:
                    if re.search(pattern, content):
                        results.append(("medium", f"Suspicious pattern match: {pattern}"))
                except Exception:
                    pass  # Skip failed pattern matches
        
        return results
    
    def setup_ui(self):
        """Set up the user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.flows_tab = ttk.Frame(self.notebook)
        self.packets_tab = ttk.Frame(self.notebook)
        self.alerts_tab = ttk.Frame(self.notebook)
        self.config_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.flows_tab, text="Network Flows")
        self.notebook.add(self.packets_tab, text="Packet Analysis")
        self.notebook.add(self.alerts_tab, text="Alerts & Response")
        self.notebook.add(self.config_tab, text="Configuration")
          # Control panel frame at the top
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Get interface info but don't display dropdown
        self.get_interface_info()
        
        # Create a fixed Wi-Fi interface with hardcoded values
        self.interface = {
            'nfstream_name': "Intel(R) Wi-Fi 6 AX201 160MHz",
            'pyshark_name': "Wi-Fi",
            'scapy_name': "Wi-Fi",
            'mac_address': "Unknown",
            'ip_address': "Unknown"
        }
        
        # Show which interface we're using
        ttk.Label(self.control_frame, text="Using Wi-Fi Interface").pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.start_button = ttk.Button(self.control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        # Status label
        self.status_label = ttk.Label(self.control_frame, text="Status: Idle")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Setup tabs content
        self.setup_flows_tab()
        self.setup_packets_tab()
        self.setup_alerts_tab()
        self.setup_config_tab()
    
    def setup_flows_tab(self):
        """Set up the Network Flows tab with NFStream data"""
        # Create frame for filters
        filter_frame = ttk.Frame(self.flows_tab)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.flow_filter_entry = ttk.Entry(filter_frame, width=40)
        self.flow_filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.apply_flow_filter).pack(side=tk.LEFT, padx=5)
        
        # Create treeview for flows
        self.flows_tree = ttk.Treeview(self.flows_tab)
        self.flows_tree["columns"] = ("time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packets", "bytes", "duration", "risk")
        
        # Configure columns
        for col in self.flows_tree["columns"]:
            self.flows_tree.heading(col, text=col.replace("_", " ").title())
            width = 100
            if col in ["src_ip", "dst_ip"]:
                width = 120
            elif col == "time":
                width = 150
            self.flows_tree.column(col, width=width)
        
        # Add scrollbars
        flow_y_scroll = ttk.Scrollbar(self.flows_tab, orient="vertical", command=self.flows_tree.yview)
        flow_x_scroll = ttk.Scrollbar(self.flows_tab, orient="horizontal", command=self.flows_tree.xview)
        self.flows_tree.configure(yscrollcommand=flow_y_scroll.set, xscrollcommand=flow_x_scroll.set)
        
        # Pack everything
        flow_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        flow_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.flows_tree.pack(fill=tk.BOTH, expand=True)
    
    def setup_packets_tab(self):
        """Set up the Packet Analysis tab with Pyshark data"""
        # Split view with packet list on top and packet details on bottom
        packets_paned = ttk.PanedWindow(self.packets_tab, orient=tk.VERTICAL)
        packets_paned.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for packet list
        packet_list_frame = ttk.Frame(packets_paned)
        packets_paned.add(packet_list_frame, weight=1)
        
        # Bottom frame for packet details
        packet_detail_frame = ttk.Frame(packets_paned)
        packets_paned.add(packet_detail_frame, weight=1)
        
        # Packet list treeview
        self.packets_tree = ttk.Treeview(packet_list_frame)
        self.packets_tree["columns"] = ("time", "src", "dst", "protocol", "length", "info")
        
        # Configure columns
        for col in self.packets_tree["columns"]:
            self.packets_tree.heading(col, text=col.title())
            width = 100
            if col == "info":
                width = 300
            elif col in ["src", "dst"]:
                width = 120
            self.packets_tree.column(col, width=width)
        
        # Scrollbars for packet list
        packet_y_scroll = ttk.Scrollbar(packet_list_frame, orient="vertical", command=self.packets_tree.yview)
        packet_x_scroll = ttk.Scrollbar(packet_list_frame, orient="horizontal", command=self.packets_tree.xview)
        self.packets_tree.configure(yscrollcommand=packet_y_scroll.set, xscrollcommand=packet_x_scroll.set)
        
        packet_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        packet_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.packets_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection event to show details
        self.packets_tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
        # Packet details text area
        self.packet_details_text = scrolledtext.ScrolledText(packet_detail_frame)
        self.packet_details_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_alerts_tab(self):
        """Set up the Alerts & Response tab"""
        # Split view with alerts on top and blocked IPs on bottom
        alerts_paned = ttk.PanedWindow(self.alerts_tab, orient=tk.VERTICAL)
        alerts_paned.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for alerts
        alerts_frame = ttk.Frame(alerts_paned)
        alerts_paned.add(alerts_frame, weight=2)
        
        # Bottom frame for blocked IPs
        blocked_frame = ttk.Frame(alerts_paned)
        alerts_paned.add(blocked_frame, weight=1)
        
        # Alerts list
        ttk.Label(alerts_frame, text="Security Alerts").pack(anchor=tk.W, padx=10, pady=5)
        
        self.alerts_tree = ttk.Treeview(alerts_frame)
        self.alerts_tree["columns"] = ("time", "severity", "source", "destination", "alert_type", "details")
        
        # Configure columns
        for col in self.alerts_tree["columns"]:
            self.alerts_tree.heading(col, text=col.replace("_", " ").title())
            width = 100
            if col == "details":
                width = 300
            self.alerts_tree.column(col, width=width)
        
        # Add scrollbars
        alerts_y_scroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        alerts_x_scroll = ttk.Scrollbar(alerts_frame, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=alerts_y_scroll.set, xscrollcommand=alerts_x_scroll.set)
        
        alerts_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        alerts_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Manual response controls
        response_frame = ttk.Frame(alerts_frame)
        response_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(response_frame, text="Response Action:").pack(side=tk.LEFT)
        self.response_combobox = ttk.Combobox(response_frame, values=["Block IP", "Reset Connection", "Log Only"], width=15)
        self.response_combobox.pack(side=tk.LEFT, padx=5)
        self.response_combobox.set("Block IP")
        
        ttk.Button(response_frame, text="Execute", command=self.execute_response).pack(side=tk.LEFT, padx=5)
        
        # Blocked IPs
        ttk.Label(blocked_frame, text="Blocked IPs").pack(anchor=tk.W, padx=10, pady=5)
        
        self.blocked_tree = ttk.Treeview(blocked_frame)
        self.blocked_tree["columns"] = ("ip", "time_blocked", "reason")
        
        # Configure columns
        for col in self.blocked_tree["columns"]:
            self.blocked_tree.heading(col, text=col.replace("_", " ").title())
            width = 150
            if col == "reason":
                width = 300
            self.blocked_tree.column(col, width=width)
        
        # Add scrollbars
        blocked_y_scroll = ttk.Scrollbar(blocked_frame, orient="vertical", command=self.blocked_tree.yview)
        blocked_x_scroll = ttk.Scrollbar(blocked_frame, orient="horizontal", command=self.blocked_tree.xview)
        self.blocked_tree.configure(yscrollcommand=blocked_y_scroll.set, xscrollcommand=blocked_x_scroll.set)
        
        blocked_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        blocked_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.blocked_tree.pack(fill=tk.BOTH, expand=True)
        
        # Unblock button
        ttk.Button(blocked_frame, text="Unblock Selected", command=self.unblock_selected_ip).pack(anchor=tk.E, padx=10, pady=5)
    
    def setup_config_tab(self):
        """Set up the Configuration tab"""
        # Create frames for different config sections
        detection_frame = ttk.LabelFrame(self.config_tab, text="Detection Configuration")
        detection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        response_frame = ttk.LabelFrame(self.config_tab, text="Response Configuration")
        response_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Detection thresholds
        ttk.Label(detection_frame, text="Max packets per second:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_pps_var = tk.StringVar(value=str(self.thresholds["max_packets_per_second"]))
        ttk.Entry(detection_frame, textvariable=self.max_pps_var, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max connections per minute:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_conn_var = tk.StringVar(value=str(self.thresholds["max_connections_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_conn_var, width=10).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max DNS queries per minute:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_dns_var = tk.StringVar(value=str(self.thresholds["max_dns_queries_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_dns_var, width=10).grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max failed connections:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_failed_var = tk.StringVar(value=str(self.thresholds["max_failed_connections"]))
        ttk.Entry(detection_frame, textvariable=self.max_failed_var, width=10).grid(row=3, column=1, padx=5, pady=5)
        
        # Custom malicious IP input
        ttk.Label(detection_frame, text="Add malicious IP:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_malicious_ip = ttk.Entry(detection_frame, width=20)
        self.new_malicious_ip.grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(detection_frame, text="Add", command=self.add_malicious_ip).grid(row=4, column=2, padx=5, pady=5)
        
        # Response options
        ttk.Label(response_frame, text="Default response:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.default_response_var = tk.StringVar(value="Block IP")
        ttk.Combobox(response_frame, textvariable=self.default_response_var, 
                    values=["Block IP", "Reset Connection", "Log Only"], 
                    state="readonly").grid(row=0, column=1, padx=5, pady=5)
        
        self.auto_response_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(response_frame, text="Auto-respond to threats", 
                       variable=self.auto_response_var).grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save button
        ttk.Button(self.config_tab, text="Save Configuration", command=self.save_configuration).pack(pady=10)
    
    def get_interface_info(self):
        """Get detailed information about network interfaces with friendly names"""
        self.interface_info = {}  # Reset interface info
        
        try:
            # Use psutil to get network interfaces - already imported in __init__.py
            for iface, addrs in psutil.net_if_addrs().items():
                # Skip non-active interfaces
                if not self.is_interface_up(iface, addrs):
                    continue
                
                # Get IPv4 and MAC addresses
                ip_addr = "No IP"
                mac_addr = "Unknown"
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        ip_addr = addr.address
                    elif addr.family == psutil.AF_LINK:  # MAC address
                        mac_addr = addr.address
                
                # Build friendly name
                friendly_name = f"{self.get_interface_friendly_name(iface)} ({iface}: {ip_addr})"
                
                # Store mapping between friendly name and actual identifiers
                self.interface_info[friendly_name] = {
                    'scapy_name': iface,          # Name for Scapy
                    'pyshark_name': iface,        # Name for PyShark
                    'nfstream_name': iface,       # Name for NFStream
                    'mac_address': mac_addr,
                    'ip_address': ip_addr
                }
                
                # Special case for Windows - PyShark often uses "Wi-Fi" instead of interface name
                if "wireless" in iface.lower() or "wi-fi" in iface.lower() or "wlan" in iface.lower():
                    self.interface_info[friendly_name]['pyshark_name'] = "Wi-Fi"
                elif "ethernet" in iface.lower() or "eth" in iface.lower():
                    self.interface_info[friendly_name]['pyshark_name'] = "Ethernet"
                
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            # Fallback to default interfaces
            hostname = socket.gethostname()
            try:
                local_ip = socket.gethostbyname(hostname)
            except:
                local_ip = "Unknown"
            
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                  for elements in range(0, 8*6, 8)][::-1])
            
            self.interface_info = {
                "Default Network Interface": {
                    'scapy_name': None, 
                    'pyshark_name': None, 
                    'nfstream_name': None,
                    'mac_address': mac,
                    'ip_address': local_ip
                }
            }
    
    def get_interface_friendly_name(self, iface):
        """Convert technical interface name to a friendly name"""
        friendly_names = {
            'eth': 'Ethernet',
            'en': 'Ethernet',
            'wlan': 'Wi-Fi',
            'wlp': 'Wi-Fi',
            'wl': 'Wi-Fi',
            'ppp': 'Cellular',
            'usb': 'USB',
            'tun': 'VPN Tunnel',
            'vmnet': 'Virtual',
            'docker': 'Docker',
            'br': 'Bridge',
            'veth': 'Virtual Ethernet'
        }
        
        # Try to find a match at the beginning of the interface name
        for prefix, name in friendly_names.items():
            if iface.startswith(prefix):
                return name
        
        # Special case for Windows-style interface names
        if 'wireless' in iface.lower() or 'wi-fi' in iface.lower():
            return 'Wi-Fi'
        elif 'ethernet' in iface.lower() or 'local area connection' in iface.lower():
            return 'Ethernet'
        
        # If no match found, use the technical name
        return f'Interface'
    
    def is_interface_up(self, iface, addrs=None):
        """Check if an interface is up and active"""
        try:
            if addrs is None:
                addrs = psutil.net_if_addrs().get(iface, [])
            
            # Check if interface has an IPv4 address
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return True
            return False
        except Exception:
            return False
    
    def toggle_monitoring(self):
        """Start or stop the monitoring process"""
        if self.is_monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    def start_monitoring(self):
        """Start the network monitoring process"""
        # Interface is already configured as Wi-Fi
        
        # Special handling for different tools
        print(f"Starting monitoring with interfaces:")
        print(f"  NFStream: {self.interface['nfstream_name']}")
        print(f"  PyShark: {self.interface['pyshark_name']}")
        print(f"  Scapy: {self.interface['scapy_name']}")
        
        self.is_monitoring = True
        self.start_button.config(text="Stop Monitoring")
        self.status_label.config(text=f"Status: Monitoring {self.interface['nfstream_name']}")
        
        # Clear existing data
        self.flows_tree.delete(*self.flows_tree.get_children())
        self.packets_tree.delete(*self.packets_tree.get_children())
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the network monitoring process"""
        self.is_monitoring = False
        self.start_button.config(text="Start Monitoring")
        self.status_label.config(text="Status: Idle")
        
        # Wait for thread to finish
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def monitoring_loop(self):
        """Main monitoring loop running in a separate thread"""
        try:
            # Start NFStream for flow analysis
            nfstream_thread = threading.Thread(target=self.nfstream_monitor)
            nfstream_thread.daemon = True
            nfstream_thread.start()
            
            # Start Pyshark for packet analysis
            pyshark_thread = threading.Thread(target=self.pyshark_monitor)
            pyshark_thread.daemon = True
            pyshark_thread.start()
            
            # Wait for monitoring to stop
            while self.is_monitoring:
                time.sleep(0.5)
        except Exception as e:
            print(f"Error in monitoring loop: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Monitoring error: {str(e)}"))
            self.root.after(0, self.stop_monitoring)
    
    def nfstream_monitor(self):
        """NFStream monitoring process"""
        try:
            interface_name = self.interface['nfstream_name']
            print(f"Starting NFStream monitoring on interface: {interface_name}")
            
            # Create a NFStreamer instance for real-time monitoring
            streamer = NFStreamer(source=interface_name, 
                                active_timeout=1, 
                                idle_timeout=30,
                                accounting_mode=0)  # 0 = online mode
            
            # Process flows
            for flow in streamer:
                if not self.is_monitoring:
                    break
                
                # Process the flow for security analysis
                risk_score = self.analyze_flow(flow)
                
                # Update the UI
                self.root.after(0, lambda f=flow, rs=risk_score: self.update_flow_ui(f, rs))
                
        except Exception as e:
            print(f"Error in NFStream monitoring: {e}")
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"NFStream error: {msg}"))
    
    def pyshark_monitor(self):
        """Pyshark monitoring process for detailed packet analysis"""
        try:
            interface_name = self.interface['pyshark_name']
            print(f"Starting PyShark monitoring on interface: {interface_name}")

            # Create a Pyshark capture for detailed packet analysis
            capture = pyshark.LiveCapture(interface=interface_name)
            
            # Set up a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run the capture with the new event loop
            loop.run_until_complete(self._capture_packets(capture))
            loop.close()

        except Exception as e:
            print(f"Error in Pyshark monitoring: {e}")
            error_msg = str(e)
            if self.is_monitoring:  # Only show error if still monitoring
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"Pyshark error: {msg}"))
    
    async def _capture_packets(self, capture):
        """Async helper for PyShark packet capture"""
        try:
            async for packet in capture.sniff_continuously():
                if not self.is_monitoring:
                    break
                self.analyze_packet(packet)
        except Exception as e:
            print(f"Error in async packet capture: {e}")
            if self.is_monitoring:
                error_msg = str(e)
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"Packet capture error: {msg}"))
    
    def analyze_packet(self, packet):
        """Analyze a packet for security issues and update UI"""
        try:
            # Extract packet information
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # Get source and destination
            src = "Unknown"
            dst = "Unknown"
            protocol = packet.highest_layer
            length = packet.length
            info = self.get_packet_summary(packet)
            
            # Extract IP addresses if available
            if hasattr(packet, 'ip'):
                src = packet.ip.src
                dst = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src = packet.ipv6.src
                dst = packet.ipv6.dst
            
            # Store packet for later reference
            packet_id = f"{timestamp}_{src}_{dst}"
            
            # Add to UI in main thread
            packet_data = (timestamp, src, dst, protocol, length, info)
            self.root.after(0, lambda p=packet, pd=packet_data, pid=packet_id: self.add_packet_to_ui(p, pd, pid))
            
            # Check packet payload for malicious content
            self.check_packet_payload(packet, src, dst)
            
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def add_packet_to_ui(self, packet, packet_data, packet_id):
        """Add packet to the UI"""
        if not self.is_monitoring:
            return
        
        # Add to tree
        item_id = self.packets_tree.insert("", "end", values=packet_data)
        
        # Store packet reference
        self.packets_tree.item(item_id, tags=(packet_id,))
        
        # Auto-scroll to show latest
        self.packets_tree.see(item_id)
    
    def get_packet_summary(self, packet):
        """Generate a summary of the packet"""
        summary = packet.highest_layer
        
        # Add protocol-specific information
        if hasattr(packet, 'tcp'):
            flags = []
            if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1':
                flags.append('SYN')
            if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1':
                flags.append('ACK')
            if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                flags.append('FIN')
            if hasattr(packet.tcp, 'flags_rst') and packet.tcp.flags_rst == '1':
                flags.append('RST')
            
            flags_str = ' '.join(flags)
            summary = f"TCP {packet.tcp.srcport} → {packet.tcp.dstport} {flags_str}"
            
            if hasattr(packet, 'http'):
                if hasattr(packet.http, 'request_method'):
                    summary = f"HTTP {packet.http.request_method} {packet.http.request_uri}"
                elif hasattr(packet.http, 'response_code'):
                    summary = f"HTTP Response {packet.http.response_code}"
        
        elif hasattr(packet, 'udp'):
            summary = f"UDP {packet.udp.srcport} → {packet.udp.dstport}"
            
            if hasattr(packet, 'dns'):
                if hasattr(packet.dns, 'qry_name'):
                    summary = f"DNS Query for {packet.dns.qry_name}"
                elif hasattr(packet.dns, 'resp_name'):
                    summary = f"DNS Response for {packet.dns.resp_name}"
        
        return summary
    
    def check_packet_payload(self, packet, src_ip, dst_ip):
        """Check packet payload for malicious content"""
        try:
            # Look for suspicious patterns in the payload
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                payload = packet.tcp.payload
                
                # Check for suspicious patterns
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, payload):
                        # Found a suspicious pattern
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Malicious Payload",
                            "details": f"Suspicious pattern detected: {pattern}"
                        }
                        self.root.after(0, lambda a=alert_details: self.add_alert(a))
                        
                        # Auto-respond if enabled
                        if self.auto_response_var.get():
                            self.root.after(0, lambda ip=src_ip: self.block_ip(ip, "Suspicious payload"))
                        break
            
            # Check for HTTP suspicious user agents
            if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
                user_agent = packet.http.user_agent
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, user_agent):
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "Medium",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Suspicious User Agent",
                            "details": f"Suspicious user agent: {user_agent}"
                        }
                        self.root.after(0, lambda a=alert_details: self.add_alert(a))
        except Exception as e:
            print(f"Error checking packet payload: {e}")

    def show_packet_details(self, event):
        """Show detailed information about the selected packet"""
        selected_items = self.packets_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        packet_id = self.packets_tree.item(item_id, "tags")[0]
        
        # Clear previous details
        self.packet_details_text.delete(1.0, tk.END)
        
        # Get packet data
        values = self.packets_tree.item(item_id, "values")
        timestamp, src, dst, protocol, length, info = values
        
        # Display basic info
        self.packet_details_text.insert(tk.END, f"Time: {timestamp}\n")
        self.packet_details_text.insert(tk.END, f"Source: {src}\n")
        self.packet_details_text.insert(tk.END, f"Destination: {dst}\n")
        self.packet_details_text.insert(tk.END, f"Protocol: {protocol}\n")
        self.packet_details_text.insert(tk.END, f"Length: {length} bytes\n")
        self.packet_details_text.insert(tk.END, f"Info: {info}\n\n")
        
        # Would normally display more packet details here, but we don't have the
        # actual packet object stored. In a real implementation, we would store
        # packet objects or their string representations.
        self.packet_details_text.insert(tk.END, "Detailed protocol information would be displayed here.\n")
        self.packet_details_text.insert(tk.END, "This would include TCP/IP headers, payload samples, etc.")

    def add_alert(self, alert_details):
        """Add an alert to the alerts tab"""
        # Add to tree
        item_id = self.alerts_tree.insert("", 0, values=(
            alert_details["time"],
            alert_details["severity"],
            alert_details["source"],
            alert_details["destination"],
            alert_details["alert_type"],
            alert_details["details"]
        ))
        
        # Color code based on severity
        if alert_details["severity"] == "High":
            self.alerts_tree.item(item_id, tags=("high_severity",))
        elif alert_details["severity"] == "Medium":
            self.alerts_tree.item(item_id, tags=("medium_severity",))
        
        # Configure tag colors
        self.alerts_tree.tag_configure("high_severity", background="#ffcccc")
        self.alerts_tree.tag_configure("medium_severity", background="#ffffcc")
        
        # Switch to alerts tab to show new alert
        self.notebook.select(self.alerts_tab)
        
        # Play an alert sound
        self.root.bell()

    def block_ip(self, ip, reason):
        """Block an IP address"""
        if ip in self.blocked_ips:
            return  # Already blocked
        
        self.blocked_ips.add(ip)
        
        # Add to blocked list UI
        item_id = self.blocked_tree.insert("", "end", values=(
            ip,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            reason
        ))
        
        # Send TCP RST packets using Scapy to terminate connections
        try:
            # This would normally be implemented with actual Scapy code
            # to send RST packets to the malicious IP
            print(f"Blocking {ip} with RST packets")
            
            # In a real implementation, we would use Scapy to craft and send RST packets
            # Example (not actually executed here for safety):
            # pkt = IP(dst=ip)/TCP(flags="R", dport=range(1, 1024))
            # send(pkt, verbose=0)
        except Exception as e:
            print(f"Error blocking IP: {e}")

    def unblock_selected_ip(self):
        """Unblock the selected IP address"""
        selected_items = self.blocked_tree.selection()
        if not selected_items:
            messagebox.showinfo("Info", "No IP selected")
            return
        
        item_id = selected_items[0]
        ip = self.blocked_tree.item(item_id, "values")[0]
        
        # Remove from blocked set
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        
        # Remove from UI
        self.blocked_tree.delete(item_id)
        
        messagebox.showinfo("Unblock", f"IP {ip} has been unblocked")

    def execute_response(self):
        """Execute the selected response action for the selected alert"""
        # Get selected alert
        selected_alerts = self.alerts_tree.selection()
        if not selected_alerts:
            messagebox.showinfo("Info", "No alert selected")
            return
        
        # Get source IP from the selected alert
        alert_item = selected_alerts[0]
        src_ip = self.alerts_tree.item(alert_item, "values")[2]  # Source IP is in the 3rd column
        
        # Get selected response action
        action = self.response_combobox.get()
        
        # Execute the action
        if action == "Block IP":
            self.block_ip(src_ip, "Manual block from alert")
            messagebox.showinfo("Response", f"Blocked IP {src_ip}")
        elif action == "Reset Connection":
            # This would use Scapy to send RST packets
            messagebox.showinfo("Response", f"Reset connections from {src_ip}")
        elif action == "Log Only":
            messagebox.showinfo("Response", f"Logged activity from {src_ip}")

    def apply_flow_filter(self):
        """Apply filter to the flows view"""
        filter_text = self.flow_filter_entry.get().lower()
        if not filter_text:
            # Clear filter
            for item in self.flows_tree.get_children():
                self.flows_tree.item(item, tags=self.flows_tree.item(item, "tags"))
            return
        
        # Apply filter
        for item in self.flows_tree.get_children():
            values = self.flows_tree.item(item, "values")
            # Convert all values to string and check if filter text is in any of them
            if any(filter_text in str(value).lower() for value in values):
                # Keep this item visible
                self.flows_tree.item(item, tags=self.flows_tree.item(item, "tags"))
            else:
                # Hide this item by setting a "hidden" tag
                current_tags = self.flows_tree.item(item, "tags")
                if isinstance(current_tags, str):
                    current_tags = (current_tags,)
                self.flows_tree.item(item, tags=current_tags + ("hidden",))
        
        # Configure hidden tag to be invisible
        self.flows_tree.tag_configure("hidden", foreground="#ffffff", background="#ffffff")
    
    def add_malicious_ip(self):
        """Add a custom IP to the malicious IP list"""
        ip = self.new_malicious_ip.get().strip()
        if not ip:
            messagebox.showinfo("Info", "Please enter an IP address")
            return
            
        try:
            # Validate IP
            ipaddress.ip_address(ip)
            
            # Add to threat list
            self.threat_ips.add(ip)
            
            # Clear the entry field
            self.new_malicious_ip.delete(0, tk.END)
            
            # Show confirmation
            messagebox.showinfo("Success", f"Added {ip} to malicious IP list")
            print(f"Added malicious IP: {ip}")
            
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address format")
    
    def save_configuration(self):
        """Save the current configuration"""
        try:
            # Update thresholds from UI inputs
            self.thresholds["max_packets_per_second"] = int(self.max_pps_var.get())
            self.thresholds["max_connections_per_minute"] = int(self.max_conn_var.get())
            self.thresholds["max_dns_queries_per_minute"] = int(self.max_dns_var.get())
            self.thresholds["max_failed_connections"] = int(self.max_failed_var.get())
            
            # Show confirmation
            messagebox.showinfo("Configuration", "Settings saved successfully")
            print(f"Updated thresholds: {self.thresholds}")
            
        except ValueError as ve:
            messagebox.showerror("Error", "Please enter valid numbers for all thresholds")
            print(f"Configuration error: {ve}")
    
    def analyze_flow(self, flow):
        """Analyze a network flow for security issues"""
        risk_score = 0
        
        try:
            # Extract flow info
            src_ip = flow.src_ip if hasattr(flow, 'src_ip') else "Unknown"
            dst_ip = flow.dst_ip if hasattr(flow, 'dst_ip') else "Unknown"
            
            # Check for known malicious IPs
            if src_ip in self.threat_ips:
                risk_score += 80
                self.root.after(0, lambda: self.add_alert({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "High",
                    "source": src_ip,
                    "destination": dst_ip,
                    "alert_type": "Malicious Source IP",
                    "details": f"Connection from known malicious IP: {src_ip}"
                }))
            
            if dst_ip in self.threat_ips:
                risk_score += 80
                self.root.after(0, lambda: self.add_alert({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "High",
                    "source": src_ip,
                    "destination": dst_ip,
                    "alert_type": "Malicious Destination IP",
                    "details": f"Connection to known malicious IP: {dst_ip}"
                }))
            
            # Check for traffic anomalies
            if hasattr(flow, 'bidirectional_packets') and flow.bidirectional_packets > self.thresholds["max_packets_per_second"]:
                risk_score += 40
                self.root.after(0, lambda: self.add_alert({
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "Medium",
                    "source": src_ip,
                    "destination": dst_ip,
                    "alert_type": "Traffic Anomaly",
                    "details": f"High packet rate: {flow.bidirectional_packets} packets"
                }))
                
        except Exception as e:
            print(f"Error analyzing flow: {e}")
        
        # Cap risk score at 100
        return min(100, risk_score)
    
    def update_flow_ui(self, flow, risk_score):
        """Update the UI with flow information"""
        if not self.is_monitoring:
            return
            
        try:
            # Format timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Extract flow information safely with defaults
            src_ip = getattr(flow, 'src_ip', "Unknown")
            dst_ip = getattr(flow, 'dst_ip', "Unknown")
            protocol = getattr(flow, 'protocol', "Unknown")
            src_port = getattr(flow, 'src_port', "Unknown")
            dst_port = getattr(flow, 'dst_port', "Unknown")
            packets = getattr(flow, 'bidirectional_packets', 0)
            bytes_count = getattr(flow, 'bidirectional_bytes', 0)
            
            # Calculate duration
            duration = "N/A"
            if hasattr(flow, 'bidirectional_duration_ms'):
                duration = f"{flow.bidirectional_duration_ms/1000:.2f}s"
            
            # Determine risk level text
            if risk_score >= 80:
                risk_text = f"High ({risk_score})"
            elif risk_score >= 40:
                risk_text = f"Medium ({risk_score})"
            else:
                risk_text = f"Low ({risk_score})"
                
            # Add to flow tree
            item_id = self.flows_tree.insert("", 0, values=(
                timestamp, src_ip, dst_ip, protocol, 
                src_port, dst_port, packets, bytes_count, 
                duration, risk_text
            ))
            
            # Apply color based on risk level
            if risk_score >= 80:
                self.flows_tree.item(item_id, tags=("high_risk",))
            elif risk_score >= 40:
                self.flows_tree.item(item_id, tags=("medium_risk",))
                
            # Make sure the tags are configured
            self.flows_tree.tag_configure("high_risk", background="#ffcccc")
            self.flows_tree.tag_configure("medium_risk", background="#ffffcc")
            
            # Auto-scroll to show the latest entry
            self.flows_tree.see(item_id)
            
        except Exception as e:
            print(f"Error updating flow UI: {e}")