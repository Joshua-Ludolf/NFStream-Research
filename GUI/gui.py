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
        self.packet_store = {}    # Store packet objects by ID for later reference
        
        # Track active PyShark captures and their event loops for clean shutdown
        self.active_captures = []
        self.active_captures_lock = threading.Lock()
        
        # Protocol mapping dictionary - comprehensive list of IP protocols
        self.protocol_map = {
            0: "HOPOPT",
            1: "ICMP",
            2: "IGMP",
            3: "GGP",
            4: "IPv4",
            5: "ST",
            6: "TCP",
            7: "CBT",
            8: "EGP",
            9: "IGP",
            10: "BBN-RCC-MON",
            11: "NVP-II",
            12: "PUP",
            13: "ARGUS",
            14: "EMCON",
            15: "XNET",
            16: "CHAOS",
            17: "UDP",
            58: "ICMPv6",
            47: "GRE",
            48: "DSR",
            49: "BNA",
            50: "ESP",
            51: "AH",
            52: "I-NLSP",
            53: "SWIPE",
            54: "NARP",
            55: "MOBILE",
            56: "TLSP",
            57: "SKIP",
            58: "IPv6-ICMP",
            59: "IPv6-NoNxt",
            60: "IPv6-Opts",
            61: "Any host internal protocol",
            62: "CFTP",
            63: "Any local network",
            64: "SAT-EXPAK",
            65: "KRYPTOLAN",
            66: "RVD",
            67: "IPPC",
            68: "Any distributed file system",
            69: "SAT-MON",
            70: "VISA",
            71: "IPCV",
            72: "CPNX",
            73: "CPHB",
            74: "WSN",
            75: "PVP",
            76: "BR-SAT-MON",
            77: "SUN-ND",
            78: "WB-MON",
            79: "WB-EXPAK",
            80: "ISO-IP",
            81: "VMTP",
            82: "SECURE-VMTP",
            83: "VINES",
            84: "TTP",
            85: "NSFNET-IGP",
            86: "DGP",
            87: "TCF",
            88: "EIGRP",
            89: "OSPF",
            90: "Sprite-RPC",
            91: "LARP",
            92: "MTP",
            93: "AX.25",
            94: "IPIP",
            95: "MICP",
            96: "SCC-SP",
            97: "ETHERIP",
            98: "ENCAP",
            99: "Any private encryption scheme",
            100: "GMTP",
            101: "IFMP",
            102: "PNNI",
            103: "PIM",
            104: "ARIS",
            105: "SCPS",
            106: "QNX",
            107: "A/N",
            108: "IPComp",
            109: "SNP",
            110: "Compaq-Peer",
            111: "IPX-in-IP",
            112: "VRRP",
            113: "PGM",
            114: "Any 0-hop protocol",
            115: "L2TP",
            116: "DDX",
            117: "IATP",
            118: "STP",
            119: "SRP",
            120: "UTI",
            121: "SMP",
            122: "SM",
            123: "PTP",
            124: "ISIS over IPv4",
            125: "FIRE",
            126: "CRTP",
            127: "CRUDP",
            128: "SSCOPMCE",
            129: "IPLT",
            130: "SPS",
            131: "PIPE",
            132: "SCTP",
            133: "FC",
            134: "RSVP-E2E-IGNORE",
            135: "Mobility Header",
            136: "UDPLite",
            137: "MPLS-in-IP",
            138: "manet",
            139: "HIP",
            140: "Shim6",
            141: "WESP",
            142: "ROHC",
            143: "Ethernet",
            144: "AGGFRAG",
            145: "NSH",
            146: "Fast LWE",
            239: "HIP",
            253: "Experimental",
            254: "Experimental",
            255: "Reserved"
        }
        
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
        
        # Create a fixed Wi-Fi interface with hardcoded values
        self.interface = {
            'nfstream_name': "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter", # Replace with actual interface Description
            'pyshark_name': "Wi-Fi", # Replace with wifi (windows) or eth0 (linux) or wlan0 (mac)
            'scapy_name': "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter" # Replace with actual interface Description
        }
        # Show which interface we're using
        ttk.Label(self.control_frame, text="Using Wi-Fi Interface").pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.start_button = ttk.Button(self.control_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        # Stop button (initially disabled)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.NORMAL)
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
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
        self.packets_tree.pack(fill=tk.BOTH, expand=True)        # Bind selection event to show details
        self.packets_tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        
        # Packet details text area - create with normal state initially
        self.packet_details_text = scrolledtext.ScrolledText(packet_detail_frame, wrap=tk.WORD)
        self.packet_details_text.pack(fill=tk.BOTH, expand=True)
        
        # Make it read-only by binding key events instead of disabling
        self.packet_details_text.bind("<Key>", lambda e: "break")  # Prevent typing
        self.packet_details_text.bind("<Control-c>", lambda e: None)  # Allow copy

    
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
        self.response_combobox = ttk.Combobox(response_frame, values=["Block IP", "Reset Connection", "Log Only"], width=15, state="readonly")
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
        
        # Detection thresholds        ttk.Label(detection_frame, text="Max packets per second:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_pps_var = tk.StringVar(value=str(self.thresholds["max_packets_per_second"]))
        ttk.Entry(detection_frame, textvariable=self.max_pps_var, width=10, state="readonly").grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(detection_frame, text="Max connections per minute:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_conn_var = tk.StringVar(value=str(self.thresholds["max_connections_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_conn_var, width=10, state="readonly").grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(detection_frame, text="Max DNS queries per minute:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_dns_var = tk.StringVar(value=str(self.thresholds["max_dns_queries_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_dns_var, width=10, state="readonly").grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(detection_frame, text="Max failed connections:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_failed_var = tk.StringVar(value=str(self.thresholds["max_failed_connections"]))
        ttk.Entry(detection_frame, textvariable=self.max_failed_var, width=10, state="readonly").grid(row=3, column=1, padx=5, pady=5)
          # Custom malicious IP input
        ttk.Label(detection_frame, text="Add malicious IP:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_malicious_ip = ttk.Entry(detection_frame, width=20, state="readonly")
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
        
        # Initialize packet tracking
        self.packet_store = {}  # Reset packet store
        self.active_captures = []  # Reset active captures list
        self.flow_tracking = {}  # Reset flow tracking
        self.flow_tracking_lock = threading.Lock()
        
        self.is_monitoring = True
        self.start_button.config(state=tk.DISABLED)  # Disable start button 
        self.stop_button.config(state=tk.NORMAL)  # Enable stop button
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
        if self.is_monitoring:
            # First, set monitoring flag to false to signal threads to stop
            self.is_monitoring = False
            
            if self.monitor_thread and self.monitor_thread.is_alive():
                print("Waiting for monitoring thread to stop...")
                self.monitor_thread.join(timeout=5.0)
                if self.monitor_thread.is_alive():
                    print("Warning: Monitoring thread did not stop in time.")
                else:
                    print("Monitoring thread stopped successfully.")

            # Ensure all PyShark captures are closed properly
            self.close_active_captures()

            # Ensure all PyShark processes are terminated
            self.kill_pyshark_processes()            # Reset UI state
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_label.config(text="Monitoring stopped")
            
            # Clear flow tracking
            with self.flow_tracking_lock:
                self.flow_tracking.clear()
                
            # Clear packet store to free memory
            self.packet_store.clear()
            
            # Reset any queues that might be blocked
            if hasattr(self, 'flow_packet_queue'):
                with contextlib.suppress(Exception):
                    while not self.flow_packet_queue.empty():
                        self.flow_packet_queue.get_nowait()
                        
            if hasattr(self, 'packet_queue'):
                with contextlib.suppress(Exception):
                    while not self.packet_queue.empty():
                        self.packet_queue.get_nowait()
            
            # Reset monitor thread
            self.monitor_thread = None
            print("Monitoring resources reset successfully")    
    
    def close_active_captures(self):
        """Enhanced method to gracefully close all active PyShark captures and their event loops."""
        with self.active_captures_lock:
            if not self.active_captures:
                print("No active captures to close")
                return

            print(f"Closing {len(self.active_captures)} active captures...")
            for capture_info in self.active_captures:
                try:
                    capture = capture_info.get('capture')
                    eventloop = capture_info.get('loop')

                    if capture:
                        print(f"Closing capture {capture_info.get('id', 'unknown')}")
                        # Clear any stored packets to free memory
                        if hasattr(capture, '_packets'):
                            capture._packets.clear()
                        
                        # Instead of using the .close() method which tries to use the event loop internally,
                        # we'll manually clean up critical resources
                        try:
                            # Directly access and close the subprocess if it exists
                            if hasattr(capture, "_proc"):
                                if hasattr(capture._proc, "kill"):
                                    capture._proc.kill()
                                elif hasattr(capture._proc, "terminate"):
                                    capture._proc.terminate()
                        except Exception as e:
                            print(f"Error terminating capture process: {e}")

                    # Handle the event loop separately after dealing with the capture
                    if eventloop and not eventloop.is_closed():
                        try:
                            # Try to properly cancel any pending tasks
                            try:
                                pending_tasks = asyncio.all_tasks(eventloop) if hasattr(asyncio, 'all_tasks') else []
                                for task in pending_tasks:
                                    task.cancel()
                            except Exception:
                                pass  # Ignore task cancellation errors
                                
                            # Make sure to close the loop even if task cancellation failed
                            if not eventloop.is_closed():
                                eventloop.close()
                                
                        except Exception as e:
                            print(f"Error closing event loop: {e}")

                except Exception as e:
                    print(f"Error during capture cleanup: {e}")

            self.active_captures.clear()
            print("All captures closed")
    
    def monitoring_loop(self):
        """Main monitoring loop running in a separate thread"""
        try:
            print("Starting main monitoring loop")
            # Create queues for inter-thread communication
            self.flow_packet_queue = queue.Queue()
            self.packet_queue = queue.Queue()
            
            # Start NFStream for flow analysis in a separate thread
            nfstream_thread = threading.Thread(target=self.nfstream_monitor)
            nfstream_thread.daemon = True
            nfstream_thread.start()
            
            # Start PyShark for packet capture in a separate thread
            pyshark_thread = threading.Thread(target=self.pyshark_monitor)
            pyshark_thread.daemon = True
            pyshark_thread.start()
            
            print("Started NFStream and PyShark monitoring threads")
            
            # Main loop - process queued items and keep thread alive
            while self.is_monitoring:
                # Process any queued flow packet analysis requests
                try:
                    # Process up to 5 items per loop iteration to avoid blocking
                    for _ in range(5):
                        if self.flow_packet_queue.empty():
                            break
                        flow_data = self.flow_packet_queue.get_nowait()
                        if flow_data:
                            # Process the flow data by analyzing corresponding packets
                            self.analyze_flow_packets(flow_data)
                except queue.Empty:
                    pass
                except Exception as queue_e:
                    print(f"Error processing flow queue: {queue_e}")
                
                # Process any queued packets from PyShark
                try:
                    # Process up to 10 packets per iteration
                    for _ in range(10):
                        if self.packet_queue.empty():
                            break
                        packet_data = self.packet_queue.get_nowait()
                        if packet_data:
                            # Process the packet on the UI thread
                            self.root.after(0, lambda p=packet_data: self.process_packet(*p))
                except queue.Empty:
                    pass
                except Exception as pkt_e:
                    print(f"Error processing packet queue: {pkt_e}")
                
                # Sleep a short time to prevent high CPU usage
                time.sleep(0.1)
                
            print("Monitoring loop ended")
            
        except Exception as e:
            print(f"Critical error in monitoring loop: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Monitoring error: {str(e)}"))
            self.root.after(0, self.stop_monitoring)

    def nfstream_monitor(self):
        """NFStream monitoring process"""
        try:
            interface_name = self.interface['nfstream_name']
            
            # Create a NFStreamer instance for real-time monitoring
            streamer = NFStreamer(source=interface_name, 
                                active_timeout=1, 
                                idle_timeout=30,
                                accounting_mode=0,  # 0 = online mode
                                bpf_filter=None)    # No BPF filter to capture all traffic
            # Create flow tracking dictionary to correlate flows with packets
            self.flow_tracking = {}
            self.flow_tracking_lock = threading.Lock()
            
            # Process flows
            for flow in streamer:
                if not self.is_monitoring:
                    break
                
                # Process the flow for security analysis
                risk_score = self.analyze_flow(flow)
                
                # Update the UI
                self.root.after(0, lambda f=flow, rs=risk_score: self.update_flow_ui(f, rs))
                  # Queue this flow for packet analysis - less restrictive criteria
                should_analyze = True  # Default to analyzing all flows to ensure we see activity
                
                # Create a flow key for tracking
                flow_key = self._create_flow_key(flow)
                
                print(f"Flow detected: {flow_key} with risk score {risk_score}")
                
                # Create message about the flow properties for debugging
                flow_props = []
                if hasattr(flow, 'application_name'):
                    flow_props.append(f"app={flow.application_name}")
                if hasattr(flow, 'bidirectional_packets'):
                    flow_props.append(f"packets={flow.bidirectional_packets}")
                if hasattr(flow, 'bidirectional_bytes'):
                    flow_props.append(f"bytes={flow.bidirectional_bytes}")
                
                print(f"Flow properties: {', '.join(flow_props)}")
                
                # Queue for packet analysis
                self.flow_packet_queue.put({
                    'flow': flow,
                    'flow_key': flow_key,
                    'risk_score': risk_score,
                    'timestamp': datetime.now()
                })
                print(f"Added flow to analysis queue: {flow_key}")
                
        except Exception as e:
            print(f"Error in NFStream monitoring: {e}")
            error_msg = str(e)
            self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"NFStream error: {msg}"))      
              

    def pyshark_monitor(self):
        """Pyshark monitoring process for detailed packet analysis"""
        try:
            # Only create a single capture instance to avoid spawning too many dumpcap processes
            interface_name = self.interface['pyshark_name']
            print(f"Starting PyShark monitoring on interface: {interface_name}")
            
            # Each thread needs its own event loop
            try:
                # Set a clean new event loop for this thread
                if hasattr(asyncio, 'get_event_loop') and hasattr(asyncio, 'set_event_loop'):
                    try:
                        old_loop = asyncio.get_event_loop()
                        if old_loop.is_running() or old_loop.is_closed():
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                    except Exception:
                        # If we can't get the current loop, create a new one
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                else:
                    # Python 3.10+ style
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                print(f"Successfully created event loop for PyShark")
                  # Create a capture instance with a specific BPF filter to avoid certain noisy protocols
                bpf_filter = "not broadcast and not multicast and not arp"
                
                # Always use live capture mode for production
                print(f"Starting live capture on interface: {interface_name}")
                capture = pyshark.LiveCapture(
                    interface=interface_name,
                    bpf_filter=bpf_filter,
                    display_filter="ip",  # Only show IP packets
                    use_json=True,
                    include_raw=True
                )
                    
                # Register this capture for cleanup
                with self.active_captures_lock:
                        self.active_captures.append({
                            'id': 'main_capture',
                            'capture': capture,
                            'loop': loop
                        })
                    
                # Keep sniffing packets in small batches
                packets_processed = 0
                while self.is_monitoring:
                        try:
                            # Sniff a small batch with timeout
                            capture.sniff(packet_count=10, timeout=2)
                            batch_packets = list(capture._packets) if hasattr(capture, '_packets') else []
                              # Process captured packets
                            for packet in batch_packets:
                                if not self.is_monitoring:
                                    break
                                
                                # Process packet directly since queue_packet_for_processing doesn't exist
                                self.analyze_packet(packet)
                                packets_processed += 1
                                

                                # Provide feedback on packet processing
                                if packets_processed % 20 == 0:
                                    print(f"Processed {packets_processed} packets")
                            

                            # Clear packets to avoid memory issues
                            if hasattr(capture, '_packets'):
                                capture._packets.clear()
                                

                            # Short delay to prevent CPU thrashing
                            time.sleep(0.1)
                            
                        except KeyboardInterrupt:
                            print("PyShark capture interrupted")
                            break
                        except Exception as batch_err:
                            print(f"Error in packet batch processing: {batch_err}")
                            time.sleep(1)  # Back off on errors
                            if not self.is_monitoring:
                                break
                
                print("PyShark monitoring completed")
            
            except Exception as inner_e:
                print(f"PyShark capture failed: {inner_e}")
                error_msg = str(inner_e)
                if "Event loop is closed" in error_msg:
                    print("Event loop was closed - this is expected during shutdown")
                elif "Permission denied" in error_msg:
                    error_msg = "Permission denied capturing packets. Try running the application as administrator."
                    self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", msg))
                else:
                    print("Disabling PyShark monitoring due to initialization error")
                    self.root.after(0, lambda msg=error_msg: messagebox.showwarning("Warning", f"Packet analysis disabled: {msg}"))
                
        except Exception as e:
            print(f"Error in PyShark monitoring: {e}")
            if self.is_monitoring:  # Only show error if still monitoring
                self.root.after(0, lambda msg=str(e): messagebox.showerror("Error", f"PyShark error: {msg}"))


    def _capture_packets_with_loop(self, capture, loop):
        """Capture packets using the provided event loop"""
        try:
            # Use a more traditional approach without nested async functions
            # This avoids the 'object has no attribute' issue
            while self.is_monitoring:
                try:
                    # Capture a small batch of packets with timeout
                    capture.sniff(packet_count=5, timeout=1)

                    # Process the captured packets synchronously
                    for packet in list(capture._packets):
                        if not self.is_monitoring:
                            break
                        # Process each packet
                        self.analyze_packet(packet)

                    # Clear packets after processing to avoid memory buildup
                    if hasattr(capture, '_packets'):
                        capture._packets.clear()

                    # Small delay to prevent CPU spinning
                    time.sleep(0.1)

                except KeyboardInterrupt:
                    break  # Allow clean exit on Ctrl+C
                except Exception as e:
                    # Print error but continue monitoring
                    print(f"Packet capture error: {e}")
                    time.sleep(1)  # Avoid tight loop on errors
                    if not self.is_monitoring:
                        break
        
        except Exception as e:
            print(f"Fatal error in packet capture with loop: {e}")
            if self.is_monitoring:
                error_msg = str(e)
                self.root.after(0, lambda msg=error_msg: messagebox.showerror("Error", f"Packet capture error: {msg}"))

    # Keep the original methods for compatibility with other code that might use them
    def _capture_packets_simple(self, capture, loop=None):
        """Legacy method - now forwards to the loop version if a loop is provided, otherwise non-async version"""
        if loop:
            self._capture_packets_with_loop(capture, loop)
        else:
            self._capture_packets_simple_nonasync(capture)

    def _capture_packets_simple_nonasync(self, capture):
        """Simple non-async capture method to avoid event loop conflicts"""
        try:
            # Define the packet callback function for live capture
            def packet_callback(packet):
                if self.is_monitoring:
                    try:
                        self.analyze_packet(packet)
                    except Exception as e:
                        print(f"Error processing packet: {e}")
            
            print("Starting packet capture loop")
            
            # Use purely synchronous approach without asyncio
            while self.is_monitoring:
                try:
                    # Capture a small batch of packets with timeout
                    # This allows us to regularly check if monitoring should stop
                    # Using very small packet_count to avoid blocking for too long
                    capture.sniff(packet_count=5, timeout=1)
                    
                    # Process the captured packets
                    for packet in list(capture._packets):
                        if not self.is_monitoring:
                            break
                        packet_callback(packet)
                    
                    # Clear packets after processing to avoid memory buildup
                    if hasattr(capture, '_packets'):
                        capture._packets.clear()
                    
                    # Small delay to prevent CPU spinning
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    break  # Allow clean exit on Ctrl+C
                except Exception as e:
                    # Print error but continue monitoring
                    print(f"Packet capture error: {e}")
                    time.sleep(1)  # Avoid tight loop on errors
                    if not self.is_monitoring:
                        break
            
            print("Packet capture loop ended")
            
        except Exception as e:
            print(f"Fatal error in packet capture: {e}")
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
            
            # Check if this packet is from or to a blocked IP
            if src in self.blocked_ips:
                # Skip processing and enforce block
                print(f"Packet from blocked IP {src} detected - enforcing block")
                # Send TCP RST packets to terminate the connection
                self.send_reset_packets(src)
                return
            
            if dst in self.blocked_ips:
                # Skip processing and enforce block
                print(f"Packet to blocked IP {dst} detected - enforcing block")
                # Send TCP RST packets to terminate the connection
                self.send_reset_packets(dst)
                return
                
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
        
        # Store packet object for later reference (with debug output)
        self.packet_store[packet_id] = packet
        print(f"Added packet to store with ID: {packet_id}")
        
        # Periodically clean old packets to prevent memory issues
        if len(self.packet_store) > 1000:
            # Keep only the 500 most recent packets
            keys_to_remove = list(self.packet_store.keys())[:-500]
            for key in keys_to_remove:
                del self.packet_store[key]
            print(f"Cleaned packet store, now contains {len(self.packet_store)} packets")
        
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
        
        # Handle DNS packets safely with proper error handling
        try:
            if hasattr(packet, 'dns'):
                if hasattr(packet.dns, 'qry_name'):
                    dns_name = getattr(packet.dns, 'qry_name', "unknown")
                    summary = f"DNS Query for {dns_name}"
                elif hasattr(packet.dns, 'resp_name'):
                    dns_name = getattr(packet.dns, 'resp_name', "unknown")
                    summary = f"DNS Response for {dns_name}"
        except Exception as e:
            print(f"Error processing DNS packet summary: {e}")
            summary = "DNS Packet (error processing details)"
        
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
                        # Found a suspicious pattern - always use HIGH severity for payload matches
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
                          # Check for suspicious DNS queries
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                try:
                    dns_query = str(packet.dns.qry_name).lower()
                    
                    # Check if this packet involves a blocked DNS server (either source or destination)
                    # This handles the case where an IP was blocked but DNS queries are still coming through
                    if dst_ip in self.blocked_ips and hasattr(packet, 'udp') and hasattr(packet.udp, 'dstport') and packet.udp.dstport == '53':
                        print(f"Blocking DNS query to blocked server {dst_ip}")
                        # For DNS, we need to drop all future packets rather than just sending RST
                        # No need to send another alert since the IP is already blocked
                        return
                        
                    # Check if this is a query for a known malicious domain
                    for domain in self.threat_domains:
                        if domain.lower() in dns_query:
                            alert_details = {
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "severity": "High", 
                                "source": src_ip,
                                "destination": dst_ip,
                                "alert_type": "Malicious DNS Query",
                                "details": f"Query for known malicious domain: {dns_query}"
                            }
                            self.root.after(0, lambda a=alert_details: self.add_alert(a))
                            
                            # Auto-respond if enabled and set to Block IP
                            if self.auto_response_var.get() and self.default_response_var.get() == "Block IP":
                                # Block both the client making the query and the DNS server
                                self.root.after(0, lambda ip=src_ip: self.block_ip(ip, f"DNS query for malicious domain: {dns_query}"))
                                if dst_ip != src_ip:  # Avoid blocking twice if it's the same IP
                                    self.root.after(0, lambda ip=dst_ip: self.block_ip(ip, f"DNS server for malicious domain: {dns_query}"))
                            break
                except Exception as dns_error:
                    print(f"Error processing DNS query check: {dns_error}")
                    # Continue processing other aspects of the packet even if DNS check fails
            
            # Check for HTTP suspicious user agents
            if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
                user_agent = packet.http.user_agent
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, user_agent):
                        # User agent matches are now HIGH severity to match Scapy's alerts
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Suspicious User Agent",
                            "details": f"Suspicious user agent: {user_agent}"
                        }
                        self.root.after(0, lambda a=alert_details: self.add_alert(a))
                        
                        # Auto-respond to suspicious user agents the same as payloads
                        if self.auto_response_var.get():
                            self.root.after(0, lambda ip=src_ip: self.block_ip(ip, "Suspicious user agent"))
            
            # Also check if IP is in our threat list (consistent with flow analysis)
            if src_ip in self.threat_ips:
                alert_details = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "High",
                    "source": src_ip,
                    "destination": dst_ip,
                    "alert_type": "Malicious Source IP",
                    "details": f"Packet from known malicious IP: {src_ip}"
                }
                self.root.after(0, lambda a=alert_details: self.add_alert(a))
                  # Auto-block if auto-respond is enabled and default response is Block IP
                if self.auto_response_var.get() and self.default_response_var.get() == "Block IP":
                    self.root.after(0, lambda ip=src_ip: self.block_ip(ip, "Malicious source IP - auto-blocked"))
            
            if dst_ip in self.threat_ips:
                alert_details = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "High",
                    "source": src_ip,
                    "destination": dst_ip,
                    "alert_type": "Malicious Destination IP",
                    "details": f"Packet to known malicious IP: {dst_ip}"
                }
                self.root.after(0, lambda a=alert_details: self.add_alert(a))
                
                # Auto-block if auto-respond is enabled
                if self.auto_response_var.get():
                    self.root.after(0, lambda ip=dst_ip: self.block_ip(ip, "Malicious destination IP - auto-blocked"))
                    
        except Exception as e:
            print(f"Error checking packet payload: {e}")
            
    def show_packet_details(self, event):
        """Show detailed information about the selected packet"""
        selected_items = self.packets_tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        item_tags = self.packets_tree.item(item_id, "tags")
        
        # Ensure we have tags before accessing them
        if not item_tags:
            self.packet_details_text.delete(1.0, tk.END)
            self.packet_details_text.insert(tk.END, "No packet ID associated with this entry.\n")
            return
            
        packet_id = item_tags[0]
        
        # Clear previous details
        self.packet_details_text.delete(1.0, tk.END)
        
        # Get packet data from the treeview (this is always available)
        values = self.packets_tree.item(item_id, "values")
        timestamp, src, dst, protocol, length, info = values

        # Retrieve the stored packet object
        packet = self.packet_store.get(packet_id)
        
        if packet is None:
            # Display basic information from the UI values even if packet isn't in store
            self.packet_details_text.insert(tk.END, "=== Basic Packet Information ===\n")
            self.packet_details_text.insert(tk.END, f"Packet ID: {packet_id}\n")
            self.packet_details_text.insert(tk.END, f"Time: {timestamp}\n")
            self.packet_details_text.insert(tk.END, f"Source: {src}\n")
            self.packet_details_text.insert(tk.END, f"Destination: {dst}\n")
            self.packet_details_text.insert(tk.END, f"Protocol: {protocol}\n")
            self.packet_details_text.insert(tk.END, f"Length: {length} bytes\n")
            self.packet_details_text.insert(tk.END, f"Info: {info}\n\n")
            self.packet_details_text.insert(tk.END, "Detailed packet information not available.\n")
            self.packet_details_text.insert(tk.END, f"Packet may have been cleaned from memory to conserve resources.\n")
            return
            
        # Show detailed protocol information
        self.packet_details_text.insert(tk.END, f"=== Protocol Details ===\n")
        self.packet_details_text.insert(tk.END, f"Packet ID: {packet_id}\n")
        self.packet_details_text.insert(tk.END, f"Time: {timestamp}\n")
        self.packet_details_text.insert(tk.END, f"Length: {length} bytes\n")
        self.packet_details_text.insert(tk.END, f"Info: {info}\n")
        self.packet_details_text.insert(tk.END, f"Alert: {self.check_alerts(packet_id)}\n\n")
        # TCP details
        if hasattr(packet, 'tcp'):

            self.packet_details_text.insert(tk.END, f"TCP Details:\n")
            self.packet_details_text.insert(tk.END, f"  Source Port: {packet.tcp.srcport}\n")
            self.packet_details_text.insert(tk.END, f"  Destination Port: {packet.tcp.dstport}\n")
              # Show TCP flags - Enhanced flag detection 
            flags = []
            
            # Try multiple flag attribute naming patterns
            # Pattern 1: flags_syn, flags_ack, etc.
            flag_names = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']
            for flag in flag_names:
                # Check with flags_ prefix
                if hasattr(packet.tcp, f'flags_{flag}') and getattr(packet.tcp, f'flags_{flag}') in ['1', True, 1]:
                    flags.append(flag.upper())
                # Check with flag_ prefix
                elif hasattr(packet.tcp, f'flag_{flag}') and getattr(packet.tcp, f'flag_{flag}') in ['1', True, 1]:
                    flags.append(flag.upper())
                # Check with no prefix
                elif hasattr(packet.tcp, flag) and getattr(packet.tcp, flag) in ['1', True, 1]:
                    flags.append(flag.upper())
            
            # Pattern 2: Direct flags attribute that contains all flags
            if not flags and hasattr(packet.tcp, 'flags'):
                try:
                    # Try to interpret as hex
                    flag_value = str(packet.tcp.flags)
                    # Common hex representations
                    if '0x' in flag_value:
                        flag_int = int(flag_value, 16)
                        if flag_int & 0x02: flags.append('SYN')
                        if flag_int & 0x10: flags.append('ACK')
                        if flag_int & 0x01: flags.append('FIN')
                        if flag_int & 0x04: flags.append('RST')
                        if flag_int & 0x08: flags.append('PSH')
                        if flag_int & 0x20: flags.append('URG')
                    # String representation like '......S.'
                    elif len(flag_value) >= 8:
                        if 'S' in flag_value: flags.append('SYN')
                        if 'A' in flag_value: flags.append('ACK')
                        if 'F' in flag_value: flags.append('FIN')
                        if 'R' in flag_value: flags.append('RST')
                        if 'P' in flag_value: flags.append('PSH')
                        if 'U' in flag_value: flags.append('URG')
                except:
                    pass
            
            if flags:
                self.packet_details_text.insert(tk.END, f"  Flags: {' '.join(flags)}\n")
            else:
                self.packet_details_text.insert(tk.END, f"  Flags: None detected\n")
            
            if hasattr(packet.tcp, 'seq'):
                self.packet_details_text.insert(tk.END, f"  Sequence Number: {packet.tcp.seq}\n")
            if hasattr(packet.tcp, 'ack'):
                self.packet_details_text.insert(tk.END, f"  Acknowledgment Number: {packet.tcp.ack}\n")
            if hasattr(packet.tcp, 'window_size'):
                self.packet_details_text.insert(tk.END, f"  Window Size: {packet.tcp.window_size}\n")

        # UDP details
        if hasattr(packet, 'udp'):
            self.packet_details_text.insert(tk.END, f"UDP Details:\n")
            self.packet_details_text.insert(tk.END, f"  Source Port: {packet.udp.srcport}\n")
            self.packet_details_text.insert(tk.END, f"  Destination Port: {packet.udp.dstport}\n")
            if hasattr(packet.udp, 'length'):
                self.packet_details_text.insert(tk.END, f"  Length: {packet.udp.length}\n")        # HTTP details
        if hasattr(packet, 'http'):
            self.packet_details_text.insert(tk.END, f"HTTP Details:\n")
            
            # First try common attribute names
            if hasattr(packet.http, 'request_method'):
                self.packet_details_text.insert(tk.END, f"  Method: {packet.http.request_method}\n")
            if hasattr(packet.http, 'request_uri'):
                self.packet_details_text.insert(tk.END, f"  URI: {packet.http.request_uri}\n")
            if hasattr(packet.http, 'request_version'):
                self.packet_details_text.insert(tk.END, f"  Version: {packet.http.request_version}\n")
            if hasattr(packet.http, 'response_code'):
                self.packet_details_text.insert(tk.END, f"  Status Code: {packet.http.response_code}\n")
            if hasattr(packet.http, 'response_phrase'):
                self.packet_details_text.insert(tk.END, f"  Status: {packet.http.response_phrase}\n")
            if hasattr(packet.http, 'user_agent'):
                self.packet_details_text.insert(tk.END, f"  User-Agent: {packet.http.user_agent}\n")
            if hasattr(packet.http, 'host'):
                self.packet_details_text.insert(tk.END, f"  Host: {packet.http.host}\n")
            
            # Enhanced HTTP header examination - check all http attributes
            displayed_headers = set(['request_method', 'request_uri', 'request_version', 
                                     'response_code', 'response_phrase', 'user_agent', 'host'])
            
            # Get all attributes
            all_attrs = dir(packet.http)
            
            # Extract and display headers that might be in different formats
            for attr in all_attrs:
                if attr.startswith('__') or attr in displayed_headers:
                    continue
                
                try:
                    value = getattr(packet.http, attr)
                    
                    # Skip methods and internal attributes
                    if callable(value) or attr.startswith('_'):
                        continue
                    
                    # Format the header name nicely
                    header_name = attr.replace('_', '-').title()
                    self.packet_details_text.insert(tk.END, f"  {header_name}: {value}\n")
                except Exception:
                    pass
                    
            # If PyShark provides a fields dictionary, try to extract HTTP headers
            if hasattr(packet.http, '_all_fields'):
                for field_name, field_value in packet.http._all_fields.items():
                    if field_name.startswith('http.') and 'header' in field_name:
                        header_parts = field_name.split('.')
                        if len(header_parts) >= 3:
                            header_name = header_parts[-2].replace('_', '-').title()
                            self.packet_details_text.insert(tk.END, f"  {header_name}: {field_value}\n")
                  # DNS details
        if hasattr(packet, 'dns'):
            self.packet_details_text.insert(tk.END, f"DNS Details:\n")
            
            # Get all available attributes for DNS
            dns_attributes = dir(packet.dns)
            displayed_something = False
            
            # Check common DNS attributes
            if hasattr(packet.dns, 'qry_name'):
                self.packet_details_text.insert(tk.END, f"  Query: {packet.dns.qry_name}\n")
                displayed_something = True
            if hasattr(packet.dns, 'qry_type'):
                self.packet_details_text.insert(tk.END, f"  Query Type: {packet.dns.qry_type}\n")
                displayed_something = True
            if hasattr(packet.dns, 'resp_name'):
                self.packet_details_text.insert(tk.END, f"  Response: {packet.dns.resp_name}\n")
                displayed_something = True
            if hasattr(packet.dns, 'resp_type'):
                self.packet_details_text.insert(tk.END, f"  Response Type: {packet.dns.resp_type}\n")
                displayed_something = True
            
            # Add any other useful DNS attributes that might be present
            for attr in ['flags', 'id', 'count_queries', 'count_answers', 'dns_time']:
                if attr in dns_attributes:
                    value = getattr(packet.dns, attr)
                    if value:
                        self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                        displayed_something = True
            
            # If no attributes were displayed, show a message
            if not displayed_something:
                self.packet_details_text.insert(tk.END, f"  [DNS packet detected but no detailed fields available]\n")        # ICMP and ICMPv6 details
        if hasattr(packet, 'icmpv6'):
            self.packet_details_text.insert(tk.END, f"ICMPv6 Details:\n")
            if hasattr(packet.icmpv6, 'type'):
                icmp_type = packet.icmpv6.type
                # ICMPv6 type descriptions
                icmpv6_types = {
                    "1": "Destination Unreachable",
                    "2": "Packet Too Big",
                    "3": "Time Exceeded",
                    "4": "Parameter Problem", 
                    "128": "Echo Request",
                    "129": "Echo Reply",
                    "133": "Router Solicitation",
                    "134": "Router Advertisement",
                    "135": "Neighbor Solicitation",
                    "136": "Neighbor Advertisement",
                    "137": "Redirect"
                }
                type_desc = icmpv6_types.get(icmp_type, "")
                if type_desc:
                    self.packet_details_text.insert(tk.END, f"  Type: {icmp_type} ({type_desc})\n")
                else:
                    self.packet_details_text.insert(tk.END, f"  Type: {icmp_type}\n")
                
            if hasattr(packet.icmpv6, 'code'):
                self.packet_details_text.insert(tk.END, f"  Code: {packet.icmpv6.code}\n")
            if hasattr(packet.icmpv6, 'checksum'):
                self.packet_details_text.insert(tk.END, f"  Checksum: {packet.icmpv6.checksum}\n")
            
            # Additional ICMPv6-specific fields
            if hasattr(packet.icmpv6, 'nd_target'):
                self.packet_details_text.insert(tk.END, f"  Target Address: {packet.icmpv6.nd_target}\n")
            if hasattr(packet.icmpv6, 'opt_linkaddr'):
                self.packet_details_text.insert(tk.END, f"  Link-Layer Address: {packet.icmpv6.opt_linkaddr}\n")
            if hasattr(packet.icmpv6, 'data'):
                self.packet_details_text.insert(tk.END, f"  Data: {packet.icmpv6.data}\n")
        
        # Handle ICMPv4
        elif hasattr(packet, 'icmp'):
            self.packet_details_text.insert(tk.END, f"ICMP Details:\n")
            if hasattr(packet.icmp, 'type'):
                icmp_type = packet.icmp.type
                # Add ICMP type descriptions
                icmp_types = {
                    "0": "Echo Reply",
                    "3": "Destination Unreachable",
                    "5": "Redirect",
                    "8": "Echo Request",
                    "11": "Time Exceeded"
                }
                type_desc = icmp_types.get(icmp_type, "")
                if type_desc:
                    self.packet_details_text.insert(tk.END, f"  Type: {icmp_type} ({type_desc})\n")
                else:
                    self.packet_details_text.insert(tk.END, f"  Type: {icmp_type}\n")
            
            if hasattr(packet.icmp, 'code'):
                self.packet_details_text.insert(tk.END, f"  Code: {packet.icmp.code}\n")
            if hasattr(packet.icmp, 'checksum'):
                self.packet_details_text.insert(tk.END, f"  Checksum: {packet.icmp.checksum}\n")
            if hasattr(packet.icmp, 'data'):
                self.packet_details_text.insert(tk.END, f"  Data: {packet.icmp.data}\n")
          # Handle packet data display
        if hasattr(packet, 'data'):
            self.packet_details_text.insert(tk.END, f"\nPacket Data Summary:\n")
            self.packet_details_text.insert(tk.END, f"  Packet ID: {packet_id}\n")
            self.packet_details_text.insert(tk.END, f"  Time: {timestamp}\n")
            self.packet_details_text.insert(tk.END, f"  Length: {length} bytes\n")
            self.packet_details_text.insert(tk.END, f"  Info: {info}\n")
            self.packet_details_text.insert(tk.END, f"  Alert: {self.check_alerts(packet_id)}\n\n")
            
            try:
                # Display hexadecimal representation of raw data if available
                self.packet_details_text.insert(tk.END, f"Raw Data Hexadecimal:\n")
                if hasattr(packet, 'raw_packet') and packet.raw_packet:
                    # Try to format the raw data as hexadecimal bytes
                    raw_data = packet.raw_packet
                    if isinstance(raw_data, bytes):
                        # Create a formatted hex dump with 16 bytes per line
                        MAX_DISPLAY_BYTES = 128  # Limit display to avoid overwhelming the UI
                        
                        for i in range(0, min(len(raw_data), MAX_DISPLAY_BYTES), 16):
                            # Get chunk of up to 16 bytes
                            chunk = raw_data[i:i+16]
                            
                            # Format as hex
                            hex_line = ' '.join(f'{b:02x}' for b in chunk)
                            
                            # Add ASCII representation where possible
                            ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                            
                            # Add the formatted line with offset
                            self.packet_details_text.insert(tk.END, f"  {i:04x}: {hex_line.ljust(48)} | {ascii_repr}\n")
                        
                        if len(raw_data) > MAX_DISPLAY_BYTES:
                            self.packet_details_text.insert(tk.END, f"  ... {len(raw_data) - MAX_DISPLAY_BYTES} more bytes not shown ...\n")
                    else:
                        # Try to convert to string if it's not bytes
                        self.packet_details_text.insert(tk.END, f"  {str(raw_data)}\n")
                else:
                    # Try to access binary data through various alternative attributes
                    found_data = False
                    for attr_name in ['binary', 'binary_data', 'data', 'payload', 'raw']:
                        if hasattr(packet, attr_name):
                            data_value = getattr(packet, attr_name)
                            if data_value:
                                self.packet_details_text.insert(tk.END, f"  Data available in '{attr_name}' field\n")
                                found_data = True
                                break
                    
                    if not found_data:
                        self.packet_details_text.insert(tk.END, "  Raw data structure available but format cannot be displayed\n")
            except Exception as e:
                self.packet_details_text.insert(tk.END, f"  [Error displaying packet data: {str(e)}]\n")
        
        if hasattr(packet, 'arp'):
            self.packet_details_text.insert(tk.END, f"ARP Details:\n")
            if hasattr(packet.arp, 'op'):
                self.packet_details_text.insert(tk.END, f"  Operation: {packet.arp.op}\n")
            if hasattr(packet.arp, 'psrc'):
                self.packet_details_text.insert(tk.END, f"  Source IP: {packet.arp.psrc}\n")
            if hasattr(packet.arp, 'pdst'):
                self.packet_details_text.insert(tk.END, f"  Destination IP: {packet.arp.pdst}\n")
            if hasattr(packet.arp, 'hwsrc'):
                self.packet_details_text.insert(tk.END, f"  Source MAC: {packet.arp.hwsrc}\n")
            if hasattr(packet.arp, 'hwdst'):
                self.packet_details_text.insert(tk.END, f"  Destination MAC: {packet.arp.hwdst}\n")
            if hasattr(packet, 'tls'):
                self.packet_details_text.insert(tk.END, f"TLS Details:\n")
            
                # Get all available attributes for TLS
                tls_attributes = dir(packet.tls)
                displayed_something = False

                # Check common TLS attributes
                if hasattr(packet.tls, 'handshake_type'):
                    self.packet_details_text.insert(tk.END, f"  Handshake Type: {packet.tls.handshake_type}\n")
                    displayed_something = True
                if hasattr(packet.tls, 'record_version'):
                    self.packet_details_text.insert(tk.END, f"  Record Version: {packet.tls.record_version}\n")
                    displayed_something = True
                if hasattr(packet.tls, 'record_length'):
                    self.packet_details_text.insert(tk.END, f"  Record Length: {packet.tls.record_length}\n")
                    displayed_something = True
                
                # Handle the 'record' attribute which often contains TLS record data
                if hasattr(packet.tls, 'record'):
                    try:
                        # Extract content type for each record
                        self.packet_details_text.insert(tk.END, f"  Content Type: ")
                        if hasattr(packet.tls, 'record_content_type'):
                            self.packet_details_text.insert(tk.END, f"{packet.tls.record_content_type}\n")
                            displayed_something = True
                        elif hasattr(packet.tls, 'contenttype'):
                            self.packet_details_text.insert(tk.END, f"{packet.tls.contenttype}\n")
                            displayed_something = True
                        else:
                            # Try to decode common content types
                            content_types = {
                                20: "Change Cipher Spec",
                                21: "Alert",
                                22: "Handshake",
                                23: "Application Data"
                            }
                            if hasattr(packet.tls, 'type'):
                                type_num = int(packet.tls.type)
                                type_name = content_types.get(type_num, f"Unknown ({type_num})")
                                self.packet_details_text.insert(tk.END, f"{type_name}\n")
                                displayed_something = True
                            else:
                                self.packet_details_text.insert(tk.END, "Unknown\n")
                    except Exception as e:
                        self.packet_details_text.insert(tk.END, f"Error parsing record: {str(e)}\n")
                        displayed_something = True

                # Look for additional TLS fields that might exist
                for attr in ['record_content_type', 'handshake_version', 'cipher_suite', 
                             'extension_type', 'server_name', 'handshake_certificate',
                             'handshake_session_id', 'handshake_random_time']:
                    if attr in tls_attributes:
                        try:
                            value = getattr(packet.tls, attr)
                            if value:
                                self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                                displayed_something = True
                        except Exception:
                            pass  # Skip if attribute access causes error
            
                # Get any field that starts with 'tls.' to catch TLS-related fields
                try:
                    for field in packet.tls._all_fields:
                        if field.startswith('tls.') and not any(field.endswith(x) for x in ['type', 'version', 'length']):
                            try:
                                field_name = field.split('.')[-1]
                                value = packet.tls.get_field(field)
                                if value:
                                    self.packet_details_text.insert(tk.END, f"  {field_name.replace('_', ' ').title()}: {value}\n")
                                    displayed_something = True
                            except Exception:
                                pass
                except Exception:
                    pass
            
                # If no attributes were displayed, show a message
                if not displayed_something:
                    self.packet_details_text.insert(tk.END, f"  [TLS packet detected but no detailed fields available]\n")
            
        if hasattr(packet, 'mdns'):
                self.packet_details_text.insert(tk.END, f"mDNS Details:\n")
                
                # Get all available attributes for mDNS
                mdns_attributes = dir(packet.mdns)
                displayed_something = False
                
                # Check common mDNS attributes
                if hasattr(packet.mdns, 'transaction_id'):
                    self.packet_details_text.insert(tk.END, f"  Transaction ID: {packet.mdns.transaction_id}\n")
                    displayed_something = True
                if hasattr(packet.mdns, 'flags'):
                    self.packet_details_text.insert(tk.END, f"  Flags: {packet.mdns.flags}\n")
                    displayed_something = True
                if hasattr(packet.mdns, 'questions'):
                    self.packet_details_text.insert(tk.END, f"  Questions: {packet.mdns.questions}\n")
                    displayed_something = True
                if hasattr(packet.mdns, 'answers'):
                    self.packet_details_text.insert(tk.END, f"  Answers: {packet.mdns.answers}\n")
                    displayed_something = True
                
                # Add any other useful mDNS attributes that might be present
                for attr in ['qry_name', 'qry_type', 'resp_name', 'count_queries', 'count_answers']:
                    if attr in mdns_attributes:
                        try:
                            value = getattr(packet.mdns, attr)
                            if value:
                                self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                                displayed_something = True
                        except Exception:
                            pass  # Skip if attribute access causes error

                # Check for service discovery information
                if hasattr(packet.mdns, 'service'):
                    self.packet_details_text.insert(tk.END, f"  Service: {packet.mdns.service}\n")
                    displayed_something = True
                if hasattr(packet.mdns, 'service_instance'):
                    self.packet_details_text.insert(tk.END, f"  Service Instance: {packet.mdns.service_instance}\n")
                    displayed_something = True
                
                # If no attributes were displayed, show a message
                if not displayed_something:
                    self.packet_details_text.insert(tk.END, f"  [mDNS packet detected but no detailed fields available]\n")
            
        if hasattr(packet, 'quic'):
                self.packet_details_text.insert(tk.END, f"QUIC Details:\n")
                
                # Get all available attributes for QUIC
                quic_attributes = dir(packet.quic)
                displayed_something = False
                
                # Check common QUIC attributes
                if hasattr(packet.quic, 'version'):
                    self.packet_details_text.insert(tk.END, f"  Version: {packet.quic.version}\n")
                    displayed_something = True
                if hasattr(packet.quic, 'connection_id'):
                    self.packet_details_text.insert(tk.END, f"  Connection ID: {packet.quic.connection_id}\n")
                    displayed_something = True
                
                # Look for additional QUIC fields that might exist
                for attr in ['packet_number', 'payload_length', 'flags']:
                    if attr in quic_attributes:
                        try:
                            value = getattr(packet.quic, attr)
                            if value:
                                self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                                displayed_something = True
                        except Exception:
                            pass  # Skip if attribute access causes error
            
        if hasattr(packet, 'mdns'):
                self.packet_details_text.insert(tk.END, f"mDNS Details:\n")
                
                # Get all available attributes for mDNS
                mdns_attributes = dir(packet.mdns)
                displayed_something = False
                
                # Check common mDNS attributes
                if hasattr(packet.mdns, 'transaction_id'):
                    self.packet_details_text.insert(tk.END, f"  Transaction ID: {packet.mdns.transaction_id}\n")
                    displayed_something = True
                if hasattr(packet.mdns, 'flags'):
                    self.packet_details_text.insert(tk.END, f"  Flags: {packet.mdns.flags}\n")
                    displayed_something = True
                
                # Look for additional mDNS fields that might exist
                for attr in ['query_type', 'response_code', 'answers']:
                    if attr in mdns_attributes:
                        try:
                            value = getattr(packet.mdns, attr)
                            if value:
                                self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                                displayed_something = True
                        except Exception:
                            pass  # Skip if attribute access causes error

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
          
    def send_reset_packets(self, ip):
        """Send TCP reset packets to an IP address to terminate connections"""
        try:
            # Use the local interface for sending packets
            iface = self.interface['scapy_name']
            
            # Create a TCP Reset packet with flags="R" to multiple common ports
            # This will reset any active connections to these ports
            common_ports = [80, 443, 22, 21, 25, 110, 143, 3389, 8080]
            for port in common_ports:
                # Create a packet with the Reset flag set
                pkt = IP(dst=ip)/TCP(flags="R", dport=port)
                # Send the packet without verbose output
                send(pkt, verbose=0, iface=iface)
                
                # Also send RST packet in the other direction (as source IP)
                # This helps ensure connections are terminated in both directions
                src_pkt = IP(src=ip)/TCP(flags="R", sport=port)
                send(src_pkt, verbose=0, iface=iface)
            
            # Also send a more comprehensive packet for a range of ports
            # This covers other potential connections
            fin_pkt = IP(dst=ip)/TCP(flags="F", dport=(1024, 10000))
            send(fin_pkt, verbose=0, iface=iface, count=1)
            
            print(f"Sent TCP RST packets to {ip} on common ports")
        except Exception as e:
            print(f"Error sending reset packets: {e}")
    
    def block_ip(self, ip, reason):
        """Block an IP address"""
        if ip in self.blocked_ips:
            return  # Already blocked
        
        # Validate IP address before blocking to avoid crashes
        try:
            # Check if it's a valid IP
            ipaddress.ip_address(ip)
            
            # Add to blocked set
            self.blocked_ips.add(ip)
            
            # Add to blocked list UI
            item_id = self.blocked_tree.insert("", "end", values=(
                ip,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                reason
            ))
            
            # Send TCP RST packets using Scapy to terminate connections
            try:
                print(f"Blocking {ip} with RST packets")
                self.send_reset_packets(ip)
            except Exception as e:
                print(f"Error sending reset packets: {e}")
                
            # Ensure proper refresh of the UI
            self.root.update_idletasks()
            
            return True
        except ValueError:
            print(f"Invalid IP address format: {ip}, could not block")
            messagebox.showerror("Error", f"Invalid IP address format: {ip}")
            return False
        except Exception as e:
            print(f"Error blocking IP {ip}: {e}")
            messagebox.showerror("Error", f"Failed to block IP {ip}: {e}")
            return False


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
            # Block the IP permanently regardless of severity level
            self.block_ip(src_ip, "Manual block from alert")
            # Switch to the Blocked IPs tab to show the user that the IP was blocked
            self.notebook.select(self.alerts_tab)
            # Highlight the newly blocked IP in the blocked IPs list
            for item in self.blocked_tree.get_children():
                if self.blocked_tree.item(item, "values")[0] == src_ip:
                    self.blocked_tree.selection_set(item)
                    self.blocked_tree.see(item)
                    break
            messagebox.showinfo("Response", f"IP {src_ip} has been permanently blocked.\nUse 'Unblock Selected' to remove this block if needed.")
        elif action == "Reset Connection":
            # This would use Scapy to send RST packets
            messagebox.showinfo("Response", f"Reset connections from {src_ip}")
        elif action == "Log Only":
            messagebox.showinfo("Response", f"Logged activity from {src_ip}")    # Filter functionality removed as requested

    
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
            
            # Check if either IP is in the blocked list (permanent block)
            if src_ip in self.blocked_ips:
                # Auto-block this flow since it's from a blocked IP
                self.block_ip(src_ip, "Previously blocked IP detected")
                risk_score += 100
                return risk_score
            
            if dst_ip in self.blocked_ips:
                # Auto-block this flow since it's going to a blocked IP
                self.block_ip(dst_ip, "Previously blocked IP detected")
                risk_score += 100
                return risk_score
            
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
                
                # Auto-block if auto-respond is enabled
                if self.auto_response_var.get() and self.default_response_var.get() == "Block IP":
                    self.root.after(0, lambda ip=src_ip: self.block_ip(ip, "Malicious source IP - auto-blocked"))
            
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
                
                # Auto-block if auto-respond is enabled
                if self.auto_response_var.get() and self.default_response_var.get() == "Block IP":
                    self.root.after(0, lambda ip=dst_ip: self.block_ip(ip, "Malicious destination IP - auto-blocked"))
            
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
            
            # Convert protocol number to protocol name
            protocol_num = getattr(flow, 'protocol', 0)
            protocol = self.protocol_map.get(protocol_num, str(protocol_num))
            
            src_port = getattr(flow, 'src_port', None)
            dst_port = getattr(flow, 'dst_port', None)
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

    def check_alerts(self, packet_id):
        """Check if the given packet ID has triggered any alerts.
        
        Args:
            packet_id (str): The ID of the packet to check
            
        Returns:
            str: Alert information if found, or a message indicating no alerts
        """
        # Parse the packet ID to extract source IP (format: timestamp_src_dst)
        try:
            parts = packet_id.split('_')
            if len(parts) >= 2:
                src_ip = parts[1]
                
                # Check if this IP is in any alert
                for item_id in self.alerts_tree.get_children():
                    alert_values = self.alerts_tree.item(item_id, "values")
                    alert_src = alert_values[2]  # Source IP is in the 3rd column
                    
                    if alert_src == src_ip:
                        return f"⚠️ {alert_values[1]} alert: {alert_values[4]}"
        except Exception as e:
            return f"Error checking alerts: {e}"
            
        return "No alerts for this packet"

    def _create_flow_key(self, flow):
        """Create a unique key for tracking a flow"""
        # Extract the flow 5-tuple (IPs, ports, protocol)
        src_ip = getattr(flow, 'src_ip', 'unknown')
        dst_ip = getattr(flow, 'dst_ip', 'unknown')
        src_port = getattr(flow, 'src_port', 0)
        dst_port = getattr(flow, 'dst_port', 0)
        protocol = getattr(flow, 'protocol', 0)
        
        # Create a consistent key regardless of direction
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def analyze_flow_packets(self, flow_data):
        """Analyze packets for a specific flow using PyShark
        
        This function creates a targeted PyShark capture for packets matching a specific flow
        identified by NFStream, enabling detailed packet inspection for interesting flows.
        
        Args:
            flow_data (dict): Dictionary containing flow information
        """
        try:
            # Extract flow data
            flow = flow_data['flow']
            flow_key = flow_data['flow_key']
            risk_score = flow_data['risk_score']
            
            src_ip = getattr(flow, 'src_ip', None)
            dst_ip = getattr(flow, 'dst_ip', None)
            src_port = getattr(flow, 'src_port', None)
            dst_port = getattr(flow, 'dst_port', None)
            protocol = getattr(flow, 'protocol', None)
            
            if not (src_ip and dst_ip):
                print(f"Missing IP information for flow analysis: {src_ip} -> {dst_ip}")
                return
                
            # Determine protocol name for filter
            proto_name = "ip"  # Default
            if protocol == 6:
                proto_name = "tcp"
            elif protocol == 17:
                proto_name = "udp"
            elif protocol == 1:
                proto_name = "icmp"
            
            # Build capture filter
            capture_filter = ""
            
            # Create bidirectional filter
            filter_a_to_b = f"host {src_ip} and host {dst_ip}"
            
            if src_port and dst_port:
                if proto_name in ["tcp", "udp"]:
                    filter_a_to_b += f" and {proto_name} port {src_port} and {proto_name} port {dst_port}"
                    
            capture_filter = filter_a_to_b
            
            print(f"PyShark analyzing flow: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} ({proto_name})")
            print(f"Using filter: {capture_filter}")            # Create and set an event loop for this thread - CRITICAL FOR PYSHARK
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Create capture with specific filter for this flow
            capture = pyshark.LiveCapture(
                interface=self.interface['pyshark_name'],
                bpf_filter=capture_filter,
                display_filter=None,
                use_json=True,
                include_raw=False,
                use_ek=True,  # Use tshark's ek output format which is more stable
                debug=False   # Disable debug to reduce noise
            )
            
            # Register this capture for proper cleanup later
            with self.active_captures_lock:
                self.active_captures.append({
                    'capture': capture,
                    'loop': loop,
                    'flow_key': flow_key
                })
            
            # Check if we should still be monitoring - exit early if monitoring was stopped
            if not self.is_monitoring:
                print(f"Monitoring stopped, aborting capture for flow {flow_key}")
                return
              # Capture packets using a synchronous approach with better error handling
            try:
                packet_count = 0
                # Use a small timeout and reduced packet count to be more responsive to shutdown signals
                capture.sniff(timeout=3, packet_count=20)
                      # Process captured packets - checking monitoring state before each operation
                try:
                    if not self.is_monitoring:
                        print(f"Monitoring stopped during packet processing for flow {flow_key}")
                        return
                    
                    # Create a local copy of packets to process to avoid any potential async issues
                    packets = []
                    if hasattr(capture, '_packets'):
                        packets = list(capture._packets)
                        # Clear original packets right away to reduce memory usage and avoid concurrent access
                        capture._packets.clear()
                    
                    # Process each packet in our local copy
                    for packet in packets:
                        # Check if monitoring was stopped during packet processing
                        if not self.is_monitoring:
                            print(f"Monitoring stopped during packet processing for flow {flow_key}")
                            break
                            
                        packet_count += 1
                        # Use a reference to the packet and perform UI updates in main thread
                        # Make a shallow copy of the reference to further isolate from the original capture
                        packet_ref = packet  # Create a reference to avoid capture issues
                        self.root.after(0, lambda p=packet_ref: self.analyze_flow_specific_packet(p, flow_key))
                        
                    print(f"Processed {packet_count} packets for flow {flow_key}")
                except Exception as packet_err:
                    print(f"Error processing packet in targeted capture: {packet_err}")
                
                print(f"Completed targeted capture for flow {flow_key}: {packet_count} packets captured")
                
            except KeyboardInterrupt:
                print("Capture stopped by user")
            except Exception as sniff_error:
                if "Event loop is closed" in str(sniff_error):
                    print(f"Event loop was closed during capture for flow {flow_key} - this is expected during shutdown")
                else:
                    print(f"Error during packet sniffing for flow {flow_key}: {sniff_error}")
            finally:
                # Clean up resources safely
                try:
                    # Remove this capture from active captures
                    with self.active_captures_lock:
                        self.active_captures = [c for c in self.active_captures if c['flow_key'] != flow_key]
                    
                    # Close the event loop if it's still open
                    if loop and not loop.is_closed():
                        loop.close()
                except Exception as cleanup_error:
                    print(f"Error cleaning up capture resources for flow {flow_key}: {cleanup_error}")
            
        except Exception as e:
            print(f"Error in targeted packet capture: {e}")
            
            # Ensure cleanup if an error occurs
            try:
                # Remove this capture from active captures
                with self.active_captures_lock:
                    self.active_captures = [c for c in self.active_captures if c['flow_key'] != flow_key]
                
                # Close the event loop if it's still open
                if loop and not loop.is_closed():
                    loop.close()
            except Exception:
                pass  # Ignore cleanup errors during exception handling
    
    def analyze_flow_specific_packet(self, packet, flow_key):
        """Analyze a packet specifically for a tracked flow
        
        Args:
            packet: PyShark packet object
            flow_key (str): Flow tracking key for context
        """
        try:
            # Get flow data for context
            with self.flow_tracking_lock:
                if flow_key not in self.flow_tracking:
                    return
                flow_data = self.flow_tracking[flow_key]
                risk_score = flow_data.get('risk_score', 0)
            
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
            
            # Add flow context to packet info
            info = f"[Flow: {flow_key}] {info}"
            
            # Store packet for later reference with special key indicating flow context
            packet_id = f"{timestamp}_{src}_{dst}_flow_{flow_key}"
            
            # Add to UI with flow context
            packet_data = (timestamp, src, dst, protocol, length, info)
            
            # Store packet and add to UI
            self.packet_store[packet_id] = packet
            item_id = self.packets_tree.insert("", "end", values=packet_data)
            self.packets_tree.item(item_id, tags=(packet_id,))
            
            # Apply special styling for flow-specific packets
            if risk_score >= 80:
                self.packets_tree.item(item_id, tags=(packet_id, "high_risk_flow"))
            elif risk_score >= 40:
                self.packets_tree.item(item_id, tags=(packet_id, "medium_risk_flow"))
            else:
                self.packets_tree.item(item_id, tags=(packet_id, "low_risk_flow"))
                
            # Configure tags
            self.packets_tree.tag_configure("high_risk_flow", background="#ffcccc")
            self.packets_tree.tag_configure("medium_risk_flow", background="#ffffcc")
            self.packets_tree.tag_configure("low_risk_flow", background="#e6f2ff")
            
            # Check packet payload for malicious content
            self.check_packet_payload(packet, src, dst)
            
            # Auto-scroll to show latest
            self.packets_tree.see(item_id)
            
        except Exception as e:
            print(f"Error analyzing flow-specific packet: {e}")    
            
    def kill_pyshark_processes(self):
        """Force-kill any PyShark dumpcap processes that might still be running"""
        try:

            
            print("Terminating any running PyShark capture processes...")
            
            # First, try to gracefully close any captures that we're tracking
            with self.active_captures_lock:
                if self.active_captures:
                    print(f"Gracefully closing {len(self.active_captures)} tracked PyShark captures...")
                    for capture_info in self.active_captures:
                        try:
                            # Close the capture
                            capture = capture_info.get('capture')
                            if capture:
                                if hasattr(capture, 'close'):
                                    capture.close()
                                if hasattr(capture, 'eventloop') and capture.eventloop:
                                    capture.eventloop = None  # Break reference to event loop
                                if hasattr(capture, '_packets'):
                                    capture._packets.clear()  # Clear any stored packets
                            

                            # Close the event loop if it exists
                            loop = capture_info.get('loop')
                            if loop and not loop.is_closed():
                                pending_tasks = asyncio.all_tasks(loop) if hasattr(asyncio, 'all_tasks') else []
                                if pending_tasks:
                                    # Cancel any pending tasks
                                    for task in pending_tasks:
                                        task.cancel()
                                loop.run_until_complete(asyncio.gather(*pending_tasks, return_exceptions=True))
                                loop.close()
                        except Exception as e:
                            print(f"Error closing capture {capture_info.get('id', 'unknown')}: {e}")

                    # Clear the tracked captures
                    self.active_captures = []
            
            # After graceful cleanup, find and forcefully terminate any remaining processes
            killed = 0
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    cmdline = proc.info['cmdline'] if proc.info['cmdline'] else []
                    cmdline_str = " ".join(cmdline).lower() if cmdline else ""
                    
                    # Find dumpcap processes
                    if proc_name == "dumpcap" or proc_name == "dumpcap.exe":
                        print(f"Found dumpcap process: PID {proc.pid}")
                        os.kill(proc.pid, signal.SIGTERM)
                        killed += 1
                    # Also look for tshark processes
                    elif proc_name == "tshark" or proc_name == "tshark.exe":
                        print(f"Found tshark process: PID {proc.pid}")
                        os.kill(proc.pid, signal.SIGTERM)
                        killed += 1
                    # Look for any Python process that might be running PyShark
                    elif ("python" in proc_name and 
                          ("pyshark" in cmdline_str or "dumpcap" in cmdline_str or "tshark" in cmdline_str)):
                        print(f"Found PyShark related Python process: PID {proc.pid}")
                        os.kill(proc.pid, signal.SIGTERM)
                        killed += 1
                except Exception as kill_error:
                    print(f"Error terminating process: {kill_error}")
                    
            print(f"Terminated {killed} PyShark/dumpcap processes")
            
            # Add a small delay to let processes terminate completely
            time.sleep(0.5)
            
        except Exception as e:
            print(f"Error killing PyShark processes: {e}")

