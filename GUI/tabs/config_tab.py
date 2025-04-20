import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress

class ConfigTab:
    """Class to manage the Configuration tab functionality"""
    
    def __init__(self, parent, root, app):
        """Initialize the configuration tab
        
        Args:
            parent: The parent notebook
            root: The main tkinter window
            app: The main application object (NetworkMonitor)
        """
        self.parent = parent
        self.root = root
        self.app = app
        self.config_tab = ttk.Frame(parent)
        
        # Default thresholds
        self.thresholds = {
            "max_packets_per_second": 1000,
            "max_connections_per_minute": 100,
            "max_dns_queries_per_minute": 50,
            "max_failed_connections": 10
        }
        
        # Load thresholds from app if available
        if hasattr(app, 'thresholds'):
            self.thresholds = app.thresholds
        
        # Create the UI components
        self.setup_config_tab()
    
    def setup_config_tab(self):
        """Set up the Configuration tab"""
        # Create frames for different config sections
        detection_frame = ttk.LabelFrame(self.config_tab, text="Detection Configuration")
        detection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        response_frame = ttk.LabelFrame(self.config_tab, text="Response Configuration")
        response_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Detection thresholds        
        ttk.Label(detection_frame, text="Max packets per second:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_pps_var = tk.StringVar(master=self.root, value=str(self.thresholds["max_packets_per_second"]))
        ttk.Entry(detection_frame, textvariable=self.max_pps_var, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max connections per minute:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_conn_var = tk.StringVar(master=self.root, value=str(self.thresholds["max_connections_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_conn_var, width=10).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max DNS queries per minute:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_dns_var = tk.StringVar(master=self.root, value=str(self.thresholds["max_dns_queries_per_minute"]))
        ttk.Entry(detection_frame, textvariable=self.max_dns_var, width=10).grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(detection_frame, text="Max failed connections:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_failed_var = tk.StringVar(master=self.root, value=str(self.thresholds["max_failed_connections"]))
        ttk.Entry(detection_frame, textvariable=self.max_failed_var, width=10).grid(row=3, column=1, padx=5, pady=5)
        
        # Custom malicious IP input
        ttk.Label(detection_frame, text="Add malicious IP:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_malicious_ip = ttk.Entry(detection_frame, width=20)
        self.new_malicious_ip.grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(detection_frame, text="Add", command=self.add_malicious_ip).grid(row=4, column=2, padx=5, pady=5)
        
        # Response options
        ttk.Label(response_frame, text="Default response:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.default_response_var = tk.StringVar(master=self.root, value="Block IP")
        ttk.Combobox(response_frame, textvariable=self.default_response_var, 
                    values=["Block IP", "Reset Connection", "Log Only"], 
                    state="readonly").grid(row=0, column=1, padx=5, pady=5)
        
        self.auto_response_var = tk.BooleanVar(master=self.root, value=True)
        ttk.Checkbutton(response_frame, text="Auto-respond to threats", 
                       variable=self.auto_response_var).grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save button
        ttk.Button(self.config_tab, text="Save Configuration", command=self.save_configuration).pack(pady=10)
    
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
            if hasattr(self.app, 'threat_ips'):
                self.app.threat_ips.add(ip)
            
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
            
            # Update app's thresholds if applicable
            if hasattr(self.app, 'thresholds'):
                self.app.thresholds = self.thresholds.copy()
            
            # Update response preferences
            if hasattr(self.app, 'auto_response_var'):
                self.app.auto_response_var = self.auto_response_var
            if hasattr(self.app, 'default_response_var'):
                self.app.default_response_var = self.default_response_var
            
            # Show confirmation
            messagebox.showinfo("Configuration", "Settings saved successfully")
            print(f"Updated thresholds: {self.thresholds}")
            
        except ValueError as ve:
            messagebox.showerror("Error", "Please enter valid numbers for all thresholds")
            print(f"Configuration error: {ve}")

# For backwards compatibility with existing code
def setup_config_tab(notebook):
    """Legacy function to set up the Configuration tab"""
    config_tab = ttk.Frame(notebook)

    # Create frames for different config sections
    detection_frame = ttk.LabelFrame(config_tab, text="Detection Configuration")
    detection_frame.pack(fill="x", padx=10, pady=10)

    response_frame = ttk.LabelFrame(config_tab, text="Response Configuration")
    response_frame.pack(fill="x", padx=10, pady=10)

    # Detection thresholds
    ttk.Label(detection_frame, text="Max packets per second:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(detection_frame, width=10).grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(detection_frame, text="Max connections per minute:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(detection_frame, width=10).grid(row=1, column=1, padx=5, pady=5)

    # Response options
    ttk.Label(response_frame, text="Default response:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Combobox(response_frame, values=["Block IP", "Reset Connection", "Log Only"], state="readonly").grid(row=0, column=1, padx=5, pady=5)

    return config_tab
