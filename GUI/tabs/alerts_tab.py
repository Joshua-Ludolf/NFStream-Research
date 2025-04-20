import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from ..responses import block_ip, unblock_ip, send_reset_packets, get_blocked_ips

class AlertsTab:
    """Class to manage the Alerts & Response tab functionality"""
    
    def __init__(self, parent, root, app):
        """Initialize the alerts tab
        
        Args:
            parent: The parent notebook
            root: The main tkinter window
            app: The main application object (NetworkMonitor)
        """
        self.parent = parent
        self.root = root
        self.app = app
        self.alerts_tab = ttk.Frame(parent)
        self.blocked_ips = set()  # Track blocked IPs
        
        # Create the UI components
        self.setup_alerts_tab()
        
        # Load previously blocked IPs from persistent storage
        self.load_blocked_ips()
    
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
        self.parent.select(self.alerts_tab)
        
        # Play an alert sound
        self.root.bell()
    
    def execute_response(self):
        """Execute the selected response action for the selected alert"""
        # Get selected alert
        selected_alerts = self.alerts_tree.selection()
        if not selected_alerts:
            messagebox.showinfo("Info", "No alert selected")
            return
        
        # Get alert details from the selected alert
        alert_item = selected_alerts[0]
        alert_values = self.alerts_tree.item(alert_item, "values")
        
        # Use the Source IP (column 2) for all actions - this is the malicious IP
        src_ip = alert_values[2]  # Source IP is in the 3rd column
        
        # Get selected response action
        action = self.response_combobox.get()
        
        # Execute the action
        if action == "Block IP":
            # Block the Source IP permanently regardless of alert type
            self.block_ip(src_ip, f"Manual block from alert: {alert_values[4]}")
            # Switch to the Blocked IPs tab to show the user that the IP was blocked
            self.parent.select(self.alerts_tab)
            # Highlight the newly blocked IP in the blocked IPs list
            for item in self.blocked_tree.get_children():
                if self.blocked_tree.item(item, "values")[0] == src_ip:
                    self.blocked_tree.selection_set(item)
                    self.blocked_tree.see(item)
                    break
            messagebox.showinfo("Response", f"Source IP {src_ip} has been permanently blocked.\nUse 'Unblock Selected' to remove this block if needed.")
        elif action == "Reset Connection":
            send_reset_packets(src_ip)
            messagebox.showinfo("Response", f"Reset connections from {src_ip}")
        elif action == "Log Only":
            messagebox.showinfo("Response", f"Logged activity from {src_ip}")
    
    def block_ip(self, ip, reason):
        """Block an IP address"""
        if ip in self.blocked_ips:
            return  # Already blocked
        
        # Validate IP address before blocking to avoid crashes
        try:
            # Add to blocked set
            self.blocked_ips.add(ip)
            self.app.blocked_ips.add(ip)  # Update the main app's blocked IPs set
            
            # Add to blocked list UI
            item_id = self.blocked_tree.insert("", "end", values=(
                ip,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                reason
            ))
            
            # Call the block_ip function from responses.py with the reason
            # This will also save the IP to persistent storage
            block_ip(ip, reason)
            
            # Update BPF filters for all capturing interfaces
            if hasattr(self.app, 'update_capture_filters'):
                self.app.update_capture_filters()
                
            # Ensure proper refresh of the UI
            self.root.update_idletasks()
            
            print(f"Successfully blocked IP {ip} - will remain blocked until manually unblocked")
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
            print("No items selected")
            return
        
        item_id = selected_items[0]
        ip = self.blocked_tree.item(item_id, "values")[0]
        
        # Remove from blocked set
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        if ip in self.app.blocked_ips:
            self.app.blocked_ips.remove(ip)
        
        # Call the unblock_ip function from responses.py
        unblock_ip(ip)
        
        # Remove from UI
        self.blocked_tree.delete(item_id)
        print(f"Unblocked IP: {ip}")

    def load_blocked_ips(self):
        """Load previously blocked IPs from persistent storage"""
        try:
            # Get blocked IPs from persistent storage
            blocked_ips_dict = get_blocked_ips()
            
            # Add each blocked IP to the UI and in-memory sets
            for ip, details in blocked_ips_dict.items():
                if ip not in self.blocked_ips:
                    # Add to blocked sets
                    self.blocked_ips.add(ip)
                    if hasattr(self.app, 'blocked_ips'):
                        self.app.blocked_ips.add(ip)
                    
                    # Add to blocked list UI
                    self.blocked_tree.insert("", "end", values=(
                        ip,
                        details.get("time_blocked", "Unknown"),
                        details.get("reason", "Persistent block")
                    ))
            
            if blocked_ips_dict:
                print(f"Loaded {len(blocked_ips_dict)} previously blocked IPs")
        except Exception as e:
            print(f"Error loading blocked IPs: {e}")

# For backwards compatibility with existing code
def setup_alerts_tab(notebook):
    """Legacy function to set up the Alerts & Response tab"""
    alerts_tab = ttk.Frame(notebook)

    # Create treeview for alerts
    alerts_tree = ttk.Treeview(alerts_tab)
    alerts_tree["columns"] = ("time", "severity", "source", "destination", "alert_type", "details")

    # Configure columns
    for col in alerts_tree["columns"]:
        alerts_tree.heading(col, text=col.replace("_", " ").title())
        alerts_tree.column(col, width=100)

    # Add scrollbars
    alerts_y_scroll = ttk.Scrollbar(alerts_tab, orient="vertical", command=alerts_tree.yview)
    alerts_x_scroll = ttk.Scrollbar(alerts_tab, orient="horizontal", command=alerts_tree.xview)
    alerts_tree.configure(yscrollcommand=alerts_y_scroll.set, xscrollcommand=alerts_x_scroll.set)

    alerts_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    alerts_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
    alerts_tree.pack(fill=tk.BOTH, expand=True)

    return alerts_tab
