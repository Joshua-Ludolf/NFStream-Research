import tkinter as tk
from tkinter import ttk
from datetime import datetime

class FlowsTab:
    """Class to manage the Network Flows tab functionality"""
    
    def __init__(self, parent, root, app):
        """Initialize the flows tab
        
        Args:
            parent: The parent notebook
            root: The main tkinter window
            app: The main application object (NetworkMonitor)
        """
        self.parent = parent
        self.root = root
        self.app = app
        self.flows_tab = ttk.Frame(parent)
        
        # Create the UI components
        self.setup_flows_tab()
        
        # Protocol mapping dictionary for display purposes
        self.protocol_map = {
            0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 
            5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 
            10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 
            15: "XNET", 16: "CHAOS", 17: "UDP", 58: "ICMPv6", 47: "GRE", 
            48: "DSR", 49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 
            53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP",
            # ... more protocols can be added as needed
        }
    
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
    
    def update_flow_ui(self, flow, risk_score):
        """Update the UI with flow information"""
        try:
            # Format timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Handle both dictionary and object flow formats
            if isinstance(flow, dict):
                src_ip = flow.get('src_ip', "Unknown")
                dst_ip = flow.get('dst_ip', "Unknown")
                protocol_num = flow.get('protocol', 0)
                src_port = flow.get('src_port', 0)
                dst_port = flow.get('dst_port', 0)
                packets = flow.get('bidirectional_packets', 0)
                bytes_count = flow.get('bidirectional_bytes', 0)
                duration_ms = flow.get('bidirectional_duration_ms', 0)
            else:
                # Extract flow information safely with defaults
                src_ip = getattr(flow, 'src_ip', "Unknown")
                dst_ip = getattr(flow, 'dst_ip', "Unknown")
                protocol_num = getattr(flow, 'protocol', 0)
                src_port = getattr(flow, 'src_port', 0)
                dst_port = getattr(flow, 'dst_port', 0)
                packets = getattr(flow, 'bidirectional_packets', 
                                 getattr(flow, 'packets', 0))
                bytes_count = getattr(flow, 'bidirectional_bytes', 
                                     getattr(flow, 'bytes', 0))
                duration_ms = getattr(flow, 'bidirectional_duration_ms', 
                                     getattr(flow, 'duration_ms', 0))
            
            # Convert protocol number to protocol name
            protocol = self.protocol_map.get(protocol_num, str(protocol_num))
            
            # Calculate duration
            duration = "N/A"
            if duration_ms > 0:
                duration = f"{duration_ms/1000:.2f}s"
            
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

    def clear_flows(self):
        """Clear all flows from the treeview"""
        self.flows_tree.delete(*self.flows_tree.get_children())

# For backwards compatibility with existing code
def setup_flows_tab(notebook):
    """Legacy function to set up the Network Flows tab"""
    flows_tab = ttk.Frame(notebook)

    # Create treeview for flows
    flows_tree = ttk.Treeview(flows_tab)
    flows_tree["columns"] = ("time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packets", "bytes", "duration", "risk")

    # Configure columns
    for col in flows_tree["columns"]:
        flows_tree.heading(col, text=col.replace("_", " ").title())
        flows_tree.column(col, width=100)

    # Add scrollbars
    flow_y_scroll = ttk.Scrollbar(flows_tab, orient="vertical", command=flows_tree.yview)
    flow_x_scroll = ttk.Scrollbar(flows_tab, orient="horizontal", command=flows_tree.xview)
    flows_tree.configure(yscrollcommand=flow_y_scroll.set, xscrollcommand=flow_x_scroll.set)

    flow_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    flow_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
    flows_tree.pack(fill=tk.BOTH, expand=True)

    return flows_tab
