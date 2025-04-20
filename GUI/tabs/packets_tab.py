import tkinter as tk
from tkinter import ttk, scrolledtext
import re
from datetime import datetime

class PacketsTab:
    """Class to manage the Packet Analysis tab functionality"""
    
    def __init__(self, parent, root, app):
        """Initialize the packets tab
        
        Args:
            parent: The parent notebook
            root: The main tkinter window
            app: The main application object (NetworkMonitor)
        """
        self.parent = parent
        self.root = root
        self.app = app
        self.packets_tab = ttk.Frame(parent)
        self.packet_store = {}  # Store packet objects by ID for later reference
        
        # Create the UI components
        self.setup_packets_tab()
    
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
        
        # Packet details text area - create with normal state initially
        self.packet_details_text = scrolledtext.ScrolledText(packet_detail_frame, wrap=tk.WORD)
        self.packet_details_text.pack(fill=tk.BOTH, expand=True)
        
        # Make it read-only by binding key events instead of disabling
        self.packet_details_text.bind("<Key>", lambda e: "break")  # Prevent typing
        self.packet_details_text.bind("<Control-c>", lambda e: None)  # Allow copy
    
    def add_packet_to_ui(self, packet, packet_data, packet_id):
        """Add packet to the UI"""
        if not self.app.is_monitoring:
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
                self.packet_details_text.insert(tk.END, f"  Length: {packet.udp.length}\n")
        
        # Process additional protocol details if needed
        self._add_http_details(packet)
        self._add_dns_details(packet)
        self._add_icmp_details(packet)
        self._add_tls_details(packet)
        self._add_mdns_details(packet)
        self._add_quic_details(packet)
        
        # Add raw data display
        self._add_raw_data_display(packet, packet_id, timestamp, length, info)
    
    def _add_http_details(self, packet):
        """Add HTTP details to the packet details text area"""
        if not hasattr(packet, 'http'):
            return
            
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
    
    def _add_dns_details(self, packet):
        """Add DNS details to the packet details text area"""
        if not hasattr(packet, 'dns'):
            return
            
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
            self.packet_details_text.insert(tk.END, f"  [DNS packet detected but no detailed fields available]\n")
    
    def _add_icmp_details(self, packet):
        """Add ICMP details to the packet details text area"""
        # ICMPv6
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
        
        # ICMPv4
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
    
    def _add_tls_details(self, packet):
        """Add TLS details to the packet details text area"""
        if not hasattr(packet, 'tls'):
            return
            
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
        for attr in ['packet_number', 'payload_length', 'flags']:
            if attr in tls_attributes:
                try:
                    value = getattr(packet.tls, attr)
                    if value:
                        self.packet_details_text.insert(tk.END, f"  {attr.replace('_', ' ').title()}: {value}\n")
                        displayed_something = True
                except Exception:
                    pass  # Skip if attribute access causes error
    
        # If no attributes were displayed, show a message
        if not displayed_something:
            self.packet_details_text.insert(tk.END, f"  [TLS packet detected but no detailed fields available]\n")
    
    def _add_mdns_details(self, packet):
        """Add mDNS details to the packet details text area"""
        if not hasattr(packet, 'mdns'):
            return
            
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
        
        # Enhanced mDNS field extraction - try to access common DNS-like fields that may work for mDNS too
        # mDNS often uses same field structure as DNS but with different attribute names
        dns_field_names = [
            ('dns.flags', 'Flags'), 
            ('dns.id', 'ID'),
            ('dns.count.queries', 'Query Count'),
            ('dns.count.answers', 'Answer Count'),
            ('dns.qry.name', 'Query Name'),
            ('dns.qry.type', 'Query Type'),
            ('dns.resp.name', 'Response Name'),
            ('dns.resp.ttl', 'Response TTL'),
            ('dns.resp.addr', 'Response Address')
        ]
        
        # Try to access all fields directly
        if hasattr(packet.mdns, '_all_fields'):
            for field_name, display_name in dns_field_names:
                if field_name in packet.mdns._all_fields:
                    self.packet_details_text.insert(tk.END, f"  {display_name}: {packet.mdns._all_fields[field_name]}\n")
                    displayed_something = True
        
        # Try to access field dictionary if available
        if hasattr(packet.mdns, 'field_names'):
            for field_name in packet.mdns.field_names:
                try:
                    if field_name not in ['_all_fields', '_field_prefix']:
                        value = getattr(packet.mdns, field_name)
                        self.packet_details_text.insert(tk.END, f"  {field_name.replace('_', ' ').title()}: {value}\n")
                        displayed_something = True
                except Exception:
                    pass
        
        # If no attributes were displayed, show a message - but only once
        if not displayed_something:
            self.packet_details_text.insert(tk.END, f"  [mDNS packet detected but no detailed fields available]\n")
    
    def _add_quic_details(self, packet):
        """Add QUIC details to the packet details text area"""
        if not hasattr(packet, 'quic'):
            return
                
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
    
    def _add_raw_data_display(self, packet, packet_id, timestamp, length, info):
        """Add raw data display to the packet details text area"""
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
                if hasattr(self.app, 'alerts_tab') and hasattr(self.app.alerts_tab, 'alerts_tree'):
                    for item_id in self.app.alerts_tab.alerts_tree.get_children():
                        alert_values = self.app.alerts_tab.alerts_tree.item(item_id, "values")
                        alert_src = alert_values[2]  # Source IP is in the 3rd column
                        
                        if alert_src == src_ip:
                            return f"⚠️ {alert_values[1]} alert: {alert_values[4]}"
        except Exception as e:
            return f"Error checking alerts: {e}"
            
        return "No alerts for this packet"
    
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
    
    def clear_packets(self):
        """Clear all packets from the treeview"""
        self.packets_tree.delete(*self.packets_tree.get_children())
        self.packet_store.clear()

# For backwards compatibility with existing code
def setup_packets_tab(notebook):
    """Legacy function to set up the Packet Analysis tab"""
    packets_tab = ttk.Frame(notebook)

    # Create treeview for packets
    packets_tree = ttk.Treeview(packets_tab)
    packets_tree["columns"] = ("time", "src", "dst", "protocol", "length", "info")

    # Configure columns
    for col in packets_tree["columns"]:
        packets_tree.heading(col, text=col.title())
        packets_tree.column(col, width=100)

    # Add scrollbars
    packet_y_scroll = ttk.Scrollbar(packets_tab, orient="vertical", command=packets_tree.yview)
    packet_x_scroll = ttk.Scrollbar(packets_tab, orient="horizontal", command=packets_tree.xview)
    packets_tree.configure(yscrollcommand=packet_y_scroll.set, xscrollcommand=packet_x_scroll.set)

    packet_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    packet_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
    packets_tree.pack(fill=tk.BOTH, expand=True)

    return packets_tab
