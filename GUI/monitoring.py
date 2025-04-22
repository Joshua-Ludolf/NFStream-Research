# filepath: c:\Users\Joshu\Downloads\Computer Security\NFStream-Research\GUI\monitoring.py
import threading
import time
import os
import sys
import platform
import subprocess
from datetime import datetime
import json
import re
import uuid
import asyncio
import socket

# Global variables for monitoring control
is_monitoring = False
active_threads = []
active_captures = []
active_captures_lock = threading.Lock()
nfstream_streamer = None  # Global reference to NFStream streamer

# Add global set for blocked IPs that will be used across all monitoring methods
BLOCKED_IPS = set()
IP_BLOCK_LOCK = threading.Lock()

try:
    # Try to import NFStream for flow-based analysis
    import nfstream
    NFSTREAM_AVAILABLE = True
except ImportError:
    print("NFStream not available. Flow-based analysis will be disabled.")
    NFSTREAM_AVAILABLE = False

try:
    # Try to import PyShark for packet-level analysis
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    print("PyShark not available. Packet-level analysis will be disabled.")
    PYSHARK_AVAILABLE = False

try:
    # Try to import Scapy for custom packet handling
    from scapy.all import conf as scapy_conf
    from scapy.all import IP, TCP, send, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    print("Scapy not available. Custom packet handling will be disabled.")
    SCAPY_AVAILABLE = False

# Reference to the main app
global_app = None

def set_app_reference(app):
    """Set the reference to the main application for callbacks
    
    Args:
        app: The main NetworkMonitor application
    """
    global global_app
    global_app = app
    print("Successfully set app reference to monitoring module")

def get_network_interfaces():
    """Get hardcoded network interface configuration
    
    Returns:
        dict: Dictionary mapping interface friendly names to technical details
    """
    # Use specific hardcoded interface values from gui.py
    interfaces = {
        "Wi-Fi": {
            'nfstream_name': "Intel(R) Wi-Fi 6 AX201 160MHz",  # Actual interface description
            'pyshark_name': "Wi-Fi",  # Windows name (would be eth0 on Linux or wlan0 on Mac)
            'scapy_name': "Intel(R) Wi-Fi 6 AX201 160MHz",  # Actual interface description
            'friendly_name': "Wi-Fi Interface"
        }
    }
    
    # Debug output
    print(f"Using hardcoded network interface: {', '.join(interfaces.keys())}")
    print(f"  NFStream name: {interfaces['Wi-Fi']['nfstream_name']}")
    print(f"  PyShark name: {interfaces['Wi-Fi']['pyshark_name']}")
    print(f"  Scapy name: {interfaces['Wi-Fi']['scapy_name']}")
    
    return interfaces

def start_monitoring(interface_name=None):
    """Start the monitoring process
    
    Args:
        interface_name (str, optional): The name of the interface to monitor. Defaults to None.
    """
    global is_monitoring, active_threads
    
    # If no interface was specified, use Wi-Fi
    if not interface_name:
        interface_name = "Wi-Fi"
        print(f"No interface specified, using: {interface_name}")
    
    print(f"Starting monitoring on interface: {interface_name}")
    
    # Set monitoring flag
    is_monitoring = True
    
    try:
        # Always start both PyShark and NFStream monitoring simultaneously
        # Start NFStream thread first
        if NFSTREAM_AVAILABLE:
            print("Starting NFStream monitoring thread...")
            nfstream_thread = threading.Thread(target=nfstream_monitor, args=(interface_name,))
            nfstream_thread.daemon = True
            nfstream_thread.start()
            active_threads.append(nfstream_thread)
        else:
            print("NFStream not available - flow monitoring disabled")
        
        # Start PyShark thread next
        if PYSHARK_AVAILABLE:
            print("Starting PyShark monitoring thread...")
            pyshark_thread = threading.Thread(target=pyshark_monitor, args=(interface_name,))
            pyshark_thread.daemon = True
            pyshark_thread.start()
            active_threads.append(pyshark_thread)
        else:
            print("PyShark not available - packet monitoring disabled")
            
        # Confirm both monitoring systems are active
        print(f"Monitoring active with {len(active_threads)} thread(s)")
        
        return True
    except Exception as e:
        print(f"Error starting monitoring: {e}")
        is_monitoring = False
        return False

def stop_monitoring():
    """Stop the monitoring process"""
    global is_monitoring, active_threads, active_captures, nfstream_streamer
    
    print("Stopping monitoring...")
    
    # Signal threads to stop
    is_monitoring = False
    
    # Give threads a moment to notice the flag change
    time.sleep(0.5)
    
    # Handle NFStream cleanup
    if 'nfstream_streamer' in globals() and nfstream_streamer is not None:
        print("Shutting down NFStream streamer...")
        # In your version, NFStream doesn't have shutdown() or close() methods
        # We'll just set it to None and let Python's garbage collector handle it
        nfstream_streamer = None
        print("NFStream reference cleared")
      # Close any active PyShark captures
    with active_captures_lock:
        for capture in active_captures:
            try:
                # Check if capture has a close method
                if hasattr(capture, 'close'):
                    # Handle different types of close methods
                    if asyncio.iscoroutinefunction(capture.close):
                        # For coroutine close methods, use a separate event loop
                        try:
                            # Create a new event loop for cleanup
                            temp_loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(temp_loop)
                            # Run the close coroutine in this temp loop
                            temp_loop.run_until_complete(capture.close())
                            temp_loop.close()
                        except Exception as async_e:
                            print(f"Error in async close: {async_e}")
                    else:
                        # For synchronous close methods
                        capture.close()
                
                # Handle event loop cleanup separately
                if hasattr(capture, 'eventloop') and capture.eventloop is not None:
                    try:
                        if not capture.eventloop.is_closed():
                            # Cancel any pending tasks
                            tasks = asyncio.all_tasks(capture.eventloop) if hasattr(asyncio, 'all_tasks') else []
                            for task in tasks:
                                task.cancel()
                            capture.eventloop.close()
                    except Exception as loop_e:
                        print(f"Error closing event loop: {loop_e}")
            except Exception as e:
                print(f"Error closing capture: {e}")
        
        # Clear the list
        active_captures.clear()
    
    # Try to join the threads with timeout
    for thread in active_threads:
        if thread.is_alive():
            thread.join(timeout=2.0)
            
    # If threads are still alive after timeout, try more aggressive measures
    for thread in active_threads:
        if thread.is_alive():
            print(f"Thread {thread.name} still running, forcing termination...")
            # We can't forcefully terminate threads in Python, but we can log this
    
    # Clear the thread list
    active_threads.clear()
    
    print("Monitoring stopped.")
    return True

def nfstream_monitor(interface_name):
    """Monitor network flows using NFStream
    
    Args:
        interface_name (str): Interface to monitor
    """
    global nfstream_streamer  # Add global reference to track the streamer
    
    if not NFSTREAM_AVAILABLE:
        print("NFStream not available. Flow monitoring disabled.")
        return
    
    print(f"NFStream monitoring started on {interface_name}")
    
    try:
        # Get the interface name to use with NFStream
        # Use the hardcoded interface name from the app if available
        if interface_name == "Wi-Fi" and global_app and hasattr(global_app, 'interface'):
            nfstream_iface = global_app.interface['nfstream_name']
            print(f"Using NFStream interface name from app: {nfstream_iface}")
        else:
            # Direct interface name mapping for platform specific use
            if platform.system() == "Windows":
                # On Windows, we often need to use the adapter description
                nfstream_iface = "Intel(R) Wi-Fi 6 AX201 160MHz"
            elif platform.system() == "Linux":
                # On Linux, we typically use the interface name
                nfstream_iface = "wlan0"
            elif platform.system() == "Darwin":  # macOS
                nfstream_iface = "en0"
            else:
                nfstream_iface = interface_name
            print(f"Using platform-specific NFStream interface: {nfstream_iface}")

        try:
            # Attempt to speed up capturing by using these parameters if your version supports them
            print("Attempting to create NFStream flow meter with fast capture settings...")
            try:
                # Try with all parameters for newer versions
                nfstream_streamer = nfstream.NFStreamer(
                    source=nfstream_iface,
                    accounting_mode=1,  # Generate flow statistics immediately
                    idle_timeout=1,    # Very short idle timeout (1 second)
                    active_timeout=10,  # Short active timeout (10 seconds)
                    n_dissections=0,   # Disable deep packet inspection for speed
                    statistical_analysis=True  # Enable statistical analysis
                )
            except TypeError:
                # Fall back to simpler parameters for older versions
                print("Using simplified parameters for older NFStream version")
                nfstream_streamer = nfstream.NFStreamer(source=nfstream_iface)
                
            print("NFStream flow meter created successfully!")
            
            # Process flows in real-time
            flow_count = 0
            for flow in nfstream_streamer:
                if not is_monitoring:
                    break
                    
                flow_count += 1
                if flow_count % 5 == 0:
                    print(f"Processed {flow_count} flows")
                
                try:
                    # Get source IP address from flow
                    src_ip = getattr(flow, 'src_ip', "unknown")
                    dst_ip = getattr(flow, 'dst_ip', "unknown")
                    
                    # Check if the source IP is blocked - if so, drop the flow
                    with IP_BLOCK_LOCK:
                        if src_ip in BLOCKED_IPS:
                            print(f"🛑 NFStream dropping flow from blocked IP: {src_ip} -> {dst_ip}")
                            continue  # Skip this flow
                    
                    # Calculate a risk score for the flow
                    risk_score = calculate_flow_risk(flow)
                    
                    # Print basic flow info regardless of UI
                    src_ip = getattr(flow, 'src_ip', "unknown")
                    dst_ip = getattr(flow, 'dst_ip', "unknown")
                    protocol = getattr(flow, 'protocol', 0)
                    src_port = getattr(flow, 'src_port', 0)
                    dst_port = getattr(flow, 'dst_port', 0)
                    
                    # Debug print to help identify flow attributes
                    print(f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{protocol}] Risk: {risk_score}")
                    
                    # Update UI with flow information
                    if global_app and hasattr(global_app, 'update_flow_ui'):
                        # Instead of passing the raw flow object which might have version-specific attributes,
                        # create a standardized dictionary with the extracted attributes
                        flow_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'protocol': protocol,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'bidirectional_packets': getattr(flow, 'bidirectional_packets', getattr(flow, 'packets', 1)),
                            'bidirectional_bytes': getattr(flow, 'bidirectional_bytes', getattr(flow, 'bytes', 0)),
                            'bidirectional_duration_ms': getattr(flow, 'bidirectional_duration_ms', 
                                                                getattr(flow, 'duration_ms', 0))
                        }
                        
                        print(f"Sending flow to UI: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                        
                        # Use the UI's main thread to update the flow display
                        if hasattr(global_app.root, 'after'):
                            global_app.root.after(1, lambda: global_app.update_flow_ui(flow_data, risk_score))
                        else:
                            # Direct call as fallback
                            global_app.update_flow_ui(flow_data, risk_score)
                    
                    # Check for high-risk flows and trigger alerts
                    if risk_score >= 80:
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Suspicious Flow",
                            "details": f"High risk flow detected (score: {risk_score})"
                        }
                        
                        if global_app and hasattr(global_app, 'add_alert'):
                            global_app.add_alert(alert_details)
                        else:
                            print(f"ALERT: {alert_details}")
                            
                except Exception as inner_e:
                    print(f"Error processing flow: {inner_e}")
                    
            print("NFStream monitoring completed or stopped")
            
        except Exception as flow_e:
            print(f"Error with NFStream flow meter: {flow_e}")
            
            # Try to use sample PCAP files for demonstration if live capture fails
            try_sample_pcaps()
        
    except Exception as e:
        print(f"Error in NFStream monitoring: {e}")

def try_sample_pcaps():
    """Try to use sample PCAP files for demonstration"""
    global nfstream_streamer
    
    print("Trying to use a sample PCAP file for demonstration...")
    
    # Fallback to a sample pcap if available
    sample_pcaps = ["demo.pcap", "wifi.pcap", "wifi.pcapng", "sample.pcap"]
    pcap_found = False
    
    for pcap in sample_pcaps:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pcap_path = os.path.join(base_dir, pcap)
        if os.path.exists(pcap_path):
            print(f"Using sample PCAP file: {pcap_path}")
            pcap_found = True
            try:
                # Try to use the PCAP file with NFStream
                nfstream_streamer = nfstream.NFStreamer(source=pcap_path)
                
                # Process PCAP flows
                flow_count = 0
                for flow in nfstream_streamer:
                    if not is_monitoring:
                        break
                        
                    flow_count += 1
                    if flow_count % 5 == 0:
                        print(f"Processed {flow_count} sample flows from PCAP")
                    
                    # Calculate risk score
                    risk_score = calculate_flow_risk(flow)
                    
                    # Basic flow info
                    src_ip = getattr(flow, 'src_ip', "unknown")
                    dst_ip = getattr(flow, 'dst_ip', "unknown")
                    protocol = getattr(flow, 'protocol', 0)
                    src_port = getattr(flow, 'src_port', 0)
                    dst_port = getattr(flow, 'dst_port', 0)
                    
                    print(f"Flow (from PCAP): {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    
                    # Update UI
                    if global_app and hasattr(global_app, 'update_flow_ui'):
                        # Create standardized flow dictionary
                        flow_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'protocol': protocol,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'bidirectional_packets': getattr(flow, 'bidirectional_packets', 
                                                            getattr(flow, 'packets', 1)),
                            'bidirectional_bytes': getattr(flow, 'bidirectional_bytes', 
                                                         getattr(flow, 'bytes', 0)),
                            'bidirectional_duration_ms': getattr(flow, 'bidirectional_duration_ms', 
                                                              getattr(flow, 'duration_ms', 0))
                        }
                        
                        # Use main thread for UI updates
                        if hasattr(global_app.root, 'after'):
                            global_app.root.after(1, lambda: global_app.update_flow_ui(flow_data, risk_score))
                        else:
                            global_app.update_flow_ui(flow_data, risk_score)
                
                break  # Exit loop after successful PCAP processing
                
            except Exception as pcap_e:
                print(f"Error using PCAP file: {pcap_e}")
    
    if not pcap_found:
        print("No sample PCAP files found for demonstration.")
        
        # Generate some synthetic flows as absolute fallback
        generate_synthetic_flows()

def generate_synthetic_flows():
    """Generate synthetic flows for demonstration when no real traffic or PCAPs are available"""
    if not global_app or not hasattr(global_app, 'update_flow_ui'):
        print("Cannot generate synthetic flows - no UI reference")
        return
        
    print("Generating synthetic network flows for demonstration...")
    
    # Common protocols to simulate
    protocols = [6, 17]  # TCP, UDP
    
    # Generate 10 synthetic flows with a slight delay between them
    for i in range(10):
        if not is_monitoring:
            break
            
        # Create random IPs
        src_ip = f"192.168.1.{10 + i}"
        dst_ip = f"203.0.113.{50 + i}"
        
        # Choose protocol
        protocol = protocols[i % len(protocols)]
        
        # Ports
        src_port = 1024 + (i * 100)
        dst_port = [80, 443, 53, 22, 3389][i % 5]
        
        # Other attributes
        packets = 10 + (i * 5)
        bytes_count = packets * 500
        duration_ms = 1000 + (i * 500)
        
        # Risk score - make some high risk
        risk_score = 30
        if i % 5 == 0:
            risk_score = 85  # High risk
        elif i % 3 == 0:
            risk_score = 60  # Medium risk
        
        # Create flow data dictionary
        flow_data = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'bidirectional_packets': packets,
            'bidirectional_bytes': bytes_count,
            'bidirectional_duration_ms': duration_ms
        }
        
        print(f"Synthetic flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Update UI
        if hasattr(global_app.root, 'after'):
            global_app.root.after(1, lambda: global_app.update_flow_ui(flow_data, risk_score))
        else:
            global_app.update_flow_ui(flow_data, risk_score)
            
        # Slight delay between synthetic flows
        time.sleep(0.5)

def pyshark_monitor(interface_name):
    """Monitor packets using PyShark
    
    Args:
        interface_name (str): Interface to monitor
    """
    if not PYSHARK_AVAILABLE:
        print("PyShark not available. Packet monitoring disabled.")
        return
        
    print(f"PyShark monitoring started on {interface_name}")
    
    try:
        # Get the interface name to use with PyShark
        pyshark_iface = interface_name
        if interface_name == "Wi-Fi" and global_app and hasattr(global_app, 'interface'):
            pyshark_iface = global_app.interface['pyshark_name']
            print(f"Using PyShark interface from app: {pyshark_iface}")
        
        # Create a new event loop for this thread
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        except Exception as loop_e:
            print(f"Error setting up event loop: {loop_e}")
            loop = None
        
        try:
            # Simple capture without complex options
            # This should work with most PyShark versions
            capture = pyshark.LiveCapture(interface=pyshark_iface)
            
            # Register the capture object for proper cleanup
            with active_captures_lock:
                active_captures.append(capture)
            
            # Process packets safely
            max_packets = 100  # Limit for safe testing
            count = 0
            
            print("Starting packet capture...")
            
            # Use a simple callback to process packets one at a time
            for packet in capture.sniff_continuously():
                if not is_monitoring or count >= max_packets:
                    break
                
                # Process the packet
                try:
                    process_packet(packet, count)
                except Exception as packet_e:
                    print(f"Error processing packet #{count}: {packet_e}")
                
                count += 1
                
                # Periodically check monitoring status
                if count % 10 == 0:
                    print(f"Processed {count} packets")
                    if not is_monitoring:
                        break
            
            # Close the capture properly
            try:
                if hasattr(capture, 'close'):
                    capture.close()
            except Exception as close_e:
                print(f"Error closing capture: {close_e}")
                
        except Exception as capture_e:
            print(f"Error with PyShark capture: {capture_e}")
            
            # Try alternative method for older PyShark versions
            try:
                print("Trying alternative PyShark capture method...")
                capture = pyshark.LiveCapture(interface=pyshark_iface)
                capture.sniff(timeout=5, packet_count=10)
                
                for i, packet in enumerate(capture):
                    process_packet(packet, i)
                    
            except Exception as alt_e:
                print(f"Alternative PyShark method also failed: {alt_e}")
        
    except Exception as e:
        print(f"Error in PyShark monitoring: {e}")
        
def process_packet(packet, packet_counter):
    """Process a packet captured by PyShark
    
    Args:
        packet: The PyShark packet object
        packet_counter: Packet sequence number
    """
    try:
        # Extract basic packet information
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Try to extract IP addresses
        src_ip = ""
        dst_ip = ""
        protocol = "?"
        length = 0
        
        # Try to get packet length
        if hasattr(packet, 'length'):
            length = packet.length
        elif hasattr(packet, 'captured_length'):
            length = packet.captured_length
        elif hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'len'):
            length = packet.frame_info.len
            
        # Get protocol information
        if hasattr(packet, 'highest_layer'):
            protocol = packet.highest_layer
        elif hasattr(packet, 'transport_layer'):
            protocol = packet.transport_layer
            
        # Try to get IP addresses
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            
        # Check if source IP is blocked - if so, drop the packet
        with IP_BLOCK_LOCK:
            if src_ip in BLOCKED_IPS:
                print(f"🛑 PyShark dropping packet from blocked IP: {src_ip} -> {dst_ip}")
                return  # Drop the packet by returning early
                
        # Create a simple summary
        summary = f"{protocol} packet"
        if hasattr(packet, 'highest_layer'):
            summary = f"{packet.highest_layer} packet"
        
        # Generate a unique ID for this packet
        packet_id = f"pkt_{packet_counter}_{timestamp}"
        
        # Create packet data tuple
        packet_data = (timestamp, src_ip, dst_ip, protocol, length, summary)
        
        # Print packet info to console
        print(f"Packet [{packet_counter}]: {src_ip} -> {dst_ip} [{protocol}] {length} bytes")
        
        # Update UI with packet information
        if global_app and hasattr(global_app, 'add_packet_to_ui'):
            # Use main thread for UI updates
            if hasattr(global_app.root, 'after'):
                global_app.root.after(1, lambda: global_app.add_packet_to_ui(packet, packet_data, packet_id))
            else:
                global_app.add_packet_to_ui(packet, packet_data, packet_id)
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def calculate_flow_risk(flow):
    """Calculate a risk score for a network flow
    
    Args:
        flow: NFStream flow object
        
    Returns:
        int: Risk score between 0-100
    """
    risk_score = 0
    alert_details = None
    
    try:
        # Get critical flow attributes
        src_ip = getattr(flow, 'src_ip', "unknown")
        dst_ip = getattr(flow, 'dst_ip', "unknown")
        
        # Hardcoded known malicious IPs (same as in trigger_alert.py)
        known_malicious_ips = [
            "192.168.1.100",  # Example malicious IP
            "10.0.0.99",      # Example malicious IP
            "203.0.113.0",    # Example from TEST-NET-3 block
            "198.51.100.0",   # Example from TEST-NET-2 block
            "192.0.2.0"       # Example from TEST-NET-1 block
        ]
        
        # Check if any flow IP matches known malicious IPs
        for ip in known_malicious_ips:
            if src_ip == ip or dst_ip == ip:
                risk_score += 75
                print(f"HIGH ALERT: Detected known malicious IP: {ip}")
                
                # Create alert details to be shown in the UI
                if global_app and hasattr(global_app, 'add_security_alert'):
                    alert_details = {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": "High",
                        "source": src_ip,
                        "destination": dst_ip,
                        "alert_type": "Malicious IP",
                        "details": f"Traffic involving known malicious IP: {ip}"
                    }
                    # Schedule alert to be displayed in UI on main thread
                    if hasattr(global_app.root, 'after'):
                        global_app.root.after(0, lambda a=alert_details: global_app.add_security_alert(a))
                break
                
        # Check for unusual ports
        if hasattr(flow, 'dst_port'):
            unusual_ports = [22, 23, 1433, 3306, 5432, 6379, 27017, 21, 25, 110, 143, 4444, 5555]
            if flow.dst_port in unusual_ports:
                risk_score += 10
        
        # Check traffic volumes
        if hasattr(flow, 'bidirectional_bytes'):
            if flow.bidirectional_bytes > 10000000:
                risk_score += 15  # Large data transfers
            elif flow.bidirectional_bytes > 1000000:
                risk_score += 5   # Medium data transfers
        
        # Check application name for suspicious patterns (if available)
        if hasattr(flow, 'application_name'):
            suspicious_apps = ['bittorrent', 'ssh', 'telnet', 'irc', 'tor', 'malware']
            if any(app in flow.application_name.lower() for app in suspicious_apps):
                risk_score += 30
                
                # Create alert for suspicious application
                if global_app and hasattr(global_app, 'add_security_alert') and not alert_details:
                    alert_details = {
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": "Medium",
                        "source": src_ip,
                        "destination": dst_ip,
                        "alert_type": "Suspicious Application",
                        "details": f"Suspicious application detected: {flow.application_name}"
                    }
                    # Schedule alert to be displayed in UI on main thread
                    if hasattr(global_app.root, 'after'):
                        global_app.root.after(0, lambda a=alert_details: global_app.add_security_alert(a))
        
        # Check for known malicious IPs if app reference is available
        if global_app and hasattr(global_app, 'threat_ips'):
            try:
                if src_ip and src_ip in global_app.threat_ips:
                    risk_score += 50
                    print(f"High risk: {src_ip} is in threat list")
                    
                    # Create alert for threat IP
                    if hasattr(global_app, 'add_security_alert') and not alert_details:
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Threat List IP",
                            "details": f"Source IP {src_ip} is in threat intelligence list"
                        }
                        if hasattr(global_app.root, 'after'):
                            global_app.root.after(0, lambda a=alert_details: global_app.add_security_alert(a))
                    
                if dst_ip and dst_ip in global_app.threat_ips:
                    risk_score += 50
                    print(f"High risk: {dst_ip} is in threat list")
                    
                    # Create alert for threat IP
                    if hasattr(global_app, 'add_security_alert') and not alert_details:
                        alert_details = {
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "alert_type": "Threat List IP",
                            "details": f"Destination IP {dst_ip} is in threat intelligence list"
                        }
                        if hasattr(global_app.root, 'after'):
                            global_app.root.after(0, lambda a=alert_details: global_app.add_security_alert(a))
                    
            except Exception as threat_e:
                print(f"Error checking threat IPs: {threat_e}")
    
    except Exception as e:
        print(f"Error calculating flow risk: {e}")
    
    # Cap the risk score at 100
    return min(risk_score, 100)

def update_blocked_ips(ip_set):
    """Update the global blocked IPs set from Scapy's list
    
    Args:
        ip_set (set): Set of IP addresses to block
    """
    with IP_BLOCK_LOCK:
        BLOCKED_IPS.clear()
        BLOCKED_IPS.update(ip_set)
    print(f"Updated blocked IPs list for monitoring - {len(BLOCKED_IPS)} IPs blocked")
    
def get_blocked_ips():
    """Get the current set of blocked IPs
    
    Returns:
        set: Set of currently blocked IP addresses
    """
    with IP_BLOCK_LOCK:
        return set(BLOCKED_IPS)  # Return a copy of the set

def block_ip_in_monitoring(ip):
    """Add an IP address to the blocked list
    
    Args:
        ip (str): IP address to block
        
    Returns:
        bool: True if successful
    """
    try:
        with IP_BLOCK_LOCK:
            BLOCKED_IPS.add(ip)
        print(f"Added {ip} to monitoring blocked IPs list")
        return True
    except Exception as e:
        print(f"Error adding IP to monitoring block list: {e}")
        return False
        
def unblock_ip_in_monitoring(ip):
    """Remove an IP address from the blocked list
    
    Args:
        ip (str): IP address to unblock
        
    Returns:
        bool: True if successful
    """
    try:
        with IP_BLOCK_LOCK:
            if ip in BLOCKED_IPS:
                BLOCKED_IPS.remove(ip)
        print(f"Removed {ip} from monitoring blocked IPs list")
        return True
    except Exception as e:
        print(f"Error removing IP from monitoring block list: {e}")
        return False
