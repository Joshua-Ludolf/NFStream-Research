import os
import json
import subprocess
import tempfile
import threading
import queue
import time
from datetime import datetime
from scapy.all import IP, TCP, UDP, send, sr1, ICMP, conf, sniff, get_if_list

# Set Scapy to operate with higher performance
conf.verb = 0  # Reduce verbosity

# File to store blocked IPs persistently
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

# Global variables for packet filtering
BLOCKED_IPS = set()
FIREWALL_ENABLED = False
SNIFFER_THREAD = None
SNIFFER_STOP_EVENT = threading.Event()
PACKET_QUEUE = queue.Queue(maxsize=1000)  # Queue for handling packets

# Statistics for monitoring
BLOCKED_PACKET_COUNT = 0
ALLOWED_PACKET_COUNT = 0

# Lock for thread safety
LOCK = threading.Lock()

# Import the monitoring module to sync block lists
try:
    from GUI import monitoring
except ImportError:
    # Try relative import if the above fails
    try:
        import monitoring
    except ImportError:
        print("Warning: Could not import monitoring module, NFStream/PyShark integration disabled")
        monitoring = None

def get_blocked_ips():
    """Get the list of blocked IPs from the persistent storage"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return data
        except Exception as e:
            print(f"Error loading blocked IPs: {e}")
    return {}

def save_blocked_ips(blocked_ips_dict):
    """Save the list of blocked IPs to persistent storage"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips_dict, f, indent=2)
    except Exception as e:
        print(f"Error saving blocked IPs: {e}")

def run_powershell_command(command):
    """Run a PowerShell command with elevated privileges if possible"""
    try:
        # Create a temporary PowerShell script
        with tempfile.NamedTemporaryFile(delete=False, suffix='.ps1') as temp:
            temp_path = temp.name
            temp.write(command.encode('utf-8'))
        
        # Try to run PowerShell with elevated privileges using Start-Process
        # This will prompt UAC if running without admin rights
        ps_cmd = f'powershell.exe -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList \'-ExecutionPolicy Bypass -File \"{temp_path}\"\' -Verb RunAs -Wait"'
        
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        # Clean up the temp file
        try:
            os.unlink(temp_path)
        except:
            pass
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error running PowerShell command: {e}")
        return False

def packet_filter(packet):
    """Filter packets based on blocked IPs
    
    Args:
        packet: Scapy packet
        
    Returns:
        bool: True if packet should be allowed, False if it should be dropped
    """
    global BLOCKED_PACKET_COUNT, ALLOWED_PACKET_COUNT
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        with LOCK:
            # Primary focus: Block packets where the source IP is in our blocklist
            if src_ip in BLOCKED_IPS:
                print(f"🛑 Blocking packet from {src_ip} to {dst_ip} (blocked source)")
                BLOCKED_PACKET_COUNT += 1
                return False
        
        ALLOWED_PACKET_COUNT += 1
        return True
    
    ALLOWED_PACKET_COUNT += 1
    return True

def packet_handler(packet):
    """Handle packet in sniffing process"""
    try:
        # Only process packets with IP layer
        if IP in packet:
            # Queue the packet for processing (non-blocking)
            try:
                PACKET_QUEUE.put(packet, block=False)
            except queue.Full:
                # Queue is full, drop the packet
                pass
    except Exception as e:
        print(f"Error in packet handler: {e}")

def process_packet_queue():
    """Process packets from the queue"""
    while not SNIFFER_STOP_EVENT.is_set():
        try:
            # Get packet with timeout to allow checking stop event
            packet = PACKET_QUEUE.get(timeout=0.1)
            
            # Apply filter
            if not packet_filter(packet):
                # Drop packet by not forwarding it
                continue
                
            # Here we would forward the packet if needed
            
        except queue.Empty:
            # No packets in queue, continue checking stop event
            continue
        except Exception as e:
            print(f"Error processing packet queue: {e}")
            
    print("Packet queue processor stopped")

def start_packet_filtering():
    """Start the packet filtering system"""
    global SNIFFER_THREAD, FIREWALL_ENABLED, SNIFFER_STOP_EVENT
    
    if FIREWALL_ENABLED:
        print("Packet filtering already enabled")
        return
        
    # Reset the stop event
    SNIFFER_STOP_EVENT = threading.Event()
    
    # Start queue processor thread
    queue_thread = threading.Thread(target=process_packet_queue)
    queue_thread.daemon = True
    queue_thread.start()
    
    # Try to determine the best interface to use
    try:
        interfaces = get_if_list()
        if not interfaces:
            print("No network interfaces found")
            return False
        
        # Prefer interfaces that are more likely to be main network connections
        preferred_interfaces = [
            iface for iface in interfaces 
            if any(name in iface.lower() for name in ['ethernet', 'wi-fi', 'wlan', 'eth'])
        ]
        
        sniffer_interface = preferred_interfaces[0] if preferred_interfaces else interfaces[0]
        print(f"Starting packet sniffing on interface: {sniffer_interface}")
    except Exception as e:
        print(f"Error determining network interface: {e}")
        sniffer_interface = None  # Let Scapy choose default
    
    try:
        # Start sniffing in a separate thread
        SNIFFER_THREAD = threading.Thread(
            target=lambda: sniff(
                iface=sniffer_interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: SNIFFER_STOP_EVENT.is_set()
            )
        )
        SNIFFER_THREAD.daemon = True
        SNIFFER_THREAD.start()
        
        FIREWALL_ENABLED = True
        print("Scapy packet filtering started successfully")
        return True
    except Exception as e:
        print(f"Error starting packet filtering: {e}")
        return False

def stop_packet_filtering():
    """Stop the packet filtering system"""
    global SNIFFER_THREAD, FIREWALL_ENABLED, SNIFFER_STOP_EVENT
    
    if not FIREWALL_ENABLED:
        return
        
    try:
        # Signal the sniffer thread to stop
        SNIFFER_STOP_EVENT.set()
        
        # Wait for the sniffer thread to finish (with timeout)
        if SNIFFER_THREAD and SNIFFER_THREAD.is_alive():
            SNIFFER_THREAD.join(timeout=2)
            
        FIREWALL_ENABLED = False
        SNIFFER_THREAD = None
        print("Packet filtering stopped")
        
        # Print statistics
        print(f"Blocking statistics: {BLOCKED_PACKET_COUNT} packets blocked, {ALLOWED_PACKET_COUNT} packets allowed")
    except Exception as e:
        print(f"Error stopping packet filtering: {e}")

def block_ip(ip, reason="Manual block"):
    """Block a given IP address using Scapy packet filtering and Windows Firewall"""
    print(f"Blocking IP: {ip}")
    
    try:
        # Add to blocked IPs set
        with LOCK:
            BLOCKED_IPS.add(ip)
        
        # Sync with monitoring module for NFStream and PyShark blocking
        if monitoring:
            monitoring.block_ip_in_monitoring(ip)
            print(f"IP {ip} added to NFStream and PyShark blocking")
        
        # Start the packet filtering system if not already running
        if not FIREWALL_ENABLED:
            success = start_packet_filtering()
            if not success:
                print("Warning: Failed to start Scapy packet filtering")
        
        # First terminate any existing connections with this IP using TCP RST
        terminate_connections_with_scapy(ip)
        
        # Add Windows Firewall rules as backup blocking mechanism
        ps_script = f'''
        # Block inbound traffic
        New-NetFirewallRule -DisplayName "Block {ip} (IN)" -Direction Inbound -Action Block -RemoteAddress {ip} -Priority 1

        # Block outbound traffic
        New-NetFirewallRule -DisplayName "Block {ip} (OUT)" -Direction Outbound -Action Block -RemoteAddress {ip} -Priority 1
        
        Write-Output "IP {ip} has been blocked in both directions."
        '''
        
        success = run_powershell_command(ps_script)
        
        if success:
            print(f"Successfully added firewall rules to block {ip}")
        else:
            print(f"Warning: Failed to add firewall rules for {ip}. Falling back to netsh...")
            os.system(f'netsh advfirewall firewall add rule name="Block {ip} (IN)" dir=in action=block remoteip={ip}')
            os.system(f'netsh advfirewall firewall add rule name="Block {ip} (OUT)" dir=out action=block remoteip={ip}')
        
        # Save to persistent storage
        blocked_ips = get_blocked_ips()
        blocked_ips[ip] = {
            "time_blocked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason
        }
        save_blocked_ips(blocked_ips)
        
        print(f"IP {ip} is now being actively blocked by Scapy packet filter")
        return True
    except Exception as e:
        print(f"Error while blocking IP {ip}: {e}")
        return False

def unblock_ip(ip):
    """Unblock a given IP address"""
    print(f"Unblocking IP: {ip}")
    
    try:
        # Remove from blocked IPs set
        with LOCK:
            if ip in BLOCKED_IPS:
                BLOCKED_IPS.remove(ip)
        
        # Sync with monitoring module for NFStream and PyShark
        if monitoring:
            monitoring.unblock_ip_in_monitoring(ip)
            print(f"IP {ip} removed from NFStream and PyShark blocking")
        
        # Create a PowerShell script to remove both inbound and outbound rules
        ps_script = f'''
        # Remove inbound rule
        Remove-NetFirewallRule -DisplayName "Block {ip} (IN)" -ErrorAction SilentlyContinue
        
        # Remove outbound rule
        Remove-NetFirewallRule -DisplayName "Block {ip} (OUT)" -ErrorAction SilentlyContinue
        
        Write-Output "IP {ip} has been unblocked."
        '''
        
        success = run_powershell_command(ps_script)
        
        if success:
            print(f"Successfully removed firewall rules for {ip}")
        else:
            print(f"Warning: Failed to remove firewall rules for {ip} using PowerShell")
            
            # Fall back to netsh if PowerShell method failed
            print("Attempting fallback to netsh...")
            os.system(f'netsh advfirewall firewall delete rule name="Block {ip} (IN)"')
            os.system(f'netsh advfirewall firewall delete rule name="Block {ip} (OUT)"')
            os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
        
        # Remove from persistent storage
        blocked_ips = get_blocked_ips()
        if ip in blocked_ips:
            del blocked_ips[ip]
            save_blocked_ips(blocked_ips)
            
        return True
    except Exception as e:
        print(f"Error while unblocking IP {ip}: {e}")
        return False

def send_reset_packets(ip):
    """Send TCP reset packets to terminate connections with the given IP"""
    print(f"Sending TCP reset packets to {ip}")
    terminate_connections_with_scapy(ip)

def terminate_connections_with_scapy(ip):
    """Terminate existing connections to the IP using Scapy"""
    print(f"Using Scapy to terminate existing connections with {ip}")
    
    try:
        # Get active connections for targeted termination
        connections = get_active_connections(ip)
        
        # Send TCP reset packets to terminate TCP connections
        for conn in connections:
            if conn["protocol"] == "TCP":
                # Send RST to remote endpoint
                rst_packet = IP(dst=conn["remote_ip"])/TCP(dport=int(conn["remote_port"]), 
                                                           sport=int(conn["local_port"]), 
                                                           flags="R")
                send(rst_packet, count=3)  # Send multiple RST packets to increase chances of termination
                
                # Send RST from perspective of remote endpoint
                rst_packet = IP(dst=conn["local_ip"])/TCP(dport=int(conn["local_port"]), 
                                                          sport=int(conn["remote_port"]), 
                                                          flags="R")
                send(rst_packet, count=3)
        
        # If no specific connections found, send general RSTs
        if not connections:
            print(f"No active connections found with {ip}, sending general TCP RST packets")
            # Create generic reset packets for common ports
            common_ports = [80, 443, 22, 23, 25, 53, 3389]
            for port in common_ports:
                # Client to server
                rst_packet = IP(dst=ip)/TCP(dport=port, sport=random.randint(10000, 60000), flags="R")
                send(rst_packet, count=2)
                
                # Server to client
                rst_packet = IP(src=ip)/TCP(sport=port, dport=random.randint(10000, 60000), flags="R")
                send(rst_packet, count=2)
                
        print(f"Sent termination packets to {ip}")
        return True
    except Exception as e:
        print(f"Scapy error terminating connections to {ip}: {e}")
        return False

def get_active_connections(ip):
    """Get list of active connections with a specific IP"""
    connections = []
    try:
        # Use netstat to get active connections
        output = subprocess.check_output(["netstat", "-ano"], text=True)
        lines = output.split('\n')
        
        for line in lines:
            if ip in line:
                parts = line.split()
                if len(parts) >= 5 and ('TCP' in parts[0] or 'UDP' in parts[0]):
                    protocol = parts[0]
                    local_endpoint = parts[1]
                    remote_endpoint = parts[2]
                    
                    # Parse local endpoint
                    local_ip, local_port = local_endpoint.rsplit(':', 1)
                    
                    # Parse remote endpoint
                    remote_ip, remote_port = remote_endpoint.rsplit(':', 1)
                    
                    if remote_ip == ip:
                        connections.append({
                            "protocol": protocol,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port
                        })
        
        return connections
    except Exception as e:
        print(f"Error getting active connections: {e}")
        return []

# Load blocked IPs from persistent storage on module import
try:
    stored_blocked_ips = get_blocked_ips()
    if stored_blocked_ips:
        for ip in stored_blocked_ips:
            BLOCKED_IPS.add(ip)
            # Also add to monitoring module for NFStream and PyShark
            if monitoring:
                monitoring.block_ip_in_monitoring(ip)
        print(f"Loaded {len(BLOCKED_IPS)} blocked IPs from storage")
except Exception as e:
    print(f"Error loading blocked IPs on startup: {e}")

# Add missing import for random
import random
