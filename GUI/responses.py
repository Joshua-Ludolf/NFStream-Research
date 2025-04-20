import os
import json
import subprocess
import tempfile
from scapy.all import IP, TCP, send
from datetime import datetime

# File to store blocked IPs persistently
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(__file__), "blocked_ips.json")

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

def block_ip(ip, reason="Manual block"):
    """Block a given IP address using Windows Firewall"""
    print(f"Blocking IP: {ip}")
    
    try:
        # Create a PowerShell script to add both inbound and outbound rules
        ps_script = f'''
        # Block inbound traffic
        New-NetFirewallRule -DisplayName "Block {ip} (IN)" -Direction Inbound -Action Block -RemoteAddress {ip}
        
        # Block outbound traffic
        New-NetFirewallRule -DisplayName "Block {ip} (OUT)" -Direction Outbound -Action Block -RemoteAddress {ip}
        
        Write-Output "IP {ip} has been blocked in both directions."
        '''
        
        success = run_powershell_command(ps_script)
        
        if success:
            print(f"Successfully added firewall rules to block {ip}")
        else:
            print(f"Warning: Failed to add firewall rules for {ip}. Rules may not have been created.")
            
            # Fall back to netsh if PowerShell method failed
            print("Attempting fallback to netsh...")
            os.system(f'netsh advfirewall firewall add rule name="Block {ip} (IN)" dir=in action=block remoteip={ip}')
            os.system(f'netsh advfirewall firewall add rule name="Block {ip} (OUT)" dir=out action=block remoteip={ip}')
        
        # Save to persistent storage
        blocked_ips = get_blocked_ips()
        blocked_ips[ip] = {
            "time_blocked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason
        }
        save_blocked_ips(blocked_ips)
        
        return True
    except Exception as e:
        print(f"Error while blocking IP {ip}: {e}")
        return False

def unblock_ip(ip):
    """Unblock a given IP address"""
    print(f"Unblocking IP: {ip}")
    
    try:
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
    
    # Remove from persistent storage
    blocked_ips = get_blocked_ips()
    if ip in blocked_ips:
        del blocked_ips[ip]
        save_blocked_ips(blocked_ips)
    
    return True

def send_reset_packets(ip):
    """Send TCP reset packets to terminate connections with the given IP"""
    print(f"Sending TCP reset packets to {ip}")
    # Create a TCP reset packet
    packet = IP(dst=ip)/TCP(flags="R")
    send(packet, verbose=False)
