from nfstream import NFStreamer
import pandas as pd
import os
import time
import platform
import pyshark
from scapy.all import rdpcap, wrpcap, sniff


def get_interfaces():
    """Get network interfaces in a cross-platform way"""
    system = platform.system()
    interfaces = []
    
    try:
        if system == "Windows":
            from scapy.arch import get_windows_if_list
            interfaces = get_windows_if_list()
            for idx, iface in enumerate(interfaces):
                print(f"{idx}. Name: {iface['name']}, Description: {iface['description']}")
        
        elif system == "Linux":
            from scapy.arch.linux import get_if_list
            interface_names = get_if_list()
            for idx, name in enumerate(interface_names):
                interfaces.append({'name': name, 'description': name, 'guid': name})
                print(f"{idx}. Interface: {name}")
        
        elif system == "Darwin":  # macOS
            from scapy.arch.unix import get_if_list
            interface_names = get_if_list()
            for idx, name in enumerate(interface_names):
                interfaces.append({'name': name, 'description': name, 'guid': name})
                print(f"{idx}. Interface: {name}")
        
        else:
            print(f"Unsupported platform: {system}")
            return None
            
        return interfaces
        
    except ImportError:
        print("Could not import scapy. Install it with: pip install scapy")
        return None
    except Exception as e:
        print(f"Error listing network interfaces: {str(e)}")
        return None

def format_interface_name(system, interface):
    """Format interface name based on OS"""
    if system == "Windows":
        return f"\\Device\\NPF_{interface['guid']}"
    elif system == "Linux" or system == "Darwin":
        return interface['name']
    else:
        return interface['name']

def analyze_flow_with_pyshark(flow_record, pcap_file):
    """Analyze specific flow packets using pyshark"""
    try:
        # Create filter to find packets related to this flow
        flow_filter = f"(ip.src == {flow_record.src_ip} and ip.dst == {flow_record.dst_ip})"
        
        # For bidirectional analysis, also include reverse direction
        if flow_record.bidirectional_packets > 0:
            flow_filter += f" or (ip.src == {flow_record.dst_ip} and ip.dst == {flow_record.src_ip})"
        
        # Use pyshark to analyze packets in the flow
        print(f"\nAnalyzing packets for flow: {flow_record.src_ip}:{flow_record.src_port} → {flow_record.dst_ip}:{flow_record.dst_port}")
        print(f"Protocol: {flow_record.protocol}, Application: {flow_record.application_name}")
        
        # Create file capture with display filter
        capture = pyshark.FileCapture(pcap_file, display_filter=flow_filter, keep_packets=False)
        
        # Analyze the first few packets in this flow
        packet_count = 0
        for i, packet in enumerate(capture):
            if i >= 5:  # Limit to first 5 packets
                break
                
            print(f"\nPacket {i+1}:")
            if hasattr(packet, 'ip'):
                print(f"  Source IP: {packet.ip.src}")
                print(f"  Destination IP: {packet.ip.dst}")
                
                if hasattr(packet, 'tcp'):
                    print(f"  TCP Port: {packet.tcp.srcport} → {packet.tcp.dstport}")
                    if hasattr(packet.tcp, 'payload'):
                        print(f"  Payload: {packet.tcp.payload[:30]}...")
                elif hasattr(packet, 'udp'):
                    print(f"  UDP Port: {packet.udp.srcport} → {packet.udp.dstport}")
            
            packet_count += 1
            
        if packet_count == 0:
            print("  No matching packets found in capture file")
            
        capture.close()
        return packet_count
        
    except Exception as e:
        print(f"Error analyzing flow with pyshark: {str(e)}")
        return 0

def extract_packets_with_scapy(flow_record, pcap_file, output_dir="flow_packets"):
    """Extract packets for a specific flow using scapy and save to a new pcap file"""
    try:
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Create output filename based on flow details
        flow_id = f"{flow_record.src_ip}_{flow_record.src_port}_to_{flow_record.dst_ip}_{flow_record.dst_port}"
        output_pcap = os.path.join(output_dir, f"flow_{flow_id}.pcap")
        
        # Read packets from source pcap
        packets = rdpcap(pcap_file)
        flow_packets = []
        
        # Filter packets for this flow
        for packet in packets:
            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                ip_dst = packet["IP"].dst
                
                # Check if packet belongs to this flow (both directions)
                if ((ip_src == flow_record.src_ip and ip_dst == flow_record.dst_ip) or
                    (ip_src == flow_record.dst_ip and ip_dst == flow_record.src_ip)):
                    flow_packets.append(packet)
        
        # Save to new pcap if we found any packets
        if flow_packets:
            wrpcap(output_pcap, flow_packets)
            print(f"  Extracted {len(flow_packets)} packets to {output_pcap}")
            return len(flow_packets)
        else:
            print("  No matching packets found for extraction")
            return 0
            
    except Exception as e:
        print(f"Error extracting flow packets with scapy: {str(e)}")
        return 0

def live_capture_to_pcap(interface_name, duration=10, output_file=None):
    """Capture live traffic to a pcap file using scapy instead of pyshark"""
    if output_file is None:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_file = f"live_capture_{timestamp}.pcap"
    
    print(f"Starting packet capture on {interface_name} for {duration} seconds...")
    
    # Use scapy for live capture to avoid asyncio issues in threads
    packets = []
    
    def packet_callback(packet):
        packets.append(packet)
    
    try:
        sniff(iface=interface_name, prn=packet_callback, 
              timeout=duration, store=False)
        
        if packets:
            wrpcap(output_file, packets)
            print(f"Packet capture completed. Saved to {output_file}")
        else:
            print(f"No packets captured during the {duration} second window")
        
        return output_file
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")
        return None

def main():
    # Detect OS
    system = platform.system()
    print(f"Detected operating system: {system}")
    
    # Get interfaces in a cross-platform way
    print("\nAvailable network interfaces:")
    interfaces = get_interfaces()
    
    if not interfaces:
        print("\nFalling back to pcap file analysis...")
        use_live = False
    else:
        print("\nWould you like to:")
        print("1. Analyze live traffic (enter interface number)")
        print("2. Analyze pcap file")
        
        choice = input("Enter your choice (1 or 2): ")
        
        if choice == "1":
            try:
                iface_idx = int(input("Enter interface number: "))
                if 0 <= iface_idx < len(interfaces):
                    # Format interface name according to OS
                    interface_name = format_interface_name(system, interfaces[iface_idx])
                    use_live = True
                else:
                    print("Invalid interface number, falling back to pcap file...")
                    use_live = False
            except ValueError:
                print("Invalid input, falling back to pcap file analysis...")
                use_live = False
        else:
            use_live = False

    # Get pcap file only if using option 2
    pcap_file = None
    if not use_live:
        pcap_input = input(f"Pcap file(*.pcap or *.pcapng): ")
        pcap_file = os.path.join(os.getcwd(), pcap_input if pcap_input else "wifi.pcap")
        
        if not os.path.isfile(pcap_file):
            raise FileNotFoundError(f"The file {pcap_file} does not exist.")

    # Process with NFStream
    print("\nAnalyzing traffic with NFStream...")

    if use_live:
        capture_duration = int(input("Enter capture duration in seconds (default: 10): ") or "10")
        print(f"\nStarting live capture on interface: {interface_name}")
        print(f"Capture will run for {capture_duration} seconds...")
        print("Waiting for network flows...\n")
        
        # First capture traffic to a pcap file for later analysis with pyshark/scapy
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        live_pcap_file = f"live_capture_{timestamp}.pcap"
        
        # Use scapy to capture packets to a file instead of PyShark
        # to avoid asyncio issues in thread
        print("Capturing packets to file for detailed analysis...")
        capture_thread = None
        
        try:
            import threading
            capture_thread = threading.Thread(
                target=live_capture_to_pcap, 
                args=(interface_name, capture_duration, live_pcap_file)
            )
            capture_thread.daemon = True
            capture_thread.start()
        except Exception as e:
            print(f"Warning: Could not start packet capture thread: {str(e)}")
        
        # Analyze with NFStream in real time
        flow_streamer = NFStreamer(
            source=interface_name,
            idle_timeout=1,
            active_timeout=2,
            accounting_mode=2  # Collect all metrics
        )
        start_time = time.time()
        timeout = capture_duration
    else:
        print("\nAnalyzing pcap file with NFStream...")
        flow_streamer = NFStreamer(
            source=pcap_file,
            idle_timeout=1,
            active_timeout=2,
            accounting_mode=2  # Collect all metrics
        )

    try:
        # Process flows with NFStream and use pyshark/scapy for deeper packet analysis
        flow_count = 0
        
        # Tell user what they will see
        print("\nFlow Analysis:")
        print("1. NFStream identifies network flows")
        if use_live:
            print("2. Real-time flow analysis of live traffic")
            print("3. PyShark inspects individual packets within each flow")
            print("4. Scapy extracts flow packets to separate pcap files")
        else:
            print("2. PyShark inspects individual packets within each flow")
            print("3. Scapy extracts flow packets to separate pcap files")
        print()
        
        flows_data = []  # Store flow data for live capture
        
        for flow in flow_streamer:
            flow_count += 1
            
            # Print NFStream flow information
            print(f"\n{'=' * 60}")
            print(f"Flow #{flow_count} detected:")
            print(f"Source: {flow.src_ip}:{flow.src_port}")
            print(f"Destination: {flow.dst_ip}:{flow.dst_port}")
            print(f"Protocol: {flow.protocol}")
            print(f"Application: {flow.application_name}")
            print(f"Category: {flow.application_category_name}")
            print(f"Total packets: {flow.bidirectional_packets}")
            print(f"Total bytes: {flow.bidirectional_bytes}")
            print(f"{'=' * 60}")
            
            # For live capture, store flow data for later saving
            if use_live:
                flows_data.append({
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'application': flow.application_name,
                    'category': flow.application_category_name,
                    'packets': flow.bidirectional_packets,
                    'bytes': flow.bidirectional_bytes,
                    'duration': flow.bidirectional_duration_ms
                })
            
            # Use pyshark to analyze specific packets in this flow (only for pcap file analysis)
            if not use_live:
                print("\nPyShark packet analysis:")
                analyze_flow_with_pyshark(flow, pcap_file)
                
                print("\nScapy packet extraction:")
                extract_packets_with_scapy(flow, pcap_file)
                
            # Check for timeout if doing live capture
            if use_live and (time.time() - start_time) >= timeout:
                print(f"\nCapture timeout reached ({timeout} seconds)")
                break
                
        print(f"\nTotal flows analyzed: {flow_count}")
        
        # Save flow data to CSV
        if flow_count > 0:
            if use_live:
                # For live capture, save the collected flow data
                output_csv = f"live_capture_{timestamp}_flows.csv"
                pd.DataFrame(flows_data).to_csv(output_csv, index=False)
                print(f"Flow data saved to {output_csv}")
                
                # Now analyze the captured pcap file with pyshark and scapy
                if os.path.exists(live_pcap_file) and os.path.getsize(live_pcap_file) > 0:
                    print("\n\nAnalyzing captured packets with PyShark and Scapy...")
                    # Create a new NFStream for the captured file to get flow objects
                    print("Reprocessing captured packets with NFStream...")
                    pcap_streamer = NFStreamer(source=live_pcap_file, accounting_mode=2)
                    
                    for pcap_flow in pcap_streamer:
                        print(f"\nAnalyzing flow: {pcap_flow.src_ip}:{pcap_flow.src_port} → {pcap_flow.dst_ip}:{pcap_flow.dst_port}")
                        
                        print("\nPyShark packet analysis:")
                        analyze_flow_with_pyshark(pcap_flow, live_pcap_file)
                        
                        print("\nScapy packet extraction:")
                        extract_packets_with_scapy(pcap_flow, live_pcap_file)
            else:
                # For pcap analysis, use the NFStream to_pandas method
                df = flow_streamer.to_pandas()
                output_csv = f"{pcap_file}_flows.csv"
                df.to_csv(output_csv)
                print(f"Flow data saved to {output_csv}")
            
    except KeyboardInterrupt:
        print("\nAnalysis stopped by user")
        print(f"Total flows analyzed: {flow_count}")
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")

if __name__ == "__main__":
    main()