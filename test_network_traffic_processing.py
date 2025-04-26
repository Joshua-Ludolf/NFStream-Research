import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import threading
import sys
import os
import time
import json
from datetime import datetime

# Add the project root to Python path to allow importing from the GUI package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import mock classes from the unit test file
from test_network_monitor import MockTk, MockNotebook
from GUI.main import NetworkMonitor

class MockPacket:
    """Mock packet class to simulate network packets"""
    def __init__(self, src_ip, dst_ip, protocol, src_port=None, dst_port=None, 
                 payload=None, timestamp=None, length=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.timestamp = timestamp or datetime.now().isoformat()
        self.length = length or 64

    def get_property(self, prop_name):
        """Simulate property access similar to pyshark packets"""
        if prop_name == 'ip.src':
            return self.src_ip
        elif prop_name == 'ip.dst':
            return self.dst_ip
        elif prop_name == 'ip.proto':
            return self.protocol
        elif prop_name == '_ws.col.Time':
            return self.timestamp
        elif prop_name == 'frame.len':
            return self.length
        elif prop_name.startswith('tcp') and self.protocol == 6:
            if prop_name == 'tcp.srcport':
                return self.src_port
            elif prop_name == 'tcp.dstport':
                return self.dst_port
        elif prop_name.startswith('udp') and self.protocol == 17:
            if prop_name == 'udp.srcport':
                return self.src_port
            elif prop_name == 'udp.dstport':
                return self.dst_port
        return None

class MockFlow:
    """Mock flow class to simulate NFStream flows"""
    def __init__(self, src_ip, dst_ip, protocol, src_port=None, dst_port=None,
                 bytes=None, packets=None, duration=None, application_name=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port or 0
        self.dst_port = dst_port or 0
        self.bytes = bytes or 1024
        self.packets = packets or 10
        self.duration_ms = duration or 500
        self.application_name = application_name or "Unknown"
        
    def to_dict(self):
        """Convert flow to dictionary format"""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "bytes": self.bytes,
            "packets": self.packets,
            "duration_ms": self.duration_ms,
            "application_name": self.application_name
        }

class TestNetworkTrafficProcessing(unittest.TestCase):
    """Test suite for network traffic processing in NetworkMonitor"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock Tk root with the tk attribute
        self.root = MockTk()
        
        # Mock all dependent modules and classes
        self.patcher1 = patch('GUI.main.FlowsTab')
        self.mock_flows_tab_cls = self.patcher1.start()
        self.mock_flows_tab = MagicMock()
        self.mock_flows_tab_cls.return_value = self.mock_flows_tab
        self.mock_flows_tab.flows_tab = MagicMock()
        
        self.patcher2 = patch('GUI.main.PacketsTab')
        self.mock_packets_tab_cls = self.patcher2.start()
        self.mock_packets_tab = MagicMock()
        self.mock_packets_tab_cls.return_value = self.mock_packets_tab
        self.mock_packets_tab.packets_tab = MagicMock()
        
        self.patcher3 = patch('GUI.main.AlertsTab')
        self.mock_alerts_tab_cls = self.patcher3.start()
        self.mock_alerts_tab = MagicMock()
        self.mock_alerts_tab_cls.return_value = self.mock_alerts_tab
        self.mock_alerts_tab.alerts_tab = MagicMock()
        
        self.patcher4 = patch('GUI.main.ConfigTab')
        self.mock_config_tab_cls = self.patcher4.start()
        self.mock_config_tab = MagicMock()
        self.mock_config_tab_cls.return_value = self.mock_config_tab
        self.mock_config_tab.config_tab = MagicMock()
        
        # Mock the monitoring related functions
        self.patcher5 = patch('GUI.main.set_app_reference')
        self.mock_set_app_reference = self.patcher5.start()
        
        self.patcher6 = patch('GUI.main.start_monitoring')
        self.mock_start_monitoring = self.patcher6.start()
        
        self.patcher7 = patch('GUI.main.stop_monitoring')
        self.mock_stop_monitoring = self.patcher7.start()
        
        # Mock load_threat_intelligence to provide test data
        self.patcher8 = patch('GUI.main.load_threat_intelligence')
        self.mock_load_threat = self.patcher8.start()
        self.mock_load_threat.return_value = {
            'threat_ips': {'1.2.3.4', '5.6.7.8'},
            'threat_domains': {'malicious.com', 'evil.org'}
        }
        
        # Patch ttk.Notebook to use our mock
        self.patcher9 = patch('tkinter.ttk.Notebook', MockNotebook)
        self.patcher9.start()
        
        # Patch additional tkinter components
        self.patcher10 = patch('tkinter.ttk.Frame')
        self.mock_frame = self.patcher10.start()
        
        self.patcher11 = patch('tkinter.ttk.Label')
        self.mock_label = self.patcher11.start()
        
        self.patcher12 = patch('tkinter.ttk.Button')
        self.mock_button = self.patcher12.start()
        self.mock_button_instance = MagicMock()
        self.mock_button.return_value = self.mock_button_instance
        
        self.patcher13 = patch('tkinter.StringVar')
        self.mock_stringvar = self.patcher13.start()
        self.mock_stringvar_instance = MagicMock()
        self.mock_stringvar.return_value = self.mock_stringvar_instance
        
        # Create NetworkMonitor instance with mocked dependencies
        self.app = NetworkMonitor(self.root)
        
        # Ensure threading.Thread is mocked to avoid actual thread creation
        self.original_thread = threading.Thread
        threading.Thread = MagicMock()
        
    def tearDown(self):
        """Tear down test fixtures after each test method."""
        self.patcher1.stop()
        self.patcher2.stop()
        self.patcher3.stop()
        self.patcher4.stop()
        self.patcher5.stop()
        self.patcher6.stop()
        self.patcher7.stop()
        self.patcher8.stop()
        self.patcher9.stop()
        self.patcher10.stop()
        self.patcher11.stop()
        self.patcher12.stop()
        self.patcher13.stop()
        
        # Restore threading.Thread
        threading.Thread = self.original_thread
    
    # ...rest of test methods remain the same...
    
    def test_process_normal_packet(self):
        """Test processing of a normal network packet."""
        # Create a mock packet representing normal web traffic
        mock_packet = MockPacket(
            src_ip="192.168.1.5",
            dst_ip="142.250.190.78",  # Google
            protocol=6,  # TCP
            src_port=54321,
            dst_port=443,  # HTTPS
            length=128
        )
        
        # Prepare packet data similar to what monitoring.py might prepare
        packet_data = {
            "timestamp": mock_packet.timestamp,
            "src_ip": mock_packet.src_ip,
            "dst_ip": mock_packet.dst_ip,
            "protocol": "TCP",
            "length": mock_packet.length,
            "src_port": mock_packet.src_port,
            "dst_port": mock_packet.dst_port,
        }
        
        # Simulate processing the packet
        self.app.add_packet_to_ui(mock_packet, packet_data, packet_id=1)
        
        # Verify the packet was sent to the packets tab
        self.mock_packets_tab.add_packet_to_ui.assert_called_with(
            mock_packet, packet_data, 1
        )
        
        # Verify no alerts were generated for normal traffic
        self.mock_alerts_tab.add_alert.assert_not_called()
    
    def test_process_malicious_packet(self):
        """Test processing of a packet from a known malicious IP."""
        # Add a known bad IP to the app's threat IPs
        self.app.threat_ips = {'10.0.0.99', '1.2.3.4', '5.6.7.8'}
        
        # Create a mock packet from a known malicious IP
        mock_packet = MockPacket(
            src_ip="10.0.0.99",  # Malicious source IP
            dst_ip="192.168.1.5",  # Local machine
            protocol=6,  # TCP
            src_port=12345,
            dst_port=22,  # SSH port - suspicious
            length=64
        )
        
        # Prepare packet data
        packet_data = {
            "timestamp": mock_packet.timestamp,
            "src_ip": mock_packet.src_ip,
            "dst_ip": mock_packet.dst_ip,
            "protocol": "TCP",
            "length": mock_packet.length,
            "src_port": mock_packet.src_port,
            "dst_port": mock_packet.dst_port,
        }
        
        # Setup the alert functionality in alerts_tab
        self.app.alerts_tab = self.mock_alerts_tab
        self.app.alerts_tab.add_alert = MagicMock()
        
        # Check if the IP is flagged as malicious
        threat_results = self.app.check_threat_indicators(ip=mock_packet.src_ip)
        self.assertEqual(len(threat_results), 1)
        
        # Simulate adding an alert based on the threat check
        if threat_results:
            alert_data = {
                "timestamp": mock_packet.timestamp,
                "level": "High",
                "source_ip": mock_packet.src_ip,
                "destination_ip": mock_packet.dst_ip,
                "message": f"Traffic from known malicious IP ({mock_packet.src_ip})"
            }
            self.app.add_alert(alert_data)
        
        # Verify the alert was created
        self.app.alerts_tab.add_alert.assert_called_once()
    
    def test_process_suspicious_payload(self):
        """Test processing a packet with suspicious payload."""
        # Create a mock packet with SQL injection attempt
        mock_packet = MockPacket(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol=6,  # TCP
            src_port=54321,
            dst_port=80,  # HTTP
            payload="GET /login.php?username=admin' OR 1=1 -- HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        
        # Prepare packet data with the suspicious payload
        packet_data = {
            "timestamp": mock_packet.timestamp,
            "src_ip": mock_packet.src_ip,
            "dst_ip": mock_packet.dst_ip,
            "protocol": "TCP",
            "length": mock_packet.length,
            "src_port": mock_packet.src_port,
            "dst_port": mock_packet.dst_port,
            "payload": mock_packet.payload
        }
        
        # Setup the alert functionality
        self.app.alerts_tab = self.mock_alerts_tab
        self.app.alerts_tab.add_alert = MagicMock()
        
        # Check for suspicious content
        threat_results = self.app.check_threat_indicators(content=packet_data["payload"])
        
        # Verify the content was flagged as suspicious
        self.assertEqual(len(threat_results), 1)
        self.assertEqual(threat_results[0]["type"], "Content")
        self.assertEqual(threat_results[0]["threat_level"], "Medium")
        
        # Simulate adding an alert for the suspicious payload
        if threat_results:
            alert_data = {
                "timestamp": mock_packet.timestamp,
                "level": threat_results[0]["threat_level"],
                "source_ip": mock_packet.src_ip,
                "destination_ip": mock_packet.dst_ip,
                "message": f"Suspicious pattern detected: {threat_results[0]['value']}"
            }
            self.app.add_alert(alert_data)
        
        # Verify the alert was created
        self.app.alerts_tab.add_alert.assert_called_once()
    
    def test_process_network_flow(self):
        """Test processing a network flow."""
        # Create a mock flow
        mock_flow = MockFlow(
            src_ip="192.168.1.5",
            dst_ip="142.250.190.78",
            protocol=6,  # TCP
            src_port=54321,
            dst_port=443,  # HTTPS
            bytes=15000,
            packets=25,
            duration=2500,
            application_name="HTTPS"
        )
        
        # Setup the flow tab functionality
        self.app.flows_tab = self.mock_flows_tab
        self.app.flows_tab.update_flow_ui = MagicMock()
        
        # Calculate a mock risk score (normally this would be more complex)
        risk_score = 0.1  # Low risk for normal HTTPS traffic
        
        # Update the flow UI
        self.app.update_flow_ui(mock_flow.to_dict(), risk_score)
        
        # Verify the flow was sent to the flows tab
        self.app.flows_tab.update_flow_ui.assert_called_with(mock_flow.to_dict(), risk_score)
    
    def test_process_high_risk_flow(self):
        """Test processing a flow with high risk characteristics."""
        # Create a mock flow with suspicious characteristics
        mock_flow = MockFlow(
            src_ip="203.0.113.1",  # External IP
            dst_ip="192.168.1.5",  # Internal IP
            protocol=6,  # TCP
            src_port=31337,  # Suspicious port
            dst_port=3389,  # RDP - potentially risky if unexpected
            bytes=500000,  # Large amount of data
            packets=5000,
            duration=120000,  # 2 minutes of sustained traffic
            application_name="Unknown"
        )
        
        # Setup the UI components
        self.app.flows_tab = self.mock_flows_tab
        self.app.flows_tab.update_flow_ui = MagicMock()
        self.app.alerts_tab = self.mock_alerts_tab
        self.app.alerts_tab.add_alert = MagicMock()
        
        # Calculate a high risk score based on characteristics
        # In a real app, this would be determined by more complex logic
        risk_score = 0.85  # High risk
        
        # Update the flow UI
        flow_dict = mock_flow.to_dict()
        self.app.update_flow_ui(flow_dict, risk_score)
        
        # Verify the flow was sent to the flows tab
        self.app.flows_tab.update_flow_ui.assert_called_with(flow_dict, risk_score)
        
        # Simulate alert creation for high-risk flow
        if risk_score > 0.7:  # Threshold for high risk
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "level": "High",
                "source_ip": mock_flow.src_ip,
                "destination_ip": mock_flow.dst_ip,
                "message": f"High risk flow detected (score: {risk_score:.2f})"
            }
            self.app.add_alert(alert_data)
        
        # Verify the alert was created
        self.app.alerts_tab.add_alert.assert_called_once()


if __name__ == '__main__':
    unittest.main()