import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import threading
import sys
import os
import json

# Add the project root to Python path to allow importing from the GUI package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import mock classes from the unit test file
from test_network_monitor import MockTk, MockNotebook
from GUI.main import NetworkMonitor
from GUI.threat_intelligence import load_threat_intelligence

class TestNetworkMonitorIntegration(unittest.TestCase):
    """Integration tests for NetworkMonitor with its components"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock Tk root with the tk attribute
        self.root = MockTk()
        
        # Mock the tab classes but let them create real objects
        self.patcher1 = patch('GUI.main.FlowsTab')
        self.mock_flows_tab_cls = self.patcher1.start()
        self.mock_flows_tab = MagicMock()
        self.mock_flows_tab_cls.return_value = self.mock_flows_tab
        self.mock_flows_tab.flows_tab = MagicMock()  # Mock the actual tab frame
        
        self.patcher2 = patch('GUI.main.PacketsTab')
        self.mock_packets_tab_cls = self.patcher2.start()
        self.mock_packets_tab = MagicMock()
        self.mock_packets_tab_cls.return_value = self.mock_packets_tab
        self.mock_packets_tab.packets_tab = MagicMock()  # Mock the actual tab frame
        
        self.patcher3 = patch('GUI.main.AlertsTab')
        self.mock_alerts_tab_cls = self.patcher3.start()
        self.mock_alerts_tab = MagicMock()
        self.mock_alerts_tab_cls.return_value = self.mock_alerts_tab
        self.mock_alerts_tab.alerts_tab = MagicMock()  # Mock the actual tab frame
        
        self.patcher4 = patch('GUI.main.ConfigTab')
        self.mock_config_tab_cls = self.patcher4.start()
        self.mock_config_tab = MagicMock()
        self.mock_config_tab_cls.return_value = self.mock_config_tab
        self.mock_config_tab.config_tab = MagicMock()  # Mock the actual tab frame
        
        # Only patch the monitoring module's function calls
        self.patcher5 = patch('GUI.main.set_app_reference')
        self.mock_set_app_reference = self.patcher5.start()
        
        self.patcher6 = patch('GUI.main.start_monitoring')
        self.mock_start_monitoring = self.patcher6.start()
        
        self.patcher7 = patch('GUI.main.stop_monitoring')
        self.mock_stop_monitoring = self.patcher7.start()
        
        # Patch ttk.Notebook to use our mock
        self.patcher8 = patch('tkinter.ttk.Notebook', MockNotebook)
        self.patcher8.start()
        
        # Patch additional tkinter components
        self.patcher9 = patch('tkinter.ttk.Frame')
        self.mock_frame = self.patcher9.start()
        
        self.patcher10 = patch('tkinter.ttk.Label')
        self.mock_label = self.patcher10.start()
        
        self.patcher11 = patch('tkinter.ttk.Button')
        self.mock_button = self.patcher11.start()
        self.mock_button_instance = MagicMock()
        self.mock_button.return_value = self.mock_button_instance
        
        self.patcher12 = patch('tkinter.StringVar')
        self.mock_stringvar = self.patcher12.start()
        self.mock_stringvar_instance = MagicMock()
        self.mock_stringvar.return_value = self.mock_stringvar_instance
        
        # Create NetworkMonitor instance with mocked dependencies
        self.app = NetworkMonitor(self.root)
        
        # Mock threading.Thread to avoid actual thread creation
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
        
        # Restore threading.Thread
        threading.Thread = self.original_thread
        
    # ...rest of test methods remain the same...
    
    def test_threat_intelligence_integration(self):
        """Test integration with threat intelligence components."""
        # Create a temporary threat intelligence file for testing
        test_threat_data = {
            'threat_ips': ['1.2.3.4', '5.6.7.8'],
            'threat_domains': ['badsite.com', 'malware.net']
        }
        
        # Test the check_threat_indicators integration with threat data
        with patch('GUI.main.load_threat_intelligence', return_value=test_threat_data):
            # Create a new app instance with the mocked threat data
            test_app = NetworkMonitor(self.root)
            
            # Test known malicious IP
            results = test_app.check_threat_indicators(ip='1.2.3.4')
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['type'], 'IP')
            
            # Test known malicious domain
            results = test_app.check_threat_indicators(domain='badsite.com')
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['type'], 'Domain')
    
    def test_monitoring_flow_integration(self):
        """Test monitoring flow integration with UI components and threads."""
        # Setup UI elements
        self.app.start_stop_button = self.mock_button_instance
        self.app.status_var = self.mock_stringvar_instance
        
        # Test the complete monitoring workflow
        self.assertFalse(self.app.is_monitoring)
        
        # Start monitoring
        self.app.toggle_monitoring()
        self.assertTrue(self.app.is_monitoring)
        self.app.start_stop_button.config.assert_called_with(text="Stop Monitoring")
        self.app.status_var.set.assert_called_with("Monitoring Active")
        
        # Verify proper thread creation
        threading.Thread.assert_called_with(
            target=self.mock_start_monitoring,
            args=("Wi-Fi",)
        )
        
        # The monitoring module should have been given a reference to the app
        self.mock_set_app_reference.assert_called_with(self.app)
        
        # Stop monitoring
        self.app.toggle_monitoring()
        self.assertFalse(self.app.is_monitoring)
        self.app.start_stop_button.config.assert_called_with(text="Start Monitoring")
        self.app.status_var.set.assert_called_with("Ready")
        
        # Verify stop_monitoring was called
        self.mock_stop_monitoring.assert_called_once()
    
    def test_tab_integration(self):
        """Test integration between NetworkMonitor and its tabs."""
        # Test flow update propagation
        flow_data = {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": 6}
        risk_score = 0.8
        
        self.app.update_flow_ui(flow_data, risk_score)
        self.mock_flows_tab.update_flow_ui.assert_called_with(flow_data, risk_score)
        
        # Test packet update propagation
        packet = MagicMock()
        packet_data = {"protocol": "TCP", "length": 1500}
        packet_id = 42
        
        self.app.add_packet_to_ui(packet, packet_data, packet_id)
        self.mock_packets_tab.add_packet_to_ui.assert_called_with(packet, packet_data, packet_id)
        
        # Test alert propagation
        alert_data = {
            "timestamp": "2025-04-26 12:34:56",
            "level": "High",
            "source_ip": "192.168.1.100",
            "message": "Possible intrusion attempt"
        }
        
        self.app.add_alert(alert_data)
        self.mock_alerts_tab.add_alert.assert_called_with(alert_data)
    
    def test_threat_detection_workflow(self):
        """Test the complete threat detection workflow."""
        # 1. Setup mock for threat intelligence
        with patch.object(self.app, 'threat_ips', {'10.0.0.99'}):
            # 2. Simulate receiving a flow from a malicious IP
            flow = {
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.1.5",
                "protocol": 6,
                "src_port": 12345,
                "dst_port": 80
            }
            
            # 3. Check if the IP is recognized as a threat
            threat_results = self.app.check_threat_indicators(ip="10.0.0.99")
            self.assertEqual(len(threat_results), 1)
            self.assertEqual(threat_results[0]['threat_level'], "High")
            
            # 4. Simulate the alert tab having the block_ip method
            self.app.alerts_tab.block_ip = MagicMock(return_value=True)
            
            # 5. Block the malicious IP
            result = self.app.block_ip("10.0.0.99", "Known malicious IP")
            self.assertTrue(result)
            self.app.alerts_tab.block_ip.assert_called_with("10.0.0.99", "Known malicious IP")


if __name__ == '__main__':
    unittest.main()