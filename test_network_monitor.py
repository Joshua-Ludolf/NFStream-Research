import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import threading
import sys
import os

# Add the project root to Python path to allow importing from the GUI package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class MockNotebook:
    """Mock for ttk.Notebook that doesn't require tk"""
    def __init__(self, master):
        self.master = master
        
    def pack(self, **kwargs):
        pass
        
    def add(self, child, **kwargs):
        pass

class MockTk:
    """Mock for Tk that provides expected attributes"""
    def __init__(self):
        self.tk = {}  # Provide the tk attribute needed by widgets
        
    def title(self, title_str):
        self._title = title_str
        
    def geometry(self, geometry_str):
        self._geometry = geometry_str

from GUI.main import NetworkMonitor

class TestNetworkMonitor(unittest.TestCase):
    """Test suite for NetworkMonitor class"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock Tk root with the tk attribute
        self.root = MockTk()
        
        # Mock all external dependencies
        self.patcher1 = patch('GUI.main.load_threat_intelligence')
        self.mock_load_threat = self.patcher1.start()
        self.mock_load_threat.return_value = {
            'threat_ips': {'192.168.1.100', '10.0.0.1'},
            'threat_domains': {'malicious.com', 'evil.org'}
        }
        
        self.patcher2 = patch('GUI.main.FlowsTab')
        self.mock_flows_tab = self.patcher2.start()
        
        self.patcher3 = patch('GUI.main.PacketsTab')
        self.mock_packets_tab = self.patcher3.start()
        
        self.patcher4 = patch('GUI.main.AlertsTab')
        self.mock_alerts_tab = self.patcher4.start()
        
        self.patcher5 = patch('GUI.main.ConfigTab')
        self.mock_config_tab = self.patcher5.start()
        
        self.patcher6 = patch('GUI.main.set_app_reference')
        self.mock_set_app_reference = self.patcher6.start()
        
        self.patcher7 = patch('GUI.main.start_monitoring')
        self.mock_start_monitoring = self.patcher7.start()
        
        self.patcher8 = patch('GUI.main.stop_monitoring')
        self.mock_stop_monitoring = self.patcher8.start()
        
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
        
        # Mock the threading.Thread to avoid actual thread creation
        self.original_thread = threading.Thread
        threading.Thread = MagicMock()
    
    def tearDown(self):
        """Tear down test fixtures after each test method."""
        # Stop all patches
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
    
    def test_init(self):
        """Test initialization of NetworkMonitor class."""
        # Verify monitoring state
        self.assertFalse(self.app.is_monitoring)
        
        # Verify interface setup
        self.assertEqual(self.app.interface['friendly_name'], "Wi-Fi Interface")
        self.assertEqual(self.app.interface['nfstream_name'], "Intel(R) Wi-Fi 6 AX201 160MHz")
        
        # Verify threat data
        self.assertEqual(self.app.threat_ips, {'192.168.1.100', '10.0.0.1'})
        self.assertEqual(self.app.threat_domains, {'malicious.com', 'evil.org'})
        
        # Verify protocol map
        self.assertEqual(self.app.protocol_map[6], "TCP")
        self.assertEqual(self.app.protocol_map[17], "UDP")
    
    def test_setup_interface(self):
        """Test setup_interface method."""
        # Reset the interface and call setup_interface
        self.app.interface = None
        self.app.setup_interface()
        
        # Verify interface was set correctly
        self.assertEqual(self.app.interface['friendly_name'], "Wi-Fi Interface")
        self.assertEqual(self.app.interface['nfstream_name'], "Intel(R) Wi-Fi 6 AX201 160MHz")
        self.assertEqual(self.app.interface['pyshark_name'], "Wi-Fi")
        self.assertEqual(self.app.interface['scapy_name'], "Intel(R) Wi-Fi 6 AX201 160MHz")
        
        # Verify backward compatibility
        self.assertEqual(self.app.interface_info["Wi-Fi"], "Wi-Fi Interface")
    
    def test_toggle_monitoring_start(self):
        """Test toggle_monitoring when starting monitoring."""
        # Set initial state to not monitoring
        self.app.is_monitoring = False
        
        # Mock the start_monitoring method
        self.app.start_monitoring = MagicMock()
        
        # Call toggle_monitoring
        self.app.toggle_monitoring()
        
        # Verify start_monitoring was called
        self.app.start_monitoring.assert_called_once()
    
    def test_toggle_monitoring_stop(self):
        """Test toggle_monitoring when stopping monitoring."""
        # Set initial state to monitoring
        self.app.is_monitoring = True
        
        # Mock the stop_monitoring method
        self.app.stop_monitoring = MagicMock()
        
        # Call toggle_monitoring
        self.app.toggle_monitoring()
        
        # Verify stop_monitoring was called
        self.app.stop_monitoring.assert_called_once()
    
    def test_start_monitoring(self):
        """Test start_monitoring method."""
        # Mock the UI components
        self.app.start_stop_button = self.mock_button_instance
        self.app.status_var = self.mock_stringvar_instance
        
        # Call start_monitoring
        self.app.start_monitoring()
        
        # Verify UI updates
        self.assertTrue(self.app.is_monitoring)
        self.app.start_stop_button.config.assert_called_with(text="Stop Monitoring")
        self.app.status_var.set.assert_called_with("Monitoring Active")
        
        # Verify thread creation with correct arguments
        threading.Thread.assert_called_with(
            target=self.mock_start_monitoring,
            args=("Wi-Fi",)
        )
        
        # Verify thread was started
        thread_instance = threading.Thread.return_value
        thread_instance.start.assert_called_once()
    
    def test_stop_monitoring(self):
        """Test stop_monitoring method."""
        # Setup
        self.app.is_monitoring = True
        self.app.start_stop_button = self.mock_button_instance
        self.app.status_var = self.mock_stringvar_instance
        self.app.monitor_thread = MagicMock()
        self.app.monitor_thread.is_alive.return_value = True
        
        # Call stop_monitoring
        self.app.stop_monitoring()
        
        # Verify UI updates
        self.assertFalse(self.app.is_monitoring)
        self.app.start_stop_button.config.assert_called_with(text="Start Monitoring")
        self.app.status_var.set.assert_called_with("Ready")
        
        # Verify stop_monitoring was called
        self.mock_stop_monitoring.assert_called_once()
        
        # Verify thread join was called
        self.app.monitor_thread.join.assert_called_with(timeout=2.0)
    
    def test_check_threat_indicators_ip(self):
        """Test check_threat_indicators with IP addresses."""
        # Test known malicious IP
        results = self.app.check_threat_indicators(ip='192.168.1.100')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], 'IP')
        self.assertEqual(results[0]['value'], '192.168.1.100')
        self.assertEqual(results[0]['threat_level'], 'High')
        
        # Test safe IP
        results = self.app.check_threat_indicators(ip='192.168.1.1')
        self.assertEqual(len(results), 0)
    
    def test_check_threat_indicators_domain(self):
        """Test check_threat_indicators with domains."""
        # Test known malicious domain
        results = self.app.check_threat_indicators(domain='malicious.com')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], 'Domain')
        self.assertEqual(results[0]['value'], 'malicious.com')
        
        # Test safe domain
        results = self.app.check_threat_indicators(domain='google.com')
        self.assertEqual(len(results), 0)
    
    def test_check_threat_indicators_content(self):
        """Test check_threat_indicators with content matching patterns."""
        # Test content with SQL injection pattern
        results = self.app.check_threat_indicators(content="login.php?user=' OR 1=1 --")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], 'Content')
        self.assertEqual(results[0]['threat_level'], 'Medium')
        
        # Test safe content
        results = self.app.check_threat_indicators(content="normal user input")
        self.assertEqual(len(results), 0)
    
    def test_add_alert(self):
        """Test add_alert method."""
        # Setup mock alerts_tab with add_alert method
        self.app.alerts_tab = MagicMock()
        self.app.alerts_tab.add_alert = MagicMock()
        
        # Call add_alert
        alert_details = {"level": "High", "message": "Suspicious traffic detected"}
        self.app.add_alert(alert_details)
        
        # Verify add_alert was called on alerts_tab
        self.app.alerts_tab.add_alert.assert_called_with(alert_details)
    
    def test_update_flow_ui(self):
        """Test update_flow_ui method."""
        # Setup mock flows_tab with update_flow_ui method
        self.app.flows_tab = MagicMock()
        self.app.flows_tab.update_flow_ui = MagicMock()
        
        # Call update_flow_ui
        flow = {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8"}
        risk_score = 0.75
        self.app.update_flow_ui(flow, risk_score)
        
        # Verify update_flow_ui was called on flows_tab
        self.app.flows_tab.update_flow_ui.assert_called_with(flow, risk_score)
    
    def test_add_packet_to_ui(self):
        """Test add_packet_to_ui method."""
        # Setup mock packets_tab with add_packet_to_ui method
        self.app.packets_tab = MagicMock()
        self.app.packets_tab.add_packet_to_ui = MagicMock()
        
        # Call add_packet_to_ui
        packet = MagicMock()
        packet_data = {"protocol": "TCP", "length": 64}
        packet_id = 12345
        self.app.add_packet_to_ui(packet, packet_data, packet_id)
        
        # Verify add_packet_to_ui was called on packets_tab
        self.app.packets_tab.add_packet_to_ui.assert_called_with(packet, packet_data, packet_id)
    
    def test_block_ip(self):
        """Test block_ip method."""
        # Setup mock alerts_tab with block_ip method
        self.app.alerts_tab = MagicMock()
        self.app.alerts_tab.block_ip = MagicMock(return_value=True)
        
        # Call block_ip
        result = self.app.block_ip("192.168.1.100", "Malicious activity")
        
        # Verify block_ip was called on alerts_tab and returned correctly
        self.app.alerts_tab.block_ip.assert_called_with("192.168.1.100", "Malicious activity")
        self.assertTrue(result)
        
        # Test when alerts_tab doesn't have block_ip method
        self.app.alerts_tab = MagicMock(spec=[])  # No methods
        result = self.app.block_ip("192.168.1.100", "Malicious activity")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()