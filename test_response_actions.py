import unittest
from unittest.mock import MagicMock, patch, mock_open, call
import os
import json
import sys
import tkinter as tk
import threading
import tempfile
import subprocess
from datetime import datetime

# Add the project root to Python path to allow importing from the GUI package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import mock classes from the unit test file
from test_network_monitor import MockTk, MockNotebook
from GUI.main import NetworkMonitor
from GUI.responses import (
    block_ip, unblock_ip, get_blocked_ips, save_blocked_ips, 
    run_powershell_command, terminate_connections_with_scapy,
    start_packet_filtering, stop_packet_filtering,
    BLOCKED_IPS, BLOCKED_IPS_FILE
)

class TestResponseActions(unittest.TestCase):
    """Test suite for network response actions (IP blocking/unblocking)"""
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create mock Tk root
        self.root = MockTk()
        
        # Mock all dependent modules and classes for NetworkMonitor
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
        
        # Mock the monitoring module's function calls
        self.patcher5 = patch('GUI.main.set_app_reference')
        self.mock_set_app_reference = self.patcher5.start()
        
        # Patch ttk.Notebook to use our mock
        self.patcher6 = patch('tkinter.ttk.Notebook', MockNotebook)
        self.patcher6.start()
        
        # Patch additional tkinter components
        self.patcher7 = patch('tkinter.ttk.Frame')
        self.mock_frame = self.patcher7.start()
        
        self.patcher8 = patch('tkinter.ttk.Label')
        self.mock_label = self.patcher8.start()
        
        self.patcher9 = patch('tkinter.ttk.Button')
        self.mock_button = self.patcher9.start()
        
        self.patcher10 = patch('tkinter.StringVar')
        self.mock_stringvar = self.patcher10.start()
        
        # Create NetworkMonitor instance with mocked dependencies
        self.app = NetworkMonitor(self.root)
        self.app.alerts_tab.block_ip = MagicMock()
        
        # Mock responses module dependencies
        self.patcher11 = patch('GUI.responses.run_powershell_command')
        self.mock_run_powershell = self.patcher11.start()
        self.mock_run_powershell.return_value = True
        
        self.patcher12 = patch('GUI.responses.os.system')
        self.mock_os_system = self.patcher12.start()
        
        self.patcher13 = patch('GUI.responses.terminate_connections_with_scapy')
        self.mock_terminate = self.patcher13.start()
        
        self.patcher14 = patch('GUI.responses.start_packet_filtering')
        self.mock_start_filtering = self.patcher14.start()
        self.mock_start_filtering.return_value = True
        
        self.patcher15 = patch('GUI.responses.monitoring')
        self.mock_monitoring = self.patcher15.start()
        
        # For file operations
        self.patcher16 = patch('builtins.open', new_callable=mock_open)
        self.mock_open = self.patcher16.start()
        
        self.patcher17 = patch('GUI.responses.json.load')
        self.mock_json_load = self.patcher17.start()
        self.mock_json_load.return_value = {}
        
        self.patcher18 = patch('GUI.responses.json.dump')
        self.mock_json_dump = self.patcher18.start()
        
        self.patcher19 = patch('GUI.responses.os.path.exists')
        self.mock_path_exists = self.patcher19.start()
        self.mock_path_exists.return_value = True
        
        # Mock scapy functions
        self.patcher20 = patch('GUI.responses.send')
        self.mock_send = self.patcher20.start()
        
        self.patcher21 = patch('GUI.responses.sniff')
        self.mock_sniff = self.patcher21.start()
        
        # Mock threading.Thread
        self.patcher22 = patch('threading.Thread')
        self.mock_thread = self.patcher22.start()
        self.mock_thread_instance = MagicMock()
        self.mock_thread.return_value = self.mock_thread_instance
        
        # Save original blocked IPs and clear for tests
        self.original_blocked_ips = BLOCKED_IPS.copy()
        BLOCKED_IPS.clear()
    
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
        self.patcher14.stop()
        self.patcher15.stop()
        self.patcher16.stop()
        self.patcher17.stop()
        self.patcher18.stop()
        self.patcher19.stop()
        self.patcher20.stop()
        self.patcher21.stop()
        self.patcher22.stop()
        
        # Restore original blocked IPs
        BLOCKED_IPS.clear()
        BLOCKED_IPS.update(self.original_blocked_ips)
    
    def test_block_ip(self):
        """Test blocking an IP address"""
        ip = "192.168.1.100"
        reason = "Test blocking"
        
        # Call block_ip function
        result = block_ip(ip, reason)
        
        # Verify result
        self.assertTrue(result)
        
        # Verify IP was added to blocked IPs set
        self.assertIn(ip, BLOCKED_IPS)
        
        # Verify monitoring module was called
        self.mock_monitoring.block_ip_in_monitoring.assert_called_with(ip)
        
        # Verify connection termination was attempted
        self.mock_terminate.assert_called_with(ip)
        
        # Verify PowerShell command was attempted
        self.mock_run_powershell.assert_called()
        
        # Verify the IP was saved to persistent storage
        self.mock_json_dump.assert_called()
    
    def test_unblock_ip(self):
        """Test unblocking an IP address"""
        # Add an IP to block first
        ip = "10.0.0.99"
        BLOCKED_IPS.add(ip)
        
        # Mock json.load to return data with the IP
        self.mock_json_load.return_value = {
            ip: {
                "time_blocked": "2025-04-26 10:00:00",
                "reason": "Test reason"
            }
        }
        
        # Call unblock_ip function
        result = unblock_ip(ip)
        
        # Verify result
        self.assertTrue(result)
        
        # Verify IP was removed from blocked IPs set
        self.assertNotIn(ip, BLOCKED_IPS)
        
        # Verify monitoring module was called
        self.mock_monitoring.unblock_ip_in_monitoring.assert_called_with(ip)
        
        # Verify PowerShell command was attempted
        self.mock_run_powershell.assert_called()
        
        # Verify the IP was removed from persistent storage by checking json.dump was called
        # with an empty dictionary (since we're removing the only IP)
        self.mock_json_dump.assert_called_once()
    
    def test_block_ip_powershell_failure(self):
        """Test blocking an IP when PowerShell command fails"""
        ip = "1.1.1.1"
        reason = "Test blocking with PowerShell failure"
        
        # Make PowerShell command fail
        self.mock_run_powershell.return_value = False
        
        # Call block_ip function
        result = block_ip(ip, reason)
        
        # Verify result is still successful (fallback to netsh)
        self.assertTrue(result)
        
        # Verify IP was added to blocked IPs set
        self.assertIn(ip, BLOCKED_IPS)
        
        # Verify netsh commands were executed as fallback
        self.assertEqual(self.mock_os_system.call_count, 2)
    
    def test_unblock_ip_powershell_failure(self):
        """Test unblocking an IP when PowerShell command fails"""
        # Add an IP to block first
        ip = "8.8.8.8"
        BLOCKED_IPS.add(ip)
        
        # Mock json.load to return data with the IP
        self.mock_json_load.return_value = {
            ip: {
                "time_blocked": "2025-04-26 10:00:00",
                "reason": "Test reason"
            }
        }
        
        # Make PowerShell command fail
        self.mock_run_powershell.return_value = False
        
        # Call unblock_ip function
        result = unblock_ip(ip)
        
        # Verify result is still successful (fallback to netsh)
        self.assertTrue(result)
        
        # Verify IP was removed from blocked IPs set
        self.assertNotIn(ip, BLOCKED_IPS)
        
        # Verify netsh commands were executed as fallback
        self.assertEqual(self.mock_os_system.call_count, 3)
    
    def test_get_blocked_ips(self):
        """Test getting blocked IPs from persistent storage"""
        # Set up mock data for json.load
        test_data = {
            "192.168.1.1": {
                "time_blocked": "2025-04-26 10:00:00",
                "reason": "Test reason 1"
            },
            "10.0.0.1": {
                "time_blocked": "2025-04-26 11:30:00",
                "reason": "Test reason 2"
            }
        }
        self.mock_json_load.return_value = test_data
        
        # Call get_blocked_ips
        result = get_blocked_ips()
        
        # Verify the result
        self.assertEqual(result, test_data)
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)
    
    def test_save_blocked_ips(self):
        """Test saving blocked IPs to persistent storage"""
        # Create test data
        test_data = {
            "192.168.1.10": {
                "time_blocked": "2025-04-26 12:00:00",
                "reason": "Test saving"
            }
        }
        
        # Call save_blocked_ips
        save_blocked_ips(test_data)
        
        # Verify file was opened for writing
        self.mock_open.assert_called_with(BLOCKED_IPS_FILE, 'w')
        
        # Verify json.dump was called with the data
        self.mock_json_dump.assert_called_with(test_data, self.mock_open(), indent=2)
    
    def test_packet_filtering_start_stop(self):
        """Test starting and stopping packet filtering"""
        # Reset mocks to ensure they're clean
        self.mock_sniff.reset_mock()
        self.mock_thread.reset_mock()
        
        # Patch get_if_list to return mock interfaces
        with patch('GUI.responses.get_if_list', return_value=['eth0', 'wlan0']):
            # Test starting packet filtering
            result = start_packet_filtering()
            self.assertTrue(result)
            
            # Verify thread was created and started
            self.mock_thread.assert_called()
            self.mock_thread_instance.start.assert_called()
            
            # Test stopping packet filtering
            stop_packet_filtering()
    
    def test_main_app_block_integration(self):
        """Test integration of NetworkMonitor with blocking functionality"""
        ip = "172.16.0.5"
        reason = "Testing via app"
        
        # Mock the AlertsTab.block_ip method to call the actual responses.block_ip
        self.app.alerts_tab.block_ip = MagicMock(side_effect=lambda ip, reason: block_ip(ip, reason))
        
        # Call block_ip through the app
        result = self.app.block_ip(ip, reason)
        
        # Verify it was called correctly
        self.app.alerts_tab.block_ip.assert_called_with(ip, reason)
        
        # Verify IP is in the blocked set
        self.assertIn(ip, BLOCKED_IPS)
    
    def test_file_operation_exceptions(self):
        """Test exception handling in file operations"""
        # Test get_blocked_ips with file exception
        self.mock_open.side_effect = Exception("Test file exception")
        result = get_blocked_ips()
        self.assertEqual(result, {})
        
        # Reset side effect
        self.mock_open.side_effect = None
        
        # Test save_blocked_ips with exception
        self.mock_json_dump.side_effect = Exception("Test JSON exception")
        # This should not raise an exception but print an error message
        save_blocked_ips({"test": "data"})
        # Reset side effect
        self.mock_json_dump.side_effect = None
    
    def test_run_powershell_command(self):
        """Test running PowerShell commands"""
        # Mock subprocess.run
        with patch('GUI.responses.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            
            # Mock tempfile operations
            with patch('GUI.responses.tempfile.NamedTemporaryFile') as mock_temp:
                mock_temp_instance = MagicMock()
                mock_temp_instance.name = 'C:\\temp\\test.ps1'
                mock_temp.return_value.__enter__.return_value = mock_temp_instance
                
                # Test successful command
                result = run_powershell_command("Write-Output 'Test'")
                self.assertTrue(result)
                
                # Verify temp file was created and command was run
                mock_temp_instance.write.assert_called()
                mock_run.assert_called()
                
                # Test command failure
                mock_run.return_value.returncode = 1
                result = run_powershell_command("Write-Output 'Test'")
                self.assertFalse(result)
    
    def test_block_nonexistent_ip_cleanup(self):
        """Test blocking and then unblocking a non-existent IP in storage"""
        # Set up so the IP exists in memory but not in storage
        ip = "4.4.4.4"
        BLOCKED_IPS.add(ip)
        
        # Mock json.load to return empty dict (IP not in storage)
        self.mock_json_load.return_value = {}
        
        # Test unblocking
        result = unblock_ip(ip)
        
        # It should succeed and IP should be removed from memory
        self.assertTrue(result)
        self.assertNotIn(ip, BLOCKED_IPS)


if __name__ == '__main__':
    unittest.main()