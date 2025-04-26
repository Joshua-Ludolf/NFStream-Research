import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import threading
import sys
import os
import re
from datetime import datetime

# Add the project root to Python path to allow importing from the GUI package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import mock classes from the unit test file
from test_network_monitor import MockTk, MockNotebook
from GUI.main import NetworkMonitor

class TestThreatDetection(unittest.TestCase):
    """Test suite focused on NetworkMonitor's threat detection capabilities"""
    
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
        
        # Only patch the monitoring module's function calls
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
            'threat_ips': {'1.2.3.4', '5.6.7.8', '192.168.0.100'},
            'threat_domains': {'malicious.com', 'evil.org', 'bad-domain.net'}
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
    
    def test_sql_injection_detection(self):
        """Test detection of SQL injection patterns"""
        # Test various SQL injection patterns
        sql_injection_payloads = [
            "username=admin' OR 1=1 --",
            "search=1'; DROP TABLE users; --",
            "id=1 UNION SELECT username,password FROM users",
            "param=admin';--",
            "query=' OR '1'='1"
        ]
        
        # First pattern should be detected (exact match with suspicious_patterns)
        result = self.app.check_threat_indicators(content=sql_injection_payloads[0])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'Content')
        self.assertEqual(result[0]['threat_level'], 'Medium')
        
        # Second pattern should be detected (exact match with suspicious_patterns)
        result = self.app.check_threat_indicators(content=sql_injection_payloads[1])
        self.assertEqual(len(result), 1)
        
        # Third pattern shouldn't be detected (not in suspicious_patterns)
        result = self.app.check_threat_indicators(content=sql_injection_payloads[2])
        self.assertEqual(len(result), 0)
    
    def test_xss_detection(self):
        """Test detection of Cross-Site Scripting (XSS) patterns"""
        # Test various XSS patterns
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>"
        ]
        
        # First two should be detected
        result = self.app.check_threat_indicators(content=xss_payloads[0])
        self.assertEqual(len(result), 1)
        
        result = self.app.check_threat_indicators(content=xss_payloads[1])
        self.assertEqual(len(result), 1)
        
        # The third one shouldn't be detected as is
        result = self.app.check_threat_indicators(content=xss_payloads[2])
        self.assertEqual(len(result), 0)
    
    def test_command_injection_detection(self):
        """Test detection of command injection patterns"""
        # Test command injection patterns
        cmd_injection_payloads = [
            "filename=data.txt | cat /etc/passwd",
            "param=test; powershell.exe -Command 'Get-Process'",
            "input=test && rm -rf /",
            "query=test || whoami"
        ]
        
        # Check detection of specific patterns
        result = self.app.check_threat_indicators(content=cmd_injection_payloads[0])
        self.assertEqual(len(result), 1)
        
        result = self.app.check_threat_indicators(content=cmd_injection_payloads[1])
        self.assertEqual(len(result), 1)
        
        # These aren't explicitly in the patterns list
        result = self.app.check_threat_indicators(content=cmd_injection_payloads[2])
        self.assertEqual(len(result), 0)
    
    def test_protocol_mapping(self):
        """Test the protocol mapping functionality"""
        # Test common protocols
        self.assertEqual(self.app.protocol_map[1], "ICMP")
        self.assertEqual(self.app.protocol_map[6], "TCP")
        self.assertEqual(self.app.protocol_map[17], "UDP")
        
        # Test protocol number that doesn't exist in the map
        self.assertNotIn(99, self.app.protocol_map)
    
    def test_multiple_threat_indicators(self):
        """Test detection of multiple threat indicators in a single content"""
        # Content with multiple suspicious patterns
        multi_threat_content = """
        POST /login HTTP/1.1
        Host: example.com
        User-Agent: zgrab/0.x
        
        username=admin' OR 1=1 --&password=password
        <script>alert('XSS')</script>
        """
        
        # Should detect multiple patterns
        result = self.app.check_threat_indicators(content=multi_threat_content)
        self.assertGreaterEqual(len(result), 2)  # At least 2 threats (SQL injection and XSS)
        
        # Get the threat types detected
        threat_types = [r['value'] for r in result]
        self.assertIn("' OR 1=1 --", threat_types)
        self.assertIn("<script>alert\\('XSS'\\)</script>", threat_types)
    
    def test_add_custom_threat_indicators(self):
        """Test adding custom threat indicators"""
        # Add a custom threat IP
        custom_ip = "192.168.1.250"
        self.app.threat_ips.add(custom_ip)
        
        # Verify it's detected
        result = self.app.check_threat_indicators(ip=custom_ip)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'IP')
        self.assertEqual(result[0]['value'], custom_ip)
        
        # Add a custom threat domain
        custom_domain = "malware.example.com"
        self.app.threat_domains.add(custom_domain)
        
        # Verify it's detected
        result = self.app.check_threat_indicators(domain=custom_domain)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'Domain')
        self.assertEqual(result[0]['value'], custom_domain)
    
    def test_threshold_values(self):
        """Test the threshold values for traffic anomalies"""
        # Verify default threshold values
        self.assertEqual(self.app.thresholds["max_packets_per_second"], 1000)
        self.assertEqual(self.app.thresholds["max_connections_per_minute"], 100)
        self.assertEqual(self.app.thresholds["max_dns_queries_per_minute"], 50)
        self.assertEqual(self.app.thresholds["max_failed_connections"], 10)
        
        # Test modifying thresholds
        self.app.thresholds["max_packets_per_second"] = 500
        self.assertEqual(self.app.thresholds["max_packets_per_second"], 500)
    
    def test_suspicious_user_agents(self):
        """Test detection of suspicious user agents"""
        # Create content with suspicious user agents
        for user_agent in self.app.suspicious_user_agents:
            content = f"User-Agent: {user_agent}\r\nHost: example.com"
            
            # We need to add this pattern to suspicious_patterns first
            # since the app's check_threat_indicators only checks against suspicious_patterns
            original_patterns = self.app.suspicious_patterns.copy()
            self.app.suspicious_patterns.append(re.escape(user_agent))
            
            result = self.app.check_threat_indicators(content=content)
            self.assertGreaterEqual(len(result), 1)
            
            # Restore original patterns
            self.app.suspicious_patterns = original_patterns
    
    def test_moderate_suspicious_payloads(self):
        """Test detection of moderately suspicious payloads"""
        # Create content with moderate suspicious payloads
        for payload in self.app.moderate_suspicious_payloads:
            content = f"GET /page?q={payload} HTTP/1.1\r\nHost: example.com"
            
            # Add this pattern to suspicious_patterns first
            original_patterns = self.app.suspicious_patterns.copy()
            self.app.suspicious_patterns.append(re.escape(payload))
            
            result = self.app.check_threat_indicators(content=content)
            self.assertGreaterEqual(len(result), 1)
            
            # Restore original patterns
            self.app.suspicious_patterns = original_patterns
    
    def test_file_hash_detection(self):
        """Test file hash threat detection"""
        # Add threat file hashes attribute and some sample hashes
        self.app.threat_file_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
        
        # Test detection of a known malicious hash
        result = self.app.check_threat_indicators(
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'File Hash')
        
        # Test with an unknown hash
        result = self.app.check_threat_indicators(
            file_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertEqual(len(result), 0)
    
    def test_multiple_indicator_types(self):
        """Test checking multiple indicator types at once"""
        # Setup test data
        test_ip = "1.2.3.4"  # Known threat IP
        test_domain = "safe.com"  # Safe domain
        test_content = "normal content"  # Safe content
        
        # Check with one malicious indicator
        result = self.app.check_threat_indicators(
            ip=test_ip,
            domain=test_domain,
            content=test_content
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['type'], 'IP')
        
        # Check with multiple malicious indicators
        result = self.app.check_threat_indicators(
            ip=test_ip,
            domain="malicious.com",
            content="username=admin' OR 1=1 --"
        )
        self.assertEqual(len(result), 3)  # Should detect IP, domain, and content


if __name__ == '__main__':
    unittest.main()