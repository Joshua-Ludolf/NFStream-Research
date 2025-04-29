# NFStream-GUI

## Project Overview

This repository contains various scripts and tools for analyzing network traffic and enhancing computer security. The main components of this project include:

- **NFStream Code Walkthrough**: Demonstrates how to use the `NFStreamer` class to read a pcap file and print the flows using NFStream.
- **Graphical User Interface (GUI)**: Provides a user-friendly interface for selecting and analyzing pcap files using NFStream.
- **Threat Detection**: Built-in capabilities to detect suspicious patterns, malicious IP addresses, and anomalous network behavior.
- **Alert Trigger System**: A script for generating test traffic to demonstrate alert capabilities.
- **Real-time Monitoring**: Capability to monitor network interfaces in real-time and detect suspicious activities.
- **Response Actions**: Tools for responding to threats, including IP blocking and connection termination.

## Files and Directories

- `guidemo.py`: Entry point script to run the GUI for NFStream.
- `trigger_alert.py`: Script for generating test traffic to trigger and demonstrate alert capabilities.
- `demo.pcap` and `wifi.pcap`: Sample packet capture files for analysis.
- `milestone-1-Alexander James, Joshua Ludolf, and Matthew Trevino.ipynb`: First milestone Jupyter notebook.
- `Milestone-2-Alexander James, Joshua Ludolf, and Matthew Trevino.ipynb`: Second milestone Jupyter notebook.
- `requirements.txt`: List of dependencies required for the project.
- `LICENSE`: GNU General Public License for the project.
- `GUI/`: Directory containing the GUI implementation for NFStream:
  - `__init__.py`: Package initialization file with imports and version information.
  - `main.py`: Main GUI implementation with the `NetworkMonitor` class for traffic analysis and threat detection.
  - `monitoring.py`: Network monitoring functionality.
  - `responses.py`: Implementation of response actions like IP blocking.
  - `threat_intelligence.py`: Threat intelligence data loading and management.
  - `tabs/`: Directory containing UI tab implementations:
    - `flows_tab.py`: Network flows analysis tab.
    - `packets_tab.py`: Packet inspection and analysis tab.
    - `alerts_tab.py`: Security alerts and response actions tab.
    - `config_tab.py`: Application configuration tab.
- `test_*.py`: Unit and integration tests:
  - `test_threat_detection.py`: Tests for threat detection capabilities.
  - `test_network_monitor.py`: Tests for the NetworkMonitor class.
  - `test_response_actions.py`: Tests for threat response actions.
  - `test_network_traffic_processing.py`: Tests for network traffic processing.
  - `test_network_monitor_integration.py`: Integration tests.

## Features

- **Real-time Network Monitoring**: Monitor network interfaces in real-time.
- **Traffic Analysis**: Analyze network flows and packet data.
- **Threat Detection**: 
  - SQL Injection pattern detection
  - Cross-Site Scripting (XSS) detection
  - Command injection detection
  - Suspicious user agent identification
  - Malicious IP and domain identification
- **Response Actions**:
  - IP blocking capability
  - Connection termination
- **Customizable Thresholds**: Configure traffic anomaly thresholds.
- **User-friendly Interface**: Tabbed interface for different aspects of network monitoring.

## Installation

To install the required dependencies, run:
```bash
pip install -r requirements.txt
```
with uv python package manager:
```bash
uv add pip install -r requirements.txt
or
uv add <library to add>
```

## Usage

### Running the Jupyter Notebook
To run the Jupyter notebook, use:
```bash
jupyter notebook milestone-1-Alexander\ James,\ Joshua\ Ludolf,\ and\ Matthew\ Trevino.ipynb
```



### Running the GUI
To run the GUI, use:
```bash
python guidemo.py
```



### Running the Alert Trigger System
To simulate network traffic and trigger alerts, use:
```bash
python trigger_alert.py
```
with uv python package manager:

```bash
uv run trigger_alert.py
```

### Running Tests
To run the test suite, use:
```bash
python -m unittest discover -p "test_*.py"
```
with uv python package manager:

```bash
uv run test_*.py
```

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Authors

- Alexander James
- Joshua Ludolf
- Matthew Trevino

## Version

Current version: 1.0.0
