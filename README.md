# NFStream-GUI

## Project Overview

This repository contains various scripts and tools for analyzing network traffic and enhancing computer security. The main components of this project include:

- **NFStream Code Walkthrough**: Demonstrates how to use the NFStreamer class to read a pcap file and print the flows using NFStream.
- **Graphical User Interface (GUI)**: Provides a user-friendly interface for selecting and analyzing pcap files using NFStream.
- **Threat Detection**: Built-in capabilities to detect suspicious patterns, malicious IP addresses, and anomalous network behavior.
- **Alert Trigger System**: A script for generating test traffic to demonstrate alert capabilities.

## Files and Directories

- `main.py`: Main Python script for network analysis functionality.
- `guidemo.py`: Python script to run the GUI for NFStream.
- `trigger_alert.py`: Script for generating test traffic to trigger and demonstrate alert capabilities.
- `demo.pcap` and `wifi.pcap`: Sample packet capture files for analysis.
- `milestone-1-Alexander James, Joshua Ludolf, and Matthew Trevino.ipynb`: First milestone Jupyter notebook.
- `Milestone-2-Alexander James, Joshua Ludolf, and Matthew Trevino.ipynb`: Second milestone Jupyter notebook.
- `requirements.txt`: List of dependencies required for the project.
- `LICENSE`: GNU General Public License for the project.
- `GUI/`: Directory containing the GUI implementation for NFStream:
  - `__init__.py`: Package initialization file with imports and version information.
  - `gui.py`: Main GUI implementation with NetworkMonitor class for traffic analysis and threat detection.

## Installation

To install the required dependencies, run:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Jupyter Notebook
To run the Jupyter notebook, use:
```bash
jupyter notebook demo.ipynb
```

### Running the Python Script
To run the Python script, use:
```bash
python demo.py
```

### Running the GUI
To run the GUI, use:
```bash
python guidemo.py
```

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
