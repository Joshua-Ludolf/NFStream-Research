'''
    PyShark
        Strengths
        - Wireshark Integration: Access to all Wireshark dissectors for comprehensive protocol support
        - Readable Output: Human-friendly packet information similar to Wireshark GUI
        - Familiar Interface: Easy transition for Wireshark users
        - Deep Packet Inspection: Excellent for detailed protocol analysis

        Weaknesses
        - Performance: Much slower than NFStream, relies on tshark processes
        - Resource Intensive: High memory usage when dealing with large captures
        - Dependency on Wireshark: Requires Wireshark/tshark installation
        - Limited Packet Creation: Not designed for packet crafting like Scapy
        - Jupyter Notebook Limitations: Often encounters execution issues in Jupyter Notebook environments due to asynchronous processing requirements
'''
import pyshark
cap = pyshark.FileCapture('wifi.pcap')
for packet in cap:
    print(packet)
cap.close()