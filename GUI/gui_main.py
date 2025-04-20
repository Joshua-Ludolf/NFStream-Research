from tkinter import Tk
from GUI.tabs.flows_tab import setup_flows_tab
from GUI.tabs.packets_tab import setup_packets_tab
from GUI.tabs.alerts_tab import setup_alerts_tab
from GUI.tabs.config_tab import setup_config_tab
from GUI.threat_intelligence import load_threat_intelligence
from GUI.monitoring import start_monitoring, stop_monitoring
from GUI.responses import block_ip, unblock_ip

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-time Network Detection and Response System")
        self.root.geometry("1200x800")

        # Initialize variables
        self.is_monitoring = False
        self.threat_data = load_threat_intelligence()

        # Setup UI
        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.flows_tab = setup_flows_tab(self.notebook)
        self.packets_tab = setup_packets_tab(self.notebook)
        self.alerts_tab = setup_alerts_tab(self.notebook)
        self.config_tab = setup_config_tab(self.notebook)

        self.notebook.add(self.flows_tab, text="Network Flows")
        self.notebook.add(self.packets_tab, text="Packet Analysis")
        self.notebook.add(self.alerts_tab, text="Alerts & Response")
        self.notebook.add(self.config_tab, text="Configuration")

    def toggle_monitoring(self):
        """Start or stop the monitoring process"""
        if self.is_monitoring:
            stop_monitoring()
            self.is_monitoring = False
        else:
            start_monitoring()
            self.is_monitoring = True

if __name__ == "__main__":
    root = Tk()
    app = NetworkMonitor(root)
    root.mainloop()
