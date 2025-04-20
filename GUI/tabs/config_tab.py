from tkinter import ttk

def setup_config_tab(notebook):
    """Set up the Configuration tab"""
    config_tab = ttk.Frame(notebook)

    # Create frames for different config sections
    detection_frame = ttk.LabelFrame(config_tab, text="Detection Configuration")
    detection_frame.pack(fill="x", padx=10, pady=10)

    response_frame = ttk.LabelFrame(config_tab, text="Response Configuration")
    response_frame.pack(fill="x", padx=10, pady=10)

    # Detection thresholds
    ttk.Label(detection_frame, text="Max packets per second:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(detection_frame, width=10).grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(detection_frame, text="Max connections per minute:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
    ttk.Entry(detection_frame, width=10).grid(row=1, column=1, padx=5, pady=5)

    # Response options
    ttk.Label(response_frame, text="Default response:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    ttk.Combobox(response_frame, values=["Block IP", "Reset Connection", "Log Only"], state="readonly").grid(row=0, column=1, padx=5, pady=5)

    return config_tab
