from tkinter import ttk

def setup_packets_tab(notebook):
    """Set up the Packet Analysis tab"""
    packets_tab = ttk.Frame(notebook)

    # Create treeview for packets
    packets_tree = ttk.Treeview(packets_tab)
    packets_tree["columns"] = ("time", "src", "dst", "protocol", "length", "info")

    # Configure columns
    for col in packets_tree["columns"]:
        packets_tree.heading(col, text=col.title())
        packets_tree.column(col, width=100)

    # Add scrollbars
    packet_y_scroll = ttk.Scrollbar(packets_tab, orient="vertical", command=packets_tree.yview)
    packet_x_scroll = ttk.Scrollbar(packets_tab, orient="horizontal", command=packets_tree.xview)
    packets_tree.configure(yscrollcommand=packet_y_scroll.set, xscrollcommand=packet_x_scroll.set)

    packet_y_scroll.pack(side="right", fill="y")
    packet_x_scroll.pack(side="bottom", fill="x")
    packets_tree.pack(fill="both", expand=True)

    return packets_tab
