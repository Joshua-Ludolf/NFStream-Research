from tkinter import ttk

def setup_flows_tab(notebook):
    """Set up the Network Flows tab"""
    flows_tab = ttk.Frame(notebook)

    # Create treeview for flows
    flows_tree = ttk.Treeview(flows_tab)
    flows_tree["columns"] = ("time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packets", "bytes", "duration", "risk")

    # Configure columns
    for col in flows_tree["columns"]:
        flows_tree.heading(col, text=col.replace("_", " ").title())
        flows_tree.column(col, width=100)

    # Add scrollbars
    flow_y_scroll = ttk.Scrollbar(flows_tab, orient="vertical", command=flows_tree.yview)
    flow_x_scroll = ttk.Scrollbar(flows_tab, orient="horizontal", command=flows_tree.xview)
    flows_tree.configure(yscrollcommand=flow_y_scroll.set, xscrollcommand=flow_x_scroll.set)

    flow_y_scroll.pack(side="right", fill="y")
    flow_x_scroll.pack(side="bottom", fill="x")
    flows_tree.pack(fill="both", expand=True)

    return flows_tab
