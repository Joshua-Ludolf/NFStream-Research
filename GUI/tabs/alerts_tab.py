from tkinter import ttk

def setup_alerts_tab(notebook):
    """Set up the Alerts & Response tab"""
    alerts_tab = ttk.Frame(notebook)

    # Create treeview for alerts
    alerts_tree = ttk.Treeview(alerts_tab)
    alerts_tree["columns"] = ("time", "severity", "source", "destination", "alert_type", "details")

    # Configure columns
    for col in alerts_tree["columns"]:
        alerts_tree.heading(col, text=col.replace("_", " ").title())
        alerts_tree.column(col, width=100)

    # Add scrollbars
    alerts_y_scroll = ttk.Scrollbar(alerts_tab, orient="vertical", command=alerts_tree.yview)
    alerts_x_scroll = ttk.Scrollbar(alerts_tab, orient="horizontal", command=alerts_tree.xview)
    alerts_tree.configure(yscrollcommand=alerts_y_scroll.set, xscrollcommand=alerts_x_scroll.set)

    alerts_y_scroll.pack(side="right", fill="y")
    alerts_x_scroll.pack(side="bottom", fill="x")
    alerts_tree.pack(fill="both", expand=True)

    return alerts_tab
