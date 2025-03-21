from GUI.__init__ import *
from scapy.all import rdpcap
import pyshark

class NFStreamGUI:
    '''
        Graphical User Interface for NFStream, Scapy, and Pyshark
    '''
    def __init__(self, root):
        self.root = root
        self.root.title("NFStream GUI")
        self.root.geometry("800x600")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Set default theme
        
        self.label = ttk.Label(root, text="Select a PCAP or PCAPNG file:")
        self.label.pack(pady=10)
        
        self.file_button = ttk.Button(root, text="Browse", command=self.browse_file)
        self.file_button.pack(pady=5)
        
        self.run_button = ttk.Button(root, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=20)
        
        self.library_label = ttk.Label(root, text="Select Library:")
        self.library_label.pack(pady=5)
        
        self.library_combobox = ttk.Combobox(root, values=["NFStream", "Scapy", "Pyshark"], state="readonly")
        self.library_combobox.pack(pady=5)
        self.library_combobox.set("NFStream")
        
        self.theme_label = ttk.Label(root, text="Select Theme:")
        self.theme_label.pack(pady=5)
        
        self.theme_combobox = ttk.Combobox(root, values=self.style.theme_names(), state="readonly")
        self.theme_combobox.pack(pady=5)
        self.theme_combobox.set(self.style.theme_use())
        self.theme_combobox.bind("<<ComboboxSelected>>", self.change_theme)
        
        self.file_path = None

        self.tree = ttk.Treeview(root, style="Custom.Treeview")
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.tree_scroll = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        
        self.tree.bind("<Double-1>", self.on_double_click)
        
        self.style.configure("Custom.Treeview.Heading", font=("Helvetica", 10, "bold"), background="#4CAF50", foreground="white")
        self.style.configure("Custom.Treeview", font=("Helvetica", 10), rowheight=25)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PCAP and PCAPNG files", "*.pcap *.pcapng")])
        if self.file_path:
            self.label.config(text=f"Selected file: {os.path.basename(self.file_path)}")

    def run_analysis(self):
        if not self.file_path:
            messagebox.showerror("Error", "No file selected!")
            return

        selected_library = self.library_combobox.get()

        try:
            if selected_library == "NFStream":
                self.run_nfstreamer()
            elif selected_library == "Scapy":
                self.run_scapy()
            elif selected_library == "Pyshark":
                self.run_pyshark()
            else:
                messagebox.showerror("Error", "Invalid library selected!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_nfstreamer(self):
        streamer = NFStreamer(source=self.file_path)
        df = streamer.to_pandas()
        self.display_dataframe(df)
        messagebox.showinfo("Success", f"Processed {len(df)} flows using NFStream.")

    def run_scapy(self):
        packets = rdpcap(self.file_path)
        data = [{"Packet": i, "Summary": pkt.summary()} for i, pkt in enumerate(packets)]
        df = pd.DataFrame(data)
        self.display_dataframe(df)
        messagebox.showinfo("Success", f"Processed {len(packets)} packets using Scapy.")

    def run_pyshark(self):
        capture = pyshark.FileCapture(self.file_path)
        data = [{"Packet": i, "Summary": str(pkt)} for i, pkt in enumerate(capture)]
        df = pd.DataFrame(data)
        self.display_dataframe(df)
        messagebox.showinfo("Success", f"Processed {len(data)} packets using Pyshark.")

    def display_dataframe(self, df):
        self.tree.delete(*self.tree.get_children())
        
        self.tree["column"] = list(df.columns)
        self.tree["show"] = "headings"
        
        for column in self.tree["columns"]:
            self.tree.heading(column, text=column)
            self.tree.column(column, width=100, anchor='center')
        
        for index, row in df.iterrows():
            self.tree.insert("", "end", values=list(row))
    
    def on_double_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "heading":
            column = self.tree.identify_column(event.x)
            column_index = int(column.replace("#", "")) - 1
            self.auto_fit_column(column_index)

    def auto_fit_column(self, column_index):
        max_width = max([len(str(self.tree.set(item, column_index))) for item in self.tree.get_children()])
        column_heading = self.tree.heading(f"#{column_index + 1}")["text"]
        max_width = max(max_width, len(column_heading))
        self.tree.column(f"#{column_index + 1}", width=max_width * 10)
    
    def change_theme(self, event):
        selected_theme = self.theme_combobox.get()
        self.style.theme_use(selected_theme)