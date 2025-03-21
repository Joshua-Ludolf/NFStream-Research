from GUI.gui import *

def run_gui():
    root = tk.Tk()
    app = NFStreamGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
    # help(NFStreamGUI)
    # print(NFStreamGUI.__doc__)