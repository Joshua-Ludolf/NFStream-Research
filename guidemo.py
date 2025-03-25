'''
This script is used to run the NFStream GUI application. It initializes the main window and starts the Tkinter main loop.
It imports the NFStreamGUI class from the GUI module and creates an instance of it to display the GUI.
'''

from GUI.gui import *

def run_gui():
    root = tk.Tk()
    app = NFStreamGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()
    