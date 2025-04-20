#!/usr/bin/env python3
# main.py
# Real-time Network Detection and Response System
# Authors: Alexander James, Joshua Ludolf, & Matthew Trevino

from GUI.main import *


def check_requirements():
    """Check if all required libraries are installed"""
    try:
        import nfstream
        import pyshark
        import scapy.all
        print("All required libraries are installed.")
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install all required libraries using:")
        print("pip install -r requirements.txt")
        return False

def check_permissions():
    """Check if the application has necessary permissions"""
    is_admin = False
    
    # Check if running with admin/root privileges
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            is_admin = False
    else:  # Linux/MacOS
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        print("WARNING: This application may require administrative/root privileges")
        print("Some features like packet capture and response actions may not work correctly.")
        print("Consider running the application with elevated privileges.")
    
    return is_admin

def main():
    """Main function to run the application"""
    print("Starting Real-time Network Detection and Response System...")
    print("Version 1.0.0")
    
    # Check requirements and permissions
    if not check_requirements():
        sys.exit(1)
    check_permissions()
    
    # Initialize the GUI
    root = tk.Tk() 
    app = NetworkMonitor(root)
    
    # Run the application
    root.mainloop()

if __name__ == "__main__":
    main()
