# modules/system_info.py

import platform
import socket
import psutil
import time
from tqdm import tqdm

def display_system_info():
    # Loading animation
    print("Initializing System Scan...")
    for _ in tqdm(range(50), desc="Loading", ncols=75):
        time.sleep(0.03)

    # System Info
    print("\n=== SYSTEM INFORMATION ===")
    print(f"System: {platform.system()}")
    print(f"Node Name: {platform.node()}")
    print(f"Release: {platform.release()}")
    print(f"Version: {platform.version()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor()}")
    try:
        print(f"IP Address: {socket.gethostbyname(socket.gethostname())}")
    except:
        print("IP Address: Unable to fetch")
    print(f"RAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB")
