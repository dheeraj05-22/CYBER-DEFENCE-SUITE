# main.py
import os
import time
import sys
from modules import system_info, network_scanner, vuln_scanner

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def loading_animation(text="Loading", duration=2):
    print(f"\n{text}", end="")
    for _ in range(duration * 4):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.25)
    print("\n")

def typing_effect(text, delay=0.03):
    for ch in text:
        sys.stdout.write(ch); sys.stdout.flush(); time.sleep(delay)
    print()

def banner():
    clear_screen()
    print(r"""
   ______      __                 ____       ____                   
  / ____/_  __/ /_  ___  _____   / __ \___  / __/__  ____  ________ 
 / /   / / / / __ \/ _ \/ ___/  / / / / _ \/ /_/ _ \/ __ \/ ___/ _ \
/ /___/ /_/ / /_/ /  __/ /     / /_/ /  __/ __/  __/ / / / /__/  __/
\____/\__, /_.___/\___/_/     /_____/\___/_/  \___/_/ /_/\___/\___/ 
     /____/                                                         
   _____       _ __     
  / ___/__  __(_) /____ 
  \__ \/ / / / / __/ _ \
 ___/ / /_/ / / /_/  __/
/____/\__,_/_/\__/\___/

           🛡️  Cyber Defence Suite  🛡️
""")

def safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user.")
    except Exception as e:
        print(f"\n⚠️ Error: {e}")

def network_menu():
    while True:
        clear_screen()
        print("\nChoose Network Scan Mode:")
        print("1. 📡 Scan My Network")
        print("2. 🎯 Scan Custom Range")
        print("3. 🌍 Scan External Server")
        print("4. 🚀 Ultra / Full Port Scan")
        print("5. 🛰️ Start Real-time Monitor")
        print("6. 🛑 Stop Real-time Monitor")
        print("7. 🔍 Check ARP anomalies (snapshot)")
        print("8. 🔙 Back to Main Menu")
        c = input("\n👉 Enter your choice: ").strip()
        if c == "1":
            loading_animation("Scanning Local Network")
            safe_call(network_scanner.scan_my_network)
            input("\nPress Enter to continue...")
        elif c == "2":
            tr = input("Enter IP or range (e.g., 192.168.1.0/24): ").strip()
            loading_animation(f"Scanning {tr}")
            safe_call(network_scanner.scan_custom_range, tr)
            input("\nPress Enter to continue...")
        elif c == "3":
            t = input("Enter external host/domain: ").strip()
            loading_animation(f"Scanning {t}")
            safe_call(network_scanner.scan_external_server, t)
            input("\nPress Enter to continue...")
        elif c == "4":
            t = input("Enter target IP/domain for Ultra Scan: ").strip()
            loading_animation(f"Ultra Scanning {t}", duration=2)
            safe_call(network_scanner.full_port_scan, t)
            input("\nPress Enter to continue...")
        elif c == "5":
            sec = input("Monitor interval seconds (default 30): ").strip()
            try:
                secn = int(sec) if sec else 30
            except:
                secn = 30
            safe_call(network_scanner.start_monitor, secn)
            input("\nPress Enter to continue...")
        elif c == "6":
            safe_call(network_scanner.stop_monitor)
            input("\nPress Enter to continue...")
        elif c == "7":
            safe_call(network_scanner.check_for_arp_spoof)
            input("\nPress Enter to continue...")
        elif c == "8":
            break
        else:
            typing_effect("Invalid choice.", 0.02)
            time.sleep(1)

def main():
    while True:
        banner()
        print("Select an option:")
        print("1. 🖥️  Display System Information")
        print("2. 🌐 Network Scanner")
        print("3. ⚡ Vulnerability Scanner")
        print("4. ❌ Exit")
        ch = input("\n👉 Enter your choice: ").strip()
        if ch == "1":
            loading_animation("Fetching System Information")
            safe_call(system_info.display_system_info)
            input("\nPress Enter to continue...")
        elif ch == "2":
            network_menu()
        elif ch == "3":
            t = input("Enter target IP or domain for vulnerability scan: ").strip()
            if t:
                loading_animation(f"Scanning {t} for vulnerabilities")
                safe_call(vuln_scanner.scan_vulnerabilities, t)
            input("\nPress Enter to continue...")
        elif ch == "4":
            typing_effect("Exiting. Stay safe!", 0.03)
            break
        else:
            typing_effect("Invalid choice", 0.02)
            time.sleep(1)

if __name__ == "__main__":
    main()
