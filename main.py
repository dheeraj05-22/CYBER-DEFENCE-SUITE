# main.py
import os
import time
import sys
import threading

# load .env before anything else that needs env vars
from dotenv import load_dotenv
load_dotenv()

from modules import (
    system_info,
    network_scanner,
    vuln_scanner,
    ids_detector,
    phishing_simulator,
    log_monitor,
    # email_scanner optional; won't crash import if module missing
)

# email_scanner is imported lazily below so missing module doesn't break startup
try:
    from modules import email_scanner
except Exception:
    email_scanner = None

IDS_STATUS = "ALL interfaces (auto-detect)"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def run_email_inbox_scan():
    """Run a one-time scan of the email inbox and print summary."""
    if email_scanner is None:
        print("[!] Email scanner module missing.")
        return

    imap_host = os.getenv("EMAIL_IMAP_HOST")
    user = os.getenv("EMAIL_USER")
    passwd = os.getenv("EMAIL_PASS")

    if not (imap_host and user and passwd):
        print("[!] Email credentials missing in .env. Cannot scan inbox.")
        return

    print("\n[+] Connecting to mailbox...")
    rows = email_scanner.scan_mailbox_once(
        imap_host=imap_host,
        username=user,
        password=passwd,
        folder="INBOX",
        search_unseen=True,
        mark_seen=False,
        debug=True
    )

    if not rows:
        print("\nNo emails processed or no new emails found.")
    else:
        print("\nScan complete:")
        for r in rows:
            print(f" → {r['subject']} => {r['final_label'].upper()}")


def start_email_monitor_manual():
    """Start the background email monitor (manual trigger)."""
    if email_scanner is None:
        print("[!] Email scanner module not available.")
        return

    imap_host = os.getenv("EMAIL_IMAP_HOST")
    user = os.getenv("EMAIL_USER")
    passwd = os.getenv("EMAIL_PASS")

    if not (imap_host and user and passwd):
        print("[!] Email credentials not found in environment. Add them to .env")
        return

    try:
        email_scanner.start_email_monitor_background(
            imap_host=imap_host,
            username=user,
            password=passwd,
            folder=os.getenv("EMAIL_FOLDER", "INBOX"),
            interval=int(os.getenv("EMAIL_POLL_INTERVAL", "60")),
            search_unseen=True,
            mark_seen=True,
            limit=int(os.getenv("EMAIL_FETCH_LIMIT", "20")),
            debug=False,
        )
        print("[+] Email monitor started (background). It will poll periodically.")
    except Exception as e:
        print(f"[!] Failed to start email monitor: {e}")


def start_live_ids_background():
    """Start live IDS on ALL network interfaces automatically."""
    def runner():
        # Sniff on all valid interfaces (log_monitor handles enumeration)
        log_monitor.start_realtime_monitor(interface=None, include_all=True)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    print("\n[+] Live IDS monitor started in background (ALL interfaces).\n")


def start_email_monitor_if_configured():
    """
    Start the background email scanner monitor if .env contains EMAIL_IMAP_HOST, EMAIL_USER, EMAIL_PASS.
    Uses email_scanner.start_email_monitor_background(...) if email_scanner module is available.
    """
    if email_scanner is None:
        print("[!] Email scanner module not available (modules/email_scanner.py). Skipping email monitor.")
        return

    imap_host = os.getenv("EMAIL_IMAP_HOST")
    user = os.getenv("EMAIL_USER")
    passwd = os.getenv("EMAIL_PASS")

    if not (imap_host and user and passwd):
        print("[!] Email credentials not found in environment. To enable email scanning set EMAIL_IMAP_HOST, EMAIL_USER, EMAIL_PASS in .env")
        return

    try:
        email_scanner.start_email_monitor_background(
            imap_host=imap_host,
            username=user,
            password=passwd,
            folder=os.getenv("EMAIL_FOLDER", "INBOX"),
            interval=int(os.getenv("EMAIL_POLL_INTERVAL", "60")),
            search_unseen=True,
            mark_seen=True,
            limit=int(os.getenv("EMAIL_FETCH_LIMIT", "20")),
            debug=False,
        )
    except Exception as e:
        print(f"[!] Failed to start email monitor: {e}")


def loading_animation(text="Loading", duration=2):
    print(f"\n{text}", end="")
    for _ in range(duration * 4):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.25)
    print("\n")


def typing_effect(text, delay=0.03):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def banner():
    print(
        r"""
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
____/\__,_/_/\__/\___/

           🛡️  Cyber Defence Suite  🛡️
"""
    )
    print(f"[ Live IDS Status ]: ✅ ACTIVE on {IDS_STATUS}\n")


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
        print("5. 🔙 Back to Main Menu")
        c = input("\n👉 Enter your choice: ").strip()

        if c == "1":
            loading_animation("Scanning Local Network")
            safe_call(network_scanner.scan_my_network)
            input("\nPress Enter to continue...")

        elif c == "2":
            tr = input("Enter IP or range (e.g., 192.168.1.0/24): ").strip()
            if not tr:
                typing_effect("No target provided. Returning...", 0.02)
                time.sleep(0.6)
                continue
            loading_animation(f"Scanning {tr}")
            safe_call(network_scanner.scan_custom_range, tr)
            input("\nPress Enter to continue...")

        elif c == "3":
            t = input("Enter external host/domain: ").strip()
            if not t:
                typing_effect("No target provided. Returning...", 0.02)
                time.sleep(0.6)
                continue
            loading_animation(f"Scanning {t}")
            safe_call(network_scanner.scan_external_server, t)
            input("\nPress Enter to continue...")

        elif c == "4":
            t = input("Enter target IP/domain for Ultra Scan: ").strip()
            if not t:
                typing_effect("No target provided. Returning...", 0.02)
                time.sleep(0.6)
                continue
            loading_animation(f"Ultra Scanning {t}", duration=2)
            safe_call(network_scanner.full_port_scan, t)
            input("\nPress Enter to continue...")

        elif c == "5":
            break

        else:
            typing_effect("Invalid choice.", 0.02)
            time.sleep(1)


# ----- PHISHING SUB-MENU (only the options you requested) -----
def phishing_menu():
    while True:
        clear_screen()
        print("\n=== Phishing Module ===")
        print("1. 📧 Email Inbox Scan (IMAP)")
        print("2. 🔁 Start Background Email Monitor")
        print("3. 🔙 Back to Main Menu")

        choice = input("\n👉 Enter your choice: ").strip()

        if choice == "1":
            loading_animation("Scanning Email Inbox for Phishing")
            safe_call(run_email_inbox_scan)
            input("\nPress Enter to continue...")

        elif choice == "2":
            loading_animation("Starting Background Email Monitor")
            safe_call(start_email_monitor_manual)
            input("\nPress Enter to continue...")

        elif choice == "3":
            return  # Exit phishing menu and go back to main menu

        else:
            print("Invalid choice")
            time.sleep(1)


def main():
    # Start live IDS as soon as the suite launches (on ALL interfaces)
    start_live_ids_background()

    # Start email monitor if credentials are configured in .env
    # start_email_monitor_if_configured()

    while True:
        clear_screen()
        banner()

        print("Select an option:")
        print("1. 🖥️  Display System Information")
        print("2. 🌐 Network Scanner")
        print("3. ⚡ Vulnerability Scanner")
        print("4. 🛡️  Run Offline IDS on Sample Log")
        print("5. 🎯 Phishing Awareness Simulator")
        print("6. ❌ Exit")
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
            loading_animation("Running IDS on sample_traffic.log")
            safe_call(ids_detector.run_ids)
            input("\nPress Enter to continue...")

        elif ch == "5":
            # Open phishing sub-menu (only IMAP scan / background monitor / back)
            phishing_menu()

        elif ch == "6":
            typing_effect("Exiting. Stay safe! 🛡️", 0.03)
            break

        else:
            typing_effect("Invalid choice", 0.02)
            time.sleep(1)


if __name__ == "__main__":
    main()
