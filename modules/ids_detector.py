import os
from datetime import datetime

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SIGNATURE_FILE = os.path.join(BASE_DIR, "signatures.txt")
TRAFFIC_FILE = os.path.join(BASE_DIR, "sample_traffic.log")
ALERT_LOG = os.path.join(BASE_DIR, "ids_alerts.log")


def load_signatures():
    """
    Load attack signatures from signatures.txt
    Returns a list of lowercase signatures.
    Used by BOTH: offline IDS + live monitor.
    """
    if not os.path.exists(SIGNATURE_FILE):
        print(f"[!] Signature file not found: {SIGNATURE_FILE}")
        return []

    signatures = []
    with open(SIGNATURE_FILE, "r") as f:
        for line in f:
            sig = line.strip()
            if sig:
                signatures.append(sig.lower())

    print(f"[+] Loaded {len(signatures)} attack signatures.")
    return signatures


def run_ids(traffic_file: str = TRAFFIC_FILE):
    """
    Offline Intrusion Detection:
    - Reads a log/traffic file line by line
    - Checks each line for any signature
    - Prints alerts and appends them to ids_alerts.log
    """
    if not os.path.exists(traffic_file):
        print(f"[!] Traffic file not found: {traffic_file}")
        return

    signatures = load_signatures()
    if not signatures:
        print("[!] No signatures loaded. Exiting IDS.")
        return

    print("\n[+] IDS Engine Started...\n")

    alerts = []

    with open(traffic_file, "r", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            lower_line = line.lower()

            for sig in signatures:
                if sig in lower_line:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert = (
                        f"[{timestamp}] ALERT: '{sig}' matched in line {line_no}: "
                        f"{line.strip()}"
                    )
                    print(alert)
                    alerts.append(alert)

    if alerts:
        with open(ALERT_LOG, "a") as log_file:
            for a in alerts:
                log_file.write(a + "\n")

        print(f"\n[+] {len(alerts)} alerts saved to {os.path.basename(ALERT_LOG)}")
    else:
        print("\n[+] Detection complete. No suspicious activity found.")


if __name__ == "__main__":
    run_ids()
