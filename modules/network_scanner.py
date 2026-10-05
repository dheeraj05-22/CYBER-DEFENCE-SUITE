# modules/network_scanner.py

import subprocess
import socket
import ipaddress
import shutil
import os
import datetime
import json
import csv
import reportlab
import threading
import time
import sys
import re
from collections import defaultdict

# Optional imports
try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False

NMAP_BIN = shutil.which("nmap") or "nmap"  # rely on PATH

# Simple cache for MAC vendor lookups
_MAC_VENDOR_CACHE = {}

# Friendly heuristics mapping for vendors -> friendly device name types
VENDOR_DEVICE_HINTS = {
    "Apple": "Apple device (iPhone/Mac/iPad)",
    "Samsung": "Samsung device (Android phone/tablet/TV)",
    "Xiaomi": "Xiaomi device (phone/IoT)",
    "TP-LINK": "TP-Link (router / Wi-Fi adapter)",
    "Realtek": "Network chip (PC/IoT)",
    "Intel": "PC/Laptop (Intel NIC)",
    "Broadcom": "Network chipset (phones/routers)",
    "Cisco": "Networking gear (router/switch)",
    "Espressif": "IoT device (ESP8266/ESP32)",
}

# ----------------- Utilities -----------------
def _ensure_nmap():
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found. Install with: sudo apt install nmap")

def get_real_local_ip():
    """Return a LAN IP or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip.startswith("127.") or ip == "0.0.0.0":
            raise Exception("loopback")
        return ip
    except Exception:
        # fallback to hostname
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

def ensure_reports_dir():
    base = os.path.join(os.getcwd(), "reports")
    os.makedirs(base, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(base, f"network_scan_{ts}")
    os.makedirs(path, exist_ok=True)
    return path

def mac_vendor_lookup(mac):
    """Lookup MAC vendor using cache and public API (if requests available)."""
    if not mac:
        return "Unknown"
    mac_key = mac.upper()
    if mac_key in _MAC_VENDOR_CACHE:
        return _MAC_VENDOR_CACHE[mac_key]
    vendor = "Unknown"
    # quick OUI match using first 3 bytes
    oui = mac_key.replace(":", "")[:6]
    # try macvendors API if requests available
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
            if r.status_code == 200 and r.text.strip():
                vendor = r.text.strip()
        except Exception:
            vendor = "Unknown"
    _MAC_VENDOR_CACHE[mac_key] = vendor
    return vendor

def mac_to_friendly(vendor):
    """Map vendor name to friendly device name using heuristics."""
    if not vendor:
        return "Unknown"
    for k, v in VENDOR_DEVICE_HINTS.items():
        if k.lower() in vendor.lower():
            return v
    return vendor

def parse_arp_table():
    """Parse local ARP table using 'ip neigh' or 'arp -n' fallback."""
    entries = {}
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
        # lines: 10.2.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = None
                if "lladdr" in parts:
                    try:
                        i = parts.index("lladdr")
                        mac = parts[i+1]
                    except ValueError:
                        mac = None
                entries[ip] = mac or ""
        return entries
    except Exception:
        # fallback to arp -n
        try:
            out = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
            # parse lines with IP and HWaddress
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", line)
                if m:
                    ip, mac = m.groups()
                    entries[ip] = mac
            return entries
        except Exception:
            return entries

# ----------------- Discovery & scans -----------------
def scan_my_network():
    local_ip = get_real_local_ip()
    if not local_ip:
        print("❌ Could not determine a valid local IP. Are you connected?")
        return
    octets = local_ip.split(".")
    if len(octets) == 4:
        prefix = ".".join(octets[:3]) + ".0/24"
    else:
        print("❌ Unexpected IP format:", local_ip)
        return
    print(f"\n🔍 Detected Local Network: {prefix} (based on {local_ip})")
    scan_custom_range(prefix)

def scan_custom_range(target_range):
    _ensure_nmap()
    print(f"\n🚀 Scanning IP Range: {target_range}")
    try:
        ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        print("❌ Invalid network.")
        return
    # use nmap -sn for discovery
    try:
        cmd = ["nmap", "-sn", target_range]
        print("Using nmap for ping/ARP discovery...")
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        print(out)
        # attempt minimal structured parsing for hosts lines
        hosts = []
        for line in out.splitlines():
            if line.startswith("Nmap scan report for"):
                # line: Nmap scan report for 192.168.1.1
                parts = line.split()
                ip = parts[-1]
                hosts.append(ip)
        if not hosts:
            print("No hosts found.")
            return
        # print nicer
        for h in hosts:
            print(f"Host: {h} () - State: up")
    except subprocess.CalledProcessError as e:
        print("❌ nmap error:", e.output)
    except FileNotFoundError:
        print("❌ nmap not installed. sudo apt install nmap")

def scan_external_server(target):
    _ensure_nmap()
    print(f"\n🌍 Scanning External Server: {target}")
    try:
        cmd = ["nmap", "-Pn", target]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        print(out)
    except subprocess.CalledProcessError as e:
        print("❌ nmap error:", e.output)
    except FileNotFoundError:
        print("❌ nmap not found. Install it.")

# ----------------- Ultra / Full Port Scan -----------------
def full_port_scan(target):
    """
    Ultra full port scan (Top1000 / All / Aggressive)
    - runs nmap
    - parses some key outputs
    - collects banners, MAC vendor and builds report structure
    """
    _ensure_nmap()
    print(f"\n⚡ Ultra Full Port Scan on: {target}")
    print("1) Top 1000 ports (fast)")
    print("2) All 65535 ports (slow)")
    print("3) Aggressive (OS detection + scripts)")
    choice = input("👉 Enter choice (1-3): ").strip()
    if choice == "1":
        args = ["--top-ports", "1000", "-sV"]
        desc = "Top 1000"
    elif choice == "2":
        args = ["-p", "1-65535", "-sV"]
        desc = "All ports"
    elif choice == "3":
        args = ["-A", "-sV", "--script", "default,safe"]
        desc = "Aggressive"
    else:
        print("Invalid choice.")
        return

    # timing / stealth
    print("\nChoose timing:")
    print("1) T3 (balanced)")
    print("2) T4 (faster)")
    print("3) T5 (fastest)")
    t = input("👉 (1-3): ").strip()
    timing = "-T3"
    if t == "2":
        timing = "-T4"
    elif t == "3":
        timing = "-T5"

    # save option
    save = input("Save results to files? (y/N): ").strip().lower() == "y"
    out_base = None
    if save:
        out_dir = ensure_reports_dir()
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        out_base = os.path.join(out_dir, f"ultrascan_{safe_target}_{ts}")
        print("Saving:", out_base + ".txt / .xml")

    # build command
    nmap_cmd = ["nmap", "-Pn", timing] + args + [target]
    if out_base:
        nmap_cmd += ["-oN", out_base + ".txt", "-oX", out_base + ".xml"]

    print("Running:", " ".join(nmap_cmd))
    try:
        p = subprocess.run(nmap_cmd, capture_output=True, text=True)
        stdout = p.stdout or ""
        stderr = p.stderr or ""
        if p.returncode != 0:
            print("nmap returned non-zero code. stderr:")
            print(stderr)
        # minimal parse: look for host lines and ports
        scan_results = {
            "target": target, "timestamp": datetime.datetime.now().isoformat(), "hosts": []
        }

        # If -oX saved, we could parse XML. For now parse stdout for hosts + ports (best-effort)
        # find blocks "Nmap scan report for <ip>" and parse following lines until blank
        lines = stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("Nmap scan report for"):
                ip = line.split()[-1]
                host_entry = {"ip": ip, "hostname": "", "ports": [], "mac": "", "vendor": "", "os": ""}
                j = i + 1
                # scan following lines for 'PORT' header and 'MAC Address' or 'OS details'
                while j < len(lines) and lines[j].strip():
                    l = lines[j].strip()
                    if l.startswith("PORT"):
                        # ports follow until blank line or another header
                        k = j + 1
                        while k < len(lines) and lines[k].strip() and not lines[k].startswith("Service Info"):
                            portline = lines[k].strip()
                            m = re.match(r"(\d+)\/(tcp|udp)\s+(\w+)\s+(.+)", portline)
                            if m:
                                portno, proto, state, svc = m.groups()
                                host_entry["ports"].append({"port": int(portno), "proto": proto, "state": state, "service": svc})
                            k += 1
                        j = k
                        continue
                    if "MAC Address:" in l:
                        # format: MAC Address: 00:11:22:33:44:55 (Vendor)
                        try:
                            macpart = l.split("MAC Address:")[1].strip()
                            macaddr = macpart.split()[0]
                            vendor = " ".join(macpart.split("(")[1:]).rstrip(")") if "(" in macpart else ""
                            host_entry["mac"] = macaddr
                            if vendor:
                                host_entry["vendor"] = vendor
                            else:
                                host_entry["vendor"] = mac_vendor_lookup(macaddr)
                        except Exception:
                            pass
                    if l.lower().startswith("os details") or l.startswith("Aggressive OS guesses"):
                        host_entry["os"] = l
                    j += 1
                scan_results["hosts"].append(host_entry)
                i = j
                continue
            i += 1

        # show brief summary
        summarize_scan(scan_results)

        # if saved, write JSON too
        if out_base:
            jsonpath = out_base + ".json"
            try:
                with open(jsonpath, "w", encoding="utf-8") as jf:
                    json.dump(scan_results, jf, indent=2)
                print("Saved JSON:", jsonpath)
            except Exception as e:
                print("Failed to save JSON:", e)

        # offer to save CSV / PDF
        offer_save_options(scan_results, out_base and os.path.dirname(out_base) or ensure_reports_dir())

    except FileNotFoundError:
        print("nmap not installed. sudo apt install nmap")
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")

def summarize_scan(scan_results):
    hosts = scan_results.get("hosts", [])
    print("\n=== Scan Summary ===")
    print("Target:", scan_results.get("target"))
    print("Hosts found:", len(hosts))
    for h in hosts:
        ip = h.get("ip")
        mac = h.get("mac","")
        vendor = h.get("vendor","")
        osinfo = h.get("os","")
        print(f"- {ip}  MAC:{mac} Vendor:{vendor} OS:{osinfo}")
        open_ports = [str(p["port"]) for p in h.get("ports", []) if p.get("state") == "open"]
        if open_ports:
            print("  Open ports:", ", ".join(open_ports[:10]) + ("..." if len(open_ports)>10 else ""))

def offer_save_options(scan_results, outdir):
    print("\nSave options:")
    print("1) CSV")
    print("2) JSON")
    print("3) PDF (requires reportlab)")
    print("4) All (CSV+JSON+PDF)")
    print("5) Skip")
    ch = input("👉 Choose (1-5): ").strip()
    if ch not in ("1","2","3","4"):
        print("Skipping save.")
        return
    os.makedirs(outdir, exist_ok=True)
    if ch in ("1","4"):
        csvpath = os.path.join(outdir, "network_scan.csv")
        try:
            with open(csvpath, "w", newline='', encoding="utf-8") as cf:
                w = csv.writer(cf)
                w.writerow(["ip","mac","vendor","os","open_ports_sample"])
                for h in scan_results.get("hosts", []):
                    ports = [str(p["port"]) for p in h.get("ports", []) if p.get("state") == "open"]
                    w.writerow([h.get("ip",""), h.get("mac",""), h.get("vendor",""), h.get("os",""), ",".join(ports[:10])])
            print("Saved CSV →", csvpath)
        except Exception as e:
            print("CSV save failed:", e)
    if ch in ("2","4"):
        jsonpath = os.path.join(outdir, "network_scan.json")
        try:
            with open(jsonpath, "w", encoding="utf-8") as jf:
                json.dump(scan_results, jf, indent=2)
            print("Saved JSON →", jsonpath)
        except Exception as e:
            print("JSON save failed:", e)
    if ch in ("3","4"):
        if not HAS_REPORTLAB:
            print("ReportLab not installed. pip install reportlab")
        else:
            pdfpath = os.path.join(outdir, "network_scan.pdf")
            try:
                create_pdf_report(scan_results, pdfpath)
                print("Saved PDF →", pdfpath)
            except Exception as e:
                print("PDF save failed:", e)

def create_pdf_report(scan_results, pdfpath):
    doc = SimpleDocTemplate(pdfpath, pagesize=letter)
    styles = getSampleStyleSheet()
    flow = []
    flow.append(Paragraph("Network Scan Report", styles["Title"]))
    flow.append(Spacer(1,12))
    flow.append(Paragraph(f"Target: {scan_results.get('target')}  Generated: {scan_results.get('timestamp')}", styles["Normal"]))
    flow.append(Spacer(1,12))
    data = [["IP","MAC","Vendor","OS","Open Ports (sample)"]]
    for h in scan_results.get("hosts", []):
        ports = [str(p["port"]) for p in h.get("ports", []) if p.get("state") == "open"]
        data.append([h.get("ip",""), h.get("mac",""), h.get("vendor",""), h.get("os",""), ", ".join(ports[:10])])
    tbl = Table(data, colWidths=[80,120,120,120,120])
    tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0), colors.HexColor("#4f81bd")),
                             ("TEXTCOLOR",(0,0),(-1,0), colors.white),
                             ("GRID",(0,0),(-1,-1), .25, colors.black)]))
    flow.append(tbl)
    flow.append(Spacer(1,12))
    for h in scan_results.get("hosts", []):
        flow.append(Paragraph(f"Host {h.get('ip')}", styles["Heading4"]))
        if not h.get("ports"):
            flow.append(Paragraph("No port detail available (raw nmap output recorded).", styles["Normal"]))
        else:
            d = [["Port","Proto","State","Service","Product","Version"]]
            for p in h.get("ports", []):
                d.append([str(p.get("port","")), p.get("proto",""), p.get("state",""), p.get("service",""), p.get("product",""), p.get("version","")])
            t = Table(d, colWidths=[40,40,40,100,120,80])
            t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.25, colors.grey)]))
            flow.append(t)
        flow.append(Spacer(1,8))
    doc.build(flow)

# ----------------- Real-time monitoring & ARP spoof detection -----------------
class NetworkMonitor:
    def __init__(self, scan_interval=30):
        self.scan_interval = scan_interval
        self._running = False
        self._thread = None
        self.known = {}  # ip -> mac
        self.callbacks = []  # functions to call on events

    def start(self):
        if self._running:
            print("Monitor already running.")
            return
        self._running = True
        self.known = parse_arp_table()
        print("Initial ARP table loaded. Known devices:", len(self.known))
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("Network monitor started.")

    def stop(self):
        if not self._running:
            print("Monitor not running.")
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        print("Network monitor stopped.")

    def _loop(self):
        try:
            while self._running:
                time.sleep(self.scan_interval)
                current = parse_arp_table()
                # detect new/left devices
                new = set(current.keys()) - set(self.known.keys())
                left = set(self.known.keys()) - set(current.keys())
                changed = []
                for ip in current:
                    if ip in self.known and self.known[ip] and current[ip] and self.known[ip] != current[ip]:
                        # mac changed for same IP -> possible ARP spoof/move
                        changed.append((ip, self.known[ip], current[ip]))
                # update known
                self.known = current
                # notify
                for ip in new:
                    print(f"[MONITOR] New device: {ip} MAC:{current[ip]}")
                for ip in left:
                    print(f"[MONITOR] Device left: {ip}")
                for ip, oldmac, newmac in changed:
                    print(f"[ALERT] Possible ARP anomaly: {ip} changed MAC {oldmac} -> {newmac}")
                    # call callbacks
                    for cb in self.callbacks:
                        try:
                            cb(ip, oldmac, newmac)
                        except Exception:
                            pass
        except Exception as e:
            print("Monitor loop error:", e)

_monitor_instance = None

def start_monitor(interval=30):
    global _monitor_instance
    if _monitor_instance and _monitor_instance._running:
        print("Monitor already running.")
        return
    _monitor_instance = NetworkMonitor(scan_interval=interval)
    _monitor_instance.start()

def stop_monitor():
    global _monitor_instance
    if not _monitor_instance:
        print("Monitor is not running.")
        return
    _monitor_instance.stop()
    _monitor_instance = None

# ----------------- ARP spoof detection helper -----------------
def check_for_arp_spoof():
    """Quick ARP table check for duplicate IP mapping to multiple MACs via nmap ARP discovery or local ARP table observation."""
    # Build map ip -> set(mac) from observed ARP table and from nmap -sn with --script arp-poison? (keep simple)
    arp = parse_arp_table()
    reversed_map = defaultdict(set)
    for ip, mac in arp.items():
        if mac:
            reversed_map[ip].add(mac)
    anomalies = []
    # If any IP has more than one MAC in history we'd need history; simple runtime check:
    for ip, macs in reversed_map.items():
        if len(macs) > 1:
            anomalies.append((ip, list(macs)))
    return anomalies

# ----------------- Minimal helper for interactive compatibility -----------------
def interactive_target_selection():
    print("\n=== Network Scanner ===")
    print("1. Scan my local network")
    print("2. Scan a custom IP or range")
    print("3. Scan an external server (like google.com)")
    print("4. ⚡ Full Port Scan (Ultra Recon)")
    print("5. Start Real-time Monitor")
    print("6. Stop Real-time Monitor")
    print("7. Check ARP spoof anomalies")
    print("8. Exit")

    c = input("Select (1-8): ").strip()
    if c == "1":
        return ("normal", ".".join(get_real_local_ip().split(".")[:3]) + ".0/24")
    if c == "2":
        t = input("Enter target IP/range: ").strip()
        return ("normal", t)
    if c == "3":
        d = input("Enter domain/ip: ").strip()
        return ("normal", d)
    if c == "4":
        t = input("Enter target IP/domain for Ultra Scan: ").strip()
        return ("full", t)
    if c == "5":
        start_monitor()
        return (None, None)
    if c == "6":
        stop_monitor()
        return (None, None)
    if c == "7":
        anomalies = check_for_arp_spoof()
        if anomalies:
            print("Anomalies found:", anomalies)
        else:
            print("No ARP anomalies detected (runtime snapshot).")
        return (None, None)
    if c == "8":
        sys.exit(0)
    return (None, None)

# For standalone run
def main():
    while True:
        mode, target = interactive_target_selection()
        if not target:
            continue
        if mode == "full":
            full_port_scan(target)
        else:
            scan_custom_range(target)

if __name__ == "__main__":
    main()
