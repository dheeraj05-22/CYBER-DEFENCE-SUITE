import os
import time
import shutil
import socket
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, deque

from . import ids_detector

# Try to import scapy for live packet capture
try:
    from scapy.all import sniff, Raw, IP, IPv6, TCP, UDP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Port-scan detection tuning ---
SCAN_WINDOW_SEC = 10
SYN_THRESHOLD = 20
FIN_THRESHOLD = 15
NULL_THRESHOLD = 15
XMAS_THRESHOLD = 15
RE_ALERT_COOLDOWN = 30

_scan_state = defaultdict(lambda: deque())
_last_scan_alert = {}

_fake_listener_started = False
FAKE_LISTENER_PORT = 9898


def _play_alert_sound():
    try:
        print("\a", end="", flush=True)
        sound_players = ["paplay", "aplay"]
        sound_files = [
            "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga",
            "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga",
        ]
        for player in sound_players:
            if shutil.which(player):
                for sf in sound_files:
                    if os.path.exists(sf):
                        subprocess.Popen([player, sf],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                        return
    except:
        pass


def _log_alert(message: str):
    with open(ids_detector.ALERT_LOG, "a") as f:
        f.write(message + "\n")


def _start_fake_listener(signatures):
    """Start hidden TCP listener so echo | nc works without manual listener."""
    global _fake_listener_started
    if _fake_listener_started:
        return
    _fake_listener_started = True

    def listener():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", FAKE_LISTENER_PORT))
        sock.listen(5)
        print(f"[+] Fake IDS listener active on port {FAKE_LISTENER_PORT}")

        while True:
            try:
                conn, addr = sock.accept()
                data = conn.recv(4096).decode(errors="ignore")
                if data:
                    _inspect_payload(f"{addr[0]} -> IDS: {data}", signatures)
                conn.close()
            except:
                pass

    threading.Thread(target=listener, daemon=True).start()


def _inspect_payload(payload: str, signatures):
    if not payload:
        return
    lower_line = payload.lower()
    for sig in signatures:
        if sig in lower_line:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = f"[{timestamp}] LIVE ALERT: '{sig}' matched in traffic: {payload[:200]}"
            print(alert)
            _log_alert(alert)
            _play_alert_sound()


def _extract_ip_tcp(packet):
    ip_layer = None
    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 in packet:
        ip_layer = packet[IPv6]

    if ip_layer is None or TCP not in packet:
        return None, None, None, None

    tcp = packet[TCP]
    return ip_layer.src, ip_layer.dst, int(tcp.dport), int(tcp.flags)


def _analyze_port_scan(packet):
    src, dst, dport, flags = _extract_ip_tcp(packet)
    if src is None:
        return

    now = time.time()
    scan_type = None

    if flags == 0x02:
        scan_type = "SYN"
    elif flags == 0x01:
        scan_type = "FIN"
    elif flags == 0x00:
        scan_type = "NULL"
    elif flags & 0x29 == 0x29:
        scan_type = "XMAS"

    if not scan_type:
        return

    key = (src, dst, scan_type)
    dq = _scan_state[key]
    dq.append((now, dport))

    while dq and (now - dq[0][0] > SCAN_WINDOW_SEC):
        dq.popleft()

    unique_ports = {p for (_, p) in dq}
    threshold = {
        "SYN": SYN_THRESHOLD,
        "FIN": FIN_THRESHOLD,
        "NULL": NULL_THRESHOLD,
        "XMAS": XMAS_THRESHOLD,
    }[scan_type]

    if len(unique_ports) >= threshold:
        last_alert = _last_scan_alert.get(key, 0)
        if now - last_alert >= RE_ALERT_COOLDOWN:
            _last_scan_alert[key] = now
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = (
                f"[{timestamp}] LIVE ALERT (PORT SCAN): "
                f"Possible Nmap {scan_type} scan from {src} to {dst} - "
                f"{len(unique_ports)} ports probed"
            )
            print(alert)
            _log_alert(alert)
            _play_alert_sound()


def _packet_callback(packet, signatures):
    payload_pieces = []

    try:
        if IP in packet:
            ip = packet[IP]
        elif IPv6 in packet:
            ip = packet[IPv6]
        else:
            ip = None

        if ip:
            payload_pieces.append(f"{ip.src} -> {ip.dst} (TCP)")
    except:
        pass

    try:
        if Raw in packet:
            payload_pieces.append(packet[Raw].load.decode(errors="ignore"))
    except:
        pass

    payload = " | ".join(payload_pieces)
    _inspect_payload(payload, signatures)

    try:
        _analyze_port_scan(packet)
    except:
        pass


def start_realtime_monitor(interface=None, include_all=True):
    if not SCAPY_AVAILABLE:
        print("[!] Scapy missing. Install inside venv: pip install scapy")
        return

    signatures = ids_detector.load_signatures()

    print("\n[+] Starting LIVE IDS Monitor...")
    _start_fake_listener(signatures)
    print(f"[+] Fake listener active on port {FAKE_LISTENER_PORT}")
    print(f"[+] Interface: {interface or 'ALL'}")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        sniff(iface=interface,
              prn=lambda pkt: _packet_callback(pkt, signatures),
              store=False)
    except PermissionError:
        print("[!] Run as sudo.")
    except KeyboardInterrupt:
        print("\n[+] Live IDS stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")
