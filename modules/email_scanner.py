# modules/email_scanner.py

import os
import imaplib
import email as pyemail
from email.header import decode_header
import re
import csv
import time
import threading
import socket
from datetime import datetime
from urllib.parse import urlparse

from . import ids_detector  # reuse your signature loader and alert logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
RESULT_CSV = os.path.join(REPORTS_DIR, "email_scan_results.csv")

# Small heuristics (tweakable)
SUSPICIOUS_URL_TLDS = {".xyz", ".top", ".info", ".pw", ".ru", ".cc"}
URGENCY_WORDS = {"urgent", "verify", "immediately", "action required", "verify now", "suspend"}

# Default IMAP settings you can override when calling functions
DEFAULT_IMAP_PORT = 993
DEFAULT_FOLDER = "INBOX"


def _init_csv():
    header = [
        "timestamp", "from", "to", "subject", "has_urls", "suspicious_urls",
        "signature_matches", "heuristic_score", "final_label", "notes"
    ]
    if not os.path.exists(RESULT_CSV):
        with open(RESULT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def _save_row(row: dict):
    _init_csv()
    with open(RESULT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            row.get("timestamp"),
            row.get("from"),
            row.get("to"),
            row.get("subject"),
            row.get("has_urls"),
            ";".join(row.get("suspicious_urls", [])),
            ";".join(row.get("signature_matches", [])),
            row.get("heuristic_score"),
            row.get("final_label"),
            row.get("notes", ""),
        ])


def _decode_header_part(value):
    """
    Decode an email header part safely.
    """
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for bytes_part, encoding in parts:
        if isinstance(bytes_part, bytes):
            try:
                out.append(bytes_part.decode(encoding or "utf-8", errors="ignore"))
            except Exception:
                out.append(bytes_part.decode("utf-8", errors="ignore"))
        else:
            out.append(bytes_part)
    return "".join(out)


def _get_text_from_msg(msg):
    """
    Extract readable text from an email.message.Message (fallback plain/text)
    """
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                    parts.append(text)
                except Exception:
                    pass
        return "\n".join(parts).strip()
    else:
        try:
            return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
        except Exception:
            return ""


def _extract_urls(text):
    # basic URL regex (works for most cases). We won't fetch them, only parse domain/TLD.
    url_pattern = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
    return url_pattern.findall(text or "")


def _is_suspicious_url(url):
    try:
        p = urlparse(url)
        host = p.hostname or ""
        for t in SUSPICIOUS_URL_TLDS:
            if host.endswith(t):
                return True
        # suspicious if many subdomains or long random-looking host
        if host.count(".") >= 4:
            return True
    except Exception:
        return True
    return False


def _heuristic_scan(subject, sender, body, signatures):
    """
    Return (heuristic_score:int, signature_matches:list, suspicious_urls:list)
    Lower-level scoring: increase score for urgent words, suspicious URL, signature matches.
    """
    score = 0
    sig_matches = []

    text_to_check = " ".join([subject or "", sender or "", body or ""]).lower()
    for s in signatures:
        if s in text_to_check:
            sig_matches.append(s)
            score += 5

    # urgency words
    lowered = (subject or "").lower() + " " + (body or "").lower()
    for w in URGENCY_WORDS:
        if w in lowered:
            score += 2

    urls = _extract_urls(body)
    suspicious_urls = []
    if urls:
        score += 1
        for u in urls:
            if _is_suspicious_url(u):
                suspicious_urls.append(u)
                score += 3

    # mismatched sender/domain heuristic
    # parse sender like "Name <email@domain.com>"
    sender_email = ""
    try:
        if "<" in sender and ">" in sender:
            sender_email = sender.split("<")[-1].split(">")[0].strip()
        else:
            sender_email = sender.strip()
    except Exception:
        sender_email = sender

    # if the display name mentions a major vendor but the domain doesn't match, suspicious
    display_name = sender.split("<")[0] if "<" in sender else sender
    if "amazon" in display_name.lower() and "amazon" not in (sender_email or "").lower():
        score += 3

    return score, sig_matches, suspicious_urls


def scan_mailbox_once(imap_host: str, username: str, password: str,
                      folder: str = DEFAULT_FOLDER, port: int = DEFAULT_IMAP_PORT,
                      search_unseen: bool = True, mark_seen: bool = True, limit: int = 20,
                      use_ssl: bool = True, debug: bool = False):
    """
    Connect to IMAP and scan the latest unseen emails (or recent messages).
    Returns list of scanned items.
    - imap_host: imap.example.com (or 'imap.gmail.com')
    - username/password: credentials (use app-passwords or OAuth tokens where possible)
    - search_unseen: only process UNSEEN emails (recommended)
    - mark_seen: mark processed emails as seen to avoid reprocessing
    - limit: max messages to fetch per run
    """
    results = []
    signatures = ids_detector.load_signatures()

    if use_ssl:
        M = imaplib.IMAP4_SSL(imap_host, port=port, timeout=30)
    else:
        M = imaplib.IMAP4(imap_host, port=port, timeout=30)

    try:
        M.login(username, password)
    except imaplib.IMAP4.error as e:
        raise RuntimeError(f"IMAP login failed: {e}")

    try:
        M.select(folder)
        if search_unseen:
            typ, data = M.search(None, "(UNSEEN)")
        else:
            typ, data = M.search(None, "ALL")

        if typ != "OK":
            return results

        msg_ids = data[0].split()
        # limit to last N
        msg_ids = msg_ids[-limit:]

        for mid in msg_ids:
            try:
                typ, msg_data = M.fetch(mid, "(RFC822)")
                if typ != "OK":
                    continue
                raw = msg_data[0][1]
                msg = pyemail.message_from_bytes(raw)
                subject = _decode_header_part(msg.get("Subject", ""))
                sender = _decode_header_part(msg.get("From", ""))
                to = _decode_header_part(msg.get("To", ""))
                body = _get_text_from_msg(msg)

                # run heuristics and signature checks
                score, sig_matches, suspicious_urls = _heuristic_scan(subject, sender, body, signatures)

                final_label = "legit"
                notes = []
                if sig_matches:
                    final_label = "phishing"
                    notes.append("signature-match")
                if suspicious_urls:
                    final_label = "phishing"
                    notes.append("suspicious-url")
                if score >= 5:
                    final_label = "phishing"
                    notes.append("heuristic-score")

                timestamp = datetime.now().isoformat()
                row = {
                    "timestamp": timestamp,
                    "from": sender,
                    "to": to,
                    "subject": subject,
                    "has_urls": bool(suspicious_urls or _extract_urls(body)),
                    "suspicious_urls": suspicious_urls,
                    "signature_matches": sig_matches,
                    "heuristic_score": score,
                    "final_label": final_label,
                    "notes": ";".join(notes),
                }
                _save_row(row)
                results.append(row)

                # Optionally mark as seen
                if mark_seen:
                    M.store(mid, "+FLAGS", "\\Seen")

                # print / notify
                if final_label == "phishing":
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{ts}] EMAIL ALERT: Possible phishing detected from {sender} - Subject: {subject}")
                elif debug:
                    print(f"[INFO] Scanned email from {sender} -> {final_label} (score {score})")

            except Exception as e:
                # continue on single message errors
                if debug:
                    print("[email_scan] error:", e)
                continue

    finally:
        try:
            M.logout()
        except Exception:
            pass

    return results


def start_email_monitor_background(imap_host: str, username: str, password: str,
                                   folder: str = DEFAULT_FOLDER, interval: int = 60,
                                   **kwargs):
    """
    Start a daemon thread that polls the mailbox every `interval` seconds and scans new mail.
    kwargs forwarded to scan_mailbox_once (mark_seen, search_unseen, etc.)
    """
    def runner():
        while True:
            try:
                scan_mailbox_once(imap_host, username, password, folder=folder, **kwargs)
            except Exception as e:
                # do not crash; print error and continue
                print("[email_monitor] error:", e)
            time.sleep(interval)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    print(f"[+] Email monitor started (poll every {interval}s) for {username}@{imap_host}")
    return t


# NOTE: If you require Gmail OAuth2 (recommended), this module can be extended to
# perform XOAUTH2 login using an access token instead of plain password. For quick testing,
# use app-password (Gmail) or service account tokens for corporate mail.
