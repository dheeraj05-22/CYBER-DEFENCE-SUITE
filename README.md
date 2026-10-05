# 🛡️ Cyber Defence Suite

A modular, terminal-based Python cybersecurity toolkit designed for security assessment, network analysis, vulnerability scanning, intrusion detection, phishing analysis, and security monitoring.

> ⚠️ **Responsible Use:** This project is intended for authorized security testing, defensive research, lab environments, and educational purposes. Only scan systems and networks that you own or have explicit permission to test.

---

## 📌 Overview

Cyber Defence Suite brings multiple cybersecurity capabilities together through an interactive command-line interface.

The project is designed around separate modules so that individual security functions can be developed, tested, and extended independently.

### Core capabilities

- 🖥️ System information gathering
- 🌐 Network scanning
- 🔎 Vulnerability scanning
- 🚨 Intrusion detection
- 📧 Email and phishing analysis
- 📊 Security log monitoring
- 🎯 Phishing simulation
- 📄 Security report generation

---

## 🧩 Modules

### 🖥️ System Information

Collects system-level information using Python system and platform utilities.

### 🌐 Network Scanner

Provides network discovery and scanning capabilities, including:

- Local network scanning
- Custom IP/range scanning
- External host/domain scanning
- Full/Ultra port scanning
- Structured scan output
- PDF report generation

Uses Nmap-based scanning functionality.

### 🔎 Vulnerability Scanner

Performs vulnerability-oriented checks against a specified target using the project's scanning logic and supporting HTTP/network functionality.

### 🚨 Intrusion Detection System

Provides IDS functionality for identifying suspicious network activity using signatures and monitored traffic/log data.

The project includes:

- Offline IDS analysis
- Real-time monitoring
- Signature-based detection
- Security alert generation

### 📧 Email Security Scanner

Provides email-analysis functionality using IMAP to inspect messages and identify potentially suspicious or phishing-related content.

Email functionality can be configured through environment variables.

### 🎯 Phishing Simulator

Provides a controlled phishing-awareness simulation component for security education and testing.

### 📊 Log Monitor

Provides real-time security monitoring functionality and integrates with the IDS components for event analysis.

---

## 🏗️ Project Structure

```text
CYBER-DEFENCE-SUITE/
│
├── main.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── modules/
│   ├── __init__.py
│   ├── email_scanner.py
│   ├── ids_detector.py
│   ├── log_monitor.py
│   ├── network_scanner.py
│   ├── phishing_simulator.py
│   ├── signatures.txt
│   ├── system_info.py
│   └── vuln_scanner.py
│
├── utils/
│   ├── __init__.py
│   └── _animations_.py
│
└── tests/
    └── test_live_ids.py
```
## 🛠️ Technologies

### Programming

- Python

### Security & Networking

- Nmap
- Network Scanning
- Intrusion Detection
- Vulnerability Assessment
- Security Monitoring
- Log Analysis

### Python Libraries

- python-dotenv
- python-nmap
- requests
- psutil
- tqdm
- ReportLab

---

## ⚙️ Requirements

- Python 3.x
- Nmap
- Operating system with required networking tools
- Appropriate privileges for operations that require elevated access

### Install Nmap

On Debian/Kali-based Linux systems:

```bash
sudo apt update
sudo apt install nmap
https://linkedin.com/in/deeraj-reddy-poreddy-722731268

