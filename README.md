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
🛠️ Technologies
Programming
- Python
Security & Networking
- Nmap
- Network scanning
- Intrusion detection
- Vulnerability assessment
- Security monitoring
- Log analysis
Python Libraries
- python-dotenv
- python-nmap
- requests
- psutil
- tqdm
- ReportLab
⚙️ Requirements
- Python 3.x
- Nmap
- Operating system with networking tools available
- Appropriate privileges for operations that require elevated access
Install Nmap
On Debian/Kali-based Linux systems:
sudo apt update
sudo apt install nmap

🚀 Installation
1. Clone the repository
git clone https://github.com/dheeraj05-22/CYBER-DEFENCE-SUITE.git
cd CYBER-DEFENCE-SUITE

2. Create a virtual environment
Linux/macOS:
python3 -m venv venv
source venv/bin/activate

Windows:
python -m venv venv
venv\Scripts\activate

3. Install Python dependencies
pip install -r requirements.txt

🔐 Email Scanner Configuration
Email scanning functionality uses environment variables so credentials are not stored directly in source code.
Create a local .env file:
EMAIL_IMAP_HOST=your-imap-server
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-password

EMAIL_FOLDER=INBOX
EMAIL_POLL_INTERVAL=60
EMAIL_FETCH_LIMIT=20

Important
Never commit your .env file.
The repository is configured to ignore environment files.
▶️ Usage
Start the application with:
python main.py

The application provides an interactive terminal menu for accessing the different security modules.
Example workflow
Cyber Defence Suite
        │
        ├── System Information
        ├── Network Scanner
        │      ├── Local Network
        │      ├── Custom Range
        │      ├── External Server
        │      └── Ultra / Full Port Scan
        │
        ├── Vulnerability Scanner
        ├── Offline IDS
        └── Phishing / Email Security

🧪 Testing
The project includes a basic live IDS test script:
python tests/test_live_ids.py

The test uses the loopback interface for local monitoring.
📄 Reports
The application can generate scan-related reports during runtime.
Generated reports and runtime output are intentionally excluded from version control to avoid publishing environment-specific scan results.
🔒 Security Considerations
Some components may require:
- Administrator/root privileges
- Access to local network interfaces
- Nmap installation
- Network access
- Email configuration for IMAP-based scanning
Use the toolkit only against authorized targets.
🎯 Project Goals
The project was developed as a hands-on cybersecurity learning project to explore:
- Python programming for cybersecurity
- Network reconnaissance
- Vulnerability assessment
- Intrusion detection
- Security monitoring
- Log analysis
- Email security
- Modular software design
👨‍💻 Author
Dheeraj Reddy Poreddy
Cybersecurity Graduate | Python | Linux | AWS | Network Security | Security Monitoring
GitHub:
https://github.com/dheeraj05-22
LinkedIn:
https://linkedin.com/in/deeraj-reddy-poreddy-722731268

