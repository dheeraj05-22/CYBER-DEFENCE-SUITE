# 🛡️ Cyber Defence Suite

A modular, terminal-based Python cybersecurity toolkit designed for security assessment, network analysis, vulnerability scanning, intrusion detection, email security analysis, phishing simulation, and security monitoring.

> ⚠️ **Responsible Use:** This project is intended for authorized security testing, defensive research, lab environments, and educational purposes. Only scan systems and networks that you own or have explicit permission to test.

---

## 📌 Overview

Cyber Defence Suite brings multiple cybersecurity capabilities together through an interactive command-line interface.

The project is organized into separate modules so that individual security functions can be developed, tested, and extended independently.

### Core Capabilities

- 🖥️ System information gathering
- 🌐 Network scanning
- 🔎 Vulnerability scanning
- 🚨 Intrusion detection
- 📧 Email security analysis
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
- Full / Ultra port scanning
- Structured scan output
- PDF report generation

The network scanner uses Nmap-based scanning functionality.

### 🔎 Vulnerability Scanner

Provides vulnerability-oriented checks against a specified target using the project's scanning logic and supporting HTTP/network functionality.

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

---

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

Before running the project, make sure you have:

- Python 3.x
- Nmap
- Required Python dependencies
- Network access for network-based features
- Appropriate privileges for operations that require elevated access

### Install Nmap

On Debian/Kali-based Linux systems:

```bash
sudo apt update
sudo apt install nmap
```

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/dheeraj05-22/CYBER-DEFENCE-SUITE.git
cd CYBER-DEFENCE-SUITE
```

### 2. Create a Virtual Environment

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## 🔐 Email Scanner Configuration

The email security module uses environment variables so that email credentials are not stored directly in the source code.

Create a local `.env` file in the project root:

```env
EMAIL_IMAP_HOST=your-imap-server
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-password

EMAIL_FOLDER=INBOX
EMAIL_POLL_INTERVAL=60
EMAIL_FETCH_LIMIT=20
```

### Important

Never commit your `.env` file.

Environment files are excluded through `.gitignore`.

---

## ▶️ Usage

Start the application with:

```bash
python main.py
```

The application provides an interactive terminal menu for accessing the different security modules.

### Example Workflow

```text
Cyber Defence Suite
        │
        ├── System Information
        │
        ├── Network Scanner
        │      ├── Local Network
        │      ├── Custom Range
        │      ├── External Server
        │      └── Ultra / Full Port Scan
        │
        ├── Vulnerability Scanner
        │
        ├── Offline IDS
        │
        └── Phishing / Email Security
```

---

## 🧪 Testing

The project includes a basic live IDS test script.

Run:

```bash
python tests/test_live_ids.py
```

The test uses the loopback interface for local monitoring.

---

## 📄 Reports

The application can generate scan-related reports during runtime.

Generated reports and runtime output are intentionally excluded from version control to avoid publishing environment-specific scan results.

---

## 🔒 Security Considerations

Some components may require:

- Administrator/root privileges
- Access to local network interfaces
- Nmap installation
- Network access
- Email configuration for IMAP-based scanning

Use the toolkit only against systems and networks that you own or have explicit permission to assess.

---

## 🎯 Project Goals

This project was developed as a hands-on cybersecurity learning project to explore:

- Python programming for cybersecurity
- Network reconnaissance
- Vulnerability assessment
- Intrusion detection
- Security monitoring
- Log analysis
- Email security
- Modular software design

---

## 📚 Learning Outcomes

Through this project, I explored practical concepts including:

- Developing modular Python security tools
- Working with network scanning tools
- Collecting and analyzing security-related events
- Building signature-based detection logic
- Working with Linux and network monitoring concepts
- Managing configuration through environment variables
- Generating structured security reports
- Organizing a multi-module cybersecurity project

---

## 👨‍💻 Author

**Dheeraj Reddy Poreddy**

Cybersecurity Graduate | Python | Linux | AWS | Network Security | Security Monitoring

**GitHub:**  
https://github.com/dheeraj05-22

**LinkedIn:**  
https://linkedin.com/in/deeraj-reddy-poreddy-722731268

---

## ⚠️ Disclaimer

This project is intended for educational, defensive, and authorized security assessment purposes only.

The author is not responsible for misuse, unauthorized access, or damage caused by the use of this toolkit.
