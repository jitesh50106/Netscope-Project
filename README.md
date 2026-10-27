# NetScope PRO // Enterprise Network Scanner & Security Posture Auditor

A full-stack, enterprise-grade network scanner, reconnaissance engine, and defensive compliance auditor. NetScope audits IPv4 networks to identify active hosts, inspect open ports (up to all 65,535 ports), fingerprint software and operating system versions, and evaluate host security postures with actionable remediation guidance.

NetScope features an interactive **Cybersecurity Dark-Mode Web Dashboard** with real-time Server-Sent Events (SSE) telemetry and an industrial **Command-Line (CLI) Mode**.

---

## 🌟 Key Capabilities

### 1. Multi-Stage Host Discovery & Fingerprinting
- **ICMP Ping Sweep**: Fast round-trip latency measurement and alive checks.
- **Passive OS Fingerprinting**: Heuristic analysis using IP Time-To-Live (TTL) and banner feedback:
  - `TTL <= 64`: Linux / Unix / macOS / Android
  - `TTL <= 128`: Microsoft Windows (Windows 10/11 / Windows Server)
  - `TTL <= 255`: Network Appliances / Cisco IOS / BSD
- **Hardware MAC & Vendor Resolution**: Windows ARP table inspection identifying physical & virtual NIC manufacturers (Apple, VMware, Hyper-V, Cisco, TP-Link, Dell, etc.).
- **Reverse DNS**: Automatic reverse IP-to-hostname resolution.

### 2. Comprehensive Port Coverage & Presets
- **Top 20 Ports (Fast)**: Immediate discovery of primary remote and web ports.
- **Top 100 Common**: Standard network reconnaissance.
- **Top 1000 (Industry Standard)**: Comprehensive port coverage matching industry-standard security scanners.
- **Full 65,535 Ports Range**: Complete audit across all potential high and dynamic ports.
- **Web & Databases**: Targets HTTP/HTTPS, MSSQL, Oracle, MySQL, Postgres, Redis, MongoDB, Elasticsearch.
- **Custom Ports & Ranges**: Flexible port syntax (e.g. `21,22,80,443,8000-8080`).

### 3. Software Version Fingerprinting
- **HTTP / HTTPS**: Deep inspection of `Server`, `X-Powered-By`, and status codes (Nginx, Apache, Microsoft-IIS, Caddy, Cloudflare, etc.).
- **SSH**: Protocol and distribution parsing (e.g., `OpenSSH 8.9p1 on Ubuntu`, `Dropbear SSH on Embedded Linux`).
- **FTP / Mail / Databases**: Version banner extraction for `vsftpd`, `ProFTPD`, `MariaDB`, `MySQL`, and `Redis`.

### 4. Security Scorecard & Defensive Remediation
- **Host Posture Scoring**: Each host receives a security score from `0 to 100` and an overall letter grade (`A+`, `A`, `B`, `C`, `D`, `F`).
- **Risk Categorization**: Flags cleartext management protocols (Telnet `23`, FTP `21`), exposed administrative consoles (RDP `3389`, VNC `5900`), and accessible databases (Redis `6379`, MongoDB `27017`, MySQL `3306`).
- **Actionable Remediation**: Provides hardening advisories and maps findings to security standards (**CIS Benchmarks**, **NIST SP 800-53**, **OWASP**, **PCI-DSS**).

### 5. Multi-Format Reporting
- **Executive HTML Audit Report**: Clean, self-contained printable audit report with executive scorecard and remediation tables.
- **CSV Export**: Spreadsheet-compatible data export.
- **JSON Export**: Complete machine-readable data dump for SIEM or automated pipelines.

---

## 📁 Project Architecture

```
NetScope/
├── scanner/
│   ├── __init__.py
│   ├── models.py            # Pydantic schemas (HostResult, PortResult, ScanJobConfig, etc.)
│   ├── target_parser.py     # IP, CIDR (/24), range (10-20), Top 1000 and 65,535 port parser
│   ├── host_discovery.py    # Multi-threaded ping sweep, TTL OS detection, ARP lookup, posture scoring
│   ├── port_scanner.py      # Concurrent TCP connect scanner with top port profiles
│   ├── banner_grabber.py    # Service/version fingerprinting & defensive remediation guidance
│   ├── engine.py            # Background audit engine orchestrator with live SSE streaming
│   └── exporters.py         # CSV, JSON, and Executive HTML Audit Report generators
├── server/
│   └── app.py               # FastAPI server with REST & SSE streaming endpoints
├── static/
│   ├── index.html           # Dark-mode Cyber Recon Dashboard UI
│   ├── style.css            # Modern glassmorphism styling, glowing radar, and metrics grid
│   └── app.js               # Frontend state management, SSE listeners, and interactive UI
├── tests/
│   ├── test_target_parser.py# Target and port validation test suite (Top 1000, 65535 ports)
│   ├── test_scanner.py      # Banner grabbing, versioning, posture scorecard, and exporters
│   └── test_api.py          # FastAPI REST endpoints & HTML audit export tests
├── run.py                   # Unified launcher (starts Web UI or runs directly in CLI)
├── requirements.txt         # Project dependencies
└── README.md
```

---

## 🚀 Getting Started

### 1. Requirements
- Python 3.10+ (Tested on Python 3.13)
- Windows / Linux / macOS

### 2. Setup Virtual Environment

```powershell
# Create virtual environment
python -m venv .venv

# Activate environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

## 💻 How to Run

### Mode 1: Interactive Web Dashboard (Recommended)

Start the local web dashboard:

```powershell
python run.py
```

The browser will open to:
👉 **http://127.0.0.1:8000**

- Use **Quick: Local Subnet** or **Localhost** to populate the target.
- Select your port audit profile (**Top 20**, **Top 100**, **Top 1000 Standard**, or **Full 65,535 Ports**).
- Click **⚡ INITIATE AUDIT** to observe live host discovery, software versioning, and posture grading.
- Export results via **📄 Executive Audit Report**, **📥 CSV**, or **💾 JSON**.

---

### Mode 2: Command-Line (CLI) Audit Mode

Audit a single host with the **Top 1000** ports profile:
```powershell
python run.py scan 127.0.0.1 -p top1000
```

Audit an entire subnet and generate an **Executive HTML Report**:
```powershell
python run.py scan 192.168.1.0/24 -p top100 -o audit_report.html
```

Audit a custom IP range and save findings to CSV:
```powershell
python run.py scan 10.0.0.1-10.0.0.25 -p 21,22,80,443,3389,8000-8080 -o network_findings.csv
```

---

## 🧪 Automated Test Verification

All 26 automated unit tests verify target parsing, top 1000 ports, version extraction, security scoring, exporters, and API routes:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

```
Ran 26 tests in 0.539s
OK
```

---

## 🛡️ Ethical and Legal Notice

This software is developed strictly for authorized security auditing, defensive system administration, and educational research. Only scan networks and hosts that you own or have explicit written authorization to assess.
