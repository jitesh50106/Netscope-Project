# SQL Injection Detection, Exploitation & Mitigation Platform
### Academic Minor Project: Computer Science & Cybersecurity

[![Standard: CWE-89](https://img.shields.io/badge/CWE-89-red.svg)](https://cwe.mitre.org/data/definitions/89.html)
[![OWASP: A03:2021](https://img.shields.io/badge/OWASP-A03%3A2021--Injection-orange.svg)](https://owasp.org/Top10/A03_2021-Injection/)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green.svg)](https://fastapi.tiangolo.com)
[![Tests: 15 Passed](https://img.shields.io/badge/Tests-15%20Passed-brightgreen.svg)]()

---

## 🌟 Overview

This project is a complete, self-contained educational security research platform designed for an academic **Minor Project** titled:  
**“Detection, Exploitation, and Mitigation of SQL Injection Vulnerabilities in Web Applications”**.

It provides:
1. **Interactive Dual-State Web Application**: Side-by-side comparison of vulnerable dynamic SQL queries vs. secure parameterized queries across realistic application endpoints (Authentication, Catalog Search, and User Profile).
2. **Real-Time SQL Lexer & Token Differential Engine**: Visualizes how database parsers interpret SQL queries at the lexical token level and demonstrates how injection modifies the Abstract Syntax Tree (AST).
3. **Automated SAST Code Scanner**: A Python Abstract Syntax Tree (AST) static code analysis engine that scans Python web application code for insecure query construction (f-strings, string concatenation, `%` formatting) and verifies parameterized compliance.
4. **Command-Line Interface (CLI)**: Run static security audits directly from the terminal against any Python codebase.
5. **Academic Project Report**: Complete, printable academic report with theoretical modeling, vulnerability taxonomy, and defense-in-depth evaluation.

---

## 🚀 Quickstart Guide

### 1. Requirements
- Python 3.10 or higher
- Dependencies installed in virtual environment (`fastapi`, `uvicorn`, `pydantic`, `httpx`)

### 2. Launch Interactive Web Dashboard

To launch the web dashboard and automatically open your browser:

```powershell
# From the project root directory:
.\.venv\Scripts\python.exe sqli_run.py
```

The interactive dashboard will be accessible at:
👉 **http://127.0.0.1:8080**

---

## 💻 CLI Commands

### 1. Run Static Code Security Audit (SAST)
Audit any Python file or directory for CWE-89 SQL injection vulnerabilities:

```powershell
# Audit vulnerable service:
.\.venv\Scripts\python.exe sqli_run.py audit sqli_project/core/vulnerable_service.py

# Audit mitigated service:
.\.venv\Scripts\python.exe sqli_run.py audit sqli_project/core/mitigated_service.py
```

### 2. Break Down SQL into Lexical Tokens
Analyze how the database tokenizer breaks down an SQL statement:

```powershell
.\.venv\Scripts\python.exe sqli_run.py tokenize "SELECT * FROM users WHERE id = 1 OR 1=1 --"
```

### 3. Reset the Test Database
Re-seed the SQLite test database with sample records:

```powershell
.\.venv\Scripts\python.exe sqli_run.py reset
```

### 4. Run Automated Test Suite
Execute all 15 automated unit and integration tests:

```powershell
.\.venv\Scripts\python.exe sqli_run.py test
```

---

## 📁 Project Architecture

```
sqli_project/
├── config.py                 # System paths, database configuration, server settings
├── database/
│   ├── db.py                 # SQLite database initialization, schema migration, and seed records
│   └── __init__.py
├── core/
│   ├── vulnerable_service.py # Insecure dynamic SQL implementation (demonstrates CWE-89)
│   ├── mitigated_service.py  # Secure parameterized implementation (prepared statements & validation)
│   ├── query_analyzer.py     # SQL lexical tokenizer & token differential engine
│   ├── sast_scanner.py       # Python AST static code analysis engine
│   └── __init__.py
├── server/
│   ├── app.py                # FastAPI REST API & static file server
│   └── __init__.py
├── static/
│   ├── index.html            # Dark-mode cybersecurity laboratory web interface
│   ├── style.css             # Glassmorphic, token-highlighted styling
│   └── app.js                # Frontend controller & real-time telemetry
├── tests/
│   ├── test_vulnerability.py # Unit tests comparing vulnerable vs mitigated behavior
│   ├── test_sast_scanner.py  # Unit tests verifying AST static analysis accuracy
│   └── test_api.py          # Integration tests for REST API endpoints
├── sqli_run.py               # Unified CLI launcher & runner script
├── SQLI_PROJECT_REPORT.md    # Comprehensive Academic Minor Project Report
└── README.md                 # Project documentation (this file)
```

---

## 🛡️ Educational & Research Disclaimer

This project is developed strictly for **academic education, defensive security engineering, and authorized research**. The vulnerable implementations are isolated within a local SQLite test environment to demonstrate remediation techniques and defense-in-depth principles.
