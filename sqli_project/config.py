"""
SQL Injection Detection, Exploitation & Mitigation Platform
Configuration and Database Settings
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "sqli_demo.db"
STATIC_DIR = BASE_DIR / "static"

# Server Settings
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080

# Project Meta
PROJECT_TITLE = "Detection, Exploitation, and Mitigation of SQL Injection Vulnerabilities in Web Applications"
PROJECT_CODE = "CWE-89-AUDIT"
PROJECT_VERSION = "2.0.0"
PROJECT_AUTHOR = "Academic Minor Project Research"
