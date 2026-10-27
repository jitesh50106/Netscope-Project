#!/usr/bin/env python3
"""
========================================================================================
Academic Minor Project:
"Detection, Exploitation, and Mitigation of SQL Injection Vulnerabilities in Web Applications"
========================================================================================
Unified Launcher & Command-Line Security Audit Engine
"""

import sys
import os
import argparse
import webbrowser
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqli_project.config import (
    SERVER_HOST,
    SERVER_PORT,
    PROJECT_TITLE,
    PROJECT_VERSION,
    PROJECT_CODE
)
from sqli_project.database.db import init_db, reset_db
from sqli_project.core.sast_scanner import SASTScanner
from sqli_project.core.query_analyzer import QueryAnalyzer

BANNER = rf"""
========================================================================================
  _____ ____  _      _   ____  ______ ______ ______ _   _  _____ ______ 
 / ____/ __ \| |    (_) |  _ \|  ____|  ____|  ____| \ | |/ ____|  ____|
| (___| |  | | |     _  | |_) | |__  | |__  | |__  |  \| | (___ | |__   
 \___ \| |  | | |    | | |  _ <|  __| |  __| |  __| | . ` |\___ \|  __|  
 ____) | |__| | |____| | | |_) | |____| |    | |____| |\  |____) | |____ 
|_____/ \___\_\______|_| |____/|______|_|    |______|_| \_|_____/|______|

  Academic Minor Project: {PROJECT_TITLE}
  Standard: OWASP A03:2021 // CWE-89 // Version: {PROJECT_VERSION}
========================================================================================
"""

def print_banner():
    print(BANNER)

def cmd_serve(args):
    """Start the interactive web dashboard and API server."""
    import uvicorn
    from sqli_project.server.app import app

    print_banner()
    init_db()

    url = f"http://{args.host}:{args.port}"
    print(f"[*] Initializing SQLite academic test database...")
    print(f"[+] Server listening on: {url}")
    print(f"[*] Interactive Web Dashboard & SAST Auditor ready.")
    print(f"[*] Press CTRL+C to terminate.")

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

def cmd_audit(args):
    """Run CLI SAST audit against target Python files or directories."""
    print_banner()
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"[-] Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    py_files = []
    if target_path.is_file():
        py_files.append(target_path)
    else:
        py_files.extend(target_path.rglob("*.py"))

    print(f"[*] Running Static Application Security Testing (SAST) on {len(py_files)} file(s)...")
    print("-" * 80)

    total_critical = 0
    total_secure = 0
    total_inspected = 0

    for fpath in py_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            print(f"[-] Could not read {fpath}: {e}")
            continue

        result = SASTScanner.scan_code(code)
        if result["status"] == "SYNTAX_ERROR":
            print(f"[!] Syntax error in {fpath}: {result['error_message']}")
            continue

        findings = result["findings"]
        if findings:
            print(f"\n[FILE] {fpath}")
            for fnd in findings:
                total_inspected += 1
                if fnd["severity"] == "CRITICAL":
                    total_critical += 1
                    print(f"  [CRITICAL] Line {fnd['line_number']}: {fnd['vulnerability_type']}")
                    print(f"    CWE:     {fnd['cwe_id']}")
                    print(f"    Code:    {fnd['code_snippet']}")
                    print(f"    Details: {fnd['details']}")
                    print(f"    Patch:   {fnd['recommended_patch']}")
                else:
                    total_secure += 1
                    print(f"  [SECURE] Line {fnd['line_number']}: {fnd['vulnerability_type']}")
                    print(f"    Code:    {fnd['code_snippet']}")

    print("\n" + "=" * 80)
    print("SAST AUDIT SUMMARY:")
    print(f"  Total Files Audited:      {len(py_files)}")
    print(f"  Total Invocations:        {total_inspected}")
    print(f"  Critical SQLi (CWE-89):   {total_critical}")
    print(f"  Compliant Prepared Calls: {total_secure}")
    if total_critical == 0:
        print("  Overall Security Grade:   A+ (NO UNPARAMETERIZED DYNAMIC SQL DETECTED)")
    else:
        print(f"  Overall Security Grade:   F ({total_critical} VULNERABILITIES REQUIRE REMEDIATION)")
    print("=" * 80)

def cmd_tokenize(args):
    """Breakdown SQL query into lexical tokens via CLI."""
    print_banner()
    sql = args.sql
    print(f"[*] Lexical Analysis for SQL Input:\n    {sql}\n")
    tokens = QueryAnalyzer.tokenize(sql)
    print(f"{'TYPE':<20} {'VALUE':<30} {'SENSITIVE':<10}")
    print("-" * 65)
    for t in tokens:
        print(f"{t['type']:<20} {repr(t['value']):<30} {str(t['is_injection_sensitive']):<10}")
    print(f"\n[+] Total tokens parsed: {len(tokens)}")

def cmd_reset(args):
    """Reset SQLite database."""
    print_banner()
    print("[*] Re-seeding database with clean records...")
    reset_db()
    print("[+] Database successfully reset to initial pristine state.")

def cmd_test(args):
    """Run automated unit and integration tests."""
    print_banner()
    import unittest
    suite = unittest.defaultTestLoader.discover("sqli_project/tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)

def main():
    parser = argparse.ArgumentParser(
        description=f"{PROJECT_TITLE} - Unified Launcher & CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-command to execute")

    # 1. serve (Default)
    serve_parser = subparsers.add_parser("serve", help="Launch interactive Web Dashboard & API server")
    serve_parser.add_argument("--host", default=SERVER_HOST, help=f"Server host (default: {SERVER_HOST})")
    serve_parser.add_argument("-p", "--port", type=int, default=SERVER_PORT, help=f"Server port (default: {SERVER_PORT})")
    serve_parser.add_argument("--no-browser", action="store_true", help="Do not open web browser automatically")

    # 2. audit
    audit_parser = subparsers.add_parser("audit", help="Run AST static code scanner against Python files")
    audit_parser.add_argument("path", help="Path to Python file or directory to scan")

    # 3. tokenize
    token_parser = subparsers.add_parser("tokenize", help="Break down SQL statement into lexical tokens")
    token_parser.add_argument("sql", help="SQL query string to analyze")

    # 4. reset
    subparsers.add_parser("reset", help="Reset and seed SQLite test database")

    # 5. test
    subparsers.add_parser("test", help="Execute all unit and integration tests")

    args = parser.parse_args()

    # If no command provided, default to serve
    if args.command is None:
        args.host = SERVER_HOST
        args.port = SERVER_PORT
        args.no_browser = False
        cmd_serve(args)
    elif args.command == "serve":
        cmd_serve(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "tokenize":
        cmd_tokenize(args)
    elif args.command == "reset":
        cmd_reset(args)
    elif args.command == "test":
        cmd_test(args)

if __name__ == "__main__":
    main()
