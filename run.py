"""NetScope - Simple One-Command Network Scanner & Auditor."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from typing import Sequence


BANNER = r"""
  _   _      _   ____                       
 | \ | | ___| |_/ ___|  ___ ___  _ __   ___ 
 |  \| |/ _ \ __\___ \ / __/ _ \| '_ \ / _ \
 | |\  |  __/ |_ ___) | (_| (_) | |_) |  __/
 |_| \_|\___|\__|____/ \___\___/| .__/ \___|
                                 |_|        
  Enterprise Network Scanner & Security Posture Auditor v2.0
"""


def run_cli_scan(
    target: str,
    ports: str = "top20",
    output: str | None = None,
    timeout: float = 0.4,
    threads: int = 60,
    no_ping: bool = False,
    no_banner: bool = False,
    no_dns: bool = False,
    max_hosts: int = 512,
) -> int:
    """Execute a scan directly on a target IP or network range."""
    from scanner.engine import ScanJob
    from scanner.exporters import export_to_csv, export_to_html_report, export_to_json
    from scanner.models import ScanJobConfig

    print(BANNER)

    port_sel = "top20"
    custom_ports = None

    if ports:
        p_clean = ports.strip().lower()
        if p_clean in ("top20", "top100", "top1000", "web_db", "1-1024", "all_ports", "all"):
            port_sel = p_clean
        else:
            port_sel = "custom"
            custom_ports = ports

    config = ScanJobConfig(
        target=target,
        port_selection=port_sel,
        custom_ports=custom_ports,
        ping_discovery=not no_ping,
        banner_grab=not no_banner,
        resolve_dns=not no_dns,
        timeout=timeout,
        threads=threads,
        max_hosts=max_hosts,
    )

    job = ScanJob(config)

    def on_event(evt):
        if evt.type in ("log", "complete", "error", "host_discovered", "host_scanned"):
            print(f"[{evt.type.upper():<14}] {evt.message}")

    job.add_listener(on_event)
    print(f"[*] Starting audit on: {target}")
    report = job.run_sync()

    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if report.status == "completed":
        print("\n" + "=" * 70)
        print(f"AUDIT SUMMARY FOR {report.target}")
        print(f"Active Hosts: {report.active_hosts_count} | Open Ports: {report.total_open_ports} | Grade: {report.overall_posture_grade} ({report.average_security_score}/100)")
        print(f"High Risks: {report.total_risk_counts.get('high', 0)} | Warnings: {report.total_risk_counts.get('warning', 0)} | Duration: {report.duration_seconds}s")
        print("=" * 70)

        for host in report.hosts:
            dns = f" ({host.hostname})" if host.hostname else ""
            os_info = f" [OS: {host.os_guess}]" if host.os_guess else ""
            print(f"\nHost: {host.ip}{dns}{os_info} - Score: {host.security_score}/100 (Grade: {host.security_grade})")
            if host.mac_address:
                print(f"  MAC: {host.mac_address} ({host.mac_vendor or 'Unknown Vendor'})")
            if host.open_ports:
                for p in host.open_ports:
                    sw_info = f" ({p.software} {p.version or ''})".strip() if p.software else ""
                    print(f"  --> {p.port:>5}/tcp  {p.service:<15} [{p.risk_level.upper()}]{sw_info}")
                    if p.remediation:
                        print(f"      [ADVISORY] {p.remediation}")
            else:
                print("  No open ports discovered.")

        if output:
            if output.lower().endswith(".json"):
                data = export_to_json(report)
            elif output.lower().endswith(".html"):
                data = export_to_html_report(report)
            else:
                data = export_to_csv(report)
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
            print(f"\n[+] Audit report saved to: {output}")

    return 0 if report.status == "completed" else 1


def run_web_server(host: str = "127.0.0.1", port: int = 8000, no_browser: bool = False) -> None:
    """Launch the FastAPI Web Dashboard."""
    import uvicorn

    print(BANNER)
    url = f"http://{host}:{port}"
    print(f"[*] NetScope Web Dashboard online at: {url}")
    print("[*] Press Ctrl+C to terminate.")

    if not no_browser:
        def open_browser():
            import time
            time.sleep(1.0)
            webbrowser.open(url)
        import threading
        threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run("server.app:app", host=host, port=port, reload=False, log_level="info")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="NetScope: Network Scanner & Security Posture Auditor.",
        usage="%(prog)s [TARGET_IP] [options]\n       %(prog)s (without arguments to start web dashboard)",
    )

    # Positional target (optional - if omitted, web dashboard launches)
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target IP, CIDR subnet (e.g. 192.168.1.0/24), or range. If omitted, starts Web Dashboard.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="top20",
        help="Ports or profile: top20, top100, top1000, all, or custom '22,80,443' (default: top20)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save report to file (e.g. audit.html, scan.csv, report.json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.4,
        help="Socket timeout in seconds (default: 0.4)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=60,
        help="Concurrency worker threads (default: 60)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=512,
        help="Maximum targets allowed (default: 512)",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Disable pre-scan ping sweep",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable service banner grabbing",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Disable reverse DNS resolution",
    )

    # Web Dashboard flags
    parser.add_argument(
        "--web",
        action="store_true",
        help="Explicitly launch interactive Web Dashboard",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web server port (default: 8000)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open browser in web mode",
    )

    args = parser.parse_args(argv)

    # Support legacy subcommands "scan" or "web" if typed
    if args.target == "web":
        run_web_server(host=args.host, port=args.port, no_browser=args.no_browser)
        return 0

    if args.target == "scan":
        # If user ran "python run.py scan 127.0.0.1"
        rem_args = list(sys.argv[2:]) if len(sys.argv) > 2 else []
        if rem_args and not rem_args[0].startswith("-"):
            args.target = rem_args[0]
        else:
            args.target = None

    if args.target and not args.web:
        # Direct CLI Scan with single command!
        return run_cli_scan(
            target=args.target,
            ports=args.ports,
            output=args.output,
            timeout=args.timeout,
            threads=args.threads,
            no_ping=args.no_ping,
            no_banner=args.no_banner,
            no_dns=args.no_dns,
            max_hosts=args.max_hosts,
        )
    else:
        # No target provided or --web passed: Launch Web Dashboard!
        run_web_server(host=args.host, port=args.port, no_browser=args.no_browser)
        return 0


if __name__ == "__main__":
    sys.exit(main())
