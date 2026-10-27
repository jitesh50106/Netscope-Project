"""Unit tests for scanner modules, banners, risk analysis, versioning, and exporters."""

import unittest
from scanner.banner_grabber import (
    analyze_security_risk,
    clean_http_banner,
    parse_software_and_version,
)
from scanner.exporters import export_to_csv, export_to_html_report, export_to_json
from scanner.host_discovery import (
    calculate_security_posture,
    guess_os_by_ttl,
    lookup_mac_vendor,
)
from scanner.models import HostResult, PortResult, ScanJobConfig, ScanReport
from scanner.port_scanner import get_service_label


class TestScannerComponents(unittest.TestCase):
    def test_ttl_os_guess(self):
        self.assertEqual(guess_os_by_ttl(64), "Linux / Unix / macOS")
        self.assertEqual(guess_os_by_ttl(128), "Microsoft Windows")
        self.assertEqual(guess_os_by_ttl(255), "Network Appliance / Cisco IOS / BSD")

    def test_mac_vendor_lookup(self):
        self.assertIn("VMware", lookup_mac_vendor("00:50:56:11:22:33") or "")
        self.assertEqual(lookup_mac_vendor("B8:27:EB:AA:BB:CC"), "Raspberry Pi Foundation")
        self.assertIsNone(lookup_mac_vendor("FF:FF:FF:00:00:00"))

    def test_service_label(self):
        self.assertEqual(get_service_label(80), "http")
        self.assertEqual(get_service_label(443), "https")
        self.assertEqual(get_service_label(22), "ssh")
        self.assertEqual(get_service_label(6379), "redis")

    def test_security_risk_analysis(self):
        risk, title, desc, remediation, comp = analyze_security_risk(23)
        self.assertEqual(risk, "high")
        self.assertIn("Telnet", title)
        self.assertTrue(len(remediation) > 0)

        risk, title, _, remediation, _ = analyze_security_risk(6379)
        self.assertEqual(risk, "high")
        self.assertIn("Redis", title)

        risk, title, _, _, _ = analyze_security_risk(21)
        self.assertEqual(risk, "medium")

        risk, _, _, _, _ = analyze_security_risk(443)
        self.assertEqual(risk, "info")

    def test_version_fingerprinting(self):
        sw, ver, os_hint = parse_software_and_version("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertEqual(sw, "OpenSSH")
        self.assertEqual(ver, "8.9p1")
        self.assertEqual(os_hint, "Ubuntu Linux")

        sw, ver, _ = parse_software_and_version("http", "HTTP/1.1 200 OK [nginx/1.22.1]")
        self.assertEqual(sw, "nginx")
        self.assertEqual(ver, "1.22.1")

    def test_calculate_security_posture(self):
        ports = [
            PortResult(port=80, risk_level="info"),
            PortResult(port=23, risk_level="high"),  # -25
            PortResult(port=445, risk_level="warning"),  # -15
        ]
        score, grade, counts = calculate_security_posture(ports)
        self.assertEqual(score, 60)
        self.assertEqual(grade, "C")
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["warning"], 1)

    def test_clean_http_banner(self):
        raw_resp = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.24.0\r\n"
            "Content-Length: 10\r\n\r\n"
        )
        cleaned = clean_http_banner(raw_resp)
        self.assertIn("HTTP/1.1 200 OK", cleaned)
        self.assertIn("nginx/1.24.0", cleaned)

    def test_exporters(self):
        config = ScanJobConfig(target="127.0.0.1")
        port_item = PortResult(
            port=80,
            service="http",
            software="nginx",
            version="1.24.0",
            banner="HTTP/1.1 200 OK [nginx/1.24.0]",
            risk_level="info",
            risk_title="HTTP Service",
            remediation="Redirect to HTTPS",
        )
        host = HostResult(
            ip="127.0.0.1",
            hostname="localhost",
            os_guess="Microsoft Windows",
            ttl=128,
            latency_ms=0.5,
            security_score=95,
            security_grade="A+",
            open_ports=[port_item],
        )
        report = ScanReport(
            job_id="test-123",
            target="127.0.0.1",
            config=config,
            started_at="2026-10-12 12:00:00",
            completed_at="2026-10-12 12:00:02",
            duration_seconds=2.0,
            total_targets=1,
            active_hosts_count=1,
            total_open_ports=1,
            average_security_score=95,
            overall_posture_grade="A+",
            status="completed",
            hosts=[host],
        )

        csv_str = export_to_csv(report)
        self.assertIn("127.0.0.1", csv_str)
        self.assertIn("nginx", csv_str)
        self.assertIn("Redirect to HTTPS", csv_str)

        json_str = export_to_json(report)
        self.assertIn('"job_id": "test-123"', json_str)
        self.assertIn('"software": "nginx"', json_str)

        html_str = export_to_html_report(report)
        self.assertIn("EXECUTIVE SECURITY AUDIT REPORT", html_str)
        self.assertIn("nginx", html_str)


if __name__ == "__main__":
    unittest.main()
