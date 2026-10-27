"""Report Exporters for Scan Results (CSV, JSON, Executive HTML Audit)."""

from __future__ import annotations

import csv
import io
import json
from .models import ScanReport


def export_to_csv(report: ScanReport) -> str:
    """Generate a clean CSV report string for all discovered hosts and open ports."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Scan ID", "Target", "Host IP", "Hostname", "Status", "OS Guess",
        "Security Score", "Security Grade", "TTL", "Latency (ms)", "MAC Address",
        "MAC Vendor", "Port", "Protocol", "Service", "Software", "Version",
        "Banner", "Risk Level", "Risk Title", "Remediation", "Compliance Tag"
    ])

    for host in report.hosts:
        if host.open_ports:
            for p in host.open_ports:
                writer.writerow([
                    report.job_id,
                    report.target,
                    host.ip,
                    host.hostname or "",
                    host.status,
                    host.os_guess or "Unknown",
                    host.security_score,
                    host.security_grade,
                    host.ttl or "",
                    f"{host.latency_ms:.1f}" if host.latency_ms is not None else "",
                    host.mac_address or "",
                    host.mac_vendor or "",
                    p.port,
                    p.protocol,
                    p.service,
                    p.software or "",
                    p.version or "",
                    p.banner or "",
                    p.risk_level.upper(),
                    p.risk_title or "",
                    p.remediation or "",
                    p.compliance_tag or "",
                ])
        else:
            writer.writerow([
                report.job_id,
                report.target,
                host.ip,
                host.hostname or "",
                host.status,
                host.os_guess or "Unknown",
                host.security_score,
                host.security_grade,
                host.ttl or "",
                f"{host.latency_ms:.1f}" if host.latency_ms is not None else "",
                host.mac_address or "",
                host.mac_vendor or "",
                "", "", "", "", "", "", "INFO", "No Open Scanned Ports", "Host discovered alive", ""
            ])

    return output.getvalue()


def export_to_json(report: ScanReport) -> str:
    """Generate structured JSON representation of the scan report."""
    return report.model_dump_json(indent=2)


def export_to_html_report(report: ScanReport) -> str:
    """Generate a professional, self-contained Executive Cybersecurity Audit Report."""
    grade_color = {
        "A+": "#00e676", "A": "#00e676", "B": "#00f0ff",
        "C": "#ffab00", "D": "#ff9100", "F": "#ff1744"
    }.get(report.overall_posture_grade, "#00f0ff")

    hosts_html = ""
    for host in report.hosts:
        ports_html = ""
        for p in host.open_ports:
            risk_class = f"risk-{p.risk_level}"
            sw_text = f"{p.software} {p.version or ''}".strip() if p.software else "—"
            banner_text = p.banner or "—"
            remediation_html = ""
            if p.remediation:
                remediation_html = f"""
                <div class="remediation-box">
                    <strong>🛡️ Remediation:</strong> {p.remediation}<br>
                    <small><strong>Standard:</strong> {p.compliance_tag or 'Security Hardening'}</small>
                </div>
                """

            ports_html += f"""
            <tr class="port-row">
                <td><span class="port-badge">{p.port}/{p.protocol.upper()}</span></td>
                <td><strong>{p.service}</strong></td>
                <td>{sw_text}</td>
                <td><span class="badge {risk_class}">{p.risk_level.upper()}</span></td>
                <td>
                    <div><strong>{p.risk_title or p.service}</strong></div>
                    <div class="banner-sub">{banner_text}</div>
                    {remediation_html}
                </td>
            </tr>
            """

        hosts_html += f"""
        <div class="host-section">
            <div class="host-header">
                <div>
                    <h3>{host.ip} {f"({host.hostname})" if host.hostname else ""}</h3>
                    <div class="host-meta">
                        <span>OS: <strong>{host.os_guess or 'Unknown'}</strong></span>
                        <span>Latency: <strong>{host.latency_ms or 0:.1f}ms</strong></span>
                        <span>MAC: <strong>{host.mac_address or '—'} {f'({host.mac_vendor})' if host.mac_vendor else ''}</strong></span>
                    </div>
                </div>
                <div class="grade-badge" style="border-color: {grade_color};">
                    <span class="grade-letter">{host.security_grade}</span>
                    <span class="grade-sub">{host.security_score}/100</span>
                </div>
            </div>
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 120px;">Port</th>
                        <th style="width: 140px;">Service</th>
                        <th style="width: 180px;">Software / Version</th>
                        <th style="width: 100px;">Risk</th>
                        <th>Security Advisory &amp; Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {ports_html or '<tr><td colspan="5" style="text-align:center; padding:15px; color:#64748b;">No open ports identified.</td></tr>'}
                </tbody>
            </table>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetScope Security Audit Report - {report.target}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f8fafc;
            color: #0f172a;
            margin: 0;
            padding: 2.5rem;
            line-height: 1.5;
        }}
        .report-card {{
            max-width: 1100px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            padding: 2.5rem;
            border: 1px solid #e2e8f0;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{ margin: 0; font-size: 1.8rem; letter-spacing: -0.5px; }}
        .header .meta {{ color: #64748b; font-size: 0.85rem; margin-top: 4px; }}
        .executive-summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr) 140px;
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .summary-card {{
            background: #f1f5f9;
            padding: 1rem 1.25rem;
            border-radius: 6px;
        }}
        .summary-card .label {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; font-weight: 600; }}
        .summary-card .val {{ font-size: 1.6rem; font-weight: 700; color: #0f172a; margin-top: 4px; }}
        .overall-grade {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            border: 2px solid {grade_color};
            border-radius: 6px;
            background: #f8fafc;
        }}
        .overall-grade .letter {{ font-size: 2rem; font-weight: 800; color: {grade_color}; line-height: 1; }}
        .overall-grade .score {{ font-size: 0.75rem; color: #64748b; font-weight: 600; }}
        .host-section {{
            margin-bottom: 2.5rem;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            overflow: hidden;
        }}
        .host-header {{
            background: #0f172a;
            color: #ffffff;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .host-header h3 {{ margin: 0; font-size: 1.1rem; }}
        .host-meta {{ font-size: 0.8rem; color: #94a3b8; display: flex; gap: 1rem; margin-top: 4px; }}
        .grade-badge {{
            border: 2px solid;
            border-radius: 6px;
            padding: 4px 12px;
            text-align: center;
            background: rgba(255,255,255,0.08);
        }}
        .grade-letter {{ font-size: 1.3rem; font-weight: 700; color: #fff; display: block; line-height: 1; }}
        .grade-sub {{ font-size: 0.65rem; color: #94a3b8; }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }}
        .report-table th {{
            background: #f8fafc;
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
            color: #475569;
            font-weight: 600;
        }}
        .report-table td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid #f1f5f9;
            vertical-align: top;
        }}
        .port-badge {{
            font-family: monospace;
            font-weight: 700;
            background: #e2e8f0;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .badge {{
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            display: inline-block;
        }}
        .risk-high {{ background: #fee2e2; color: #b91c1c; }}
        .risk-warning, .risk-medium {{ background: #fef3c7; color: #b45309; }}
        .risk-info {{ background: #e0f2fe; color: #0369a1; }}
        .remediation-box {{
            background: #f8fafc;
            border-left: 3px solid #0284c7;
            padding: 6px 10px;
            margin-top: 6px;
            font-size: 0.8rem;
            color: #334155;
            border-radius: 0 4px 4px 0;
        }}
        .banner-sub {{
            font-size: 0.75rem;
            color: #64748b;
            font-family: monospace;
            margin-top: 2px;
        }}
        @media print {{
            body {{ padding: 0; background: #fff; }}
            .report-card {{ box-shadow: none; border: none; padding: 0; }}
        }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <div>
                <h1>NETSCOPE // EXECUTIVE SECURITY AUDIT REPORT</h1>
                <div class="meta">Target Scope: <strong>{report.target}</strong> | Session ID: <code>{report.job_id}</code> | Date: {report.started_at}</div>
            </div>
            <button onclick="window.print()" style="padding: 8px 16px; cursor: pointer; border-radius: 4px; border: 1px solid #cbd5e1; background: #fff; font-weight: 600;">Print / Save PDF</button>
        </div>

        <div class="executive-summary">
            <div class="summary-card">
                <div class="label">Targets Audited</div>
                <div class="val">{report.total_targets}</div>
            </div>
            <div class="summary-card">
                <div class="label">Active Hosts</div>
                <div class="val">{report.active_hosts_count}</div>
            </div>
            <div class="summary-card">
                <div class="label">Open TCP Ports</div>
                <div class="val">{report.total_open_ports}</div>
            </div>
            <div class="summary-card">
                <div class="label">High-Risk Exposures</div>
                <div class="val" style="color: {'#b91c1c' if report.total_risk_counts.get('high', 0) > 0 else '#0f172a'};">{report.total_risk_counts.get('high', 0)}</div>
            </div>
            <div class="overall-grade">
                <span class="letter">{report.overall_posture_grade}</span>
                <span class="score">{report.average_security_score}/100</span>
            </div>
        </div>

        {hosts_html}

        <div style="margin-top: 2rem; font-size: 0.75rem; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 1rem;">
            Generated by NetScope Network Reconnaissance &amp; Compliance Audit Engine. Confidential security assessment report.
        </div>
    </div>
</body>
</html>
"""
    return html
