"""Service Banner Grabbing, Version Fingerprinting, and Defensive Security Auditing."""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional, Tuple
from .models import PortResult
from .port_scanner import get_service_label

COMMON_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000}
COMMON_HTTPS_PORTS = {443, 8443, 9443}


def parse_software_and_version(service: str, banner: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract software name, version string, and OS hint from a service banner.

    Returns:
        (software, version, os_hint)
    """
    if not banner:
        return None, None, None

    banner_clean = banner.strip()
    software = None
    version = None
    os_hint = None

    # 1. OpenSSH Banner (e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6)
    if "OpenSSH" in banner_clean:
        software = "OpenSSH"
        ssh_match = re.search(r"OpenSSH_([0-9a-zA-Z\.\-]+)", banner_clean)
        if ssh_match:
            version = ssh_match.group(1)
        if "Ubuntu" in banner_clean:
            os_hint = "Ubuntu Linux"
        elif "Debian" in banner_clean:
            os_hint = "Debian Linux"
        elif "FreeBSD" in banner_clean:
            os_hint = "FreeBSD"
        elif "CentOS" in banner_clean or "RHEL" in banner_clean:
            os_hint = "Red Hat / CentOS Linux"
        elif "Windows" in banner_clean:
            os_hint = "Microsoft Windows"
        return software, version, os_hint

    # 2. Dropbear SSH (e.g. SSH-2.0-dropbear_2020.81)
    if "dropbear" in banner_clean.lower():
        software = "Dropbear SSH"
        match = re.search(r"dropbear_([0-9\.]+)", banner_clean, re.IGNORECASE)
        if match:
            version = match.group(1)
        os_hint = "Embedded Linux / OpenWrt"
        return software, version, os_hint

    # 3. HTTP Server Header matching
    if "Server:" in banner_clean or "[" in banner_clean:
        # e.g., HTTP/1.1 200 OK [nginx/1.18.0 (Ubuntu)]
        srv_match = re.search(r"\[(.*?)(?:/([0-9a-zA-Z\.\-]+))?(?:\s*\((.*?)\))?\]", banner_clean)
        if srv_match:
            srv_name, srv_ver, srv_os = srv_match.groups()
            if srv_name:
                software = srv_name.strip()
            if srv_ver:
                version = srv_ver.strip()
            if srv_os:
                os_hint = srv_os.strip()
            return software, version, os_hint

        # Direct server token search
        if "nginx" in banner_clean.lower():
            software = "Nginx"
            match = re.search(r"nginx/([0-9\.]+)", banner_clean, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "apache" in banner_clean.lower():
            software = "Apache HTTP Server"
            match = re.search(r"Apache/([0-9\.]+)", banner_clean, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "microsoft-iis" in banner_clean.lower():
            software = "Microsoft IIS"
            match = re.search(r"Microsoft-IIS/([0-9\.]+)", banner_clean, re.IGNORECASE)
            if match:
                version = match.group(1)
            os_hint = "Microsoft Windows Server"
        elif "caddy" in banner_clean.lower():
            software = "Caddy Web Server"
        elif "cloudflare" in banner_clean.lower():
            software = "Cloudflare CDN Proxy"

    # 4. FTP Banners
    if "vsftpd" in banner_clean.lower():
        software = "vsftpd"
        match = re.search(r"vsFTPd\s*([0-9\.]+)", banner_clean, re.IGNORECASE)
        if match:
            version = match.group(1)
        os_hint = "Linux"
    elif "proftpd" in banner_clean.lower():
        software = "ProFTPD"
        match = re.search(r"ProFTPD\s*([0-9\.]+)", banner_clean, re.IGNORECASE)
        if match:
            version = match.group(1)

    # 5. MySQL / MariaDB
    if "mariadb" in banner_clean.lower():
        software = "MariaDB"
        match = re.search(r"([0-9\.\-]+)-MariaDB", banner_clean, re.IGNORECASE)
        if match:
            version = match.group(1)
    elif "mysql" in banner_clean.lower():
        software = "MySQL Database"
        match = re.search(r"([0-9\.\-]+)", banner_clean)
        if match:
            version = match.group(1)

    # 6. Redis
    if "redis" in banner_clean.lower() or "PONG" in banner_clean:
        software = "Redis In-Memory Datastore"
        match = re.search(r"redis_version:([0-9\.]+)", banner_clean)
        if match:
            version = match.group(1)

    return software, version, os_hint


def analyze_security_risk(port: int, banner: Optional[str] = None) -> Tuple[str, str, str, str, str]:
    """Perform security assessment and compliance audit for the port and service.

    Returns:
        (risk_level, risk_title, risk_description, remediation, compliance_tag)
    """
    banner_lower = (banner or "").lower()

    if port == 23:
        return (
            "high",
            "Cleartext Management Protocol (Telnet)",
            "Telnet transmits credentials, commands, and administrative sessions in unencrypted cleartext across the network.",
            "Decommission Telnet immediately. Transition all remote administration to encrypted OpenSSH (port 22) or an encrypted VPN tunnel.",
            "CIS Controls 4.1 / NIST SP 800-53 AC-17",
        )

    if port == 6379:
        return (
            "high",
            "Exposed In-Memory Datastore (Redis)",
            "Redis instances exposed to the network frequently lack password authentication by default, allowing arbitrary data exfiltration or remote code execution.",
            "Bind Redis strictly to 127.0.0.1 in redis.conf (`bind 127.0.0.1`), enforce strong authentication (`requirepass`), and block port 6379 on external firewalls.",
            "OWASP Top 10 A05:2021 Security Misconfiguration",
        )

    if port == 27017:
        return (
            "high",
            "Exposed NoSQL Database (MongoDB)",
            "MongoDB listener exposed to network. In default configurations, this can expose sensitive databases without authentication.",
            "Enable role-based authorization (`security.authorization: enabled`), bind solely to local or internal management interfaces, and enforce TLS encryption.",
            "CIS MongoDB Benchmark 1.1 / PCI-DSS Req 2.2",
        )

    if port == 21:
        return (
            "medium",
            "Unencrypted File Transfer Protocol (FTP)",
            "Standard FTP passes authentication credentials and transmitted files in cleartext, susceptible to network sniffing.",
            "Migrate from cleartext FTP to SFTP (SSH File Transfer Protocol) or configure FTPS with enforced TLS 1.3 encryption.",
            "PCI-DSS Requirement 4.1 / HIPAA 164.312(e)(1)",
        )

    if port in (139, 445):
        return (
            "warning",
            "Windows SMB / NetBIOS File Sharing Active",
            "SMB port is reachable over the network. Exposed SMB services are high-value targets for lateral movement and credential relay attacks.",
            "Block ports 139 and 445 at boundary firewalls. Disable SMBv1, enforce SMB signing and SMB encryption, and isolate file-sharing hosts.",
            "CISA Cybersecurity Advisory / CIS Benchmark Microsoft Windows",
        )

    if port in (3389, 5900):
        service_name = "RDP" if port == 3389 else "VNC"
        return (
            "warning",
            f"Remote Graphical Desktop Interface ({service_name}) Exposed",
            f"{service_name} administrative port exposed. Direct exposure facilitates automated password spraying and brute-force attacks.",
            f"Restrict {service_name} access behind an authenticated VPN or Gateway. Enforce Multi-Factor Authentication (MFA) and Network Level Authentication (NLA).",
            "NIST SP 800-46 Rev. 2 / CIS Benchmark",
        )

    if port in (1433, 1521, 3306, 5432):
        db_name = {1433: "Microsoft SQL Server", 1521: "Oracle DB", 3306: "MySQL", 5432: "PostgreSQL"}.get(port, "Database")
        return (
            "medium",
            f"Relational Database Listener Exposed ({db_name})",
            f"{db_name} listener is exposed on the network interface. Databases should generally only be reachable by authorized application tiers.",
            "Restrict database network access to specific application IP addresses using host-based firewalls or cloud security group ACLs.",
            "CIS Database Benchmark / Defense-in-Depth Principle",
        )

    if port in (80, 8080, 8000) and "http" in banner_lower:
        return (
            "info",
            "Unencrypted HTTP Web Service",
            "Web service operates without transport layer encryption (HTTP), transmitting traffic in plaintext.",
            "Provision a valid TLS certificate and configure an automatic 301 Permanent Redirect to HTTPS (Port 443). Enable HSTS.",
            "OWASP Transport Layer Protection / NIST SP 800-52",
        )

    if port in COMMON_HTTPS_PORTS:
        return (
            "info",
            "Encrypted HTTPS Web Service",
            "Web service utilizes Transport Layer Security (TLS) for traffic confidentiality.",
            "Ensure legacy protocols (TLS 1.0/1.1) and weak ciphers are disabled; maintain active TLS certificates.",
            "NIST SP 800-52 Rev. 2",
        )

    if port == 22:
        return (
            "info",
            "Secure Shell Remote Administration (SSH)",
            "Encrypted remote administrative shell active.",
            "Disable root login (`PermitRootLogin no`), enforce public-key authentication, and maintain OpenSSH patch levels.",
            "CIS Controls 4.1",
        )

    return (
        "info",
        f"Active Network Service ({port}/tcp)",
        f"TCP port {port} accepted incoming connection.",
        "Ensure service has updated patches applied and access is restricted to intended users.",
        "General Hardening Best Practice",
    )


def grab_banner(ip: str, port: int, timeout: float = 0.6) -> str:
    """Attempt to capture a service identification banner from an open port."""
    # 1. Test HTTPS if port is known HTTPS
    if port in COMMON_HTTPS_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as s:
                    req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetScope/1.0\r\nConnection: close\r\n\r\n"
                    s.sendall(req.encode("ascii", errors="ignore"))
                    resp = s.recv(512).decode("utf-8", errors="replace")
                    return clean_http_banner(resp)
        except Exception:
            pass

    # 2. Test HTTP if port is known HTTP
    if port in COMMON_HTTP_PORTS or port == 80:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetScope/1.0\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode("ascii", errors="ignore"))
                resp = s.recv(512).decode("utf-8", errors="replace")
                parsed = clean_http_banner(resp)
                if parsed:
                    return parsed
        except OSError:
            pass

    # 3. Test generic banner / interactive protocols (SSH, FTP, SMTP, Redis, MySQL)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port == 6379:
                s.sendall(b"INFO\r\n")
            elif port in (80, 8080, 8000):
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")

            data = s.recv(512)
            if data:
                text = data.decode("utf-8", errors="replace")
                printable = "".join(ch for ch in text if ch.isprintable() or ch in "\t\r\n")
                cleaned = " ".join(printable.split())[:150]
                if cleaned:
                    return cleaned
    except OSError:
        pass

    return ""


def clean_http_banner(raw_response: str) -> str:
    """Extract HTTP status, Server header, and Title if present."""
    if not raw_response:
        return ""
    lines = raw_response.splitlines()
    status_line = lines[0].strip() if lines else ""
    server_info = ""
    for line in lines:
        if line.lower().startswith("server:"):
            server_info = line.split(":", 1)[1].strip()
            break
        if line.lower().startswith("x-powered-by:"):
            server_info = line.split(":", 1)[1].strip()
            break

    if server_info and status_line:
        return f"{status_line} [{server_info}]"
    elif status_line:
        return status_line
    return ""


def inspect_open_port(ip: str, port: int, banner_grab_enabled: bool = True, timeout: float = 0.6) -> Tuple[PortResult, Optional[str]]:
    """Build a detailed PortResult including service label, software version, risk scoring, and OS hints.

    Returns:
        (PortResult, os_hint)
    """
    service = get_service_label(port)
    banner = None
    if banner_grab_enabled:
        b = grab_banner(ip, port, timeout=timeout)
        banner = b if b else None

    software, version, os_hint = parse_software_and_version(service, banner)
    risk_level, risk_title, risk_desc, remediation, compliance = analyze_security_risk(port, banner)

    result = PortResult(
        port=port,
        state="open",
        protocol="tcp",
        service=service,
        software=software,
        version=version,
        banner=banner,
        risk_level=risk_level,
        risk_title=risk_title,
        risk_description=risk_desc,
        remediation=remediation,
        compliance_tag=compliance,
    )

    return result, os_hint
