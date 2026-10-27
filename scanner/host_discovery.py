"""Host Discovery: Ping sweep, TTL OS detection, ARP resolution, and Hostname lookup."""

from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
from typing import Dict, Optional, Tuple


def get_local_interfaces_info() -> Dict[str, str]:
    """Detect the local machine's primary IP, hostname, and default /24 subnet."""
    local_ip = "127.0.0.1"
    hostname = socket.gethostname()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        pass

    subnet = "127.0.0.1/32"
    if local_ip != "127.0.0.1" and "." in local_ip:
        octets = local_ip.split(".")
        subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

    return {
        "local_ip": local_ip,
        "hostname": hostname,
        "default_subnet": subnet,
        "os": platform.system(),
    }


def get_arp_cache() -> Dict[str, str]:
    """Read the operating system ARP cache to map IP addresses to MAC addresses."""
    arp_map: Dict[str, str] = {}
    try:
        cmd = ["arp", "-a"]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3)
        pattern = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})"
        )
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac = match.groups()
                arp_map[ip] = mac.replace("-", ":").upper()
    except Exception:
        pass
    return arp_map


def lookup_mac_vendor(mac: str) -> Optional[str]:
    """Identify well-known hardware vendors from the first 3 octets (OUI)."""
    if not mac or len(mac) < 8:
        return None
    prefix = mac[:8].upper()
    known_ouis = {
        "00:50:56": "VMware ESXi / Workstation",
        "00:0C:29": "VMware Virtual Machine",
        "08:00:27": "Oracle VirtualBox",
        "52:54:00": "QEMU / KVM Virtual NIC",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "E4:5F:01": "Raspberry Pi Foundation",
        "00:15:5D": "Microsoft Hyper-V Virtual NIC",
        "F0:18:98": "Apple",
        "3C:06:30": "Apple",
        "AC:DE:48": "Apple",
        "00:1A:11": "Google Fiber / Appliance",
        "70:85:C2": "ASUSTek Computer",
        "00:1F:3B": "Intel Corporate",
        "00:26:B9": "Dell Inc.",
        "34:17:EB": "Dell Inc.",
        "18:66:DA": "Dell Inc.",
        "28:18:78": "Microsoft Corporation",
        "D4:5D:64": "Cisco Systems",
        "00:00:0C": "Cisco Systems",
        "FC:EC:DA": "Ubiquiti Networks",
        "78:8A:20": "Ubiquiti Networks",
        "50:C7:BF": "TP-Link Technologies",
        "14:EB:B6": "TP-Link Technologies",
        "E4:C7:22": "TP-Link Technologies",
    }
    return known_ouis.get(prefix, None)


def guess_os_by_ttl(ttl: int) -> str:
    """Heuristic OS guess based on standard initial IP Time-To-Live (TTL)."""
    if ttl <= 64:
        return "Linux / Unix / macOS"
    elif ttl <= 128:
        return "Microsoft Windows"
    elif ttl <= 255:
        return "Network Appliance / Cisco IOS / BSD"
    return "Unknown Operating System"


def ping_host(ip: str, timeout_ms: int = 500) -> Tuple[bool, Optional[float], Optional[int]]:
    """Ping a host using system ping. Returns (is_alive, latency_ms, ttl)."""
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=(timeout_ms / 1000.0) + 1.0,
        )
        output = proc.stdout
        if proc.returncode != 0:
            return False, None, None

        ttl_match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
        ttl = int(ttl_match.group(1)) if ttl_match else None

        lat_match = re.search(r"time[<=](\d+(?:\.\d+)?)ms", output, re.IGNORECASE)
        latency = float(lat_match.group(1)) if lat_match else (0.5 if "time<1ms" in output else None)

        return True, latency, ttl
    except Exception:
        return False, None, None


def quick_socket_alive_probe(ip: str, timeout_sec: float = 0.3) -> bool:
    """Fast fallback probe against responsive ports if ICMP ping is blocked."""
    probe_ports = [80, 443, 135, 445, 22, 53]
    for port in probe_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_sec)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            pass
    return False


def discover_host_details(
    ip: str,
    ping_enabled: bool = True,
    resolve_dns: bool = True,
    arp_table: Optional[Dict[str, str]] = None,
    timeout_sec: float = 0.4,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str], Optional[int], Optional[float]]:
    """Probe an IP and collect alive status, hostname, MAC, vendor, OS guess, TTL, and latency."""
    is_alive = False
    latency_ms = None
    ttl = None
    os_guess = None

    if ping_enabled:
        timeout_ms = max(200, int(timeout_sec * 1000))
        is_alive, latency_ms, ttl = ping_host(ip, timeout_ms=timeout_ms)
        if ttl:
            os_guess = guess_os_by_ttl(ttl)

    if not is_alive:
        is_alive = quick_socket_alive_probe(ip, timeout_sec=timeout_sec)

    hostname = None
    if resolve_dns and is_alive:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

    mac = None
    vendor = None
    if arp_table and ip in arp_table:
        mac = arp_table[ip]
        vendor = lookup_mac_vendor(mac)

    return is_alive, hostname, mac, vendor, os_guess, ttl, latency_ms


def calculate_security_posture(ports: list) -> Tuple[int, str, Dict[str, int]]:
    """Compute security score (0-100), letter grade (A+ to F), and risk distribution."""
    score = 100
    counts = {"high": 0, "medium": 0, "warning": 0, "info": 0}

    for p in ports:
        lvl = getattr(p, "risk_level", "info").lower()
        if lvl == "high":
            score -= 25
            counts["high"] += 1
        elif lvl == "warning":
            score -= 15
            counts["warning"] += 1
        elif lvl == "medium":
            score -= 10
            counts["medium"] += 1
        else:
            counts["info"] += 1

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 88:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 45:
        grade = "D"
    else:
        grade = "F"

    return score, grade, counts
