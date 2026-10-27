"""High-Performance TCP Port Scanner."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional
from .models import PortResult

# Supplementary service names for ports not in standard Windows services file
KNOWN_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2222: "ssh-alt",
    3000: "react/node-dev",
    3306: "mysql",
    3389: "ms-wbt-server (rdp)",
    5000: "flask/dev-web",
    5432: "postgresql",
    5672: "rabbitmq",
    5900: "vnc",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy/alt",
    8081: "http-alt",
    8443: "https-alt",
    8888: "jupyter/http-alt",
    9000: "php-fpm/sonar",
    9092: "kafka",
    9200: "elasticsearch",
    9443: "https-alt",
    27017: "mongodb",
}


def get_service_label(port: int) -> str:
    """Resolve service name using standard OS database or known dictionary."""
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error):
        return f"port-{port}"


def check_port(ip: str, port: int, timeout: float = 0.4) -> Optional[int]:
    """Test a single TCP port. Returns port number if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return port
    except OSError:
        pass
    return None


def scan_ports_for_host(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.4,
    workers: int = 40,
    stop_check: Optional[Callable[[], bool]] = None,
) -> List[int]:
    """Scan an iterable of ports on a given IP concurrently."""
    port_list = list(ports)
    open_ports: List[int] = []

    if not port_list:
        return open_ports

    # Adjust workers to avoid unnecessary thread overhead for small port counts
    max_workers = min(workers, len(port_list), 64)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, ip, port, timeout): port
            for port in port_list
        }

        for future in as_completed(future_to_port):
            if stop_check and stop_check():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            try:
                res = future.result()
                if res is not None:
                    open_ports.append(res)
            except Exception:
                pass

    return sorted(open_ports)
