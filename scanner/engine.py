"""Scan Engine Orchestrator for Professional Network Audits."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

from .banner_grabber import inspect_open_port
from .host_discovery import (
    calculate_security_posture,
    discover_host_details,
    get_arp_cache,
)
from .models import (
    HostResult,
    PortResult,
    ScanJobConfig,
    ScanProgressEvent,
    ScanReport,
)
from .port_scanner import scan_ports_for_host
from .target_parser import parse_ports, parse_targets


class ScanJob:
    def __init__(self, config: ScanJobConfig, job_id: Optional[str] = None):
        self.job_id = job_id or str(uuid.uuid4())[:8]
        self.config = config
        self.report = ScanReport(
            job_id=self.job_id,
            target=config.target,
            config=config,
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status="running",
        )
        self.is_cancelled = threading.Event()
        self.listeners: List[Callable[[ScanProgressEvent], None]] = []
        self._lock = threading.Lock()

    def add_listener(self, listener: Callable[[ScanProgressEvent], None]) -> None:
        with self._lock:
            self.listeners.append(listener)

    def remove_listener(self, listener: Callable[[ScanProgressEvent], None]) -> None:
        with self._lock:
            if listener in self.listeners:
                self.listeners.remove(listener)

    def emit(self, event: ScanProgressEvent) -> None:
        with self._lock:
            listeners_copy = list(self.listeners)
        for fn in listeners_copy:
            try:
                fn(event)
            except Exception:
                pass

    def cancel(self) -> None:
        self.is_cancelled.set()
        self.report.status = "cancelled"
        self.emit(
            ScanProgressEvent(
                type="cancelled",
                message=f"Scan {self.job_id} cancelled by operator.",
                percent=100.0,
            )
        )

    def run_sync(self) -> ScanReport:
        start_time = time.perf_counter()
        self.emit(
            ScanProgressEvent(
                type="log",
                message=f"[*] Initializing professional audit job {self.job_id} on: {self.config.target}",
                percent=0.0,
            )
        )

        try:
            target_ips = parse_targets(self.config.target, max_hosts=self.config.max_hosts)
            target_ports = parse_ports(self.config.port_selection, self.config.custom_ports)
        except Exception as exc:
            self.report.status = "failed"
            self.report.error_message = str(exc)
            self.emit(
                ScanProgressEvent(
                    type="error",
                    message=f"Configuration error: {exc}",
                    percent=100.0,
                    payload={"error": str(exc)},
                )
            )
            return self.report

        self.report.total_targets = len(target_ips)
        port_count_desc = f"{len(target_ports)} ports" if len(target_ports) < 10000 else "all 65,535 ports"
        self.emit(
            ScanProgressEvent(
                type="log",
                message=f"[*] Target scope: {len(target_ips)} host(s) | Auditing {port_count_desc} per host",
                percent=5.0,
            )
        )

        arp_cache = get_arp_cache()
        alive_hosts: Dict[str, HostResult] = {}
        total_targets = len(target_ips)

        # Phase 1: Host Discovery
        if self.config.ping_discovery and total_targets > 1:
            self.emit(
                ScanProgressEvent(
                    type="log",
                    message=f"[*] Phase 1: Host Discovery Sweep ({total_targets} targets)...",
                    percent=10.0,
                )
            )

            workers = min(self.config.threads, total_targets, 64)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_ip = {
                    executor.submit(
                        discover_host_details,
                        ip,
                        ping_enabled=True,
                        resolve_dns=self.config.resolve_dns,
                        arp_table=arp_cache,
                        timeout_sec=self.config.timeout,
                    ): ip
                    for ip in target_ips
                }

                completed_count = 0
                for future in as_completed(future_to_ip):
                    if self.is_cancelled.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        return self.report

                    ip = future_to_ip[future]
                    completed_count += 1
                    try:
                        is_alive, hostname, mac, vendor, os_guess, ttl, latency = future.result()
                        if is_alive:
                            host_res = HostResult(
                                ip=ip,
                                status="up",
                                hostname=hostname,
                                mac_address=mac,
                                mac_vendor=vendor,
                                os_guess=os_guess,
                                ttl=ttl,
                                latency_ms=latency,
                            )
                            alive_hosts[ip] = host_res
                            label = f"{ip}" + (f" ({hostname})" if hostname else "")
                            os_label = f" [{os_guess}]" if os_guess else ""
                            self.emit(
                                ScanProgressEvent(
                                    type="host_discovered",
                                    message=f"[+] Active host: {label}{os_label}",
                                    percent=10.0 + (completed_count / total_targets) * 20.0,
                                    payload=host_res.model_dump(),
                                )
                            )
                    except Exception:
                        pass

                    progress_pct = 10.0 + (completed_count / total_targets) * 20.0
                    if completed_count % 5 == 0 or completed_count == total_targets:
                        self.emit(
                            ScanProgressEvent(
                                type="status",
                                message=f"Discovery: {completed_count}/{total_targets} hosts verified",
                                percent=progress_pct,
                            )
                        )
        else:
            for ip in target_ips:
                _, hostname, mac, vendor, os_guess, ttl, latency = discover_host_details(
                    ip,
                    ping_enabled=self.config.ping_discovery,
                    resolve_dns=self.config.resolve_dns,
                    arp_table=arp_cache,
                    timeout_sec=self.config.timeout,
                )
                alive_hosts[ip] = HostResult(
                    ip=ip,
                    status="up",
                    hostname=hostname,
                    mac_address=mac,
                    mac_vendor=vendor,
                    os_guess=os_guess,
                    ttl=ttl,
                    latency_ms=latency,
                )

        hosts_to_scan = list(alive_hosts.values())
        if not hosts_to_scan:
            self.emit(
                ScanProgressEvent(
                    type="log",
                    message="[-] No responsive hosts found during discovery phase.",
                    percent=90.0,
                )
            )

        # Phase 2: Port Scanning, Version Fingerprinting, and Risk Auditing
        self.emit(
            ScanProgressEvent(
                type="log",
                message=f"[*] Phase 2: Auditing open ports, service versions & compliance for {len(hosts_to_scan)} active host(s)...",
                percent=35.0,
            )
        )

        completed_hosts = 0
        total_open_ports = 0
        total_risks = {"high": 0, "medium": 0, "warning": 0, "info": 0}

        for host in hosts_to_scan:
            if self.is_cancelled.is_set():
                return self.report

            open_port_numbers = scan_ports_for_host(
                host.ip,
                target_ports,
                timeout=self.config.timeout,
                workers=self.config.threads,
                stop_check=self.is_cancelled.is_set,
            )

            port_results: List[PortResult] = []
            os_hints: List[str] = []

            for p in open_port_numbers:
                if self.is_cancelled.is_set():
                    return self.report
                port_res, os_hint = inspect_open_port(
                    host.ip,
                    p,
                    banner_grab_enabled=self.config.banner_grab,
                    timeout=self.config.timeout,
                )
                port_results.append(port_res)
                if os_hint:
                    os_hints.append(os_hint)
                total_open_ports += 1

                version_str = f" v{port_res.version}" if port_res.version else ""
                sw_str = f" [{port_res.software}{version_str}]" if port_res.software else ""
                risk_tag = f" <{port_res.risk_level.upper()}>" if port_res.risk_level != "info" else ""
                self.emit(
                    ScanProgressEvent(
                        type="log",
                        message=f"    --> {host.ip}:{p} open ({port_res.service}){sw_str}{risk_tag}",
                        percent=min(95.0, 35.0 + (completed_hosts / max(1, len(hosts_to_scan))) * 60.0),
                    )
                )

            # Refine OS guess if banner gave more specific distro/OS details
            if os_hints:
                host.os_guess = os_hints[0]
                host.os_details = f"Refined via banner: {', '.join(set(os_hints))}"

            # Calculate host security scorecard
            score, grade, counts = calculate_security_posture(port_results)
            host.security_score = score
            host.security_grade = grade
            host.risk_counts = counts
            host.open_ports = port_results

            for k in total_risks:
                total_risks[k] += counts.get(k, 0)

            completed_hosts += 1
            progress_pct = min(95.0, 35.0 + (completed_hosts / max(1, len(hosts_to_scan))) * 60.0)

            self.emit(
                ScanProgressEvent(
                    type="host_scanned",
                    message=f"[✓] Audited {host.ip} | Security Score: {score}/100 (Grade: {grade}) | {len(port_results)} open ports",
                    percent=progress_pct,
                    payload=host.model_dump(),
                )
            )

        # Final aggregate assessment
        elapsed = time.perf_counter() - start_time
        self.report.completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report.duration_seconds = round(elapsed, 2)
        self.report.active_hosts_count = len(hosts_to_scan)
        self.report.total_open_ports = total_open_ports
        self.report.hosts = hosts_to_scan
        self.report.total_risk_counts = total_risks

        # Overall network posture score
        if hosts_to_scan:
            avg_score = int(sum(h.security_score for h in hosts_to_scan) / len(hosts_to_scan))
            self.report.average_security_score = avg_score
            if avg_score >= 95:
                overall_grade = "A+"
            elif avg_score >= 88:
                overall_grade = "A"
            elif avg_score >= 75:
                overall_grade = "B"
            elif avg_score >= 60:
                overall_grade = "C"
            elif avg_score >= 45:
                overall_grade = "D"
            else:
                overall_grade = "F"
            self.report.overall_posture_grade = overall_grade

        self.report.status = "completed"

        self.emit(
            ScanProgressEvent(
                type="complete",
                message=f"[★] Audit complete in {elapsed:.2f}s! Overall Network Grade: {self.report.overall_posture_grade} ({self.report.average_security_score}/100).",
                percent=100.0,
                payload=self.report.model_dump(),
            )
        )
        return self.report


class ScannerEngine:
    def __init__(self):
        self.jobs: Dict[str, ScanJob] = {}
        self.history: List[ScanReport] = []
        self._lock = threading.Lock()

    def start_job(self, config: ScanJobConfig) -> ScanJob:
        job = ScanJob(config)
        with self._lock:
            self.jobs[job.job_id] = job

        def runner():
            report = job.run_sync()
            with self._lock:
                self.history.insert(0, report)
                if len(self.history) > 50:
                    self.history.pop()

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        return job

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self.jobs.get(job_id)

    def get_report(self, job_id: str) -> Optional[ScanReport]:
        with self._lock:
            if job_id in self.jobs:
                return self.jobs[job_id].report
            for item in self.history:
                if item.job_id == job_id:
                    return item
        return None

    def cancel_job(self, job_id: str) -> bool:
        job = self.get_job(job_id)
        if job and job.report.status == "running":
            job.cancel()
            return True
        return False

    def get_history(self) -> List[ScanReport]:
        with self._lock:
            return list(self.history)


engine = ScannerEngine()
