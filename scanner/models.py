from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PortResult(BaseModel):
    port: int
    state: str = "open"
    protocol: str = "tcp"
    service: str = "unknown"
    software: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    risk_level: str = "info"  # "info", "low", "medium", "high"
    risk_title: Optional[str] = None
    risk_description: Optional[str] = None
    remediation: Optional[str] = None
    compliance_tag: Optional[str] = None


class HostResult(BaseModel):
    ip: str
    status: str = "up"  # "up" or "down"
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    os_guess: Optional[str] = None  # e.g., "Microsoft Windows 10/11", "Ubuntu Linux", etc.
    os_details: Optional[str] = None
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    security_score: int = 100  # 0 to 100
    security_grade: str = "A"  # A+, A, B, C, D, F
    risk_counts: Dict[str, int] = Field(default_factory=lambda: {"high": 0, "medium": 0, "warning": 0, "info": 0})
    open_ports: List[PortResult] = Field(default_factory=list)


class ScanJobConfig(BaseModel):
    target: str
    port_selection: str = "top20"  # "top20", "top100", "top1000", "web_db", "1-1024", "all_ports", or custom
    custom_ports: Optional[str] = None
    ping_discovery: bool = True
    banner_grab: bool = True
    resolve_dns: bool = True
    timeout: float = 0.4
    threads: int = 50
    max_hosts: int = 512


class ScanProgressEvent(BaseModel):
    type: str  # "status", "host_discovered", "host_scanned", "log", "complete", "cancelled", "error"
    message: str
    percent: float = 0.0
    payload: Optional[Dict[str, Any]] = None


class ScanReport(BaseModel):
    job_id: str
    target: str
    config: ScanJobConfig
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    total_targets: int = 0
    active_hosts_count: int = 0
    total_open_ports: int = 0
    average_security_score: int = 100
    overall_posture_grade: str = "A"
    total_risk_counts: Dict[str, int] = Field(default_factory=lambda: {"high": 0, "medium": 0, "warning": 0, "info": 0})
    status: str = "running"  # "running", "completed", "cancelled", "failed"
    error_message: Optional[str] = None
    hosts: List[HostResult] = Field(default_factory=list)
