"""
Core package initialization for SQLi Detection and Mitigation Engine.
"""

from .vulnerable_service import VulnerableService
from .mitigated_service import MitigatedService
from .query_analyzer import QueryAnalyzer
from .sast_scanner import SASTScanner

__all__ = [
    "VulnerableService",
    "MitigatedService",
    "QueryAnalyzer",
    "SASTScanner"
]
