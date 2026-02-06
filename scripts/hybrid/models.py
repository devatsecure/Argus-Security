"""
Hybrid Security Analysis Data Models.

This module contains the core dataclass definitions used across the hybrid
security analysis pipeline. Extracted from hybrid_analyzer.py for better
modularity and reusability.

Classes:
    HybridFinding: Unified finding from multiple security tools
    HybridScanResult: Aggregated results from hybrid security scan
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class HybridFinding:
    """Unified finding from multiple security tools"""

    finding_id: str
    source_tool: str  # 'semgrep', 'trivy', 'checkov', 'api-security', 'dast', 'argus'
    severity: str  # 'critical', 'high', 'medium', 'low'
    category: str  # 'security', 'quality', 'performance'
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploitability: Optional[str] = None  # 'trivial', 'moderate', 'complex', 'theoretical'
    recommendation: Optional[str] = None
    references: list[str] = None
    confidence: float = 1.0
    llm_enriched: bool = False
    sandbox_validated: bool = False
    iris_verified: bool = False  # IRIS semantic analysis verification
    iris_confidence: Optional[float] = None  # IRIS confidence score (0.0-1.0)
    iris_verdict: Optional[str] = None  # 'true_positive', 'false_positive', 'uncertain'

    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class HybridScanResult:
    """Results from hybrid security scan"""

    target_path: str
    scan_timestamp: str
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_source: dict[str, int]
    findings: list[HybridFinding]
    scan_duration_seconds: float
    cost_usd: float
    phase_timings: dict[str, float]
    tools_used: list[str]
    llm_enrichment_enabled: bool


__all__ = ["HybridFinding", "HybridScanResult"]
