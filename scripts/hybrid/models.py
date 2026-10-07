"""
Hybrid Security Analysis Data Models.

This module contains the core dataclass definitions used across the hybrid
security analysis pipeline. Extracted from hybrid_analyzer.py for better
modularity and reusability.

Classes:
    HybridFinding: Unified finding from multiple security tools
    HybridScanResult: Aggregated results from hybrid security scan
"""

from dataclasses import dataclass, field


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
    line_number: int | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    exploitability: str | None = None  # 'trivial', 'moderate', 'complex', 'theoretical'
    recommendation: str | None = None
    references: list[str] = None
    confidence: float = 1.0
    llm_enriched: bool = False
    sandbox_validated: bool = False
    iris_verified: bool = False  # IRIS semantic analysis verification
    iris_confidence: float | None = None  # IRIS confidence score (0.0-1.0)
    iris_verdict: str | None = None  # 'true_positive', 'false_positive', 'uncertain'
    secret_verified: bool = False
    reachability: str = "unknown"
    service_tier: str = "unknown"

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
    scanner_health: dict[str, str] = field(default_factory=dict)
    scan_status: str = "complete"
    policy_gate_result: dict | None = None
    vulnerability_chains: dict | None = None


__all__ = ["HybridFinding", "HybridScanResult"]
