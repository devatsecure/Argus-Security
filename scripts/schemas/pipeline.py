"""
Pipeline Schemas - Typed models for data flowing between pipeline stages.

These models replace dict[str, Any] at phase boundaries, enabling:
- Compile-time type checking (via mypy / pyright)
- Runtime validation at phase transitions
- Clear documentation of stage inputs/outputs

Models defined here bridge the heterogeneous finding types already present
in the codebase (UnifiedFinding, normalizer.Finding, HybridFinding, raw
consensus dicts) into a single typed pipeline representation.

Hierarchy:
    EvidenceData          - replaces Dict[str, Any] evidence field
    BusinessContext       - replaces Dict[str, Any] business_context
    ConsensusResult       - replaces untyped consensus dict in consensus_builder
    AgentVerdictSummary   - multi-agent verdict output
    SandboxResult         - Phase 4 sandbox output
    PipelineFinding       - extends UnifiedFinding with cross-phase fields
    PipelineMetadata      - metadata about a pipeline run
    PipelineResult        - full pipeline output envelope
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from .unified_finding import (
    AssetType,
    Category,
    Severity,
    UnifiedFinding,
)


# ---------------------------------------------------------------------------
# Evidence & context sub-models
# ---------------------------------------------------------------------------


class EvidenceData(BaseModel):
    """Typed replacement for the ``Dict[str, Any]`` evidence blobs attached
    to findings.

    The ``extra = "allow"`` policy lets scanners attach additional keys
    without breaking validation, preserving forward compatibility.
    """

    message: str = ""
    snippet: str = ""
    artifact_url: str = ""
    code: Optional[str] = None  # alternate name used by some agents
    url: Optional[str] = None  # used by DAST findings
    method: Optional[str] = None  # HTTP method, used by DAST findings
    poc: Optional[str] = None  # proof-of-concept, used by DAST/sandbox

    model_config = {"extra": "allow"}


class BusinessContext(BaseModel):
    """Typed replacement for the ``Dict[str, Any]`` business_context field.

    Captures organisational metadata used by the risk-scoring and policy
    engines to adjust finding priority.
    """

    service_tier: str = "internal"
    exposure: str = "internal"
    data_classification: str = "public"

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Phase 3 - Consensus & multi-agent models
# ---------------------------------------------------------------------------


class ConsensusResult(BaseModel):
    """Typed representation of the consensus dict produced by
    ``ConsensusBuilder.aggregate_findings`` (consensus_builder.py).

    Previously stored as a plain ``dict`` under ``finding["consensus"]``.
    """

    votes: int
    total_agents: int
    consensus_level: str  # unanimous / strong / majority / weak
    confidence: float = Field(ge=0.0, le=1.0)
    agents_agree: List[str]
    all_descriptions: List[str] = Field(default_factory=list)

    @field_validator("consensus_level")
    @classmethod
    def validate_consensus_level(cls, v: str) -> str:
        """Ensure consensus_level is one of the known levels."""
        allowed = {"unanimous", "strong", "majority", "weak"}
        if v not in allowed:
            raise ValueError(
                f"consensus_level must be one of {allowed}, got '{v}'"
            )
        return v


class AgentVerdictSummary(BaseModel):
    """Structured output from multi-agent persona review (Phase 3).

    Aggregates individual agent verdicts into a single summary with
    confidence, reasoning, and actionable recommendations.
    """

    verdict: str  # confirmed / likely_true / uncertain / likely_false / false_positive
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    agreement_level: str
    agent_verdicts: Dict[str, str] = Field(default_factory=dict)
    agents_analyzed: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        """Ensure verdict is one of the recognised labels."""
        allowed = {
            "confirmed",
            "likely_true",
            "uncertain",
            "likely_false",
            "false_positive",
        }
        if v not in allowed:
            raise ValueError(
                f"verdict must be one of {allowed}, got '{v}'"
            )
        return v


# ---------------------------------------------------------------------------
# Phase 4 - Sandbox validation
# ---------------------------------------------------------------------------


class SandboxResult(BaseModel):
    """Typed output of Phase 4 Docker-based sandbox validation.

    Replaces the unstructured dict previously returned by
    ``sandbox_validator.py``.
    """

    validated: bool = False
    result: Optional[str] = None  # exploitable / not_exploitable / partial / error
    execution_time_ms: Optional[int] = None
    indicators_found: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None

    @field_validator("result")
    @classmethod
    def validate_result(cls, v: Optional[str]) -> Optional[str]:
        """Ensure result is one of the known outcomes when set."""
        if v is not None:
            allowed = {"exploitable", "not_exploitable", "partial", "error"}
            if v not in allowed:
                raise ValueError(
                    f"result must be one of {allowed}, got '{v}'"
                )
        return v


# ---------------------------------------------------------------------------
# PipelineFinding - the superset finding model
# ---------------------------------------------------------------------------


class PipelineFinding(UnifiedFinding):
    """Cross-phase finding that extends ``UnifiedFinding`` with fields
    produced by later pipeline stages (consensus, multi-agent review,
    sandbox validation, IRIS analysis).

    This is the canonical finding type that flows from Phase 2 onward.
    Earlier phases may still produce ``HybridFinding`` or normalizer
    ``Finding`` instances -- use the ``from_hybrid_finding`` and
    ``from_normalizer_finding`` class methods to convert them.

    The ``extra = "allow"`` policy ensures that ad-hoc scanner metadata
    survives round-trips without explicit schema changes.
    """

    # Fields present on HybridFinding but absent from UnifiedFinding
    title: str = ""
    description: str = ""
    recommendation: Optional[str] = None

    # Phase 3 - Consensus
    consensus: Optional[ConsensusResult] = None

    # Phase 3 - Multi-agent verdict
    agent_verdict: Optional[AgentVerdictSummary] = None

    # Phase 4 - Sandbox validation
    sandbox: Optional[SandboxResult] = None

    # IRIS semantic analysis
    iris_verified: bool = False
    iris_confidence: Optional[float] = None
    iris_verdict: Optional[str] = None

    model_config = {
        "extra": "allow",
        "use_enum_values": True,
        "validate_assignment": True,
    }

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_hybrid_finding(cls, hf: Any) -> "PipelineFinding":
        """Convert a ``HybridFinding`` dataclass (hybrid_analyzer.py) into a
        ``PipelineFinding``.

        Field mapping (HybridFinding -> UnifiedFinding/PipelineFinding):
            finding_id   -> id
            source_tool  -> origin
            file_path    -> path
            line_number  -> line
            cwe_id       -> cwe
            cve_id       -> cve
            cvss_score   -> cvss
        """
        from dataclasses import asdict

        raw = asdict(hf) if hasattr(hf, "__dataclass_fields__") else dict(hf)

        # HybridFinding uses informal category names ("security", "quality",
        # "performance") while UnifiedFinding expects the Category enum
        # ("SAST", "SECRETS", etc.).  Map known values; default to UNKNOWN.
        _category_map = {
            "security": "SAST",
            "quality": "SAST",
            "performance": "SAST",
            "sast": "SAST",
            "secrets": "SECRETS",
            "deps": "DEPS",
            "iac": "IAC",
            "fuzz": "FUZZ",
            "runtime": "RUNTIME",
            "dast": "DAST",
            "container": "CONTAINER",
        }
        raw_category = raw.get("category", "UNKNOWN")
        normalised_category = _category_map.get(
            raw_category.lower(), raw_category.upper()
        )

        mapped: Dict[str, Any] = {
            # Identity
            "id": raw.get("finding_id", ""),
            "origin": raw.get("source_tool", "unknown"),
            # Context -- HybridFinding may not carry these; use sensible
            # defaults that satisfy UnifiedFinding's required-field constraints.
            "repo": raw.get("repo", "unknown"),
            "commit_sha": raw.get("commit_sha", "unknown"),
            "branch": raw.get("branch", "unknown"),
            # Asset
            "path": raw.get("file_path", "unknown"),
            # Classification
            "severity": raw.get("severity", "medium"),
            "category": normalised_category,
            # Optional metadata
            "line": raw.get("line_number"),
            "cwe": raw.get("cwe_id"),
            "cve": raw.get("cve_id"),
            "cvss": raw.get("cvss_score"),
            # HybridFinding-specific
            "title": raw.get("title", ""),
            "description": raw.get("description", ""),
            "recommendation": raw.get("recommendation"),
            "confidence": raw.get("confidence", 1.0),
            "llm_enriched": raw.get("llm_enriched", False),
            "references": raw.get("references") or [],
            "exploitability": raw.get("exploitability", "unknown"),
            # IRIS fields
            "iris_verified": raw.get("iris_verified", False),
            "iris_confidence": raw.get("iris_confidence"),
            "iris_verdict": raw.get("iris_verdict"),
        }

        return cls(**mapped)

    @classmethod
    def from_normalizer_finding(cls, f: Any) -> "PipelineFinding":
        """Convert a normalizer ``Finding`` dataclass (normalizer/base.py)
        into a ``PipelineFinding``.

        The normalizer Finding mirrors UnifiedFinding field names, so the
        mapping is essentially 1:1.
        """
        from dataclasses import asdict

        raw = asdict(f) if hasattr(f, "__dataclass_fields__") else dict(f)

        return cls(**raw)


# ---------------------------------------------------------------------------
# Pipeline-level metadata & result envelope
# ---------------------------------------------------------------------------


class PipelineMetadata(BaseModel):
    """Metadata about a single pipeline execution.

    Captures timing, cost, model selection, and high-level summaries that
    are useful for observability dashboards and audit logs.
    """

    version: str = "1.0.0"
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    repository: str = ""
    commit: str = ""
    branch: str = ""
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    model: str = ""
    provider: str = ""
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    categories_summary: Dict[str, int] = Field(default_factory=dict)
    phase_timings: Dict[str, float] = Field(default_factory=dict)
    tools_used: List[str] = Field(default_factory=list)
    agents_executed: List[str] = Field(default_factory=list)
    policy_decision: Optional[str] = None


class PipelineResult(BaseModel):
    """Top-level envelope for the complete output of a pipeline run.

    Contains the list of validated ``PipelineFinding`` objects, execution
    metadata, and optional policy-gate / raw-scan payloads for downstream
    consumers.
    """

    findings: List[PipelineFinding]
    metadata: PipelineMetadata
    policy_gate_result: Optional[Dict[str, Any]] = None
    raw_scan_result: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def findings_by_severity(self) -> Dict[str, int]:
        """Return a dict counting findings per severity level."""
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def findings_by_source(self) -> Dict[str, int]:
        """Return a dict counting findings per origin / source_tool."""
        counts: Dict[str, int] = {}
        for f in self.findings:
            origin = f.origin
            counts[origin] = counts.get(origin, 0) + 1
        return counts

    def critical_findings(self) -> List[PipelineFinding]:
        """Return all findings with critical severity."""
        return [
            f
            for f in self.findings
            if (f.severity if isinstance(f.severity, str) else f.severity.value)
            == "critical"
        ]
