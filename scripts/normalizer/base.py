"""Base classes for finding normalization"""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class Finding:
    """Unified finding format for all security tools"""

    # Identity
    id: str
    origin: str  # semgrep, trivy, trufflehog, gitleaks, checkov, argus

    # Context
    repo: str
    commit_sha: str
    branch: str

    # Asset
    path: str
    asset_type: str = "code"  # code, image, iac, binary, config

    # Classification
    rule_id: str = ""
    rule_name: str = ""
    category: str = "UNKNOWN"  # SAST, SECRETS, DEPS, IAC, FUZZ, RUNTIME
    severity: str = "medium"  # info, low, medium, high, critical

    # Optional fields with defaults
    pr_number: Optional[int] = None
    line: Optional[int] = None
    resource_id: Optional[str] = None

    # Risk metrics
    cvss: Optional[float] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    stride: Optional[str] = None

    # Evidence
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    # Enrichment
    reachability: str = "unknown"  # yes, no, unknown
    exploitability: str = "unknown"  # trivial, moderate, complex, theoretical, unknown
    secret_verified: str = "na"  # true, false, na

    # Ownership
    owner_team: Optional[str] = None
    service_tier: str = "internal"  # public, internal, private

    # Computed
    risk_score: float = 0.0

    # Noise & Intelligence (NEW - Phase 1)
    noise_score: float = 0.0  # 0-1, higher = more likely noise/FP
    false_positive_probability: float = 0.0  # ML-based FP prediction
    historical_fix_rate: float = 0.0  # % of similar findings that were fixed
    correlation_group_id: Optional[str] = None  # Links related findings

    # Business Context (NEW - Phase 1)
    business_context: dict[str, Any] = field(
        default_factory=lambda: {
            "service_tier": "internal",  # critical/high/medium/low
            "exposure": "internal",  # public/internal/private
            "data_classification": "public",  # pii/financial/public
        }
    )

    # Suppression (NEW - Phase 1)
    suppression_id: Optional[str] = None
    suppression_expires_at: Optional[str] = None
    suppression_reason: Optional[str] = None

    # Auto-fix (NEW - Phase 1)
    auto_fixable: bool = False
    fix_suggestion: Optional[str] = None
    fix_confidence: float = 0.0

    # Timestamps
    first_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Status
    status: str = "open"  # open, triaged, accepted, fixed, false_positive, suppressed

    # Metadata
    llm_enriched: bool = False
    confidence: float = 1.0

    def dedup_key(self) -> str:
        """Generate SHA256 deduplication key"""
        # Use repo, path, rule_id, line as unique identifier
        key_string = f"{self.repo}:{self.path}:{self.rule_id}:{self.line or 0}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create Finding from dictionary"""
        return cls(**data)

    def validate(self) -> bool:
        """
        Validate finding data integrity.

        Returns:
            True if valid

        Raises:
            ValueError: If finding has invalid data
        """
        if not self.path or self.path.strip() in ("", "."):
            raise ValueError("path cannot be empty")
        if not self.origin:
            raise ValueError("origin cannot be empty")
        if not self.id:
            raise ValueError("id cannot be empty")
        return True

    def to_pydantic(self):
        """
        Convert Finding to a pydantic-like object with attribute access.

        Returns:
            Object with finding attributes, or None if conversion fails
        """
        try:
            from types import SimpleNamespace

            data = self.to_dict()
            # Convert path to a Path-like object that supports str()
            ns = SimpleNamespace(**data)
            return ns
        except Exception:
            return None

    def calculate_risk_score(self) -> float:
        """
        Calculate risk score using PRD formula:
        score = base(CVSS|severity) + 3*exploitability + 2*reachability + exposure + secret_boost
        """
        # Base score (0-10)
        if self.cvss:
            base = self.cvss
        else:
            severity_map = {"critical": 9.0, "high": 7.0, "medium": 4.5, "low": 2.0, "info": 0.5}
            base = severity_map.get(self.severity, 0.0)

        # Exploitability multiplier (0-3)
        exploit_map = {"trivial": 1.0, "moderate": 0.7, "complex": 0.4, "theoretical": 0.1, "unknown": 0.5}
        exploit_score = 3.0 * exploit_map.get(self.exploitability, 0.5)

        # Reachability multiplier (0-2)
        reach_map = {"yes": 1.0, "no": 0.0, "unknown": 0.5}
        reach_score = 2.0 * reach_map.get(self.reachability, 0.5)

        # Exposure (0-2)
        exposure_map = {"public": 2.0, "internal": 1.0, "private": 0.5}
        exposure_score = exposure_map.get(self.service_tier, 1.0)

        # Secret boost (+5 if verified)
        secret_boost = 5.0 if self.secret_verified == "true" else 0.0

        # Final score (capped at 10.0)
        score = base + exploit_score + reach_score + exposure_score + secret_boost
        return min(score, 10.0)


class Normalizer(ABC):
    """Base class for tool-specific normalizers"""

    def __init__(self, validate_output: bool = False):
        self.origin = self.__class__.__name__.replace("Normalizer", "").lower()
        self.validate_output = validate_output

    @abstractmethod
    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert tool-specific output to Finding objects

        Args:
            raw_output: Raw JSON/dict from security tool

        Returns:
            List of Finding objects
        """
        pass

    def normalize_and_validate(self, raw_output: dict, validate_input: bool = True) -> list[Finding]:
        """
        Normalize and optionally validate findings.

        Args:
            raw_output: Raw JSON/dict from security tool
            validate_input: Whether to validate input data

        Returns:
            List of validated Finding objects
        """
        findings = self.normalize(raw_output)

        if self.validate_output:
            validated = []
            for finding in findings:
                try:
                    finding.validate()
                    validated.append(finding)
                except ValueError:
                    continue
            return validated

        return findings

    def _get_git_context(self) -> dict:
        """Get current git context (repo, commit, branch)"""
        import subprocess

        try:
            repo = subprocess.check_output(["git", "config", "--get", "remote.origin.url"], text=True).strip()

            commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()

            branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()

            return {"repo": repo, "commit_sha": commit_sha, "branch": branch}
        except Exception:
            return {"repo": "unknown", "commit_sha": "unknown", "branch": "unknown"}

    def _generate_id(self, finding_data: dict) -> str:
        """Generate unique ID for finding"""
        key = f"{finding_data.get('repo')}:{finding_data.get('path')}:{finding_data.get('rule_id')}:{finding_data.get('line', 0)}"
        return hashlib.sha256(key.encode()).hexdigest()
