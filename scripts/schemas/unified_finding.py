"""
Unified Finding Schema - Strict Pydantic v2 validation

This is the core schema for all security findings in Argus.
All normalizers must output findings in this format.

Key fixes:
- Path must be a valid Path object, never empty or "."
- CWE must match pattern CWE-\d+
- All optional fields properly typed
- Validators ensure data consistency
"""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    """Standard severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Finding category/source"""
    SAST = "SAST"
    SECRETS = "SECRETS"
    DEPS = "DEPS"
    IAC = "IAC"
    FUZZ = "FUZZ"
    RUNTIME = "RUNTIME"
    DAST = "DAST"
    CONTAINER = "CONTAINER"
    UNKNOWN = "UNKNOWN"


class AssetType(str, Enum):
    """Type of asset being scanned"""
    CODE = "code"
    IMAGE = "image"
    IAC = "iac"
    BINARY = "binary"
    CONFIG = "config"
    CONTAINER = "container"


class Reachability(str, Enum):
    """Code reachability status"""
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class Exploitability(str, Enum):
    """Exploit difficulty"""
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    COMPLEX = "complex"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"


class SecretVerified(str, Enum):
    """Secret verification status"""
    TRUE = "true"
    FALSE = "false"
    NA = "na"


class ServiceTier(str, Enum):
    """Service exposure tier"""
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"


class FindingStatus(str, Enum):
    """Finding lifecycle status"""
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class UnifiedFinding(BaseModel):
    """
    Unified security finding format for all scanners.

    This schema enforces strict validation to prevent data format issues:
    - Path validation: Never empty, never ".", must be valid path
    - CWE validation: Must match pattern CWE-\d+
    - Enum validation: Uses enums for all status fields
    - Required fields: id, origin, repo, commit_sha, branch, path, asset_type
    """

    # ========== Identity (Required) ==========
    id: str = Field(..., min_length=1, description="Unique finding ID (SHA256 hash)")
    origin: str = Field(..., min_length=1, description="Scanner that generated finding")

    # ========== Context (Required) ==========
    repo: str = Field(..., min_length=1, description="Repository identifier")
    commit_sha: str = Field(..., min_length=1, description="Git commit SHA")
    branch: str = Field(..., min_length=1, description="Git branch name")

    # ========== Asset (Required) ==========
    path: Path = Field(..., description="File/resource path (never empty)")
    asset_type: AssetType = Field(default=AssetType.CODE, description="Type of asset")

    # ========== Classification (Optional) ==========
    rule_id: str = Field(default="", description="Scanner rule/check ID")
    rule_name: str = Field(default="", description="Human-readable rule name")
    category: Category = Field(default=Category.UNKNOWN, description="Finding category")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity level")

    # ========== Optional Metadata ==========
    pr_number: Optional[int] = Field(default=None, ge=1, description="Pull request number")
    line: Optional[int] = Field(default=None, ge=1, description="Line number in file")
    resource_id: Optional[str] = Field(default=None, description="Cloud resource ID")

    # ========== Risk Metrics ==========
    cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS score")
    cve: Optional[str] = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$", description="CVE identifier")
    cwe: Optional[str] = Field(default=None, pattern=r"^CWE-\d+$", description="CWE identifier")
    stride: Optional[str] = Field(default=None, description="STRIDE threat category")

    # ========== Evidence ==========
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evidence data (message, snippet, etc.)"
    )
    references: List[str] = Field(
        default_factory=list,
        description="Reference URLs"
    )

    # ========== Enrichment ==========
    reachability: Reachability = Field(
        default=Reachability.UNKNOWN,
        description="Code reachability status"
    )
    exploitability: Exploitability = Field(
        default=Exploitability.UNKNOWN,
        description="Exploit difficulty"
    )
    secret_verified: SecretVerified = Field(
        default=SecretVerified.NA,
        description="Secret verification status"
    )

    # ========== Ownership ==========
    owner_team: Optional[str] = Field(default=None, description="Owning team")
    service_tier: ServiceTier = Field(
        default=ServiceTier.INTERNAL,
        description="Service exposure tier"
    )

    # ========== Computed Risk ==========
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Computed risk score"
    )

    # ========== Noise & Intelligence ==========
    noise_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="False positive probability"
    )
    false_positive_probability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="ML-based FP prediction"
    )
    historical_fix_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Historical fix rate for similar findings"
    )
    correlation_group_id: Optional[str] = Field(
        default=None,
        description="Links related findings"
    )

    # ========== Business Context ==========
    business_context: Dict[str, Any] = Field(
        default_factory=lambda: {
            "service_tier": "internal",
            "exposure": "internal",
            "data_classification": "public",
        },
        description="Business context metadata"
    )

    # ========== Suppression ==========
    suppression_id: Optional[str] = Field(default=None, description="Suppression ID")
    suppression_expires_at: Optional[str] = Field(default=None, description="Suppression expiry")
    suppression_reason: Optional[str] = Field(default=None, description="Suppression reason")

    # ========== Auto-fix ==========
    auto_fixable: bool = Field(default=False, description="Can be auto-fixed")
    fix_suggestion: Optional[str] = Field(default=None, description="Fix suggestion")
    fix_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Fix confidence score"
    )

    # ========== Timestamps ==========
    first_seen_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="First seen timestamp"
    )
    last_seen_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Last seen timestamp"
    )

    # ========== Status ==========
    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Finding lifecycle status"
    )

    # ========== Metadata ==========
    llm_enriched: bool = Field(default=False, description="LLM enriched")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Finding confidence"
    )

    # ========== Validators ==========

    @field_validator('path')
    @classmethod
    def validate_path_not_empty(cls, v: Path) -> Path:
        """Ensure path is not empty or current directory"""
        if not v or str(v) == "." or str(v) == "":
            raise ValueError("Path cannot be empty or '.'")
        return v

    @field_validator('id', 'origin', 'repo', 'commit_sha', 'branch')
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        """Ensure required string fields are not empty"""
        if not v or v.strip() == "":
            raise ValueError("Field cannot be empty")
        return v

    @field_validator('cve')
    @classmethod
    def validate_cve_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate CVE format"""
        if v is not None and not v.startswith("CVE-"):
            raise ValueError(f"Invalid CVE format: {v}. Must start with 'CVE-'")
        return v

    @field_validator('cwe')
    @classmethod
    def validate_cwe_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate CWE format"""
        if v is not None and not v.startswith("CWE-"):
            raise ValueError(f"Invalid CWE format: {v}. Must start with 'CWE-'")
        return v

    @model_validator(mode='after')
    def calculate_risk_if_zero(self):
        """Auto-calculate risk score if not set"""
        if self.risk_score == 0.0:
            self.risk_score = self.calculate_risk_score()
        return self

    # ========== Methods ==========

    def calculate_risk_score(self) -> float:
        """
        Calculate risk score using formula:
        score = base(CVSS|severity) + 3*exploitability + 2*reachability + exposure + secret_boost
        """
        # Base score (0-10)
        if self.cvss:
            base = self.cvss
        else:
            severity_map = {
                Severity.CRITICAL: 9.0,
                Severity.HIGH: 7.0,
                Severity.MEDIUM: 4.5,
                Severity.LOW: 2.0,
                Severity.INFO: 0.5,
            }
            base = severity_map.get(self.severity, 0.0)

        # Exploitability multiplier (0-3)
        exploit_map = {
            Exploitability.TRIVIAL: 1.0,
            Exploitability.MODERATE: 0.7,
            Exploitability.COMPLEX: 0.4,
            Exploitability.THEORETICAL: 0.1,
            Exploitability.UNKNOWN: 0.5,
        }
        exploit_score = 3.0 * exploit_map.get(self.exploitability, 0.5)

        # Reachability multiplier (0-2)
        reach_map = {
            Reachability.YES: 1.0,
            Reachability.NO: 0.0,
            Reachability.UNKNOWN: 0.5,
        }
        reach_score = 2.0 * reach_map.get(self.reachability, 0.5)

        # Exposure (0-2)
        exposure_map = {
            ServiceTier.PUBLIC: 2.0,
            ServiceTier.INTERNAL: 1.0,
            ServiceTier.PRIVATE: 0.5,
        }
        exposure_score = exposure_map.get(self.service_tier, 1.0)

        # Secret boost (+5 if verified)
        secret_boost = 5.0 if self.secret_verified == SecretVerified.TRUE else 0.0

        # Final score (capped at 10.0)
        score = base + exploit_score + reach_score + exposure_score + secret_boost
        return min(score, 10.0)

    def dedup_key(self) -> str:
        """Generate SHA256 deduplication key"""
        key_string = f"{self.repo}:{self.path}:{self.rule_id}:{self.line or 0}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = self.model_dump()
        # Convert Path to string
        data["path"] = str(data["path"])
        # Convert enums to values
        for key, value in data.items():
            if isinstance(value, Enum):
                data[key] = value.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnifiedFinding":
        """Create UnifiedFinding from dictionary"""
        return cls(**data)

    model_config = {
        "use_enum_values": True,
        "validate_assignment": True,
        "str_strip_whitespace": True,
    }
