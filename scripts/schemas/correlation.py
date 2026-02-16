"""
Correlation Schemas - SAST/DAST correlation pipeline validation

Validates input/output for the SAST-DAST correlation engine.

Fixes:
- Validates SAST findings have all required fields
- Validates DAST findings have all required fields
- Ensures correlation results have proper structure
"""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class CorrelationStatus(str, Enum):
    """Status of SAST-DAST correlation"""
    CONFIRMED = "confirmed"  # DAST verified SAST finding is exploitable
    PARTIAL = "partial"  # Similar but not exact match
    NOT_VERIFIED = "not_verified"  # Couldn't verify (might be FP)
    NO_DAST_COVERAGE = "no_dast_coverage"  # No DAST test for this endpoint


class ExploitabilityLevel(str, Enum):
    """Exploit difficulty levels"""
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    COMPLEX = "complex"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"


class CorrelationFindingInput(BaseModel):
    """
    Finding input for correlation (SAST or DAST).
    Validates that finding has all required fields for correlation.
    """
    id: str = Field(..., min_length=1, description="Finding ID")
    path: str = Field(..., min_length=1, description="File path or URL")
    rule_id: str = Field(default="", description="Rule identifier")
    rule_name: str = Field(default="", description="Rule name")
    severity: str = Field(default="medium", description="Severity")
    cwe: Optional[str] = Field(default=None, description="CWE identifier")
    category: str = Field(default="UNKNOWN", description="Finding category")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Evidence data (message, url, method, poc, etc.)"
    )

    @field_validator('id')
    @classmethod
    def validate_id_not_empty(cls, v: str) -> str:
        """Ensure ID is not empty"""
        if not v or v.strip() == "":
            raise ValueError("Finding ID cannot be empty")
        return v

    @field_validator('path')
    @classmethod
    def validate_path_not_empty(cls, v: str) -> str:
        """
        Ensure path is not empty.
        Fixes: SAST findings had empty file paths causing correlation failures
        """
        if not v or v.strip() == "" or v == ".":
            raise ValueError("Path cannot be empty or '.'")
        return v

    model_config = {"extra": "allow"}


class CorrelationInput(BaseModel):
    """
    Input for correlation engine.
    Validates both SAST and DAST findings before correlation.
    """
    sast_findings: list[dict[str, Any]] = Field(
        ...,
        min_length=0,
        description="List of SAST findings (normalized format)"
    )
    dast_findings: list[dict[str, Any]] = Field(
        ...,
        min_length=0,
        description="List of DAST findings (normalized format)"
    )
    use_ai: bool = Field(default=True, description="Use AI for verification")

    @field_validator('sast_findings')
    @classmethod
    def validate_sast_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate each SAST finding has required fields"""
        for i, finding in enumerate(v):
            try:
                CorrelationFindingInput(**finding)
            except Exception as e:
                raise ValueError(f"SAST finding {i} validation failed: {e}") from e
        return v

    @field_validator('dast_findings')
    @classmethod
    def validate_dast_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate each DAST finding has required fields"""
        for i, finding in enumerate(v):
            try:
                CorrelationFindingInput(**finding)
            except Exception as e:
                raise ValueError(f"DAST finding {i} validation failed: {e}") from e
        return v


class FindingSummary(BaseModel):
    """Summary of a finding for correlation results"""
    id: str = Field(..., min_length=1)
    type: str = Field(default="unknown")
    path: str = Field(..., min_length=1)
    severity: str = Field(default="medium")
    cwe: Optional[str] = Field(default=None)


class CorrelationResult(BaseModel):
    """Result of correlating SAST and DAST findings"""
    sast_finding_id: str = Field(..., min_length=1, description="SAST finding ID")
    dast_finding_id: Optional[str] = Field(default=None, description="Matched DAST finding ID")
    status: CorrelationStatus = Field(..., description="Correlation status")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    exploitability: ExploitabilityLevel = Field(..., description="Exploitability level")
    reasoning: str = Field(..., min_length=1, description="Reasoning for correlation")
    poc_exploit: Optional[str] = Field(default=None, description="Proof of concept")
    match_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Match similarity score")
    sast_summary: Optional[dict[str, Any]] = Field(default=None, description="SAST finding summary")
    dast_summary: Optional[dict[str, Any]] = Field(default=None, description="DAST finding summary")

    @field_validator('reasoning')
    @classmethod
    def validate_reasoning_not_empty(cls, v: str) -> str:
        """Ensure reasoning is not empty"""
        if not v or v.strip() == "":
            raise ValueError("Reasoning cannot be empty")
        return v

    model_config = {"use_enum_values": True}


class CorrelationMetadata(BaseModel):
    """Metadata about correlation run"""
    total_findings: int = Field(..., ge=0)
    confirmed: int = Field(default=0, ge=0)
    partial: int = Field(default=0, ge=0)
    not_verified: int = Field(default=0, ge=0)
    no_coverage: int = Field(default=0, ge=0)


class CorrelationOutput(BaseModel):
    """
    Output from correlation engine.
    Ensures all correlation results have proper structure.
    """
    metadata: CorrelationMetadata = Field(..., description="Summary statistics")
    correlations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of correlation results"
    )

    @field_validator('correlations')
    @classmethod
    def validate_correlation_results(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate each correlation result"""
        for i, result in enumerate(v):
            try:
                CorrelationResult(**result)
            except Exception as e:
                raise ValueError(f"Correlation result {i} validation failed: {e}") from e
        return v

    model_config = {"extra": "allow"}
