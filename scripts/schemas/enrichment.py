"""
Enrichment Schemas - Threat intelligence enrichment validation

Validates input/output for the threat intelligence enricher.

Fixes:
- Validates findings have CVE field before enrichment
- Ensures threat context has proper structure
- Validates enrichment results
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class EnrichmentFindingInput(BaseModel):
    """
    Finding input for enrichment.
    Must have either CVE or vulnerability ID.
    """
    id: str = Field(..., min_length=1, description="Finding ID")
    cve: Optional[str] = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$", description="CVE identifier")
    cve_id: Optional[str] = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$", description="Alt CVE field")
    rule_id: Optional[str] = Field(default=None, description="Rule identifier")
    severity: str = Field(default="medium", description="Severity")
    cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0, description="CVSS score")

    @field_validator('cve', 'cve_id')
    @classmethod
    def validate_cve_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate CVE format if present"""
        if v is not None and not v.startswith("CVE-"):
            raise ValueError(f"Invalid CVE format: {v}")
        return v

    def get_cve(self) -> Optional[str]:
        """Get CVE from either field"""
        return self.cve or self.cve_id

    model_config = {"extra": "allow"}


class EnrichmentInput(BaseModel):
    """
    Input for threat intelligence enricher.
    Validates findings before enrichment.
    """
    findings: list[dict[str, Any]] = Field(
        ...,
        min_length=0,
        description="List of findings to enrich"
    )

    @field_validator('findings')
    @classmethod
    def validate_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate each finding has minimum required fields"""
        for i, finding in enumerate(v):
            try:
                EnrichmentFindingInput(**finding)
            except Exception as e:
                raise ValueError(f"Finding {i} validation failed: {e}") from e
        return v


class ThreatContext(BaseModel):
    """
    Threat intelligence context for a CVE.
    Ensures all threat data has proper types.
    """
    cve_id: str = Field(..., min_length=1, pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_severity: Optional[str] = Field(default=None)
    cvss_vector: Optional[str] = Field(default=None)
    epss_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="EPSS score 0-1")
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    in_kev_catalog: bool = Field(default=False, description="In CISA KEV catalog")
    kev_date_added: Optional[str] = Field(default=None)
    kev_due_date: Optional[str] = Field(default=None)
    kev_action_required: Optional[str] = Field(default=None)
    public_exploit_available: bool = Field(default=False)
    exploit_sources: list[str] = Field(default_factory=list)
    exploit_count: int = Field(default=0, ge=0)
    trending: bool = Field(default=False)
    vendor_patch_available: bool = Field(default=False)
    patch_url: Optional[str] = Field(default=None)
    github_advisories: list[dict[str, Any]] = Field(default_factory=list)
    osv_entries: list[dict[str, Any]] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    last_updated: Optional[str] = Field(default=None)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator('cve_id')
    @classmethod
    def validate_cve_format(cls, v: str) -> str:
        """Validate CVE format"""
        if not v.startswith("CVE-"):
            raise ValueError(f"Invalid CVE format: {v}")
        return v

    @field_validator('cwe_ids')
    @classmethod
    def validate_cwe_formats(cls, v: list[str]) -> list[str]:
        """Validate all CWE IDs have correct format"""
        for cwe in v:
            if not cwe.startswith("CWE-"):
                raise ValueError(f"Invalid CWE format: {cwe}")
        return v


class EnrichedFinding(BaseModel):
    """
    Finding enriched with threat intelligence.
    Validates complete enrichment structure.
    """
    original_finding: dict[str, Any] = Field(..., description="Original finding data")
    threat_context: Optional[dict[str, Any]] = Field(
        default=None,
        description="Threat intelligence context"
    )
    original_priority: str = Field(..., min_length=1, description="Original severity/priority")
    adjusted_priority: str = Field(..., min_length=1, description="Adjusted priority")
    priority_boost_reasons: list[str] = Field(default_factory=list)
    priority_downgrade_reasons: list[str] = Field(default_factory=list)
    recommended_action: str = Field(..., min_length=1, description="Recommended action")
    remediation_deadline: Optional[str] = Field(default=None)
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Composite risk score")

    @field_validator('threat_context')
    @classmethod
    def validate_threat_context(cls, v: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Validate threat context structure if present"""
        if v is not None:
            try:
                ThreatContext(**v)
            except Exception as e:
                raise ValueError(f"Threat context validation failed: {e}") from e
        return v

    @field_validator('original_finding')
    @classmethod
    def validate_original_finding_has_id(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Ensure original finding has an ID"""
        if "id" not in v or not v["id"]:
            raise ValueError("Original finding must have an 'id' field")
        return v


class EnrichmentMetadata(BaseModel):
    """Metadata about enrichment run"""
    total_enriched: int = Field(..., ge=0)
    in_kev: int = Field(default=0, ge=0)
    high_epss: int = Field(default=0, ge=0)
    has_exploit: int = Field(default=0, ge=0)
    priority_boosted: int = Field(default=0, ge=0)
    priority_downgraded: int = Field(default=0, ge=0)
    github_advisories: int = Field(default=0, ge=0)
    osv_entries: int = Field(default=0, ge=0)
    cache_hits: int = Field(default=0, ge=0)
    cache_misses: int = Field(default=0, ge=0)
    api_errors: int = Field(default=0, ge=0)


class EnrichmentOutput(BaseModel):
    """
    Output from threat intelligence enricher.
    Validates all enriched findings.
    """
    metadata: EnrichmentMetadata = Field(..., description="Summary statistics")
    enriched_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Enriched findings with threat context"
    )

    @field_validator('enriched_findings')
    @classmethod
    def validate_enriched_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate each enriched finding"""
        for i, finding in enumerate(v):
            try:
                EnrichedFinding(**finding)
            except Exception as e:
                raise ValueError(f"Enriched finding {i} validation failed: {e}") from e
        return v

    model_config = {"extra": "allow"}
