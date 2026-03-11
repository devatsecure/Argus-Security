"""
Scanner Output Schemas - Pydantic validation for raw scanner outputs

These schemas validate the raw output from security scanners BEFORE normalization.
This catches malformed scanner output early in the pipeline.

Fixes:
- Trivy: Validate Results structure before accessing Vulnerabilities
- Semgrep: Validate SARIF structure before accessing results
- TruffleHog: Validate SourceMetadata is dict not string
- Gitleaks: Validate file paths are not empty
- Falco: Validate event structure
"""

from typing import Any, Optional

from pydantic import BaseModel, Field, RootModel, field_validator

# ========== Semgrep SARIF Output ==========


class SARIFLocation(BaseModel):
    """SARIF physical location"""

    uri: str = Field(..., min_length=1, description="File path")
    startLine: Optional[int] = Field(default=None, ge=1)  # noqa: N815
    startColumn: Optional[int] = Field(default=None, ge=1)  # noqa: N815
    endLine: Optional[int] = Field(default=None, ge=1)  # noqa: N815
    endColumn: Optional[int] = Field(default=None, ge=1)  # noqa: N815

    @field_validator("uri")
    @classmethod
    def validate_uri_not_empty(cls, v: str) -> str:
        """Ensure URI is not empty"""
        if not v or v.strip() == "":
            raise ValueError("URI cannot be empty")
        return v


class SARIFPhysicalLocation(BaseModel):
    """SARIF physical location wrapper"""

    artifactLocation: dict[str, Any] = Field(default_factory=dict)  # noqa: N815
    region: dict[str, Any] = Field(default_factory=dict)


class SARIFResult(BaseModel):
    """SARIF result item"""

    ruleId: str = Field(..., min_length=1)  # noqa: N815
    level: str = Field(default="warning")
    message: dict[str, Any] = Field(default_factory=dict)
    locations: list[dict[str, Any]] = Field(default_factory=list)


class SARIFRun(BaseModel):
    """SARIF run"""

    tool: dict[str, Any] = Field(default_factory=dict)
    results: list[dict[str, Any]] = Field(default_factory=list)


class SemgrepOutput(BaseModel):
    """Semgrep SARIF 2.1.0 output format"""

    version: str = Field(default="2.1.0")
    runs: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("runs")
    @classmethod
    def validate_runs_structure(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate runs have expected structure"""
        for run in v:
            if not isinstance(run, dict):
                raise ValueError("Each run must be a dictionary")
            if "results" not in run:
                run["results"] = []
        return v

    model_config = {"extra": "allow"}


# ========== Trivy Output ==========


class TrivyVulnerability(BaseModel):
    """Trivy vulnerability"""

    VulnerabilityID: str = Field(..., min_length=1)
    PkgName: str = Field(default="")
    InstalledVersion: str = Field(default="")
    FixedVersion: Optional[str] = Field(default=None)
    Severity: str = Field(default="MEDIUM")
    Title: Optional[str] = Field(default=None)
    Description: Optional[str] = Field(default=None)
    PrimaryURL: Optional[str] = Field(default=None)
    References: list[str] = Field(default_factory=list)
    CVSS: dict[str, Any] = Field(default_factory=dict)
    CweIDs: list[str] = Field(default_factory=list)

    @field_validator("VulnerabilityID")
    @classmethod
    def validate_vuln_id(cls, v: str) -> str:
        """Ensure vulnerability ID is not empty"""
        if not v or v.strip() == "":
            raise ValueError("VulnerabilityID cannot be empty")
        return v


class TrivyResult(BaseModel):
    """Trivy scan result for a target"""

    Target: str = Field(..., min_length=1, description="Scan target (file/image)")
    Class: Optional[str] = Field(default=None)
    Type: Optional[str] = Field(default=None)
    Vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    Misconfigurations: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("Target")
    @classmethod
    def validate_target_not_empty(cls, v: str) -> str:
        """Ensure target is not empty"""
        if not v or v.strip() == "":
            raise ValueError("Target cannot be empty")
        return v

    @field_validator("Vulnerabilities")
    @classmethod
    def validate_vulnerabilities_are_dicts(cls, v: list[Any]) -> list[dict[str, Any]]:
        """Ensure vulnerabilities are dictionaries, not strings"""
        validated = []
        for item in v:
            if not isinstance(item, dict):
                raise ValueError(f"Vulnerability must be a dict, got {type(item).__name__}")
            validated.append(item)
        return validated


class TrivyOutput(BaseModel):
    """
    Trivy JSON output format

    Fixes AttributeError: 'str' object has no attribute 'get'
    by ensuring Vulnerabilities is always a list of dicts
    """

    SchemaVersion: Optional[int] = Field(default=None)
    ArtifactName: Optional[str] = Field(default=None)
    ArtifactType: Optional[str] = Field(default=None)
    Results: list[dict[str, Any]] = Field(default_factory=list)
    Metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("Results")
    @classmethod
    def validate_results_structure(cls, v: list[Any]) -> list[dict[str, Any]]:
        """Validate Results have expected structure"""
        validated = []
        for result in v:
            if not isinstance(result, dict):
                raise ValueError(f"Result must be a dict, got {type(result).__name__}")

            # Ensure Target exists
            if "Target" not in result or not result["Target"]:
                raise ValueError("Result missing required 'Target' field")

            # Ensure Vulnerabilities is a list of dicts
            if "Vulnerabilities" in result:
                if not isinstance(result["Vulnerabilities"], list):
                    raise ValueError("Vulnerabilities must be a list")
                for vuln in result["Vulnerabilities"]:
                    if not isinstance(vuln, dict):
                        raise ValueError(f"Vulnerability must be a dict, got {type(vuln).__name__}")

            validated.append(result)
        return validated

    model_config = {"extra": "allow"}


# ========== TruffleHog Output ==========


class TruffleHogSourceMetadata(BaseModel):
    """TruffleHog source metadata"""

    file: Optional[str] = Field(default=None)
    line: Optional[int] = Field(default=None, ge=1)
    commit: Optional[str] = Field(default=None)
    email: Optional[str] = Field(default=None)
    timestamp: Optional[str] = Field(default=None)


class TruffleHogFinding(BaseModel):
    """TruffleHog finding"""

    SourceMetadata: dict[str, Any] = Field(default_factory=dict)
    SourceID: Optional[int] = Field(default=None)
    SourceType: Optional[int] = Field(default=None)
    SourceName: Optional[str] = Field(default=None)
    DetectorType: Optional[int] = Field(default=None)
    DetectorName: str = Field(default="unknown")
    Verified: bool = Field(default=False)
    Raw: Optional[str] = Field(default=None)
    RawV2: Optional[str] = Field(default=None)
    Redacted: Optional[str] = Field(default=None)

    @field_validator("SourceMetadata")
    @classmethod
    def validate_source_metadata_is_dict(cls, v: Any) -> dict[str, Any]:
        """
        Ensure SourceMetadata is a dict, not a string.
        Fixes: AttributeError: 'str' object has no attribute 'get'
        """
        if isinstance(v, str):
            raise ValueError(f"SourceMetadata must be a dict, got string: {v}")
        if not isinstance(v, dict):
            raise ValueError(f"SourceMetadata must be a dict, got {type(v).__name__}")
        return v


class TruffleHogOutput(RootModel[list[dict[str, Any]]]):
    """TruffleHog JSON output format (array of findings)"""

    root: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("root")
    @classmethod
    def validate_findings_structure(cls, v: list[Any]) -> list[dict[str, Any]]:
        """Validate each finding has expected structure"""
        validated = []
        for finding in v:
            if not isinstance(finding, dict):
                raise ValueError(f"Finding must be a dict, got {type(finding).__name__}")

            # Ensure SourceMetadata is dict
            if "SourceMetadata" in finding:
                if not isinstance(finding["SourceMetadata"], dict):
                    raise ValueError("SourceMetadata must be a dict")

            validated.append(finding)
        return validated


# ========== Gitleaks Output ==========


class GitleaksFinding(BaseModel):
    """Gitleaks finding"""

    Description: str = Field(default="")
    StartLine: Optional[int] = Field(default=None, ge=1)
    EndLine: Optional[int] = Field(default=None, ge=1)
    StartColumn: Optional[int] = Field(default=None, ge=1)
    EndColumn: Optional[int] = Field(default=None, ge=1)
    Match: Optional[str] = Field(default=None)
    Secret: Optional[str] = Field(default=None)
    File: str = Field(..., min_length=1)
    Commit: Optional[str] = Field(default=None)
    Entropy: Optional[float] = Field(default=None)
    Author: Optional[str] = Field(default=None)
    Email: Optional[str] = Field(default=None)
    Date: Optional[str] = Field(default=None)
    Message: Optional[str] = Field(default=None)
    Tags: list[str] = Field(default_factory=list)
    RuleID: str = Field(default="unknown")

    @field_validator("File")
    @classmethod
    def validate_file_not_empty(cls, v: str) -> str:
        """
        Ensure file path is not empty.
        Fixes: Empty file paths causing correlation failures
        """
        if not v or v.strip() == "" or v == ".":
            raise ValueError("File path cannot be empty or '.'")
        return v


class GitleaksOutput(RootModel[list[dict[str, Any]]]):
    """Gitleaks JSON output format (array of findings)"""

    root: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("root")
    @classmethod
    def validate_findings_have_files(cls, v: list[Any]) -> list[dict[str, Any]]:
        """Validate each finding has a valid file path"""
        validated = []
        for finding in v:
            if not isinstance(finding, dict):
                raise ValueError(f"Finding must be a dict, got {type(finding).__name__}")

            # Ensure File exists and is not empty
            if "File" not in finding:
                raise ValueError("Finding missing required 'File' field")
            if not finding["File"] or finding["File"].strip() == "" or finding["File"] == ".":
                raise ValueError(f"Invalid file path: '{finding['File']}'")

            validated.append(finding)
        return validated


# ========== Checkov Output ==========


class CheckovFinding(BaseModel):
    """Checkov finding"""

    check_id: str = Field(..., min_length=1)
    check_name: Optional[str] = Field(default=None)
    check_result: dict[str, Any] = Field(default_factory=dict)
    code_block: Optional[list[Any]] = Field(default=None)
    file_path: str = Field(..., min_length=1)
    file_line_range: Optional[list[int]] = Field(default=None)
    resource: Optional[str] = Field(default=None)
    evaluations: Optional[dict[str, Any]] = Field(default=None)
    check_class: Optional[str] = Field(default=None)


class CheckovOutput(BaseModel):
    """Checkov JSON output format"""

    check_type: Optional[str] = Field(default=None)
    results: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


# ========== Nuclei Output ==========


class NucleiFinding(BaseModel):
    """Nuclei finding"""

    template: str = Field(..., min_length=1)
    template_id: str = Field(..., min_length=1)
    template_url: Optional[str] = Field(default=None)
    info: dict[str, Any] = Field(default_factory=dict)
    type: str = Field(default="http")
    host: Optional[str] = Field(default=None)
    matched_at: Optional[str] = Field(default=None)
    extracted_results: list[str] = Field(default_factory=list)
    ip: Optional[str] = Field(default=None)
    timestamp: Optional[str] = Field(default=None)
    curl_command: Optional[str] = Field(default=None)
    matcher_name: Optional[str] = Field(default=None)


class NucleiOutput(RootModel[list[dict[str, Any]]]):
    """Nuclei JSON-lines output (array of findings)"""

    root: list[dict[str, Any]] = Field(default_factory=list)


# ========== Falco Output ==========


class FalcoOutput(BaseModel):
    """Falco output_fields"""

    time: str = Field(..., description="Event timestamp")
    rule: str = Field(..., min_length=1, description="Rule name")
    priority: str = Field(..., description="Priority level")
    output: str = Field(..., description="Event description")
    container_id: Optional[str] = Field(default=None)
    container_name: Optional[str] = Field(default=None)
    evt_type: Optional[str] = Field(default=None)
    user: Optional[str] = Field(default=None)
    proc_name: Optional[str] = Field(default=None)
    proc_cmdline: Optional[str] = Field(default=None)
    fd_name: Optional[str] = Field(default=None)

    @field_validator("rule")
    @classmethod
    def validate_rule_not_empty(cls, v: str) -> str:
        """
        Ensure rule name is not empty.
        Fixes: Runtime security monitor couldn't parse Falco output
        """
        if not v or v.strip() == "":
            raise ValueError("Rule name cannot be empty")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        """Validate priority is a known level"""
        valid_priorities = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
        if v not in valid_priorities:
            # Allow lowercase versions
            v_title = v.title()
            if v_title not in valid_priorities:
                raise ValueError(f"Invalid priority: {v}. Must be one of {valid_priorities}")
            return v_title
        return v

    model_config = {"extra": "allow"}


class FalcoEventsOutput(RootModel[list[dict[str, Any]]]):
    """Falco JSON output (array of events)"""

    root: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("root")
    @classmethod
    def validate_events_structure(cls, v: list[Any]) -> list[dict[str, Any]]:
        """Validate each event has expected structure"""
        validated = []
        for event in v:
            if not isinstance(event, dict):
                raise ValueError(f"Event must be a dict, got {type(event).__name__}")

            # Ensure required fields exist
            if "rule" not in event or not event["rule"]:
                raise ValueError("Event missing required 'rule' field")
            if "priority" not in event or not event["priority"]:
                raise ValueError("Event missing required 'priority' field")
            if "output" not in event or not event["output"]:
                raise ValueError("Event missing required 'output' field")

            validated.append(event)
        return validated
