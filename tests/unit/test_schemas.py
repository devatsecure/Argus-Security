"""
Comprehensive tests for Pydantic schemas

Tests all schema validation rules to ensure data format consistency.
"""

import pytest
from pathlib import Path
from datetime import datetime, timezone

# Import schemas
from scripts.schemas.unified_finding import (
    UnifiedFinding,
    Severity,
    Category,
    AssetType,
    Reachability,
    Exploitability,
    SecretVerified,
    ServiceTier,
    FindingStatus,
)
from scripts.schemas.scanner_outputs import (
    SemgrepOutput,
    TrivyOutput,
    TruffleHogOutput,
    GitleaksOutput,
    FalcoOutput,
    FalcoEventsOutput,
)
from scripts.schemas.correlation import (
    CorrelationInput,
    CorrelationFindingInput,
    CorrelationResult,
    CorrelationStatus,
)
from scripts.schemas.enrichment import (
    EnrichmentInput,
    ThreatContext,
    EnrichedFinding,
)


class TestUnifiedFinding:
    """Test UnifiedFinding schema validation"""

    def test_valid_finding(self):
        """Test creating a valid finding"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            severity=Severity.HIGH,
            category=Category.SAST,
        )
        assert finding.id == "test123"
        assert finding.path == Path("src/test.py")
        assert finding.severity == Severity.HIGH

    def test_empty_path_rejected(self):
        """Test that empty paths are rejected"""
        with pytest.raises(ValueError, match="Path cannot be empty"):
            UnifiedFinding(
                id="test123",
                origin="semgrep",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path(""),
                severity=Severity.HIGH,
            )

    def test_dot_path_rejected(self):
        """Test that '.' path is rejected"""
        with pytest.raises(ValueError, match="Path cannot be empty"):
            UnifiedFinding(
                id="test123",
                origin="semgrep",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("."),
                severity=Severity.HIGH,
            )

    def test_invalid_cwe_format(self):
        """Test that invalid CWE format is rejected"""
        with pytest.raises(ValueError, match="string_pattern_mismatch"):
            UnifiedFinding(
                id="test123",
                origin="semgrep",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("src/test.py"),
                cwe="CWE123",  # Missing dash
            )

    def test_valid_cwe_format(self):
        """Test that valid CWE format is accepted"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            cwe="CWE-89",
        )
        assert finding.cwe == "CWE-89"

    def test_invalid_cve_format(self):
        """Test that invalid CVE format is rejected"""
        with pytest.raises(ValueError, match="string_pattern_mismatch"):
            UnifiedFinding(
                id="test123",
                origin="trivy",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("package.json"),
                cve="CVE2021-1234",  # Missing dash
            )

    def test_valid_cve_format(self):
        """Test that valid CVE format is accepted"""
        finding = UnifiedFinding(
            id="test123",
            origin="trivy",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("package.json"),
            cve="CVE-2021-1234",
        )
        assert finding.cve == "CVE-2021-1234"

    def test_risk_score_auto_calculation(self):
        """Test that risk score is auto-calculated"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            severity=Severity.CRITICAL,
        )
        # Should have calculated risk score
        assert finding.risk_score > 0

    def test_cvss_validation(self):
        """Test CVSS score range validation"""
        # Valid CVSS
        finding = UnifiedFinding(
            id="test123",
            origin="trivy",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("package.json"),
            cvss=7.5,
        )
        assert finding.cvss == 7.5

        # Invalid CVSS (too high)
        with pytest.raises(ValueError):
            UnifiedFinding(
                id="test123",
                origin="trivy",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("package.json"),
                cvss=11.0,
            )

    def test_line_number_validation(self):
        """Test line number must be >= 1"""
        # Valid line number
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            line=42,
        )
        assert finding.line == 42

        # Invalid line number (0)
        with pytest.raises(ValueError):
            UnifiedFinding(
                id="test123",
                origin="semgrep",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("src/test.py"),
                line=0,
            )

    def test_empty_id_rejected(self):
        """Test that empty ID is rejected"""
        with pytest.raises(ValueError, match="string_too_short"):
            UnifiedFinding(
                id="",
                origin="semgrep",
                repo="test-repo",
                commit_sha="abc123",
                branch="main",
                path=Path("src/test.py"),
            )

    def test_to_dict_conversion(self):
        """Test conversion to dictionary"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            severity=Severity.HIGH,
        )
        data = finding.to_dict()
        assert isinstance(data, dict)
        assert data["id"] == "test123"
        assert data["path"] == "src/test.py"  # Converted to string
        assert data["severity"] == "high"  # Enum to value


class TestScannerOutputSchemas:
    """Test scanner output schemas"""

    def test_semgrep_valid_sarif(self):
        """Test valid Semgrep SARIF structure"""
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "python.lang.security.sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection detected"},
                            "locations": [],
                        }
                    ],
                }
            ],
        }
        output = SemgrepOutput(**sarif)
        assert len(output.runs) == 1

    def test_trivy_valid_output(self):
        """Test valid Trivy output structure"""
        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "lodash",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        output = TrivyOutput(**trivy)
        assert len(output.Results) == 1

    def test_trivy_vulnerabilities_must_be_list(self):
        """Test that Trivy rejects non-list Vulnerabilities"""
        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": "not a list",  # INVALID
                }
            ]
        }
        with pytest.raises(ValueError, match="must be a list"):
            TrivyOutput(**trivy)

    def test_trivy_vulnerability_must_be_dict(self):
        """Test that Trivy rejects string vulnerabilities"""
        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": ["string-vulnerability"],  # INVALID
                }
            ]
        }
        with pytest.raises(ValueError, match="must be a dict"):
            TrivyOutput(**trivy)

    def test_gitleaks_empty_file_rejected(self):
        """Test that Gitleaks rejects empty file paths"""
        gitleaks = [
            {
                "File": "",  # INVALID - empty path
                "RuleID": "generic-api-key",
                "Match": "secret",
            }
        ]
        with pytest.raises(ValueError, match="Invalid file path"):
            GitleaksOutput(root=gitleaks)

    def test_gitleaks_dot_file_rejected(self):
        """Test that Gitleaks rejects '.' file path"""
        gitleaks = [
            {
                "File": ".",  # INVALID
                "RuleID": "generic-api-key",
                "Match": "secret",
            }
        ]
        with pytest.raises(ValueError, match="Invalid file path"):
            GitleaksOutput(root=gitleaks)

    def test_falco_valid_event(self):
        """Test valid Falco event structure"""
        falco_event = {
            "time": "2024-01-01T00:00:00Z",
            "rule": "Terminal shell in container",
            "priority": "Warning",
            "output": "Shell spawned in container",
        }
        output = FalcoOutput(**falco_event)
        assert output.rule == "Terminal shell in container"

    def test_falco_empty_rule_rejected(self):
        """Test that Falco rejects empty rule name"""
        falco = [
            {
                "time": "2024-01-01T00:00:00Z",
                "rule": "",  # INVALID
                "priority": "Warning",
                "output": "Event",
            }
        ]
        with pytest.raises(ValueError, match="missing required 'rule' field"):
            FalcoEventsOutput(root=falco)


class TestCorrelationSchemas:
    """Test correlation schemas"""

    def test_valid_correlation_input(self):
        """Test valid correlation input"""
        input_data = CorrelationInput(
            sast_findings=[
                {
                    "id": "sast1",
                    "path": "src/api/users.py",
                    "rule_id": "sql-injection",
                }
            ],
            dast_findings=[
                {
                    "id": "dast1",
                    "path": "http://localhost/api/users",
                    "rule_id": "sql-injection",
                }
            ],
        )
        assert len(input_data.sast_findings) == 1

    def test_correlation_empty_path_rejected(self):
        """Test that correlation rejects empty paths"""
        with pytest.raises(ValueError, match="string_too_short"):
            CorrelationInput(
                sast_findings=[
                    {
                        "id": "sast1",
                        "path": "",  # INVALID
                        "rule_id": "sql-injection",
                    }
                ],
                dast_findings=[],
            )

    def test_correlation_result_valid(self):
        """Test valid correlation result"""
        result = CorrelationResult(
            sast_finding_id="sast1",
            status=CorrelationStatus.CONFIRMED,
            confidence=0.95,
            exploitability="trivial",
            reasoning="DAST confirmed exploitation",
        )
        assert result.confidence == 0.95

    def test_correlation_empty_reasoning_rejected(self):
        """Test that empty reasoning is rejected"""
        with pytest.raises(ValueError, match="string_too_short"):
            CorrelationResult(
                sast_finding_id="sast1",
                status=CorrelationStatus.CONFIRMED,
                confidence=0.95,
                exploitability="trivial",
                reasoning="",  # INVALID
            )


class TestEnrichmentSchemas:
    """Test enrichment schemas"""

    def test_valid_threat_context(self):
        """Test valid threat context"""
        context = ThreatContext(
            cve_id="CVE-2021-1234",
            cvss_score=7.5,
            in_kev_catalog=True,
            epss_score=0.85,
        )
        assert context.cve_id == "CVE-2021-1234"
        assert context.in_kev_catalog is True

    def test_threat_context_invalid_cve(self):
        """Test that invalid CVE format is rejected"""
        with pytest.raises(ValueError, match="string_pattern_mismatch"):
            ThreatContext(
                cve_id="CVE2021-1234",  # Missing dash
            )

    def test_threat_context_epss_range(self):
        """Test EPSS score range validation"""
        # Valid EPSS
        context = ThreatContext(
            cve_id="CVE-2021-1234",
            epss_score=0.85,
        )
        assert context.epss_score == 0.85

        # Invalid EPSS (> 1.0)
        with pytest.raises(ValueError):
            ThreatContext(
                cve_id="CVE-2021-1234",
                epss_score=1.5,
            )

    def test_enriched_finding_valid(self):
        """Test valid enriched finding"""
        enriched = EnrichedFinding(
            original_finding={"id": "finding1", "severity": "high"},
            original_priority="high",
            adjusted_priority="critical",
            recommended_action="Patch immediately",
            risk_score=8.5,
        )
        assert enriched.risk_score == 8.5

    def test_enriched_finding_missing_id(self):
        """Test that original finding must have ID"""
        with pytest.raises(ValueError, match="must have an 'id' field"):
            EnrichedFinding(
                original_finding={},  # Missing ID
                original_priority="high",
                adjusted_priority="critical",
                recommended_action="Patch",
                risk_score=8.5,
            )


class TestSchemaEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_path_with_spaces(self):
        """Test that paths with spaces are valid"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/my file.py"),
        )
        assert str(finding.path) == "src/my file.py"

    def test_unicode_in_fields(self):
        """Test Unicode support in string fields"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            rule_name="SQL注入检测",  # Chinese characters
        )
        assert "注入" in finding.rule_name

    def test_very_long_path(self):
        """Test handling of very long paths"""
        long_path = "a/" * 100 + "file.py"
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path(long_path),
        )
        assert len(str(finding.path)) > 200

    def test_dedup_key_generation(self):
        """Test deduplication key generation"""
        finding = UnifiedFinding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("src/test.py"),
            rule_id="sql-injection",
            line=42,
        )
        key = finding.dedup_key()
        assert len(key) == 64  # SHA256 hex digest


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
