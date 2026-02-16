"""
Unit tests for scripts/hybrid_analyzer.py.

Tests the HybridSecurityAnalyzer class initialization, HybridFinding dataclass,
and helper methods. All external dependencies (scanners, AI clients, etc.) are
mocked so no real binaries or API keys are required.
"""

import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts directory is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from hybrid.models import HybridFinding, HybridScanResult

# ---------------------------------------------------------------------------
# HybridFinding dataclass tests
# ---------------------------------------------------------------------------


class TestHybridFinding:
    """Tests for the HybridFinding dataclass."""

    def test_minimal_creation(self):
        f = HybridFinding(
            finding_id="test-1",
            source_tool="semgrep",
            severity="high",
            category="security",
            title="SQL Injection",
            description="Unsanitized input in SQL query",
            file_path="app.py",
        )
        assert f.finding_id == "test-1"
        assert f.source_tool == "semgrep"
        assert f.severity == "high"
        assert f.category == "security"
        assert f.title == "SQL Injection"
        assert f.file_path == "app.py"

    def test_defaults(self):
        f = HybridFinding(
            finding_id="test-2",
            source_tool="trivy",
            severity="medium",
            category="security",
            title="CVE-2024-1234",
            description="Outdated dependency",
            file_path="requirements.txt",
        )
        assert f.line_number is None
        assert f.cwe_id is None
        assert f.cve_id is None
        assert f.cvss_score is None
        assert f.exploitability is None
        assert f.recommendation is None
        assert f.references == []
        assert f.confidence == 1.0
        assert f.llm_enriched is False
        assert f.sandbox_validated is False
        assert f.iris_verified is False
        assert f.iris_confidence is None
        assert f.iris_verdict is None

    def test_full_creation(self):
        f = HybridFinding(
            finding_id="test-3",
            source_tool="checkov",
            severity="critical",
            category="security",
            title="Hard-coded secret",
            description="AWS key in source code",
            file_path="config.py",
            line_number=42,
            cwe_id="CWE-798",
            cve_id="CVE-2024-9999",
            cvss_score=9.8,
            exploitability="trivial",
            recommendation="Remove the secret and rotate credentials",
            references=["https://cwe.mitre.org/data/definitions/798.html"],
            confidence=0.95,
            llm_enriched=True,
            sandbox_validated=True,
            iris_verified=True,
            iris_confidence=0.92,
            iris_verdict="true_positive",
        )
        assert f.line_number == 42
        assert f.cve_id == "CVE-2024-9999"
        assert f.cvss_score == 9.8
        assert f.iris_verified is True
        assert len(f.references) == 1

    def test_references_default_not_shared(self):
        """Each instance should get its own references list."""
        f1 = HybridFinding(
            finding_id="a",
            source_tool="s",
            severity="low",
            category="c",
            title="t",
            description="d",
            file_path="f",
        )
        f2 = HybridFinding(
            finding_id="b",
            source_tool="s",
            severity="low",
            category="c",
            title="t",
            description="d",
            file_path="f",
        )
        f1.references.append("http://example.com")
        assert f2.references == []

    def test_asdict_conversion(self):
        f = HybridFinding(
            finding_id="test-4",
            source_tool="semgrep",
            severity="medium",
            category="security",
            title="XSS",
            description="Reflected XSS",
            file_path="views.py",
        )
        d = asdict(f)
        assert isinstance(d, dict)
        assert d["finding_id"] == "test-4"
        assert d["source_tool"] == "semgrep"
        assert d["references"] == []
        assert d["confidence"] == 1.0


# ---------------------------------------------------------------------------
# HybridScanResult dataclass tests
# ---------------------------------------------------------------------------


class TestHybridScanResult:
    """Tests for the HybridScanResult dataclass."""

    def test_creation(self):
        result = HybridScanResult(
            target_path="/tmp/repo",
            scan_timestamp="2026-02-16T12:00:00Z",
            total_findings=5,
            findings_by_severity={"critical": 1, "high": 2, "medium": 2},
            findings_by_source={"semgrep": 3, "trivy": 2},
            findings=[],
            scan_duration_seconds=120.5,
            cost_usd=0.50,
            phase_timings={"phase1_static_analysis": 30.0},
            tools_used=["semgrep", "trivy"],
            llm_enrichment_enabled=True,
        )
        assert result.target_path == "/tmp/repo"
        assert result.total_findings == 5
        assert result.scan_duration_seconds == 120.5
        assert result.llm_enrichment_enabled is True


# ---------------------------------------------------------------------------
# HybridSecurityAnalyzer initialization tests
# ---------------------------------------------------------------------------


class TestHybridSecurityAnalyzerInit:
    """Tests for HybridSecurityAnalyzer.__init__().

    All external scanner/AI imports are mocked to prevent real initialization.
    """

    @patch.dict(
        "sys.modules",
        {
            "orchestrator.llm_manager": MagicMock(),
            "semgrep_scanner": MagicMock(),
            "trivy_scanner": MagicMock(),
            "checkov_scanner": MagicMock(),
            "api_security_scanner": MagicMock(),
            "supply_chain_analyzer": MagicMock(),
            "remediation_engine": MagicMock(),
            "regression_tester": MagicMock(),
            "trufflehog_scanner": MagicMock(),
            "agent_personas": MagicMock(),
            "spontaneous_discovery": MagicMock(),
        },
    )
    def test_minimal_init_all_disabled(self):
        """Initializing with all scanners disabled except semgrep."""
        from hybrid_analyzer import HybridSecurityAnalyzer

        analyzer = HybridSecurityAnalyzer(
            enable_semgrep=True,
            enable_trivy=False,
            enable_checkov=False,
            enable_api_security=False,
            enable_dast=False,
            enable_supply_chain=False,
            enable_fuzzing=False,
            enable_threat_intel=False,
            enable_remediation=False,
            enable_runtime_security=False,
            enable_regression_testing=False,
            enable_ai_enrichment=False,
            enable_sandbox=False,
            enable_multi_agent=False,
            enable_spontaneous_discovery=False,
            enable_collaborative_reasoning=False,
            enable_trufflehog=False,
            enable_iris=False,
            enable_nuclei_templates=False,
            enable_zap_baseline=False,
        )

        assert analyzer.enable_trivy is False
        assert analyzer.enable_ai_enrichment is False
        assert analyzer.enable_sandbox is False
        assert analyzer.config == {}

    @patch.dict(
        "sys.modules",
        {
            "orchestrator.llm_manager": MagicMock(),
            "semgrep_scanner": MagicMock(),
            "trivy_scanner": MagicMock(),
            "checkov_scanner": MagicMock(),
            "api_security_scanner": MagicMock(),
            "supply_chain_analyzer": MagicMock(),
            "remediation_engine": MagicMock(),
            "regression_tester": MagicMock(),
            "trufflehog_scanner": MagicMock(),
            "agent_personas": MagicMock(),
            "spontaneous_discovery": MagicMock(),
        },
    )
    def test_config_dict_stored(self):
        from hybrid_analyzer import HybridSecurityAnalyzer

        custom_config = {"max_files": 200, "enable_phase_gating": False}
        analyzer = HybridSecurityAnalyzer(
            enable_semgrep=True,
            enable_trivy=False,
            enable_checkov=False,
            enable_api_security=False,
            enable_dast=False,
            enable_supply_chain=False,
            enable_fuzzing=False,
            enable_threat_intel=False,
            enable_remediation=False,
            enable_runtime_security=False,
            enable_regression_testing=False,
            enable_ai_enrichment=False,
            enable_sandbox=False,
            enable_multi_agent=False,
            enable_spontaneous_discovery=False,
            enable_collaborative_reasoning=False,
            enable_trufflehog=False,
            enable_iris=False,
            enable_nuclei_templates=False,
            enable_zap_baseline=False,
            config=custom_config,
        )
        assert analyzer.config["max_files"] == 200
        assert analyzer.config["enable_phase_gating"] is False

    @patch.dict(
        "sys.modules",
        {
            "orchestrator.llm_manager": MagicMock(),
            "semgrep_scanner": MagicMock(),
            "trivy_scanner": MagicMock(),
            "checkov_scanner": MagicMock(),
            "api_security_scanner": MagicMock(),
            "supply_chain_analyzer": MagicMock(),
            "remediation_engine": MagicMock(),
            "regression_tester": MagicMock(),
            "trufflehog_scanner": MagicMock(),
            "agent_personas": MagicMock(),
            "spontaneous_discovery": MagicMock(),
        },
    )
    def test_no_active_features_raises_valueerror(self):
        """If all scanners and AI enrichment are disabled, should raise ValueError."""
        from hybrid_analyzer import HybridSecurityAnalyzer

        with pytest.raises(ValueError, match="At least one tool must be enabled"):
            HybridSecurityAnalyzer(
                enable_semgrep=False,
                enable_trivy=False,
                enable_checkov=False,
                enable_api_security=False,
                enable_dast=False,
                enable_supply_chain=False,
                enable_fuzzing=False,
                enable_threat_intel=False,
                enable_remediation=False,
                enable_runtime_security=False,
                enable_regression_testing=False,
                enable_ai_enrichment=False,
                enable_sandbox=False,
                enable_multi_agent=False,
                enable_spontaneous_discovery=False,
                enable_collaborative_reasoning=False,
                enable_trufflehog=False,
                enable_iris=False,
                enable_nuclei_templates=False,
                enable_zap_baseline=False,
            )


# ---------------------------------------------------------------------------
# Quality filter helper tests
# ---------------------------------------------------------------------------


class TestIsLowQualityFinding:
    """Tests for HybridSecurityAnalyzer._is_low_quality_finding()."""

    def _make_finding(self, **kwargs):
        defaults = {
            "finding_id": "test",
            "source_tool": "semgrep",
            "severity": "medium",
            "category": "security",
            "title": "Test",
            "description": "",
            "file_path": "test.py",
            "confidence": 0.1,
            "iris_verified": False,
            "cve_id": None,
        }
        defaults.update(kwargs)
        return HybridFinding(**defaults)

    def test_iris_verified_never_filtered(self):
        f = self._make_finding(iris_verified=True, description="", confidence=0.0)
        # Import statically to call static method
        from hybrid_analyzer import HybridSecurityAnalyzer

        assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is False

    def test_cve_finding_never_filtered(self):
        f = self._make_finding(cve_id="CVE-2024-1234", description="", confidence=0.0)
        from hybrid_analyzer import HybridSecurityAnalyzer

        assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is False

    def test_has_description_not_filtered(self):
        f = self._make_finding(description="Real vulnerability here", confidence=0.1)
        from hybrid_analyzer import HybridSecurityAnalyzer

        assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is False

    def test_low_confidence_no_description_is_filtered(self):
        f = self._make_finding(description="", confidence=0.1)
        from hybrid_analyzer import HybridSecurityAnalyzer

        assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is True

    def test_empty_description_variants_filtered(self):
        """Descriptions like 'none', 'unknown', 'n/a' count as empty."""
        from hybrid_analyzer import HybridSecurityAnalyzer

        for desc in ["none", "None", "unknown", "UNKNOWN", "n/a", "N/A", "  "]:
            f = self._make_finding(description=desc, confidence=0.1)
            assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is True, (
                f"Description '{desc}' should be treated as empty"
            )

    def test_above_threshold_not_filtered(self):
        f = self._make_finding(description="", confidence=0.5)
        from hybrid_analyzer import HybridSecurityAnalyzer

        assert HybridSecurityAnalyzer._is_low_quality_finding(f, 0.30) is False
