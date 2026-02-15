"""
Tests for the decomposed phase modules under hybrid.phases.

Verifies:
    - Each phase module can be imported
    - Phase functions have correct signatures (accept expected params)
    - Phase functions handle empty inputs gracefully
    - The orchestrator (HybridSecurityAnalyzer.analyze) still works end-to-end
      via mocked scanners verifying the phase flow
"""

import inspect
import sys
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from hybrid.models import HybridFinding, HybridScanResult


# ============================================================================
# Helpers
# ============================================================================

def _make_finding(**overrides: Any) -> HybridFinding:
    """Create a minimal HybridFinding with sensible defaults."""
    defaults = {
        "finding_id": "test-001",
        "source_tool": "semgrep",
        "severity": "high",
        "category": "security",
        "title": "Test finding",
        "description": "A test finding",
        "file_path": "/tmp/test.py",
    }
    defaults.update(overrides)
    return HybridFinding(**defaults)


def _make_mock_analyzer(**overrides: Any) -> MagicMock:
    """Create a mock analyzer with all enable_* flags set to False by default."""
    analyzer = MagicMock()
    analyzer.enable_semgrep = False
    analyzer.enable_trivy = False
    analyzer.enable_checkov = False
    analyzer.enable_api_security = False
    analyzer.enable_dast = False
    analyzer.enable_supply_chain = False
    analyzer.enable_fuzzing = False
    analyzer.enable_threat_intel = False
    analyzer.enable_remediation = False
    analyzer.enable_runtime_security = False
    analyzer.enable_regression_testing = False
    analyzer.enable_trufflehog = False
    analyzer.enable_ai_enrichment = False
    analyzer.enable_iris = False
    analyzer.enable_sandbox = False
    analyzer.enable_multi_agent = False
    analyzer.enable_spontaneous_discovery = False
    analyzer.enable_collaborative_reasoning = False
    analyzer.semgrep_scanner = None
    analyzer.trivy_scanner = None
    analyzer.checkov_scanner = None
    analyzer.api_security_scanner = None
    analyzer.dast_scanner = None
    analyzer.supply_chain_scanner = None
    analyzer.fuzzing_scanner = None
    analyzer.threat_intel_enricher = None
    analyzer.remediation_engine = None
    analyzer.runtime_security_monitor = None
    analyzer.regression_tester = None
    analyzer.trufflehog_scanner = None
    analyzer.sandbox_validator = None
    analyzer.ai_client = None
    analyzer.agent_personas = None
    analyzer.spontaneous_discovery = None
    analyzer.collaborative_reasoning = None
    analyzer.iris_analyzer = None
    analyzer.project_context = None
    analyzer.config = {}

    for key, value in overrides.items():
        setattr(analyzer, key, value)

    return analyzer


# ============================================================================
# Test: Module imports
# ============================================================================

class TestModuleImports:
    """Verify each phase module can be imported without errors."""

    def test_import_phases_init(self):
        import hybrid.phases
        assert hasattr(hybrid.phases, "run_phase1_scanning")
        assert hasattr(hybrid.phases, "run_phase2_enrichment")
        assert hasattr(hybrid.phases, "run_phase3_review")
        assert hasattr(hybrid.phases, "run_phase4_sandbox")
        assert hasattr(hybrid.phases, "run_phase5_policy")
        assert hasattr(hybrid.phases, "run_phase6_reporting")

    def test_import_phase1(self):
        from hybrid.phases.phase1_scanning import run_phase1_scanning
        assert callable(run_phase1_scanning)

    def test_import_phase2(self):
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment
        assert callable(run_phase2_enrichment)

    def test_import_phase3(self):
        from hybrid.phases.phase3_review import run_phase3_review
        assert callable(run_phase3_review)

    def test_import_phase4(self):
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox
        assert callable(run_phase4_sandbox)

    def test_import_phase5(self):
        from hybrid.phases.phase5_policy import run_phase5_policy
        assert callable(run_phase5_policy)

    def test_import_phase6(self):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        assert callable(run_phase6_reporting)

    def test_import_internal_helpers(self):
        """Internal helper functions should also be importable."""
        from hybrid.phases.phase3_review import _run_argus_review
        from hybrid.phases.phase4_sandbox import _run_sandbox_validation
        assert callable(_run_argus_review)
        assert callable(_run_sandbox_validation)


# ============================================================================
# Test: Function signatures
# ============================================================================

class TestFunctionSignatures:
    """Verify phase functions accept the expected keyword arguments."""

    def test_phase1_signature(self):
        from hybrid.phases.phase1_scanning import run_phase1_scanning
        sig = inspect.signature(run_phase1_scanning)
        param_names = set(sig.parameters.keys())
        assert "target_path" in param_names
        assert "analyzer" in param_names

    def test_phase2_signature(self):
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment
        sig = inspect.signature(run_phase2_enrichment)
        param_names = set(sig.parameters.keys())
        assert "all_findings" in param_names
        assert "target_path" in param_names
        assert "analyzer" in param_names

    def test_phase3_signature(self):
        from hybrid.phases.phase3_review import run_phase3_review
        sig = inspect.signature(run_phase3_review)
        param_names = set(sig.parameters.keys())
        assert "all_findings" in param_names
        assert "target_path" in param_names
        assert "analyzer" in param_names

    def test_phase4_signature(self):
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox
        sig = inspect.signature(run_phase4_sandbox)
        param_names = set(sig.parameters.keys())
        assert "all_findings" in param_names
        assert "target_path" in param_names
        assert "analyzer" in param_names

    def test_phase5_signature(self):
        from hybrid.phases.phase5_policy import run_phase5_policy
        sig = inspect.signature(run_phase5_policy)
        param_names = set(sig.parameters.keys())
        assert "all_findings" in param_names
        assert "analyzer" in param_names
        assert "output_dir" in param_names

    def test_phase6_signature(self):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        sig = inspect.signature(run_phase6_reporting)
        param_names = set(sig.parameters.keys())
        assert "all_findings" in param_names
        assert "target_path" in param_names
        assert "analyzer" in param_names
        assert "output_dir" in param_names
        assert "severity_filter" in param_names
        assert "overall_start" in param_names
        assert "phase_timings" in param_names
        assert "total_cost" in param_names
        assert "policy_gate_result" in param_names
        assert "vulnerability_chains" in param_names


# ============================================================================
# Test: Phase 1 - Scanner Orchestration
# ============================================================================

class TestPhase1Scanning:
    """Tests for run_phase1_scanning."""

    def test_empty_when_all_disabled(self, tmp_path):
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        analyzer = _make_mock_analyzer()
        findings, duration, health = run_phase1_scanning(
            target_path=str(tmp_path), analyzer=analyzer
        )
        assert findings == []
        assert duration >= 0.0
        assert isinstance(health, dict)

    def test_semgrep_findings_collected(self, tmp_path):
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        mock_scanner = MagicMock()
        analyzer = _make_mock_analyzer(
            enable_semgrep=True,
            semgrep_scanner=mock_scanner,
        )
        # _run_semgrep returns findings
        analyzer._run_semgrep.return_value = [_make_finding(finding_id="sg-1")]

        findings, duration, _health = run_phase1_scanning(
            target_path=str(tmp_path), analyzer=analyzer
        )
        assert len(findings) == 1
        assert findings[0].finding_id == "sg-1"
        analyzer._run_semgrep.assert_called_once_with(str(tmp_path))

    def test_scanner_failure_does_not_halt(self, tmp_path):
        """If one scanner raises, the phase should continue."""
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        analyzer = _make_mock_analyzer(
            enable_semgrep=True,
            semgrep_scanner=MagicMock(),
            enable_trivy=True,
            trivy_scanner=MagicMock(),
        )
        analyzer._run_semgrep.side_effect = RuntimeError("Semgrep crashed")
        analyzer._run_trivy.return_value = [_make_finding(finding_id="trivy-1")]

        findings, _, health = run_phase1_scanning(
            target_path=str(tmp_path), analyzer=analyzer
        )
        assert len(findings) == 1
        assert findings[0].finding_id == "trivy-1"
        assert health["Semgrep"] == "failed"

    def test_trufflehog_integration(self, tmp_path):
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        mock_th = MagicMock()
        mock_th.scan.return_value = {
            "findings": [
                {"detector_type": "AWS", "detector_name": "aws_key", "verified": True, "file_path": "creds.py", "line": 10}
            ]
        }
        analyzer = _make_mock_analyzer(
            enable_trufflehog=True,
            trufflehog_scanner=mock_th,
        )

        findings, _, _health = run_phase1_scanning(
            target_path=str(tmp_path), analyzer=analyzer
        )
        assert len(findings) == 1
        assert "trufflehog" in findings[0].finding_id
        assert findings[0].severity == "critical"  # verified secret


# ============================================================================
# Test: Phase 2 - AI Enrichment
# ============================================================================

class TestPhase2Enrichment:

    def test_skipped_when_ai_disabled(self, tmp_path):
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment

        analyzer = _make_mock_analyzer(enable_ai_enrichment=False)
        findings = [_make_finding()]

        result, timings = run_phase2_enrichment(
            all_findings=findings, target_path=str(tmp_path), analyzer=analyzer
        )
        assert len(result) == 1
        assert timings == {}  # no sub-phases ran

    def test_empty_findings_no_crash(self, tmp_path):
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment

        analyzer = _make_mock_analyzer(enable_ai_enrichment=True)
        result, timings = run_phase2_enrichment(
            all_findings=[], target_path=str(tmp_path), analyzer=analyzer
        )
        assert result == []

    def test_ai_enrichment_called_with_findings(self, tmp_path):
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment

        findings = [_make_finding()]
        analyzer = _make_mock_analyzer(enable_ai_enrichment=True)
        analyzer._enrich_with_ai.return_value = findings

        result, timings = run_phase2_enrichment(
            all_findings=findings, target_path=str(tmp_path), analyzer=analyzer
        )
        assert len(result) == 1
        assert "phase2_ai_enrichment" in timings
        analyzer._enrich_with_ai.assert_called_once()


# ============================================================================
# Test: Phase 3 - Multi-Agent Review
# ============================================================================

class TestPhase3Review:

    def test_skipped_when_disabled(self, tmp_path):
        from hybrid.phases.phase3_review import run_phase3_review

        analyzer = _make_mock_analyzer(enable_multi_agent=False)
        findings = [_make_finding()]

        result, duration = run_phase3_review(
            all_findings=findings, target_path=str(tmp_path), analyzer=analyzer
        )
        assert result == findings
        assert duration is None

    def test_skipped_when_no_findings(self, tmp_path):
        from hybrid.phases.phase3_review import run_phase3_review

        analyzer = _make_mock_analyzer(
            enable_multi_agent=True,
            agent_personas=MagicMock(),
        )

        result, duration = run_phase3_review(
            all_findings=[], target_path=str(tmp_path), analyzer=analyzer
        )
        assert result == []
        assert duration is None

    def test_skipped_when_no_personas(self, tmp_path):
        from hybrid.phases.phase3_review import run_phase3_review

        analyzer = _make_mock_analyzer(
            enable_multi_agent=True,
            agent_personas=None,
        )

        result, duration = run_phase3_review(
            all_findings=[_make_finding()],
            target_path=str(tmp_path),
            analyzer=analyzer,
        )
        assert duration is None

    def test_empty_findings_no_crash(self, tmp_path):
        from hybrid.phases.phase3_review import _run_argus_review

        result = _run_argus_review(
            findings=[],
            target_path=str(tmp_path),
            agent_personas=MagicMock(),
            ai_client=MagicMock(),
            collaborative_reasoning=None,
            enable_collaborative_reasoning=False,
        )
        assert result == []


# ============================================================================
# Test: Phase 4 - Sandbox Validation
# ============================================================================

class TestPhase4Sandbox:

    def test_skipped_when_disabled(self, tmp_path):
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox

        analyzer = _make_mock_analyzer(enable_sandbox=False)
        findings = [_make_finding()]

        result, duration = run_phase4_sandbox(
            all_findings=findings, target_path=str(tmp_path), analyzer=analyzer
        )
        assert result == findings
        assert duration is None

    def test_skipped_when_no_validator(self, tmp_path):
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox

        analyzer = _make_mock_analyzer(
            enable_sandbox=True,
            sandbox_validator=None,
        )

        result, duration = run_phase4_sandbox(
            all_findings=[_make_finding()],
            target_path=str(tmp_path),
            analyzer=analyzer,
        )
        assert duration is None

    def test_skipped_when_no_findings(self, tmp_path):
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox

        analyzer = _make_mock_analyzer(
            enable_sandbox=True,
            sandbox_validator=MagicMock(),
        )

        result, duration = run_phase4_sandbox(
            all_findings=[], target_path=str(tmp_path), analyzer=analyzer
        )
        assert result == []
        assert duration is None

    def test_low_severity_not_validated(self, tmp_path):
        from hybrid.phases.phase4_sandbox import _run_sandbox_validation

        findings = [_make_finding(severity="low")]
        result = _run_sandbox_validation(
            findings=findings,
            target_path=str(tmp_path),
            sandbox_validator=MagicMock(),
        )
        assert len(result) == 1
        # low severity should pass through without validation attempt

    def test_critical_finding_marked_not_validated(self, tmp_path):
        from hybrid.phases.phase4_sandbox import _run_sandbox_validation

        findings = [_make_finding(severity="critical", exploitability="trivial")]
        result = _run_sandbox_validation(
            findings=findings,
            target_path=str(tmp_path),
            sandbox_validator=MagicMock(),
        )
        assert len(result) == 1
        assert result[0].sandbox_validated is False


# ============================================================================
# Test: Phase 5 - Policy Gate
# ============================================================================

class TestPhase5Policy:

    def test_skipped_when_no_findings(self):
        from hybrid.phases.phase5_policy import run_phase5_policy

        analyzer = _make_mock_analyzer()
        policy_result, chains, timings = run_phase5_policy(
            all_findings=[], analyzer=analyzer
        )
        assert policy_result is None
        assert chains is None
        assert timings == {}

    @patch.dict("os.environ", {"ENABLE_VULNERABILITY_CHAINING": "false"}, clear=False)
    def test_policy_gate_import_error_handled(self):
        from hybrid.phases.phase5_policy import run_phase5_policy

        analyzer = _make_mock_analyzer()
        findings = [_make_finding()]

        # gate module is not installed, so ImportError should be caught
        policy_result, chains, timings = run_phase5_policy(
            all_findings=findings, analyzer=analyzer
        )
        # Should not crash, policy_result may be None if import failed
        assert "phase5_policy_gate" in timings


# ============================================================================
# Test: Phase 6 - Reporting
# ============================================================================

class TestPhase6Reporting:

    def test_result_assembly(self, tmp_path):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        import time

        findings = [_make_finding(), _make_finding(finding_id="test-002", severity="critical")]
        analyzer = _make_mock_analyzer()
        analyzer._enrich_findings.return_value = findings
        analyzer._count_by_severity.return_value = {"critical": 1, "high": 1, "medium": 0, "low": 0}
        analyzer._count_by_source.return_value = {"semgrep": 2}
        analyzer._get_enabled_tools.return_value = ["Semgrep"]
        analyzer.enable_ai_enrichment = False

        result = run_phase6_reporting(
            all_findings=findings,
            target_path=str(tmp_path),
            analyzer=analyzer,
            output_dir=None,
            severity_filter=None,
            overall_start=time.time() - 5.0,
            phase_timings={"phase1_static_analysis": 2.0},
            total_cost=0.0,
            policy_gate_result=None,
            vulnerability_chains=None,
        )

        assert isinstance(result, HybridScanResult)
        assert result.total_findings == 2
        assert result.findings_by_severity["critical"] == 1
        assert result.target_path == str(tmp_path)

    def test_severity_filter_applied(self, tmp_path):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        import time

        findings = [
            _make_finding(finding_id="f1", severity="high"),
            _make_finding(finding_id="f2", severity="low"),
        ]
        analyzer = _make_mock_analyzer()
        analyzer._enrich_findings.return_value = findings
        analyzer._count_by_severity.return_value = {"critical": 0, "high": 1, "medium": 0, "low": 1}
        analyzer._count_by_source.return_value = {"semgrep": 2}
        analyzer._get_enabled_tools.return_value = ["Semgrep"]
        analyzer.enable_ai_enrichment = False

        result = run_phase6_reporting(
            all_findings=findings,
            target_path=str(tmp_path),
            analyzer=analyzer,
            output_dir=None,
            severity_filter=["high"],
            overall_start=time.time() - 1.0,
            phase_timings={},
            total_cost=0.0,
            policy_gate_result=None,
            vulnerability_chains=None,
        )

        # Only high-severity findings should remain
        assert result.total_findings == 1
        assert all(f.severity == "high" for f in result.findings)

    def test_vulnerability_chains_attached(self, tmp_path):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        import time

        findings = [_make_finding()]
        analyzer = _make_mock_analyzer()
        analyzer._enrich_findings.return_value = findings
        analyzer._count_by_severity.return_value = {"critical": 0, "high": 1, "medium": 0, "low": 0}
        analyzer._count_by_source.return_value = {"semgrep": 1}
        analyzer._get_enabled_tools.return_value = ["Semgrep"]
        analyzer.enable_ai_enrichment = False

        chains = {"total_chains": 2, "chains": [], "statistics": {}}

        result = run_phase6_reporting(
            all_findings=findings,
            target_path=str(tmp_path),
            analyzer=analyzer,
            output_dir=None,
            severity_filter=None,
            overall_start=time.time(),
            phase_timings={},
            total_cost=0.0,
            policy_gate_result=None,
            vulnerability_chains=chains,
        )

        assert result.__dict__.get("vulnerability_chains") == chains

    def test_empty_findings_no_crash(self, tmp_path):
        from hybrid.phases.phase6_reporting import run_phase6_reporting
        import time

        analyzer = _make_mock_analyzer()
        analyzer._enrich_findings.return_value = []
        analyzer._count_by_severity.return_value = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        analyzer._count_by_source.return_value = {}
        analyzer._get_enabled_tools.return_value = []
        analyzer.enable_ai_enrichment = False

        result = run_phase6_reporting(
            all_findings=[],
            target_path=str(tmp_path),
            analyzer=analyzer,
            output_dir=None,
            severity_filter=None,
            overall_start=time.time(),
            phase_timings={},
            total_cost=0.0,
            policy_gate_result=None,
            vulnerability_chains=None,
        )

        assert isinstance(result, HybridScanResult)
        assert result.total_findings == 0


# ============================================================================
# Test: End-to-End Orchestrator
# ============================================================================

class TestOrchestratorE2E:
    """Test that HybridSecurityAnalyzer.analyze() still works with the phase modules."""

    @patch("hybrid_analyzer.detect_project_context")
    @patch("hybrid_analyzer.PROJECT_CONTEXT_AVAILABLE", False)
    def test_analyze_with_no_scanners_available(self, mock_detect, tmp_path):
        """When all scanners fail to init, analyze still runs (AI enrichment only)."""
        from hybrid_analyzer import HybridSecurityAnalyzer

        # Create a minimal analyzer with all scanners disabled but AI "enabled" to pass validation
        with patch.multiple(
            "enrichment_pipeline",
            _EPSS_OK=False,
            _FIX_OK=False,
            _VEX_OK=False,
            _DEDUP_OK=False,
        ), patch("hybrid_analyzer._REGISTRY_OK", False):
            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            # Manually set all attributes (skip __init__ scanner setup)
            analyzer.enable_semgrep = False
            analyzer.enable_trivy = False
            analyzer.enable_checkov = False
            analyzer.enable_api_security = False
            analyzer.enable_dast = False
            analyzer.enable_supply_chain = False
            analyzer.enable_fuzzing = False
            analyzer.enable_threat_intel = False
            analyzer.enable_remediation = False
            analyzer.enable_runtime_security = False
            analyzer.enable_regression_testing = False
            analyzer.enable_ai_enrichment = True  # keeps validation happy
            analyzer.enable_argus = False
            analyzer.enable_sandbox = False
            analyzer.enable_multi_agent = False
            analyzer.enable_spontaneous_discovery = False
            analyzer.enable_collaborative_reasoning = False
            analyzer.enable_trufflehog = False
            analyzer.enable_iris = False
            analyzer.enable_nuclei_templates = False
            analyzer.enable_zap_baseline = False
            analyzer.semgrep_scanner = None
            analyzer.trivy_scanner = None
            analyzer.checkov_scanner = None
            analyzer.api_security_scanner = None
            analyzer.dast_scanner = None
            analyzer.supply_chain_scanner = None
            analyzer.fuzzing_scanner = None
            analyzer.threat_intel_enricher = None
            analyzer.remediation_engine = None
            analyzer.runtime_security_monitor = None
            analyzer.regression_tester = None
            analyzer.trufflehog_scanner = None
            analyzer.sandbox_validator = None
            analyzer.ai_client = None
            analyzer.agent_personas = None
            analyzer.spontaneous_discovery = None
            analyzer.collaborative_reasoning = None
            analyzer.iris_analyzer = None
            analyzer.project_context = None
            analyzer.config = {}
            analyzer.ai_provider = None
            analyzer.dast_target_url = None
            analyzer.fuzzing_duration = 300
            analyzer.runtime_monitoring_duration = 60
            analyzer.scanner_registry = None

            result = analyzer.analyze(str(tmp_path))

            assert isinstance(result, HybridScanResult)
            assert result.total_findings == 0
            assert result.target_path == str(tmp_path)

    def test_analyze_raises_on_missing_path(self):
        """analyze() should raise FileNotFoundError for non-existent path."""
        from hybrid_analyzer import HybridSecurityAnalyzer

        analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
        # Minimal setup
        analyzer.enable_ai_enrichment = True
        analyzer.ai_client = None
        analyzer.config = {}
        analyzer.project_context = None

        with pytest.raises(FileNotFoundError):
            analyzer.analyze("/nonexistent/path/12345")


# ============================================================================
# Test: Backward Compatibility
# ============================================================================

class TestBackwardCompat:
    """Ensure existing imports and APIs still work."""

    def test_hybrid_finding_importable_from_hybrid_analyzer(self):
        from hybrid_analyzer import HybridFinding, HybridScanResult
        assert HybridFinding is not None
        assert HybridScanResult is not None

    def test_hybrid_finding_importable_from_hybrid(self):
        from hybrid import HybridFinding, HybridScanResult
        assert HybridFinding is not None
        assert HybridScanResult is not None

    def test_phase_functions_importable_from_hybrid(self):
        from hybrid import (
            run_phase1_scanning,
            run_phase2_enrichment,
            run_phase3_review,
            run_phase4_sandbox,
            run_phase5_policy,
            run_phase6_reporting,
        )
        assert callable(run_phase1_scanning)
        assert callable(run_phase6_reporting)

    def test_analyzer_has_run_argus_review(self):
        from hybrid_analyzer import HybridSecurityAnalyzer
        assert hasattr(HybridSecurityAnalyzer, "_run_argus_review")

    def test_analyzer_has_run_sandbox_validation(self):
        from hybrid_analyzer import HybridSecurityAnalyzer
        assert hasattr(HybridSecurityAnalyzer, "_run_sandbox_validation")

    def test_main_function_exists(self):
        from hybrid_analyzer import main
        assert callable(main)
