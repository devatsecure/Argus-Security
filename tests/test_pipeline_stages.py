"""
Tests for _run_checkov in ScannerOrchestrationStage.

Verifies that the method correctly converts a CheckovScanResult dataclass
into a list of dicts, handles empty findings, and gracefully degrades on
import/runtime failures.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pipeline.protocol import PipelineContext
from pipeline.stages import ScannerOrchestrationStage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_checkov_finding(**overrides):
    """Create a mock CheckovFinding with a working to_dict()."""
    defaults = {
        "check_id": "CKV_AWS_1",
        "check_name": "Ensure S3 bucket versioning is enabled",
        "check_class": "checkov.terraform.checks.resource.aws",
        "severity": "HIGH",
        "file_path": "/main.tf",
        "resource": "aws_s3_bucket.data",
        "resource_type": "aws_s3_bucket",
        "file_line_range": [10, 20],
        "guideline": "https://docs.checkov.io/...",
        "description": "S3 bucket versioning",
        "code_block": ["resource ..."],
        "check_result": {"result": "FAILED"},
        "framework": "terraform",
    }
    defaults.update(overrides)

    finding = MagicMock()
    finding.to_dict.return_value = dict(defaults)
    return finding


def _make_scan_result(findings=None):
    """Create a mock CheckovScanResult wrapping the given findings list."""
    result = MagicMock()
    result.findings = findings if findings is not None else []
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRunCheckov:
    """Tests for ScannerOrchestrationStage._run_checkov."""

    def test_returns_list_of_dicts(self):
        """_run_checkov must return a list of dicts (not a CheckovScanResult)."""
        finding1 = _make_checkov_finding(check_id="CKV_AWS_1")
        finding2 = _make_checkov_finding(check_id="CKV_AWS_2", severity="MEDIUM")
        scan_result = _make_scan_result([finding1, finding2])

        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = scan_result

        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"checkov_scanner": MagicMock(CheckovScanner=mock_scanner_cls)}):
            result = stage._run_checkov("/tmp/repo")

        assert isinstance(result, list)
        assert len(result) == 2
        for item in result:
            assert isinstance(item, dict)
        assert result[0]["check_id"] == "CKV_AWS_1"
        assert result[1]["severity"] == "MEDIUM"

    def test_empty_findings_returns_empty_list(self):
        """When Checkov finds nothing, _run_checkov returns []."""
        scan_result = _make_scan_result([])

        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = scan_result

        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"checkov_scanner": MagicMock(CheckovScanner=mock_scanner_cls)}):
            result = stage._run_checkov("/tmp/repo")

        assert result == []

    def test_import_failure_returns_empty_list(self):
        """If checkov_scanner cannot be imported, return [] gracefully."""
        stage = ScannerOrchestrationStage()

        # Force ImportError by ensuring the module is NOT available
        with patch.dict("sys.modules", {"checkov_scanner": None}):
            result = stage._run_checkov("/tmp/repo")

        assert result == []

    def test_scanner_runtime_error_returns_empty_list(self):
        """If scanner.scan() raises at runtime, return [] gracefully."""
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.side_effect = RuntimeError("scan boom")

        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"checkov_scanner": MagicMock(CheckovScanner=mock_scanner_cls)}):
            result = stage._run_checkov("/tmp/repo")

        assert result == []

    def test_findings_extend_works_after_fix(self):
        """The returned list must be compatible with ctx.findings.extend()."""
        finding = _make_checkov_finding()
        scan_result = _make_scan_result([finding])

        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = scan_result

        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"checkov_scanner": MagicMock(CheckovScanner=mock_scanner_cls)}):
            result = stage._run_checkov("/tmp/repo")

        ctx = PipelineContext()
        # This is the line that previously threw TypeError
        ctx.findings.extend(result)
        assert len(ctx.findings) == 1
        assert isinstance(ctx.findings[0], dict)


# ---------------------------------------------------------------------------
# Tests for ScannerOrchestrationStage._execute
# ---------------------------------------------------------------------------


class TestScannerOrchestrationExecute:
    """Tests for ScannerOrchestrationStage._execute (full orchestration)."""

    def test_execute_with_no_scanners_enabled(self):
        """When all scanners are disabled, _execute returns empty scanners_run
        and ctx.findings stays empty."""
        stage = ScannerOrchestrationStage()
        ctx = PipelineContext(
            target_path="/tmp/repo",
            config={
                "enable_semgrep": False,
                "enable_trivy": False,
                "enable_checkov": False,
            },
        )

        result = stage._execute(ctx)

        assert result["scanners_run"] == []
        assert ctx.findings == []

    def test_semgrep_failure_doesnt_crash(self):
        """If SemgrepScanner raises RuntimeError, _run_semgrep returns []
        and no exception propagates."""
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.side_effect = RuntimeError("semgrep boom")

        stage = ScannerOrchestrationStage()

        with patch.dict(
            "sys.modules",
            {"semgrep_scanner": MagicMock(SemgrepScanner=mock_scanner_cls)},
        ):
            result = stage._run_semgrep("/tmp/repo")

        assert result == []

    def test_trivy_failure_doesnt_crash(self):
        """If TrivyScanner raises RuntimeError, _run_trivy returns []
        and no exception propagates."""
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.side_effect = RuntimeError("trivy boom")

        stage = ScannerOrchestrationStage()

        with patch.dict(
            "sys.modules",
            {"trivy_scanner": MagicMock(TrivyScanner=mock_scanner_cls)},
        ):
            result = stage._run_trivy("/tmp/repo")

        assert result == []

    def test_execute_runs_all_enabled_scanners(self):
        """When scanners are enabled and produce findings, scanners_run lists
        them and ctx.findings is populated."""
        stage = ScannerOrchestrationStage()
        ctx = PipelineContext(
            target_path="/tmp/repo",
            config={
                "enable_semgrep": True,
                "enable_trivy": True,
                "enable_checkov": True,
            },
        )

        semgrep_findings = [{"id": "sg-1", "severity": "high"}]
        trivy_findings = [{"id": "tv-1", "severity": "critical"}]
        checkov_findings = [{"id": "ck-1", "severity": "medium"}]

        with patch.object(stage, "_run_semgrep", return_value=semgrep_findings), \
             patch.object(stage, "_run_trivy", return_value=trivy_findings), \
             patch.object(stage, "_run_checkov", return_value=checkov_findings):
            result = stage._execute(ctx)

        assert "semgrep" in result["scanners_run"]
        assert "trivy" in result["scanners_run"]
        assert "checkov" in result["scanners_run"]
        assert len(ctx.findings) == 3

    def test_execute_skips_disabled_scanners(self):
        """Only enabled scanners are run; disabled ones are skipped entirely."""
        stage = ScannerOrchestrationStage()
        ctx = PipelineContext(
            target_path="/tmp/repo",
            config={
                "enable_semgrep": True,
                "enable_trivy": False,
                "enable_checkov": False,
            },
        )

        semgrep_findings = [{"id": "sg-1"}]

        with patch.object(stage, "_run_semgrep", return_value=semgrep_findings) as mock_sg, \
             patch.object(stage, "_run_trivy") as mock_tv, \
             patch.object(stage, "_run_checkov") as mock_ck:
            result = stage._execute(ctx)

        mock_sg.assert_called_once_with("/tmp/repo")
        mock_tv.assert_not_called()
        mock_ck.assert_not_called()
        assert result["scanners_run"] == ["semgrep"]
        assert len(ctx.findings) == 1

    def test_scanner_returning_empty_not_in_scanners_run(self):
        """A scanner that returns [] should NOT appear in scanners_run."""
        stage = ScannerOrchestrationStage()
        ctx = PipelineContext(
            target_path="/tmp/repo",
            config={
                "enable_semgrep": True,
                "enable_trivy": True,
                "enable_checkov": False,
            },
        )

        with patch.object(stage, "_run_semgrep", return_value=[]), \
             patch.object(stage, "_run_trivy", return_value=[{"id": "tv-1"}]):
            result = stage._execute(ctx)

        assert "semgrep" not in result["scanners_run"]
        assert "trivy" in result["scanners_run"]
        assert len(ctx.findings) == 1

    def test_semgrep_import_error_returns_empty(self):
        """If semgrep_scanner module cannot be imported, _run_semgrep returns []."""
        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"semgrep_scanner": None}):
            result = stage._run_semgrep("/tmp/repo")

        assert result == []

    def test_trivy_import_error_returns_empty(self):
        """If trivy_scanner module cannot be imported, _run_trivy returns []."""
        stage = ScannerOrchestrationStage()

        with patch.dict("sys.modules", {"trivy_scanner": None}):
            result = stage._run_trivy("/tmp/repo")

        assert result == []
