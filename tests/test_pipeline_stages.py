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
