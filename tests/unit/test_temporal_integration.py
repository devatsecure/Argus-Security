#!/usr/bin/env python3
"""
Tests for Temporal orchestrator integration in hybrid_analyzer.py.

Covers:
- Temporal skipped when disabled in config
- Graceful fallback when temporal_orchestrator module not importable
- Graceful fallback when Temporal server is unreachable
- Successful Temporal execution path with mocked runner
- Config toggle restoration after Temporal execution
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts directory is on the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analyzer_config(**overrides):
    """Build a minimal config dict suitable for HybridSecurityAnalyzer."""
    base = {
        "enable_temporal": False,
        "temporal_server": "localhost:7233",
        "temporal_namespace": "argus",
        "temporal_retry_mode": "testing",
        "enable_phase_gating": False,
        "enable_mcp_server": False,
        "enable_heuristics": False,
        "enable_quality_filter": False,
        "deep_analysis_mode": "off",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test: Temporal skipped when disabled
# ---------------------------------------------------------------------------


class TestTemporalDisabled:
    """When enable_temporal=False, Temporal code path is never entered."""

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_temporal_not_called_when_disabled(self, tmp_path):
        """analyze() should NOT call _try_temporal_execution when toggle is off."""
        # Create a minimal target directory
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=False)

        with (
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
            patch("hybrid_analyzer.HybridSecurityAnalyzer._try_temporal_execution") as mock_temporal,
            patch("hybrid_analyzer.HybridSecurityAnalyzer._get_enabled_tools", return_value=["semgrep"]),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config
            analyzer._mcp_started = False
            analyzer.enable_ai_enrichment = False

            # Mock the phase imports to avoid full pipeline execution
            mock_result = MagicMock()
            with (
                patch(
                    "hybrid.phases.phase1_scanning.run_phase1_scanning",
                    return_value=([], 0.1, {}),
                ),
                patch(
                    "hybrid.phases.phase2_enrichment.run_phase2_enrichment",
                    return_value=([], {}),
                ),
                patch(
                    "hybrid.phases.phase3_review.run_phase3_review",
                    return_value=([], None),
                ),
                patch(
                    "hybrid.phases.phase4_sandbox.run_phase4_sandbox",
                    return_value=([], None),
                ),
                patch(
                    "hybrid.phases.phase5_policy.run_phase5_policy",
                    return_value=(None, [], {}),
                ),
                patch(
                    "hybrid.phases.phase6_reporting.run_phase6_reporting",
                    return_value=mock_result,
                ),
                patch.object(analyzer, "_validate_phase"),
            ):
                result = analyzer.analyze(str(tmp_path))

            # _try_temporal_execution should never have been called
            mock_temporal.assert_not_called()
            assert result is mock_result


# ---------------------------------------------------------------------------
# Test: Graceful fallback when module not importable
# ---------------------------------------------------------------------------


class TestTemporalModuleUnavailable:
    """When temporal_orchestrator module can't be imported, fall back gracefully."""

    def test_fallback_when_import_fails(self, tmp_path):
        """_try_temporal_execution returns None when module not available."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        with (
            patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", False),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            result = analyzer._try_temporal_execution(
                target_path=str(tmp_path),
                output_dir=None,
                severity_filter=None,
            )
            assert result is None


# ---------------------------------------------------------------------------
# Test: Graceful fallback when Temporal server unreachable
# ---------------------------------------------------------------------------


class TestTemporalServerUnreachable:
    """When AuditWorkflowRunner.run() raises, fall back gracefully."""

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_fallback_on_runner_exception(self, tmp_path):
        """_try_temporal_execution returns None when runner.run() raises."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        mock_runner = MagicMock()
        mock_runner.run.side_effect = ConnectionError("Cannot connect to Temporal server")

        mock_activities_cls = MagicMock()
        mock_runner_cls = MagicMock(return_value=mock_runner)

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", mock_activities_cls),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            result = analyzer._try_temporal_execution(
                target_path=str(tmp_path),
                output_dir=None,
                severity_filter=None,
            )
            assert result is None

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_fallback_on_runtime_error(self, tmp_path):
        """_try_temporal_execution returns None on RuntimeError (e.g. temporalio not installed)."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        mock_runner = MagicMock()
        mock_runner.run.side_effect = RuntimeError("temporalio package not installed")

        mock_runner_cls = MagicMock(return_value=mock_runner)

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            result = analyzer._try_temporal_execution(
                target_path=str(tmp_path),
                output_dir=None,
                severity_filter=None,
            )
            assert result is None


# ---------------------------------------------------------------------------
# Test: Successful Temporal execution path
# ---------------------------------------------------------------------------


class TestTemporalSuccess:
    """When Temporal runs successfully, it returns a HybridScanResult."""

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_successful_temporal_run(self, tmp_path):
        """_try_temporal_execution returns a result when runner succeeds."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        # Mock the runner
        mock_runner = MagicMock()
        mock_runner.run.return_value = {}
        mock_runner.get_summary.return_value = {
            "total_phases": 6,
            "completed_phases": 6,
            "failed_phases": 0,
            "phases": {
                "scanner_orchestration": {"status": "success", "duration_seconds": 1.0, "error": ""},
                "ai_enrichment": {"status": "success", "duration_seconds": 2.0, "error": ""},
                "multi_agent_review": {"status": "success", "duration_seconds": 1.5, "error": ""},
                "sandbox_validation": {"status": "success", "duration_seconds": 0.5, "error": ""},
                "policy_gates": {"status": "success", "duration_seconds": 0.3, "error": ""},
                "reporting": {"status": "success", "duration_seconds": 0.2, "error": ""},
            },
            "retry_policy": {},
        }

        mock_runner_cls = MagicMock(return_value=mock_runner)
        mock_analyze_result = MagicMock()

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            # Mock the recursive analyze() call (self.analyze() with temporal disabled)
            with patch.object(analyzer, "analyze", return_value=mock_analyze_result):
                result = analyzer._try_temporal_execution(
                    target_path=str(tmp_path),
                    output_dir="/tmp/out",
                    severity_filter=["critical"],
                )

            assert result is mock_analyze_result
            # Verify runner was constructed with correct retry mode
            mock_runner_cls.assert_called_once()
            call_kwargs = mock_runner_cls.call_args
            assert call_kwargs[1]["retry_mode"] == "testing"

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_temporal_config_restored_after_execution(self, tmp_path):
        """enable_temporal is restored to True after the recursive analyze() call."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        mock_runner = MagicMock()
        mock_runner.run.return_value = {}
        mock_runner.get_summary.return_value = {
            "total_phases": 6,
            "completed_phases": 6,
            "failed_phases": 0,
            "phases": {},
            "retry_policy": {},
        }

        mock_runner_cls = MagicMock(return_value=mock_runner)

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            # Track config state during the recursive analyze() call
            temporal_during_call = []

            def mock_analyze(target_path, output_dir=None, severity_filter=None):
                temporal_during_call.append(analyzer.config.get("enable_temporal"))
                return MagicMock()

            with patch.object(analyzer, "analyze", side_effect=mock_analyze):
                analyzer._try_temporal_execution(
                    target_path=str(tmp_path),
                    output_dir=None,
                    severity_filter=None,
                )

            # During recursive call, enable_temporal should have been False
            assert temporal_during_call == [False]
            # After execution, it should be restored to True
            assert analyzer.config["enable_temporal"] is True

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_temporal_config_restored_on_analyze_failure(self, tmp_path):
        """enable_temporal is restored even if the recursive analyze() raises."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        mock_runner = MagicMock()
        mock_runner.run.return_value = {}
        mock_runner.get_summary.return_value = {
            "total_phases": 6,
            "completed_phases": 6,
            "failed_phases": 0,
            "phases": {},
            "retry_policy": {},
        }

        mock_runner_cls = MagicMock(return_value=mock_runner)

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            def mock_analyze_fail(target_path, output_dir=None, severity_filter=None):
                raise ValueError("Something broke in analyze")

            with patch.object(analyzer, "analyze", side_effect=mock_analyze_fail):
                # The outer except Exception catches the ValueError from analyze()
                # and returns None (graceful fallback)
                result = analyzer._try_temporal_execution(
                    target_path=str(tmp_path),
                    output_dir=None,
                    severity_filter=None,
                )

            # Should fall back gracefully
            assert result is None
            # Config should still be restored
            assert analyzer.config["enable_temporal"] is True


# ---------------------------------------------------------------------------
# Test: Temporal summary attached to result
# ---------------------------------------------------------------------------


class TestTemporalSummaryAttachment:
    """Verify that Temporal workflow summary metadata is attached to result."""

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    def test_summary_attached_to_result(self, tmp_path):
        """Result should have temporal_summary attribute after successful run."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        expected_summary = {
            "total_phases": 6,
            "completed_phases": 5,
            "failed_phases": 1,
            "phases": {
                "scanner_orchestration": {"status": "success", "duration_seconds": 1.0, "error": ""},
                "ai_enrichment": {"status": "failed", "duration_seconds": 2.0, "error": "API key invalid"},
            },
            "retry_policy": {},
        }

        mock_runner = MagicMock()
        mock_runner.run.return_value = {}
        mock_runner.get_summary.return_value = expected_summary

        mock_runner_cls = MagicMock(return_value=mock_runner)
        mock_result = MagicMock()

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            with patch.object(analyzer, "analyze", return_value=mock_result):
                result = analyzer._try_temporal_execution(
                    target_path=str(tmp_path),
                    output_dir=None,
                    severity_filter=None,
                )

            assert result is mock_result
            assert result.__dict__["temporal_summary"] == expected_summary


# ---------------------------------------------------------------------------
# Test: Integration with analyze() dispatch
# ---------------------------------------------------------------------------


class TestAnalyzeTemporalDispatch:
    """Test that analyze() correctly dispatches to Temporal when enabled."""

    def test_analyze_calls_temporal_when_enabled(self, tmp_path):
        """analyze() should call _try_temporal_execution and return its result."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        with patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config
            analyzer._mcp_started = False
            analyzer.enable_ai_enrichment = False

            mock_temporal_result = MagicMock()

            with (
                patch.object(
                    analyzer,
                    "_try_temporal_execution",
                    return_value=mock_temporal_result,
                ) as mock_try,
                patch.object(analyzer, "_get_enabled_tools", return_value=["semgrep"]),
            ):
                result = analyzer.analyze(str(tmp_path))

            mock_try.assert_called_once_with(
                target_path=str(tmp_path),
                output_dir=None,
                severity_filter=None,
            )
            assert result is mock_temporal_result

    def test_analyze_falls_through_when_temporal_returns_none(self, tmp_path):
        """analyze() continues with direct execution when _try_temporal returns None."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True)

        with patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config
            analyzer._mcp_started = False
            analyzer.enable_ai_enrichment = False

            mock_direct_result = MagicMock()

            with (
                patch.object(analyzer, "_try_temporal_execution", return_value=None),
                patch.object(analyzer, "_get_enabled_tools", return_value=["semgrep"]),
                patch.object(analyzer, "_validate_phase"),
                patch(
                    "hybrid.phases.phase1_scanning.run_phase1_scanning",
                    return_value=([], 0.1, {}),
                ),
                patch(
                    "hybrid.phases.phase2_enrichment.run_phase2_enrichment",
                    return_value=([], {}),
                ),
                patch(
                    "hybrid.phases.phase3_review.run_phase3_review",
                    return_value=([], None),
                ),
                patch(
                    "hybrid.phases.phase4_sandbox.run_phase4_sandbox",
                    return_value=([], None),
                ),
                patch(
                    "hybrid.phases.phase5_policy.run_phase5_policy",
                    return_value=(None, [], {}),
                ),
                patch(
                    "hybrid.phases.phase6_reporting.run_phase6_reporting",
                    return_value=mock_direct_result,
                ),
            ):
                result = analyzer.analyze(str(tmp_path))

            assert result is mock_direct_result


# ---------------------------------------------------------------------------
# Test: Retry mode passed correctly
# ---------------------------------------------------------------------------


class TestTemporalRetryMode:
    """Verify the retry mode from config is passed to AuditWorkflowRunner."""

    @patch("hybrid_analyzer._TEMPORAL_IMPORT_OK", True)
    @pytest.mark.parametrize("mode", ["production", "testing", "development"])
    def test_retry_mode_from_config(self, tmp_path, mode):
        """AuditWorkflowRunner receives the correct retry_mode from config."""
        (tmp_path / "test.py").write_text("x = 1\n")

        config = _make_analyzer_config(enable_temporal=True, temporal_retry_mode=mode)

        mock_runner = MagicMock()
        mock_runner.run.return_value = {}
        mock_runner.get_summary.return_value = {
            "total_phases": 6,
            "completed_phases": 6,
            "failed_phases": 0,
            "phases": {},
            "retry_policy": {},
        }

        mock_runner_cls = MagicMock(return_value=mock_runner)

        with (
            patch("hybrid_analyzer.AuditWorkflowRunner", mock_runner_cls),
            patch("hybrid_analyzer.PipelineActivities", MagicMock()),
            patch("hybrid_analyzer.HybridSecurityAnalyzer.__init__", return_value=None),
        ):
            from hybrid_analyzer import HybridSecurityAnalyzer

            analyzer = HybridSecurityAnalyzer.__new__(HybridSecurityAnalyzer)
            analyzer.config = config

            with patch.object(analyzer, "analyze", return_value=MagicMock()):
                analyzer._try_temporal_execution(
                    target_path=str(tmp_path),
                    output_dir=None,
                    severity_filter=None,
                )

            _, kwargs = mock_runner_cls.call_args
            assert kwargs["retry_mode"] == mode
