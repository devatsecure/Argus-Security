#!/usr/bin/env python3
"""
Unit Tests for Enrichment Pipeline

Tests cover:
- _parse_bool helper
- run_enrichment_pipeline empty findings
- run_enrichment_pipeline with all steps disabled
- Individual step functions with mocked dependencies
- Error handling (each step is non-fatal)
- Metadata collection
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from enrichment_pipeline import (
    _parse_bool,
    _step_compliance,
    _step_dedup,
    _step_epss,
    _step_fix_versions,
    _step_suppression,
    _step_vex,
    run_enrichment_pipeline,
)

# ---------------------------------------------------------------------------
# _parse_bool
# ---------------------------------------------------------------------------


class TestParseBool:
    """Test _parse_bool helper"""

    def test_true_string(self):
        assert _parse_bool("true") is True
        assert _parse_bool("True") is True
        assert _parse_bool("TRUE") is True

    def test_false_string(self):
        assert _parse_bool("false") is False
        assert _parse_bool("False") is False
        assert _parse_bool("") is False

    def test_bool_values(self):
        assert _parse_bool(True) is True
        assert _parse_bool(False) is False

    def test_int_values(self):
        assert _parse_bool(1) is True
        assert _parse_bool(0) is False

    def test_none_is_false(self):
        assert _parse_bool(None) is False


# ---------------------------------------------------------------------------
# run_enrichment_pipeline
# ---------------------------------------------------------------------------


class TestRunEnrichmentPipeline:
    """Test the main pipeline function"""

    def test_empty_findings_returns_empty(self):
        findings, metadata = run_enrichment_pipeline([], {}, "/tmp/test")
        assert findings == []
        assert metadata == {}

    def test_all_steps_disabled(self):
        """When all enable_ flags are False, findings pass through unchanged"""
        config = {
            "enable_epss_scoring": False,
            "enable_fix_version_tracking": False,
            "enable_vex": False,
            "enable_vuln_deduplication": False,
            "enable_compliance_mapping": False,
            "enable_advanced_suppression": False,
        }
        findings = [{"id": "f1", "severity": "high"}]
        result, metadata = run_enrichment_pipeline(findings, config, "/tmp/test")
        assert len(result) == 1
        assert result[0]["id"] == "f1"
        assert metadata == {}

    def test_findings_are_copied(self):
        """Pipeline should not mutate the original findings list reference"""
        original = [{"id": "f1"}]
        config = {
            "enable_epss_scoring": False,
            "enable_fix_version_tracking": False,
            "enable_vex": False,
            "enable_vuln_deduplication": False,
            "enable_compliance_mapping": False,
            "enable_advanced_suppression": False,
        }
        result, _ = run_enrichment_pipeline(original, config, "/tmp/test")
        # The result list is a new list
        assert result is not original


# ---------------------------------------------------------------------------
# Individual Steps
# ---------------------------------------------------------------------------


class TestStepEPSS:
    """Test _step_epss"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_epss_scoring": False}
        result, meta = _step_epss(findings, config, "/tmp")
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._EPSS_OK", False)
    def test_module_not_available(self):
        findings = [{"id": "f1"}]
        config = {"enable_epss_scoring": True}
        result, meta = _step_epss(findings, config, "/tmp")
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._EPSS_OK", True)
    @patch("enrichment_pipeline.EPSSScorer")
    def test_epss_scoring_success(self, mock_scorer_class):
        mock_scorer = MagicMock()
        mock_scorer_class.return_value = mock_scorer
        mock_scorer.enrich_findings.return_value = [{"id": "f1", "epss": 0.05}]
        mock_scorer.fetch_scores.return_value = {}
        mock_scorer.get_summary.return_value = {"total": 1}

        findings = [{"id": "f1", "cve": "CVE-2024-0001"}]
        config = {"enable_epss_scoring": True}
        result, meta = _step_epss(findings, config, "/tmp")
        assert result[0].get("epss") == 0.05

    @patch("enrichment_pipeline._EPSS_OK", True)
    @patch("enrichment_pipeline.EPSSScorer")
    def test_epss_scoring_exception_non_fatal(self, mock_scorer_class):
        mock_scorer_class.side_effect = RuntimeError("API down")
        findings = [{"id": "f1"}]
        config = {"enable_epss_scoring": True}
        result, meta = _step_epss(findings, config, "/tmp")
        assert result == findings
        assert meta is None


class TestStepFixVersions:
    """Test _step_fix_versions"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_fix_version_tracking": False}
        result, meta = _step_fix_versions(findings, config)
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._FIX_OK", False)
    def test_module_not_available(self):
        findings = [{"id": "f1"}]
        config = {"enable_fix_version_tracking": True}
        result, meta = _step_fix_versions(findings, config)
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._FIX_OK", True)
    @patch("enrichment_pipeline.FixVersionTracker")
    def test_fix_version_success(self, mock_tracker_class):
        mock_tracker = MagicMock()
        mock_tracker_class.return_value = mock_tracker
        mock_tracker.extract_fix_info.return_value = {"fix": "1.2.3"}
        mock_tracker.enrich_findings.return_value = [{"id": "f1", "fix_version": "1.2.3"}]
        mock_tracker.get_summary.return_value = {"fixes_found": 1}

        findings = [{"id": "f1"}]
        config = {"enable_fix_version_tracking": True}
        result, meta = _step_fix_versions(findings, config)
        assert meta is not None

    @patch("enrichment_pipeline._FIX_OK", True)
    @patch("enrichment_pipeline.FixVersionTracker")
    def test_fix_version_exception_non_fatal(self, mock_tracker_class):
        mock_tracker_class.side_effect = RuntimeError("parse error")
        findings = [{"id": "f1"}]
        config = {"enable_fix_version_tracking": True}
        result, meta = _step_fix_versions(findings, config)
        assert result == findings
        assert meta is None


class TestStepVex:
    """Test _step_vex"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_vex": False}
        result, suppressed, meta = _step_vex(findings, config, "/tmp")
        assert result == findings
        assert suppressed == []
        assert meta is None

    @patch("enrichment_pipeline._VEX_OK", False)
    def test_module_not_available(self):
        findings = [{"id": "f1"}]
        config = {"enable_vex": True}
        result, suppressed, meta = _step_vex(findings, config, "/tmp")
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._VEX_OK", True)
    @patch("enrichment_pipeline.VEXProcessor")
    def test_vex_with_no_statements(self, mock_proc_class):
        mock_proc = MagicMock()
        mock_proc_class.return_value = mock_proc
        mock_proc.load_statements.return_value = []

        findings = [{"id": "f1"}]
        config = {"enable_vex": True}
        result, suppressed, meta = _step_vex(findings, config, "/tmp")
        assert result == findings
        assert suppressed == []

    @patch("enrichment_pipeline._VEX_OK", True)
    @patch("enrichment_pipeline.VEXProcessor")
    def test_vex_exception_non_fatal(self, mock_proc_class):
        mock_proc_class.side_effect = RuntimeError("VEX parse error")
        findings = [{"id": "f1"}]
        config = {"enable_vex": True}
        result, suppressed, meta = _step_vex(findings, config, "/tmp")
        assert result == findings
        assert meta is None


class TestStepDedup:
    """Test _step_dedup"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_vuln_deduplication": False}
        result, meta = _step_dedup(findings, config)
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._DEDUP_OK", True)
    @patch("enrichment_pipeline.VulnDeduplicator")
    def test_dedup_success(self, mock_dedup_class):
        mock_dedup = MagicMock()
        mock_dedup_class.return_value = mock_dedup
        mock_result = MagicMock()
        mock_result.kept_findings = [{"id": "f1"}]
        mock_dedup.deduplicate.return_value = mock_result
        mock_dedup_class.get_summary.return_value = {"removed": 1}

        findings = [{"id": "f1"}, {"id": "f1_dup"}]
        config = {"enable_vuln_deduplication": True}
        result, meta = _step_dedup(findings, config)
        assert len(result) == 1
        assert meta is not None

    @patch("enrichment_pipeline._DEDUP_OK", True)
    @patch("enrichment_pipeline.VulnDeduplicator")
    def test_dedup_exception_non_fatal(self, mock_dedup_class):
        mock_dedup_class.side_effect = RuntimeError("dedup error")
        findings = [{"id": "f1"}]
        config = {"enable_vuln_deduplication": True}
        result, meta = _step_dedup(findings, config)
        assert result == findings
        assert meta is None


class TestStepCompliance:
    """Test _step_compliance"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_compliance_mapping": False}
        result, meta = _step_compliance(findings, config, "/tmp")
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._COMPLIANCE_OK", True)
    @patch("enrichment_pipeline.ComplianceMapper")
    def test_compliance_exception_non_fatal(self, mock_mapper_class):
        mock_mapper_class.side_effect = RuntimeError("compliance error")
        findings = [{"id": "f1"}]
        config = {"enable_compliance_mapping": True}
        result, meta = _step_compliance(findings, config, "/tmp")
        assert result == findings
        assert meta is None


class TestStepSuppression:
    """Test _step_suppression"""

    def test_disabled_by_config(self):
        findings = [{"id": "f1"}]
        config = {"enable_advanced_suppression": False}
        result, meta = _step_suppression(findings, config, "/tmp", [])
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._SUPPRESSION_OK", True)
    @patch("enrichment_pipeline.AdvancedSuppressionManager")
    def test_suppression_exception_non_fatal(self, mock_mgr_class):
        mock_mgr_class.side_effect = RuntimeError("suppression error")
        findings = [{"id": "f1"}]
        config = {"enable_advanced_suppression": True}
        result, meta = _step_suppression(findings, config, "/tmp", [])
        assert result == findings
        assert meta is None

    @patch("enrichment_pipeline._SUPPRESSION_OK", True)
    @patch("enrichment_pipeline.AdvancedSuppressionManager")
    def test_suppression_success_no_rules(self, mock_mgr_class):
        mock_mgr = MagicMock()
        mock_mgr_class.return_value = mock_mgr
        mock_mgr.load_rules.return_value = []
        mock_mgr.add_vex_rules.return_value = []
        mock_mgr.add_epss_auto_suppress.return_value = []
        mock_mgr.get_expired_rules.return_value = []

        findings = [{"id": "f1"}]
        config = {"enable_advanced_suppression": True}
        result, meta = _step_suppression(findings, config, "/tmp", [])
        assert result == findings
        assert meta is not None
        assert meta["rules_loaded"] == 0
        assert meta["suppressed"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
