"""Tests for scripts/enrichment_pipeline.py — shared 6-step enrichment pipeline."""

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def all_disabled_config():
    """Config dict with every enrichment toggle explicitly disabled."""
    return {
        "enable_epss_scoring": False,
        "enable_fix_version_tracking": False,
        "enable_vex": False,
        "enable_vuln_deduplication": False,
        "enable_compliance_mapping": False,
        "enable_advanced_suppression": False,
    }


@pytest.fixture()
def sample_findings():
    """Minimal list of finding dicts for pipeline tests."""
    return [
        {"severity": "high", "message": "SQL injection", "cve_id": "CVE-2024-1234"},
        {"severity": "medium", "message": "XSS reflected"},
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnrichmentPipelineBasics:
    """Core behaviour: passthrough, return shape, edge cases."""

    def test_enrichment_pipeline_all_disabled(self, all_disabled_config, sample_findings):
        """When every feature is disabled, findings pass through unchanged."""
        from enrichment_pipeline import run_enrichment_pipeline

        result_findings, metadata = run_enrichment_pipeline(
            sample_findings, all_disabled_config, "/tmp/target",
        )
        assert result_findings == sample_findings
        assert metadata == {}

    def test_enrichment_pipeline_returns_metadata(self, all_disabled_config, sample_findings):
        """Return value is always a (findings_list, metadata_dict) tuple."""
        from enrichment_pipeline import run_enrichment_pipeline

        result = run_enrichment_pipeline(
            sample_findings, all_disabled_config, "/tmp/target",
        )
        assert isinstance(result, tuple)
        assert len(result) == 2
        findings, meta = result
        assert isinstance(findings, list)
        assert isinstance(meta, dict)

    def test_enrichment_pipeline_empty_findings(self, all_disabled_config):
        """Empty findings list returns immediately with no metadata."""
        from enrichment_pipeline import run_enrichment_pipeline

        findings, metadata = run_enrichment_pipeline(
            [], all_disabled_config, "/tmp/target",
        )
        assert findings == []
        assert metadata == {}


class TestEnrichmentPipelineEPSS:
    """Step 1: EPSS scoring integration."""

    def test_enrichment_pipeline_epss_enabled(self, sample_findings):
        """When EPSS is enabled and available, EPSSScorer.enrich_findings is called."""
        config = {
            "enable_epss_scoring": True,
            "enable_fix_version_tracking": False,
            "enable_vex": False,
            "enable_vuln_deduplication": False,
            "enable_compliance_mapping": False,
            "enable_advanced_suppression": False,
            "epss_cache_ttl_hours": "24",
        }

        mock_scorer_instance = MagicMock()
        # enrich_findings returns the same findings with EPSS scores attached
        enriched = [dict(f, epss_score=0.42) for f in sample_findings]
        mock_scorer_instance.enrich_findings.return_value = enriched
        mock_scorer_instance.fetch_scores.return_value = {"CVE-2024-1234": 0.42}
        mock_scorer_instance.get_summary.return_value = {"avg_score": 0.42}

        mock_scorer_cls = MagicMock(return_value=mock_scorer_instance)

        with patch("enrichment_pipeline._EPSS_OK", True), \
             patch("enrichment_pipeline.EPSSScorer", mock_scorer_cls):
            from enrichment_pipeline import run_enrichment_pipeline

            findings, metadata = run_enrichment_pipeline(
                sample_findings, config, "/tmp/target",
            )

        mock_scorer_cls.assert_called_once()
        mock_scorer_instance.enrich_findings.assert_called_once()
        assert "epss" in metadata


class TestEnrichmentPipelineDedup:
    """Step 4: Vulnerability deduplication integration."""

    def test_enrichment_pipeline_dedup_enabled(self, sample_findings):
        """When deduplication is enabled and available, VulnDeduplicator is called."""
        config = {
            "enable_epss_scoring": False,
            "enable_fix_version_tracking": False,
            "enable_vex": False,
            "enable_vuln_deduplication": True,
            "enable_compliance_mapping": False,
            "enable_advanced_suppression": False,
            "deduplication_strategy": "auto",
        }

        mock_dedup_result = MagicMock()
        # After dedup, only 1 finding remains
        mock_dedup_result.kept_findings = [sample_findings[0]]

        mock_dedup_instance = MagicMock()
        mock_dedup_instance.deduplicate.return_value = mock_dedup_result

        mock_dedup_cls = MagicMock(return_value=mock_dedup_instance)
        mock_get_summary = MagicMock(return_value={"removed": 1})

        with patch("enrichment_pipeline._DEDUP_OK", True), \
             patch("enrichment_pipeline.VulnDeduplicator", mock_dedup_cls):
            mock_dedup_cls.get_summary = mock_get_summary
            from enrichment_pipeline import run_enrichment_pipeline

            findings, metadata = run_enrichment_pipeline(
                sample_findings, config, "/tmp/target",
            )

        mock_dedup_cls.assert_called_once_with(strategy="auto")
        mock_dedup_instance.deduplicate.assert_called_once()
        assert "deduplication" in metadata
        assert len(findings) == 1


class TestEnrichmentPipelineGracefulFailure:
    """Pipeline must survive individual step failures without crashing."""

    def test_enrichment_pipeline_graceful_failure(self, sample_findings):
        """When a step throws an exception, the pipeline continues and returns findings."""
        config = {
            "enable_epss_scoring": True,
            "enable_fix_version_tracking": False,
            "enable_vex": False,
            "enable_vuln_deduplication": False,
            "enable_compliance_mapping": False,
            "enable_advanced_suppression": False,
        }

        # Make EPSSScorer constructor raise an exception
        mock_scorer_cls = MagicMock(side_effect=RuntimeError("EPSS API down"))

        with patch("enrichment_pipeline._EPSS_OK", True), \
             patch("enrichment_pipeline.EPSSScorer", mock_scorer_cls):
            from enrichment_pipeline import run_enrichment_pipeline

            findings, metadata = run_enrichment_pipeline(
                sample_findings, config, "/tmp/target",
            )

        # Pipeline should NOT crash -- findings are returned unchanged
        assert findings == sample_findings
        # EPSS metadata should be absent (step failed)
        assert "epss" not in metadata
