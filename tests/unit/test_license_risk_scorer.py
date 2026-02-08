"""
Tests for License Risk Scorer.

Covers license classification across all five severity tiers, unknown license
handling, case-insensitive lookups, CycloneDX component scoring (single and
batch), summary generation, and policy violation output.
"""

import os
import sys

import pytest

# Ensure the scripts directory is on the import path.
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts")
)

from scripts.license_risk_scorer import (
    LicenseCategory,
    LicenseRisk,
    LicenseRiskScorer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_component(name: str, version: str, license_ids: list[str]) -> dict:
    """Build a minimal CycloneDX component dict."""
    return {
        "name": name,
        "version": version,
        "licenses": [{"license": {"id": lid}} for lid in license_ids],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scorer():
    return LicenseRiskScorer()


# ---------------------------------------------------------------------------
# Classification – individual category tests
# ---------------------------------------------------------------------------

class TestClassifyLicense:
    """Verify classify_license returns the correct (category, severity)."""

    @pytest.mark.parametrize(
        "spdx_id",
        ["AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "EUPL-1.1", "EUPL-1.2"],
    )
    def test_forbidden_licenses(self, scorer, spdx_id):
        category, severity = scorer.classify_license(spdx_id)
        assert category is LicenseCategory.FORBIDDEN
        assert severity == "critical"

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "GPL-2.0-only",
            "GPL-2.0-or-later",
            "GPL-3.0-only",
            "GPL-3.0-or-later",
            "LGPL-2.0-only",
            "LGPL-2.1-only",
            "LGPL-3.0-only",
            "CC-BY-SA-4.0",
        ],
    )
    def test_restricted_licenses(self, scorer, spdx_id):
        category, severity = scorer.classify_license(spdx_id)
        assert category is LicenseCategory.RESTRICTED
        assert severity == "high"

    @pytest.mark.parametrize(
        "spdx_id",
        ["MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CPL-1.0", "OSL-3.0"],
    )
    def test_reciprocal_licenses(self, scorer, spdx_id):
        category, severity = scorer.classify_license(spdx_id)
        assert category is LicenseCategory.RECIPROCAL
        assert severity == "medium"

    @pytest.mark.parametrize(
        "spdx_id",
        [
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Zlib",
            "PSF-2.0",
            "BSL-1.0",
            "Artistic-2.0",
        ],
    )
    def test_notice_licenses(self, scorer, spdx_id):
        category, severity = scorer.classify_license(spdx_id)
        assert category is LicenseCategory.NOTICE
        assert severity == "low"

    @pytest.mark.parametrize(
        "spdx_id",
        ["Unlicense", "CC0-1.0", "WTFPL", "0BSD"],
    )
    def test_unencumbered_licenses(self, scorer, spdx_id):
        category, severity = scorer.classify_license(spdx_id)
        assert category is LicenseCategory.UNENCUMBERED
        assert severity == "none"


class TestUnknownAndEdgeCases:
    """Edge cases: unknown IDs, empty strings, case-insensitivity."""

    def test_unknown_license_returns_unknown(self, scorer):
        category, severity = scorer.classify_license("MADE-UP-1.0")
        assert category is LicenseCategory.UNKNOWN
        assert severity == "unknown"

    def test_empty_string_returns_unknown(self, scorer):
        category, severity = scorer.classify_license("")
        assert category is LicenseCategory.UNKNOWN
        assert severity == "unknown"

    def test_case_insensitive_mit(self, scorer):
        category, severity = scorer.classify_license("mit")
        assert category is LicenseCategory.NOTICE
        assert severity == "low"

    def test_case_insensitive_agpl(self, scorer):
        category, severity = scorer.classify_license("agpl-3.0-only")
        assert category is LicenseCategory.FORBIDDEN
        assert severity == "critical"

    def test_case_insensitive_mixed_case(self, scorer):
        category, severity = scorer.classify_license("Apache-2.0")
        assert category is LicenseCategory.NOTICE
        assert severity == "low"

        category2, severity2 = scorer.classify_license("APACHE-2.0")
        assert category2 is LicenseCategory.NOTICE
        assert severity2 == "low"


# ---------------------------------------------------------------------------
# Component scoring
# ---------------------------------------------------------------------------

class TestScoreComponent:
    """Test score_component with various CycloneDX structures."""

    def test_single_license_component(self, scorer):
        comp = _make_component("requests", "2.31.0", ["Apache-2.0"])
        risk = scorer.score_component(comp)

        assert risk is not None
        assert risk.license_id == "Apache-2.0"
        assert risk.category is LicenseCategory.NOTICE
        assert risk.severity == "low"
        assert risk.package_name == "requests"
        assert risk.package_version == "2.31.0"
        assert risk.source == "sbom"

    def test_no_licenses_returns_none(self, scorer):
        comp = {"name": "bare-package", "version": "0.1.0", "licenses": []}
        assert scorer.score_component(comp) is None

    def test_missing_licenses_key_returns_none(self, scorer):
        comp = {"name": "bare-package", "version": "0.1.0"}
        assert scorer.score_component(comp) is None

    def test_multiple_licenses_picks_highest_severity(self, scorer):
        """When a component has MIT (low) and GPL-3.0 (high), high wins."""
        comp = _make_component("dual-lib", "1.0.0", ["MIT", "GPL-3.0-only"])
        risk = scorer.score_component(comp)

        assert risk is not None
        assert risk.severity == "high"
        assert risk.category is LicenseCategory.RESTRICTED
        assert risk.license_id == "GPL-3.0-only"

    def test_multiple_licenses_forbidden_wins_over_restricted(self, scorer):
        comp = _make_component("triple-lib", "2.0.0", ["MIT", "GPL-3.0-only", "AGPL-3.0-only"])
        risk = scorer.score_component(comp)

        assert risk is not None
        assert risk.severity == "critical"
        assert risk.category is LicenseCategory.FORBIDDEN
        assert risk.license_id == "AGPL-3.0-only"

    def test_component_with_missing_name_and_version(self, scorer):
        comp = {"licenses": [{"license": {"id": "MIT"}}]}
        risk = scorer.score_component(comp)

        assert risk is not None
        assert risk.package_name == "unknown"
        assert risk.package_version == "unknown"
        assert risk.severity == "low"


# ---------------------------------------------------------------------------
# Batch scoring
# ---------------------------------------------------------------------------

class TestScoreComponents:
    """Test batch scoring via score_components."""

    def test_batch_scoring(self, scorer):
        components = [
            _make_component("pkg-a", "1.0.0", ["MIT"]),
            _make_component("pkg-b", "2.0.0", ["GPL-3.0-only"]),
            _make_component("pkg-c", "3.0.0", ["AGPL-3.0-only"]),
        ]
        risks = scorer.score_components(components)

        assert len(risks) == 3
        severities = {r.package_name: r.severity for r in risks}
        assert severities["pkg-a"] == "low"
        assert severities["pkg-b"] == "high"
        assert severities["pkg-c"] == "critical"

    def test_batch_skips_components_without_licenses(self, scorer):
        components = [
            _make_component("has-license", "1.0.0", ["MIT"]),
            {"name": "no-license", "version": "0.1.0"},
            {"name": "empty-license", "version": "0.2.0", "licenses": []},
        ]
        risks = scorer.score_components(components)
        assert len(risks) == 1
        assert risks[0].package_name == "has-license"

    def test_empty_components_list(self, scorer):
        assert scorer.score_components([]) == []


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

class TestGetSummary:
    """Test summary aggregation."""

    def test_summary_statistics(self, scorer):
        risks = [
            LicenseRisk("MIT", "MIT", LicenseCategory.NOTICE, "low", "a", "1.0"),
            LicenseRisk("MIT", "MIT", LicenseCategory.NOTICE, "low", "b", "1.0"),
            LicenseRisk("GPL-3.0-only", "GPL-3.0-only", LicenseCategory.RESTRICTED, "high", "c", "1.0"),
            LicenseRisk("AGPL-3.0-only", "AGPL-3.0-only", LicenseCategory.FORBIDDEN, "critical", "d", "1.0"),
        ]
        summary = scorer.get_summary(risks)

        assert summary["total_components"] == 4
        assert summary["by_severity"]["low"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_category"]["notice"] == 2
        assert summary["by_category"]["restricted"] == 1
        assert summary["by_category"]["forbidden"] == 1
        assert len(summary["forbidden_licenses"]) == 1
        assert len(summary["restricted_licenses"]) == 1

    def test_summary_empty_risks(self, scorer):
        summary = scorer.get_summary([])
        assert summary["total_components"] == 0
        assert summary["by_severity"] == {}
        assert summary["by_category"] == {}
        assert summary["forbidden_licenses"] == []
        assert summary["restricted_licenses"] == []

    def test_summary_no_forbidden_or_restricted(self, scorer):
        risks = [
            LicenseRisk("MIT", "MIT", LicenseCategory.NOTICE, "low", "pkg", "1.0"),
        ]
        summary = scorer.get_summary(risks)
        assert summary["forbidden_licenses"] == []
        assert summary["restricted_licenses"] == []


# ---------------------------------------------------------------------------
# Policy violations
# ---------------------------------------------------------------------------

class TestGeneratePolicyViolations:
    """Test policy violation generation."""

    def test_forbidden_generates_block(self, scorer):
        risks = [
            LicenseRisk("AGPL-3.0-only", "AGPL-3.0-only", LicenseCategory.FORBIDDEN, "critical", "evil-lib", "1.0.0"),
        ]
        violations = scorer.generate_policy_violations(risks)

        assert len(violations) == 1
        v = violations[0]
        assert v["license_id"] == "AGPL-3.0-only"
        assert v["package"] == "evil-lib@1.0.0"
        assert v["action"] == "block"
        assert "Forbidden license" in v["message"]

    def test_restricted_generates_warn(self, scorer):
        risks = [
            LicenseRisk("GPL-3.0-only", "GPL-3.0-only", LicenseCategory.RESTRICTED, "high", "gpl-pkg", "2.0.0"),
        ]
        violations = scorer.generate_policy_violations(risks)

        assert len(violations) == 1
        assert violations[0]["action"] == "warn"
        assert "Restricted license" in violations[0]["message"]

    def test_notice_license_generates_no_violations(self, scorer):
        risks = [
            LicenseRisk("MIT", "MIT", LicenseCategory.NOTICE, "low", "safe-pkg", "1.0.0"),
        ]
        violations = scorer.generate_policy_violations(risks)
        assert violations == []

    def test_custom_actions(self, scorer):
        risks = [
            LicenseRisk("AGPL-3.0-only", "AGPL", LicenseCategory.FORBIDDEN, "critical", "a", "1.0"),
            LicenseRisk("GPL-3.0-only", "GPL", LicenseCategory.RESTRICTED, "high", "b", "1.0"),
        ]
        violations = scorer.generate_policy_violations(
            risks, forbidden_action="fail", restricted_action="review"
        )

        actions = {v["license_id"]: v["action"] for v in violations}
        assert actions["AGPL-3.0-only"] == "fail"
        assert actions["GPL-3.0-only"] == "review"

    def test_empty_risks_no_violations(self, scorer):
        assert scorer.generate_policy_violations([]) == []

    def test_mixed_categories(self, scorer):
        """Only forbidden and restricted produce violations."""
        risks = [
            LicenseRisk("AGPL-3.0-only", "AGPL", LicenseCategory.FORBIDDEN, "critical", "a", "1.0"),
            LicenseRisk("GPL-3.0-only", "GPL", LicenseCategory.RESTRICTED, "high", "b", "1.0"),
            LicenseRisk("MPL-2.0", "MPL", LicenseCategory.RECIPROCAL, "medium", "c", "1.0"),
            LicenseRisk("MIT", "MIT", LicenseCategory.NOTICE, "low", "d", "1.0"),
            LicenseRisk("CC0-1.0", "CC0", LicenseCategory.UNENCUMBERED, "none", "e", "1.0"),
        ]
        violations = scorer.generate_policy_violations(risks)
        assert len(violations) == 2
        violation_ids = {v["license_id"] for v in violations}
        assert violation_ids == {"AGPL-3.0-only", "GPL-3.0-only"}
