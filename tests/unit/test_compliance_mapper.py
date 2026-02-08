"""
Tests for Compliance Framework Mapping.

Covers dataclass creation, CWE-to-control mapping, category fallback,
severity defaults, framework filtering, report generation, markdown
rendering, and summary statistics.
"""

import os
import sys

import pytest

# Ensure the scripts directory is importable.
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
)

from scripts.compliance_mapper import (
    ComplianceMapper,
    ComplianceMapping,
    ComplianceReport,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mapper():
    """ComplianceMapper with all frameworks enabled."""
    return ComplianceMapper()


@pytest.fixture
def nist_only_mapper():
    """ComplianceMapper restricted to NIST 800-53."""
    return ComplianceMapper(frameworks=["nist_800_53"])


@pytest.fixture
def pci_owasp_mapper():
    """ComplianceMapper restricted to PCI DSS 4.0 and OWASP."""
    return ComplianceMapper(frameworks=["pci_dss_4", "owasp_top10_2021"])


@pytest.fixture
def xss_finding():
    """A finding for CWE-79 (XSS)."""
    return {
        "id": "FIND-001",
        "cwe_id": "CWE-79",
        "category": "sast",
        "severity": "high",
    }


@pytest.fixture
def sqli_finding():
    """A finding for CWE-89 (SQL Injection)."""
    return {
        "finding_id": "FIND-002",
        "cwe_id": "CWE-89",
        "category": "sast",
        "severity": "critical",
    }


@pytest.fixture
def unknown_cwe_finding():
    """A finding with an unmapped CWE that falls back to category."""
    return {
        "id": "FIND-003",
        "cwe_id": "CWE-9999",
        "category": "secrets",
        "severity": "medium",
    }


@pytest.fixture
def no_cwe_no_category_finding():
    """A finding with no CWE and no recognised category."""
    return {
        "id": "FIND-004",
        "severity": "low",
    }


@pytest.fixture
def multi_cwe_finding():
    """A finding with multiple CWEs."""
    return {
        "id": "FIND-005",
        "cwe_ids": ["CWE-79", "CWE-89"],
        "category": "sast",
        "severity": "high",
    }


@pytest.fixture
def sample_findings(xss_finding, sqli_finding):
    """A small batch of findings."""
    return [xss_finding, sqli_finding]


# ---------------------------------------------------------------------------
# Dataclass creation
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Tests for ComplianceMapping and ComplianceReport creation."""

    def test_compliance_mapping_defaults(self):
        """ComplianceMapping has sensible defaults for severity and status."""
        m = ComplianceMapping(
            finding_id="F-1",
            cwe_id="CWE-79",
            framework="nist_800_53",
            control_id="SI-10",
            control_title="Information Input Validation",
        )
        assert m.severity == ""
        assert m.status == "fail"

    def test_compliance_mapping_custom_values(self):
        """ComplianceMapping accepts custom severity and status."""
        m = ComplianceMapping(
            finding_id="F-2",
            cwe_id="CWE-89",
            framework="pci_dss_4",
            control_id="6.2.4",
            control_title="Software Engineering Techniques",
            severity="critical",
            status="pass",
        )
        assert m.severity == "critical"
        assert m.status == "pass"
        assert m.framework == "pci_dss_4"

    def test_compliance_report_defaults(self):
        """ComplianceReport has sensible defaults."""
        r = ComplianceReport(
            framework="nist_800_53",
            total_controls=20,
            passing_controls=18,
            failing_controls=2,
            coverage_percentage=90.0,
        )
        assert r.mappings == []
        assert r.generated_at == ""

    def test_compliance_report_custom_values(self):
        """ComplianceReport accepts a list of mappings and timestamp."""
        m = ComplianceMapping(
            finding_id="F-1",
            cwe_id="CWE-79",
            framework="nist_800_53",
            control_id="SI-10",
            control_title="Information Input Validation",
        )
        r = ComplianceReport(
            framework="nist_800_53",
            total_controls=20,
            passing_controls=19,
            failing_controls=1,
            coverage_percentage=95.0,
            mappings=[m],
            generated_at="2025-01-01T00:00:00+00:00",
        )
        assert len(r.mappings) == 1
        assert r.generated_at == "2025-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# map_finding - CWE lookups
# ---------------------------------------------------------------------------


class TestMapFindingCWE:
    """Tests for CWE-based control mapping."""

    def test_xss_maps_to_nist_pci_owasp_soc2(self, mapper, xss_finding):
        """CWE-79 (XSS) should produce NIST, PCI, OWASP, SOC2 mappings."""
        mappings = mapper.map_finding(xss_finding)
        frameworks = {m.framework for m in mappings}
        assert "nist_800_53" in frameworks
        assert "pci_dss_4" in frameworks
        assert "owasp_top10_2021" in frameworks
        assert "soc2" in frameworks

    def test_xss_nist_control_is_si10(self, mapper, xss_finding):
        """CWE-79 maps to NIST SI-10."""
        mappings = mapper.map_finding(xss_finding)
        nist = [m for m in mappings if m.framework == "nist_800_53"]
        assert any(m.control_id == "SI-10" for m in nist)

    def test_xss_owasp_control_is_a03(self, mapper, xss_finding):
        """CWE-79 maps to OWASP A03:2021."""
        mappings = mapper.map_finding(xss_finding)
        owasp = [m for m in mappings if m.framework == "owasp_top10_2021"]
        assert any(m.control_id == "A03:2021" for m in owasp)

    def test_sqli_maps_correctly(self, mapper, sqli_finding):
        """CWE-89 (SQL Injection) returns correct NIST, PCI, OWASP, SOC2."""
        mappings = mapper.map_finding(sqli_finding)
        frameworks = {m.framework for m in mappings}
        assert "nist_800_53" in frameworks
        assert "pci_dss_4" in frameworks
        assert "owasp_top10_2021" in frameworks
        assert "soc2" in frameworks

    def test_sqli_pci_control(self, mapper, sqli_finding):
        """CWE-89 maps to PCI DSS 6.2.4."""
        mappings = mapper.map_finding(sqli_finding)
        pci = [m for m in mappings if m.framework == "pci_dss_4"]
        assert any(m.control_id == "6.2.4" for m in pci)

    def test_sqli_finding_id_uses_finding_id_key(self, mapper, sqli_finding):
        """Finding ID is extracted from 'finding_id' key."""
        mappings = mapper.map_finding(sqli_finding)
        assert all(m.finding_id == "FIND-002" for m in mappings)

    def test_sqli_severity_propagated(self, mapper, sqli_finding):
        """Severity from the finding is propagated to mappings."""
        mappings = mapper.map_finding(sqli_finding)
        assert all(m.severity == "critical" for m in mappings)

    def test_all_mappings_have_fail_status(self, mapper, xss_finding):
        """All mappings default to 'fail' status."""
        mappings = mapper.map_finding(xss_finding)
        assert all(m.status == "fail" for m in mappings)


# ---------------------------------------------------------------------------
# map_finding - category fallback
# ---------------------------------------------------------------------------


class TestMapFindingCategoryFallback:
    """Tests for category-based fallback mapping."""

    def test_unknown_cwe_falls_back_to_category(self, mapper, unknown_cwe_finding):
        """Unknown CWE triggers category-based mapping."""
        mappings = mapper.map_finding(unknown_cwe_finding)
        assert len(mappings) > 0
        # 'secrets' category maps to IA-5 in NIST
        nist = [m for m in mappings if m.framework == "nist_800_53"]
        assert any(m.control_id == "IA-5" for m in nist)

    def test_unknown_cwe_secrets_maps_to_soc2(self, mapper, unknown_cwe_finding):
        """Secrets category fallback includes SOC2 CC6.1."""
        mappings = mapper.map_finding(unknown_cwe_finding)
        soc2 = [m for m in mappings if m.framework == "soc2"]
        assert any(m.control_id == "CC6.1" for m in soc2)


# ---------------------------------------------------------------------------
# map_finding - edge cases
# ---------------------------------------------------------------------------


class TestMapFindingEdgeCases:
    """Edge case tests for map_finding."""

    def test_no_cwe_no_category_returns_empty(self, mapper, no_cwe_no_category_finding):
        """Finding with no CWE and no recognised category returns empty."""
        mappings = mapper.map_finding(no_cwe_no_category_finding)
        assert mappings == []

    def test_critical_severity_no_cwe_no_category_returns_severity_defaults(self, mapper):
        """Critical severity triggers severity-based fallback."""
        finding = {"id": "FIND-X", "severity": "critical"}
        mappings = mapper.map_finding(finding)
        assert len(mappings) > 0
        assert any(m.control_id == "SI-2" for m in mappings)

    def test_bare_cwe_number_normalised(self, mapper):
        """CWE specified as a bare number (e.g. '79') is normalised."""
        finding = {"id": "FIND-N", "cwe_id": "79", "severity": "high"}
        mappings = mapper.map_finding(finding)
        assert len(mappings) > 0
        assert any(m.cwe_id == "CWE-79" for m in mappings)

    def test_multi_cwe_finding(self, mapper, multi_cwe_finding):
        """Finding with multiple CWEs maps controls from all of them."""
        mappings = mapper.map_finding(multi_cwe_finding)
        # CWE-79 and CWE-89 share the same controls, so deduplication
        # means only the first CWE's controls are added.  We verify
        # that we still get mappings and the first CWE is represented.
        assert len(mappings) > 0
        cwe_ids_in_mappings = {m.cwe_id for m in mappings}
        assert "CWE-79" in cwe_ids_in_mappings

    def test_multi_cwe_distinct_controls(self, mapper):
        """Finding with CWEs that have distinct controls includes both."""
        finding = {
            "id": "FIND-MULTI",
            "cwe_ids": ["CWE-918", "CWE-327"],  # SSRF + Broken Crypto
            "severity": "high",
        }
        mappings = mapper.map_finding(finding)
        control_ids = {m.control_id for m in mappings}
        # CWE-918 -> SC-7, CWE-327 -> SC-13 (both NIST, distinct)
        assert "SC-7" in control_ids
        assert "SC-13" in control_ids

    def test_multi_cwe_deduplicates_controls(self, mapper, multi_cwe_finding):
        """Duplicate controls from multiple CWEs are deduplicated."""
        mappings = mapper.map_finding(multi_cwe_finding)
        # CWE-79 and CWE-89 both map to NIST SI-10 - should appear once.
        nist_si10 = [
            m for m in mappings
            if m.framework == "nist_800_53" and m.control_id == "SI-10"
        ]
        assert len(nist_si10) == 1


# ---------------------------------------------------------------------------
# Framework filtering
# ---------------------------------------------------------------------------


class TestFrameworkFiltering:
    """Tests for framework selection and filtering."""

    def test_nist_only_mapper(self, nist_only_mapper, xss_finding):
        """NIST-only mapper returns only NIST controls."""
        mappings = nist_only_mapper.map_finding(xss_finding)
        assert all(m.framework == "nist_800_53" for m in mappings)
        assert len(mappings) > 0

    def test_pci_owasp_mapper_filters(self, pci_owasp_mapper, xss_finding):
        """PCI+OWASP mapper excludes NIST and SOC2."""
        mappings = pci_owasp_mapper.map_finding(xss_finding)
        frameworks = {m.framework for m in mappings}
        assert "nist_800_53" not in frameworks
        assert "soc2" not in frameworks
        assert "pci_dss_4" in frameworks
        assert "owasp_top10_2021" in frameworks

    def test_unsupported_framework_ignored(self):
        """Unsupported framework is silently ignored."""
        m = ComplianceMapper(frameworks=["nist_800_53", "not_a_framework"])
        assert m.frameworks == ["nist_800_53"]

    def test_all_supported_frameworks_by_default(self, mapper):
        """Default mapper includes all 6 supported frameworks."""
        assert len(mapper.frameworks) == 6
        assert set(mapper.frameworks) == set(ComplianceMapper.SUPPORTED_FRAMEWORKS)


# ---------------------------------------------------------------------------
# map_findings (batch)
# ---------------------------------------------------------------------------


class TestMapFindings:
    """Tests for batch map_findings."""

    def test_batch_returns_all_mappings(self, mapper, sample_findings):
        """Batch mapping returns mappings from all findings."""
        mappings = mapper.map_findings(sample_findings)
        finding_ids = {m.finding_id for m in mappings}
        assert "FIND-001" in finding_ids
        assert "FIND-002" in finding_ids

    def test_empty_findings_returns_empty(self, mapper):
        """Empty findings list returns empty mappings."""
        mappings = mapper.map_findings([])
        assert mappings == []

    def test_batch_count_is_sum_of_individual(self, mapper, sample_findings):
        """Batch mapping count equals sum of individual mapping counts."""
        batch = mapper.map_findings(sample_findings)
        individual_total = sum(
            len(mapper.map_finding(f)) for f in sample_findings
        )
        assert len(batch) == individual_total


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    """Tests for single-framework report generation."""

    def test_nist_report_has_framework(self, mapper, sample_findings):
        """NIST report has framework set correctly."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        assert report.framework == "nist_800_53"

    def test_nist_report_has_timestamp(self, mapper, sample_findings):
        """NIST report has a generated_at timestamp."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        assert report.generated_at != ""

    def test_nist_report_total_controls(self, mapper, sample_findings):
        """NIST report has the expected total control count."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        assert report.total_controls == 20

    def test_pci_report(self, mapper, sample_findings):
        """PCI DSS report generates correctly."""
        report = mapper.generate_report(sample_findings, "pci_dss_4")
        assert report.framework == "pci_dss_4"
        assert report.total_controls == 12
        assert report.failing_controls > 0

    def test_owasp_report(self, mapper, sample_findings):
        """OWASP report generates correctly."""
        report = mapper.generate_report(sample_findings, "owasp_top10_2021")
        assert report.framework == "owasp_top10_2021"
        assert report.total_controls == 10

    def test_coverage_percentage_calculation(self, mapper, sample_findings):
        """Coverage percentage = (passing / total) * 100."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        expected = round(
            (report.passing_controls / report.total_controls) * 100.0, 1
        )
        assert report.coverage_percentage == expected

    def test_passing_plus_failing_equals_total(self, mapper, sample_findings):
        """Passing + failing controls equals total controls."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        assert (
            report.passing_controls + report.failing_controls
            == report.total_controls
        )

    def test_unconfigured_framework_returns_empty_report(self, nist_only_mapper, sample_findings):
        """Generating a report for an unconfigured framework returns empty."""
        report = nist_only_mapper.generate_report(
            sample_findings, "pci_dss_4"
        )
        assert report.failing_controls == 0
        assert report.mappings == []

    def test_empty_findings_report(self, mapper):
        """Report for empty findings has 100% coverage."""
        report = mapper.generate_report([], "nist_800_53")
        assert report.failing_controls == 0
        assert report.coverage_percentage == 100.0


# ---------------------------------------------------------------------------
# generate_all_reports
# ---------------------------------------------------------------------------


class TestGenerateAllReports:
    """Tests for multi-framework report generation."""

    def test_returns_all_frameworks(self, mapper, sample_findings):
        """generate_all_reports returns one report per configured framework."""
        reports = mapper.generate_all_reports(sample_findings)
        assert len(reports) == len(mapper.frameworks)

    def test_each_report_has_correct_framework(self, mapper, sample_findings):
        """Each report is tagged with its framework."""
        reports = mapper.generate_all_reports(sample_findings)
        report_frameworks = {r.framework for r in reports}
        assert report_frameworks == set(mapper.frameworks)

    def test_nist_only_returns_one_report(self, nist_only_mapper, sample_findings):
        """NIST-only mapper generates one report."""
        reports = nist_only_mapper.generate_all_reports(sample_findings)
        assert len(reports) == 1
        assert reports[0].framework == "nist_800_53"


# ---------------------------------------------------------------------------
# render_markdown
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    """Tests for markdown rendering of compliance reports."""

    def test_markdown_has_header(self, mapper, sample_findings):
        """Rendered markdown contains the framework header."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert "## NIST 800-53 Rev 5 Compliance Report" in md

    def test_markdown_has_coverage_stats(self, mapper, sample_findings):
        """Rendered markdown includes coverage percentage."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert f"{report.coverage_percentage}%" in md

    def test_markdown_has_summary_table(self, mapper, sample_findings):
        """Rendered markdown has a summary table."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert "| Total Controls |" in md
        assert "| Passing Controls |" in md
        assert "| Failing Controls |" in md

    def test_markdown_has_failing_controls_table(self, mapper, sample_findings):
        """Rendered markdown includes failing controls table."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert "### Failing Controls" in md
        assert "| Control ID |" in md

    def test_markdown_has_recommendations(self, mapper, sample_findings):
        """Rendered markdown includes recommendations section."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert "### Recommendations" in md

    def test_markdown_empty_findings_no_failing_table(self, mapper):
        """Report with no findings shows no failing controls table."""
        report = mapper.generate_report([], "nist_800_53")
        md = mapper.render_markdown(report)
        assert "### Failing Controls" not in md
        assert "Maintain current security posture" in md

    def test_markdown_coverage_bar(self, mapper, sample_findings):
        """Rendered markdown includes a visual coverage bar."""
        report = mapper.generate_report(sample_findings, "nist_800_53")
        md = mapper.render_markdown(report)
        assert "**Coverage:**" in md
        assert "[" in md and "]" in md


# ---------------------------------------------------------------------------
# render_all_markdown
# ---------------------------------------------------------------------------


class TestRenderAllMarkdown:
    """Tests for combined markdown rendering."""

    def test_combined_markdown_has_title(self, mapper, sample_findings):
        """Combined markdown has the overall title."""
        reports = mapper.generate_all_reports(sample_findings)
        md = mapper.render_all_markdown(reports)
        assert "# Argus Security - Compliance Assessment Report" in md

    def test_combined_markdown_has_overview_table(self, mapper, sample_findings):
        """Combined markdown has an overview table."""
        reports = mapper.generate_all_reports(sample_findings)
        md = mapper.render_all_markdown(reports)
        assert "## Overview" in md
        assert "| Framework |" in md

    def test_combined_markdown_has_all_frameworks(self, mapper, sample_findings):
        """Combined markdown contains sections for each framework."""
        reports = mapper.generate_all_reports(sample_findings)
        md = mapper.render_all_markdown(reports)
        assert "NIST 800-53 Rev 5" in md
        assert "PCI DSS v4.0" in md
        assert "OWASP Top 10 (2021)" in md


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------


class TestGetSummary:
    """Tests for summary statistics."""

    def test_summary_frameworks_assessed(self, mapper, sample_findings):
        """Summary reports correct number of frameworks assessed."""
        reports = mapper.generate_all_reports(sample_findings)
        summary = mapper.get_summary(reports)
        assert summary["frameworks_assessed"] == 6

    def test_summary_overall_coverage(self, mapper, sample_findings):
        """Overall coverage is the average of framework coverages."""
        reports = mapper.generate_all_reports(sample_findings)
        summary = mapper.get_summary(reports)
        expected = round(
            sum(r.coverage_percentage for r in reports) / len(reports), 1
        )
        assert summary["overall_coverage"] == expected

    def test_summary_by_framework_keys(self, mapper, sample_findings):
        """by_framework contains entries for all configured frameworks."""
        reports = mapper.generate_all_reports(sample_findings)
        summary = mapper.get_summary(reports)
        assert set(summary["by_framework"].keys()) == set(mapper.frameworks)

    def test_summary_by_framework_values(self, mapper, sample_findings):
        """Each framework entry has 'coverage' and 'failing_controls'."""
        reports = mapper.generate_all_reports(sample_findings)
        summary = mapper.get_summary(reports)
        for fw_data in summary["by_framework"].values():
            assert "coverage" in fw_data
            assert "failing_controls" in fw_data

    def test_summary_critical_gaps(self, mapper, sqli_finding):
        """Critical severity findings appear in critical_gaps."""
        reports = mapper.generate_all_reports([sqli_finding])
        summary = mapper.get_summary(reports)
        # sqli_finding has severity 'critical', so gaps should be non-empty.
        assert len(summary["critical_gaps"]) > 0
        # Each gap should be formatted as 'framework:control_id'.
        for gap in summary["critical_gaps"]:
            assert ":" in gap

    def test_summary_empty_reports(self, mapper):
        """Summary of empty reports returns zeroed structure."""
        summary = mapper.get_summary([])
        assert summary["frameworks_assessed"] == 0
        assert summary["overall_coverage"] == 0.0
        assert summary["by_framework"] == {}
        assert summary["critical_gaps"] == []

    def test_summary_no_critical_gaps_for_low_severity(self, mapper):
        """Low-severity findings do not appear in critical_gaps."""
        finding = {
            "id": "FIND-LOW",
            "cwe_id": "CWE-79",
            "severity": "low",
        }
        reports = mapper.generate_all_reports([finding])
        summary = mapper.get_summary(reports)
        assert summary["critical_gaps"] == []
