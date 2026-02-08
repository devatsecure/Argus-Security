#!/usr/bin/env python3
"""
Unit tests for Multi-Level Vulnerability Deduplicator

Covers:
  - DeduplicationKey hashing consistency and uniqueness
  - Key extraction with standard and alternate field names
  - Canonical selection (metadata richness + scanner priority)
  - Evidence merging
  - Full deduplication with every strategy
  - Cross-scanner merge
  - Summary / statistics
  - Edge cases (empty input, single finding)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../scripts"))

import pytest

from vuln_deduplicator import (
    DeduplicationKey,
    DeduplicationResult,
    VulnDeduplicator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**kwargs):
    """Create a minimal finding dict with sensible defaults."""
    base = {
        "scanner": "trivy",
        "cve_id": "CVE-2023-1234",
        "package_name": "lodash",
        "installed_version": "4.17.20",
        "severity": "high",
        "message": "Prototype pollution in lodash",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# DeduplicationKey tests
# ---------------------------------------------------------------------------


class TestDeduplicationKey:
    """Tests for the DeduplicationKey dataclass."""

    def test_to_hash_consistent(self):
        """Identical keys must produce the same hash every time."""
        key1 = DeduplicationKey(vuln_id="CVE-2023-0001", pkg_name="pkg")
        key2 = DeduplicationKey(vuln_id="CVE-2023-0001", pkg_name="pkg")
        assert key1.to_hash() == key2.to_hash()

    def test_to_hash_different_keys_differ(self):
        """Different keys must produce different hashes."""
        key_a = DeduplicationKey(vuln_id="CVE-2023-0001", pkg_name="pkg-a")
        key_b = DeduplicationKey(vuln_id="CVE-2023-0002", pkg_name="pkg-b")
        assert key_a.to_hash() != key_b.to_hash()

    def test_to_hash_is_hex_string(self):
        """Hash output should be a 64-char lowercase hex string (SHA-256)."""
        key = DeduplicationKey(vuln_id="CVE-2023-9999")
        h = key.to_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_default_fields_are_empty(self):
        """Optional fields default to empty strings."""
        key = DeduplicationKey(vuln_id="CVE-2023-0001")
        assert key.pkg_name == ""
        assert key.pkg_version == ""
        assert key.pkg_path == ""
        assert key.file_path == ""
        assert key.rule_id == ""


# ---------------------------------------------------------------------------
# Key extraction tests
# ---------------------------------------------------------------------------


class TestExtractKey:
    """Tests for VulnDeduplicator._extract_key."""

    def test_extract_key_standard_finding(self):
        """Standard finding fields are extracted correctly."""
        finding = {
            "cve_id": "CVE-2023-1234",
            "package_name": "requests",
            "installed_version": "2.28.0",
            "file_path": "/app/requirements.txt",
            "rule_id": "CVE-2023-1234",
        }
        key = VulnDeduplicator._extract_key(finding, "strict")
        assert key.vuln_id == "CVE-2023-1234"
        assert key.pkg_name == "requests"
        assert key.pkg_version == "2.28.0"
        assert key.file_path == "/app/requirements.txt"
        assert key.rule_id == "CVE-2023-1234"

    def test_extract_key_alternate_vuln_id(self):
        """Alternate key name 'vuln_id' is recognised."""
        finding = {"vuln_id": "CVE-2024-5678"}
        key = VulnDeduplicator._extract_key(finding, "relaxed")
        assert key.vuln_id == "CVE-2024-5678"

    def test_extract_key_alternate_vulnerability_id(self):
        """Alternate key name 'vulnerability_id' is recognised."""
        finding = {"vulnerability_id": "CVE-2024-9999"}
        key = VulnDeduplicator._extract_key(finding, "relaxed")
        assert key.vuln_id == "CVE-2024-9999"

    def test_extract_key_alternate_pkg_name(self):
        """'pkg_name' is accepted as an alias for 'package_name'."""
        finding = {"cve_id": "CVE-2023-0001", "pkg_name": "flask"}
        key = VulnDeduplicator._extract_key(finding, "standard")
        assert key.pkg_name == "flask"

    def test_extract_key_alternate_version(self):
        """'version' and 'pkg_version' are accepted aliases."""
        f1 = {"cve_id": "X", "version": "1.0"}
        f2 = {"cve_id": "X", "pkg_version": "2.0"}
        assert VulnDeduplicator._extract_key(f1, "standard").pkg_version == "1.0"
        assert VulnDeduplicator._extract_key(f2, "standard").pkg_version == "2.0"

    def test_extract_key_alternate_file_path(self):
        """'path' and 'location' are accepted aliases for 'file_path'."""
        f1 = {"cve_id": "X", "path": "/a.py"}
        f2 = {"cve_id": "X", "location": "/b.py"}
        assert VulnDeduplicator._extract_key(f1, "strict").file_path == "/a.py"
        assert VulnDeduplicator._extract_key(f2, "strict").file_path == "/b.py"

    def test_extract_key_alternate_rule_id(self):
        """'check_id' is accepted as an alias for 'rule_id'."""
        finding = {"cve_id": "X", "check_id": "CKV_AWS_1"}
        key = VulnDeduplicator._extract_key(finding, "strict")
        assert key.rule_id == "CKV_AWS_1"

    def test_extract_key_relaxed_ignores_extra_fields(self):
        """Relaxed strategy only keeps vuln_id."""
        finding = _make_finding()
        key = VulnDeduplicator._extract_key(finding, "relaxed")
        assert key.vuln_id == "CVE-2023-1234"
        assert key.pkg_name == ""
        assert key.pkg_version == ""

    def test_extract_key_standard_keeps_pkg_fields(self):
        """Standard strategy keeps vuln_id + pkg_name + version."""
        finding = _make_finding()
        key = VulnDeduplicator._extract_key(finding, "standard")
        assert key.vuln_id == "CVE-2023-1234"
        assert key.pkg_name == "lodash"
        assert key.pkg_version == "4.17.20"
        assert key.file_path == ""  # not included in standard


# ---------------------------------------------------------------------------
# Canonical selection tests
# ---------------------------------------------------------------------------


class TestSelectCanonical:
    """Tests for VulnDeduplicator._select_canonical."""

    def test_picks_finding_with_most_metadata(self):
        """The finding with the most non-empty keys wins."""
        sparse = {"cve_id": "CVE-2023-0001", "scanner": "gitleaks"}
        rich = {
            "cve_id": "CVE-2023-0001",
            "scanner": "gitleaks",
            "package_name": "pkg",
            "severity": "high",
            "description": "A vulnerability",
        }
        result = VulnDeduplicator._select_canonical([sparse, rich])
        assert result is rich

    def test_scanner_priority_tiebreaker(self):
        """When richness is equal, scanner priority breaks the tie."""
        trivy_f = {"cve_id": "CVE-2023-0001", "severity": "high", "scanner": "trivy"}
        semgrep_f = {"cve_id": "CVE-2023-0001", "severity": "high", "scanner": "semgrep"}
        gitleaks_f = {"cve_id": "CVE-2023-0001", "severity": "high", "scanner": "gitleaks"}

        result = VulnDeduplicator._select_canonical([gitleaks_f, semgrep_f, trivy_f])
        assert result is trivy_f

    def test_single_finding(self):
        """A group of one returns that finding."""
        f = _make_finding()
        assert VulnDeduplicator._select_canonical([f]) is f


# ---------------------------------------------------------------------------
# Evidence merging tests
# ---------------------------------------------------------------------------


class TestMergeEvidence:
    """Tests for VulnDeduplicator._merge_evidence."""

    def test_creates_proper_evidence_dict(self):
        """Merged evidence contains sources, count, and summaries."""
        f1 = _make_finding(scanner="trivy", message="msg-trivy")
        f2 = _make_finding(scanner="semgrep", message="msg-semgrep")

        evidence = VulnDeduplicator._merge_evidence([f1, f2])

        assert evidence["original_count"] == 2
        assert "trivy" in evidence["sources"]
        assert "semgrep" in evidence["sources"]
        assert "msg-trivy" in evidence["merged_from"]
        assert "msg-semgrep" in evidence["merged_from"]

    def test_evidence_uses_fallback_fields(self):
        """When 'message' is absent, falls back to title/description/vuln_id."""
        f = {"scanner": "trivy", "title": "A title"}
        evidence = VulnDeduplicator._merge_evidence([f])
        assert "A title" in evidence["merged_from"]

    def test_evidence_unknown_scanner(self):
        """Findings without scanner field get 'unknown'."""
        f = {"cve_id": "CVE-2023-0001"}
        evidence = VulnDeduplicator._merge_evidence([f])
        assert "unknown" in evidence["sources"]


# ---------------------------------------------------------------------------
# Deduplication tests
# ---------------------------------------------------------------------------


class TestDeduplicate:
    """Tests for VulnDeduplicator.deduplicate."""

    def test_no_duplicates(self):
        """All unique findings remain untouched."""
        findings = [
            _make_finding(cve_id="CVE-2023-0001"),
            _make_finding(cve_id="CVE-2023-0002"),
            _make_finding(cve_id="CVE-2023-0003"),
        ]
        dedup = VulnDeduplicator(strategy="relaxed")
        result = dedup.deduplicate(findings)

        assert result.original_count == 3
        assert result.deduplicated_count == 3
        assert result.duplicates_removed == 0
        assert len(result.kept_findings) == 3

    def test_exact_duplicates(self):
        """Identical findings collapse to one."""
        f1 = _make_finding(scanner="trivy")
        f2 = _make_finding(scanner="trivy")

        dedup = VulnDeduplicator(strategy="relaxed")
        result = dedup.deduplicate([f1, f2])

        assert result.original_count == 2
        assert result.deduplicated_count == 1
        assert result.duplicates_removed == 1

    def test_cross_scanner_duplicates(self):
        """Same CVE from different scanners is deduplicated."""
        f_trivy = _make_finding(scanner="trivy")
        f_semgrep = _make_finding(scanner="semgrep")

        dedup = VulnDeduplicator(strategy="relaxed")
        result = dedup.deduplicate([f_trivy, f_semgrep])

        assert result.deduplicated_count == 1
        canonical = result.kept_findings[0]
        assert "merged_evidence" in canonical
        assert canonical["merged_evidence"]["original_count"] == 2

    def test_strict_strategy(self):
        """Strict strategy differentiates by file_path."""
        f1 = _make_finding(file_path="/app/a.py", rule_id="R1")
        f2 = _make_finding(file_path="/app/b.py", rule_id="R1")

        dedup = VulnDeduplicator(strategy="strict")
        result = dedup.deduplicate([f1, f2])

        # Different file paths -> should NOT be merged under strict
        assert result.deduplicated_count == 2

    def test_relaxed_strategy(self):
        """Relaxed strategy merges findings that only share vuln_id."""
        f1 = _make_finding(package_name="pkg-a", installed_version="1.0")
        f2 = _make_finding(package_name="pkg-b", installed_version="2.0")

        dedup = VulnDeduplicator(strategy="relaxed")
        result = dedup.deduplicate([f1, f2])

        # Same CVE -> merged under relaxed
        assert result.deduplicated_count == 1

    def test_auto_strategy_cve(self):
        """Auto strategy picks 'standard' for CVE-bearing findings."""
        dedup = VulnDeduplicator(strategy="auto")
        finding = {"cve_id": "CVE-2023-0001"}
        assert dedup._determine_strategy(finding) == "standard"

    def test_auto_strategy_rule(self):
        """Auto strategy picks 'strict' for rule-based findings."""
        dedup = VulnDeduplicator(strategy="auto")
        finding = {"rule_id": "semgrep.python.xss"}
        assert dedup._determine_strategy(finding) == "strict"

    def test_auto_strategy_fallback(self):
        """Auto strategy falls back to 'relaxed'."""
        dedup = VulnDeduplicator(strategy="auto")
        finding = {"message": "something suspicious"}
        assert dedup._determine_strategy(finding) == "relaxed"

    def test_empty_input(self):
        """Empty list produces zero-count result."""
        dedup = VulnDeduplicator()
        result = dedup.deduplicate([])

        assert result.original_count == 0
        assert result.deduplicated_count == 0
        assert result.duplicates_removed == 0
        assert result.kept_findings == []
        assert result.removed_findings == []
        assert result.merge_groups == []

    def test_single_finding_no_dedup(self):
        """Single finding passes through untouched."""
        finding = _make_finding()
        dedup = VulnDeduplicator()
        result = dedup.deduplicate([finding])

        assert result.original_count == 1
        assert result.deduplicated_count == 1
        assert result.duplicates_removed == 0
        assert len(result.kept_findings) == 1

    def test_merge_groups_populated(self):
        """Merge groups metadata is correctly generated."""
        findings = [
            _make_finding(scanner="trivy"),
            _make_finding(scanner="semgrep"),
            _make_finding(scanner="checkov"),
        ]
        dedup = VulnDeduplicator(strategy="relaxed")
        result = dedup.deduplicate(findings)

        assert len(result.merge_groups) == 1
        assert result.merge_groups[0]["count"] == 3


# ---------------------------------------------------------------------------
# Cross-scanner merge tests
# ---------------------------------------------------------------------------


class TestCrossScannerMerge:
    """Tests for VulnDeduplicator.cross_scanner_merge."""

    def test_merges_scanner_fields(self):
        """Same CVE from two scanners produces unified finding."""
        f1 = _make_finding(scanner="trivy", severity="high")
        f2 = _make_finding(scanner="semgrep", severity="medium")

        dedup = VulnDeduplicator()
        merged = dedup.cross_scanner_merge([f1, f2])

        assert len(merged) == 1
        unified = merged[0]
        assert set(unified["scanners"]) == {"trivy", "semgrep"}
        assert "scanner_details" in unified
        assert "trivy" in unified["scanner_details"]
        assert "semgrep" in unified["scanner_details"]

    def test_no_cve_findings_pass_through(self):
        """Findings without a CVE are not merged."""
        f1 = {"scanner": "custom", "message": "issue A"}
        f2 = {"scanner": "custom", "message": "issue B"}

        dedup = VulnDeduplicator()
        merged = dedup.cross_scanner_merge([f1, f2])

        assert len(merged) == 2

    def test_single_scanner_single_finding_no_merge(self):
        """A unique CVE from a single scanner is returned as-is."""
        finding = _make_finding(cve_id="CVE-2099-0001", scanner="trivy")
        dedup = VulnDeduplicator()
        merged = dedup.cross_scanner_merge([finding])

        assert len(merged) == 1
        assert "scanner_details" not in merged[0]

    def test_empty_input_returns_empty(self):
        """Empty input returns empty list."""
        dedup = VulnDeduplicator()
        assert dedup.cross_scanner_merge([]) == []


# ---------------------------------------------------------------------------
# Summary / statistics tests
# ---------------------------------------------------------------------------


class TestGetSummary:
    """Tests for VulnDeduplicator.get_summary."""

    def test_summary_statistics(self):
        """Summary contains all expected fields."""
        result = DeduplicationResult(
            original_count=10,
            deduplicated_count=6,
            duplicates_removed=4,
            merge_groups=[
                {"key_hash": "aaa", "count": 3, "sources": ["trivy", "semgrep", "checkov"]},
                {"key_hash": "bbb", "count": 2, "sources": ["trivy", "gitleaks"]},
            ],
            kept_findings=[],
            removed_findings=[],
        )
        summary = VulnDeduplicator.get_summary(result)

        assert summary["original_count"] == 10
        assert summary["deduplicated_count"] == 6
        assert "reduction_percentage" in summary
        assert "by_strategy" in summary
        assert "largest_merge_groups" in summary

    def test_reduction_percentage_calculation(self):
        """Reduction percentage is (removed / original) * 100."""
        result = DeduplicationResult(
            original_count=20,
            deduplicated_count=10,
            duplicates_removed=10,
            merge_groups=[],
            kept_findings=[],
            removed_findings=[],
        )
        summary = VulnDeduplicator.get_summary(result)
        assert summary["reduction_percentage"] == 50.0

    def test_reduction_percentage_zero_original(self):
        """Zero original findings gives 0% reduction (no division by zero)."""
        result = DeduplicationResult(
            original_count=0,
            deduplicated_count=0,
            duplicates_removed=0,
        )
        summary = VulnDeduplicator.get_summary(result)
        assert summary["reduction_percentage"] == 0.0

    def test_largest_merge_groups_capped_at_five(self):
        """Only the top 5 largest merge groups are returned."""
        groups = [{"key_hash": str(i), "count": i, "sources": []} for i in range(10)]
        result = DeduplicationResult(
            original_count=50,
            deduplicated_count=40,
            duplicates_removed=10,
            merge_groups=groups,
            kept_findings=[],
            removed_findings=[],
        )
        summary = VulnDeduplicator.get_summary(result)
        assert len(summary["largest_merge_groups"]) == 5
        # They should be sorted descending by count
        counts = [g["count"] for g in summary["largest_merge_groups"]]
        assert counts == sorted(counts, reverse=True)


# ---------------------------------------------------------------------------
# Invalid strategy test
# ---------------------------------------------------------------------------


class TestInvalidStrategy:
    """Guard against invalid strategy values."""

    def test_invalid_strategy_raises(self):
        """Passing an unknown strategy raises ValueError."""
        with pytest.raises(ValueError, match="Invalid strategy"):
            VulnDeduplicator(strategy="banana")
