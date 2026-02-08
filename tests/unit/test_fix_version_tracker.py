#!/usr/bin/env python3
"""
Unit tests for Fix Version Tracker

Tests cover:
- Version parsing (valid semver, 2-part, invalid)
- Upgrade type determination (patch, minor, major, unknown)
- Upgrade message generation (standard and breaking)
- Fix info extraction from findings (multiple key conventions)
- Trivy JSON output parsing
- Finding enrichment with fix data
- Summary statistics
- Prioritization ordering
- Empty input handling
"""

import sys
from pathlib import Path

import pytest

# Add scripts to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from fix_version_tracker import FixInfo, FixVersionTracker, UpgradeType


@pytest.fixture
def tracker():
    """Create a FixVersionTracker instance for testing."""
    return FixVersionTracker()


# --- parse_version tests ---


class TestParseVersion:
    def test_valid_semver(self, tracker):
        """parse_version with a standard 3-part semver string."""
        assert tracker.parse_version("1.2.3") == (1, 2, 3)

    def test_two_part_version(self, tracker):
        """parse_version with a 2-part version string."""
        assert tracker.parse_version("1.2") == (1, 2)

    def test_single_part_version(self, tracker):
        """parse_version with a single-part version string."""
        assert tracker.parse_version("5") == (5,)

    def test_invalid_string_returns_none(self, tracker):
        """parse_version with non-numeric string returns None."""
        assert tracker.parse_version("abc") is None

    def test_empty_string_returns_none(self, tracker):
        """parse_version with empty string returns None."""
        assert tracker.parse_version("") is None

    def test_version_with_prefix_returns_none(self, tracker):
        """parse_version with 'v' prefix returns None."""
        assert tracker.parse_version("v1.2.3") is None

    def test_four_part_version(self, tracker):
        """parse_version with 4-part version string."""
        assert tracker.parse_version("1.2.3.4") == (1, 2, 3, 4)


# --- determine_upgrade_type tests ---


class TestDetermineUpgradeType:
    def test_patch_upgrade(self, tracker):
        """PATCH when only patch component changes."""
        assert tracker.determine_upgrade_type("1.2.3", "1.2.4") == UpgradeType.PATCH

    def test_minor_upgrade(self, tracker):
        """MINOR when minor component changes."""
        assert tracker.determine_upgrade_type("1.2.3", "1.3.0") == UpgradeType.MINOR

    def test_major_upgrade(self, tracker):
        """MAJOR when major component changes."""
        assert tracker.determine_upgrade_type("1.2.3", "2.0.0") == UpgradeType.MAJOR

    def test_unparseable_installed_returns_unknown(self, tracker):
        """UNKNOWN when installed version is not parseable."""
        assert tracker.determine_upgrade_type("abc", "1.2.3") == UpgradeType.UNKNOWN

    def test_unparseable_fixed_returns_unknown(self, tracker):
        """UNKNOWN when fixed version is not parseable."""
        assert tracker.determine_upgrade_type("1.2.3", "xyz") == UpgradeType.UNKNOWN

    def test_two_part_to_three_part_minor(self, tracker):
        """MINOR upgrade from 2-part to 3-part version."""
        assert tracker.determine_upgrade_type("1.2", "1.3.0") == UpgradeType.MINOR

    def test_same_version_is_patch(self, tracker):
        """PATCH when versions are identical (edge case)."""
        assert tracker.determine_upgrade_type("1.2.3", "1.2.3") == UpgradeType.PATCH


# --- generate_upgrade_message tests ---


class TestGenerateUpgradeMessage:
    def test_patch_message_format(self, tracker):
        """Standard patch upgrade message format."""
        msg = tracker.generate_upgrade_message(
            "django", "3.2.1", "3.2.15", UpgradeType.PATCH
        )
        assert msg == "Upgrade django from 3.2.1 to 3.2.15 (patch)"

    def test_minor_message_format(self, tracker):
        """Standard minor upgrade message format."""
        msg = tracker.generate_upgrade_message(
            "flask", "2.1.0", "2.3.0", UpgradeType.MINOR
        )
        assert msg == "Upgrade flask from 2.1.0 to 2.3.0 (minor)"

    def test_major_message_includes_breaking(self, tracker):
        """Major upgrade message includes BREAKING prefix."""
        msg = tracker.generate_upgrade_message(
            "requests", "1.2.3", "2.0.0", UpgradeType.MAJOR
        )
        assert msg.startswith("BREAKING:")
        assert "requests" in msg
        assert "1.2.3" in msg
        assert "2.0.0" in msg
        assert "(major)" in msg

    def test_unknown_message_format(self, tracker):
        """Unknown upgrade type message has no BREAKING prefix."""
        msg = tracker.generate_upgrade_message(
            "pkg", "old", "new", UpgradeType.UNKNOWN
        )
        assert "BREAKING" not in msg
        assert "(unknown)" in msg


# --- extract_fix_info tests ---


class TestExtractFixInfo:
    def test_complete_finding(self, tracker):
        """Extract fix info from a finding with all standard keys."""
        finding = {
            "cve_id": "CVE-2023-1234",
            "package_name": "django",
            "installed_version": "3.2.1",
            "fixed_version": "3.2.15",
        }
        result = tracker.extract_fix_info(finding)
        assert result is not None
        assert result.cve_id == "CVE-2023-1234"
        assert result.package_name == "django"
        assert result.installed_version == "3.2.1"
        assert result.fixed_version == "3.2.15"
        assert result.upgrade_type == UpgradeType.PATCH

    def test_returns_none_when_no_fix_version(self, tracker):
        """Returns None when no fixed_version or fix_version key exists."""
        finding = {
            "cve_id": "CVE-2023-5678",
            "package_name": "openssl",
            "installed_version": "1.1.1",
        }
        result = tracker.extract_fix_info(finding)
        assert result is None

    def test_alternate_key_pkg_name(self, tracker):
        """Handles pkg_name as an alternate key for package_name."""
        finding = {
            "cve_id": "CVE-2023-9999",
            "pkg_name": "numpy",
            "version": "1.21.0",
            "fix_version": "1.21.6",
        }
        result = tracker.extract_fix_info(finding)
        assert result is not None
        assert result.package_name == "numpy"
        assert result.installed_version == "1.21.0"
        assert result.fixed_version == "1.21.6"

    def test_returns_none_when_no_package_name(self, tracker):
        """Returns None when no package name key is found."""
        finding = {
            "cve_id": "CVE-2023-0001",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
        }
        result = tracker.extract_fix_info(finding)
        assert result is None

    def test_fix_info_default_source(self, tracker):
        """Default source is 'trivy' when not specified."""
        finding = {
            "cve_id": "CVE-2023-1111",
            "package_name": "flask",
            "installed_version": "2.0.0",
            "fixed_version": "2.0.3",
        }
        result = tracker.extract_fix_info(finding)
        assert result is not None
        assert result.source == "trivy"

    def test_fix_info_custom_source(self, tracker):
        """Source field is preserved when present in finding."""
        finding = {
            "cve_id": "CVE-2023-2222",
            "package_name": "lodash",
            "installed_version": "4.17.0",
            "fixed_version": "4.17.21",
            "source": "grype",
        }
        result = tracker.extract_fix_info(finding)
        assert result is not None
        assert result.source == "grype"


# --- extract_from_trivy_results tests ---


class TestExtractFromTrivyResults:
    def test_sample_trivy_output(self, tracker):
        """Parse a realistic Trivy JSON output structure."""
        trivy_output = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1000",
                            "PkgName": "django",
                            "InstalledVersion": "3.2.1",
                            "FixedVersion": "3.2.15",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-2000",
                            "PkgName": "pillow",
                            "InstalledVersion": "8.0.0",
                            "FixedVersion": "9.0.0",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-3000",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k",
                            "FixedVersion": "",
                        },
                    ],
                }
            ]
        }
        results = tracker.extract_from_trivy_results(trivy_output)
        # openssl has no fix version, so only 2 should be extracted
        assert len(results) == 2
        assert results[0].cve_id == "CVE-2023-1000"
        assert results[0].package_name == "django"
        assert results[1].cve_id == "CVE-2023-2000"
        assert results[1].source == "trivy"

    def test_empty_trivy_output(self, tracker):
        """Empty Results list returns empty list."""
        assert tracker.extract_from_trivy_results({"Results": []}) == []

    def test_no_results_key(self, tracker):
        """Missing Results key returns empty list."""
        assert tracker.extract_from_trivy_results({}) == []

    def test_null_vulnerabilities(self, tracker):
        """Handles result with null Vulnerabilities gracefully."""
        trivy_output = {
            "Results": [
                {"Target": "Dockerfile", "Vulnerabilities": None}
            ]
        }
        results = tracker.extract_from_trivy_results(trivy_output)
        assert results == []


# --- enrich_findings tests ---


class TestEnrichFindings:
    def test_adds_fix_data_to_matching_finding(self, tracker):
        """Enrichment adds fix_version, upgrade_type, upgrade_message."""
        findings = [
            {
                "cve_id": "CVE-2023-1000",
                "package_name": "django",
                "severity": "high",
            }
        ]
        fix_infos = [
            FixInfo(
                cve_id="CVE-2023-1000",
                package_name="django",
                installed_version="3.2.1",
                fixed_version="3.2.15",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="Upgrade django from 3.2.1 to 3.2.15 (patch)",
            )
        ]
        enriched = tracker.enrich_findings(findings, fix_infos)
        assert len(enriched) == 1
        assert enriched[0]["fix_version"] == "3.2.15"
        assert enriched[0]["upgrade_type"] == "patch"
        assert "django" in enriched[0]["upgrade_message"]

    def test_non_matching_finding_unchanged(self, tracker):
        """Findings without matching fix info are not modified."""
        findings = [
            {
                "cve_id": "CVE-2023-9999",
                "package_name": "unknown-pkg",
                "severity": "low",
            }
        ]
        fix_infos = [
            FixInfo(
                cve_id="CVE-2023-1000",
                package_name="django",
                installed_version="3.2.1",
                fixed_version="3.2.15",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="Upgrade django from 3.2.1 to 3.2.15 (patch)",
            )
        ]
        enriched = tracker.enrich_findings(findings, fix_infos)
        assert "fix_version" not in enriched[0]

    def test_empty_findings(self, tracker):
        """Enriching empty findings list returns empty list."""
        result = tracker.enrich_findings([], [])
        assert result == []


# --- get_summary tests ---


class TestGetSummary:
    def test_summary_statistics(self, tracker):
        """Summary correctly counts fix types and identifies major upgrades."""
        fix_infos = [
            FixInfo(
                cve_id="CVE-1",
                package_name="a",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-2",
                package_name="b",
                installed_version="1.0.0",
                fixed_version="1.1.0",
                upgrade_type=UpgradeType.MINOR,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-3",
                package_name="c",
                installed_version="1.0.0",
                fixed_version="2.0.0",
                upgrade_type=UpgradeType.MAJOR,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-4",
                package_name="d",
                installed_version="1.0.0",
                fixed_version="1.0.2",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="",
            ),
        ]
        summary = tracker.get_summary(fix_infos)
        assert summary["total_fixable"] == 4
        assert summary["by_upgrade_type"]["patch"] == 2
        assert summary["by_upgrade_type"]["minor"] == 1
        assert summary["by_upgrade_type"]["major"] == 1
        assert summary["unfixable_count"] == 0
        assert "c@1.0.0" in summary["packages_needing_major_upgrade"]

    def test_empty_fix_infos(self, tracker):
        """Summary of empty list returns zero counts."""
        summary = tracker.get_summary([])
        assert summary["total_fixable"] == 0
        assert summary["by_upgrade_type"]["patch"] == 0
        assert summary["by_upgrade_type"]["minor"] == 0
        assert summary["by_upgrade_type"]["major"] == 0
        assert summary["packages_needing_major_upgrade"] == []


# --- prioritize_fixes tests ---


class TestPrioritizeFixes:
    def test_ordering_patch_before_minor_before_major(self, tracker):
        """Prioritized list has patch first, then minor, then major."""
        fix_infos = [
            FixInfo(
                cve_id="CVE-MAJOR",
                package_name="c",
                installed_version="1.0.0",
                fixed_version="2.0.0",
                upgrade_type=UpgradeType.MAJOR,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-PATCH",
                package_name="a",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-MINOR",
                package_name="b",
                installed_version="1.0.0",
                fixed_version="1.1.0",
                upgrade_type=UpgradeType.MINOR,
                upgrade_message="",
            ),
        ]
        prioritized = tracker.prioritize_fixes(fix_infos)
        assert prioritized[0].upgrade_type == UpgradeType.PATCH
        assert prioritized[1].upgrade_type == UpgradeType.MINOR
        assert prioritized[2].upgrade_type == UpgradeType.MAJOR

    def test_prioritize_empty_list(self, tracker):
        """Prioritizing empty list returns empty list."""
        assert tracker.prioritize_fixes([]) == []

    def test_prioritize_preserves_all_items(self, tracker):
        """Prioritization does not drop any items."""
        fix_infos = [
            FixInfo(
                cve_id=f"CVE-{i}",
                package_name=f"pkg-{i}",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="",
            )
            for i in range(5)
        ]
        prioritized = tracker.prioritize_fixes(fix_infos)
        assert len(prioritized) == 5

    def test_unknown_sorted_last(self, tracker):
        """UNKNOWN upgrade type sorts after MAJOR."""
        fix_infos = [
            FixInfo(
                cve_id="CVE-UNK",
                package_name="x",
                installed_version="abc",
                fixed_version="def",
                upgrade_type=UpgradeType.UNKNOWN,
                upgrade_message="",
            ),
            FixInfo(
                cve_id="CVE-PATCH",
                package_name="y",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                upgrade_type=UpgradeType.PATCH,
                upgrade_message="",
            ),
        ]
        prioritized = tracker.prioritize_fixes(fix_infos)
        assert prioritized[0].upgrade_type == UpgradeType.PATCH
        assert prioritized[1].upgrade_type == UpgradeType.UNKNOWN
