#!/usr/bin/env python3
"""
Comprehensive tests for VEX (Vulnerability Exploitability eXchange) Processor

Tests cover:
- VEXStatus and VEXJustification enum values
- Format detection for OpenVEX, CycloneDX VEX, CSAF, and unknown documents
- Parsing of OpenVEX, CycloneDX VEX, and CSAF documents
- Loading statements from explicit paths and auto-discovery
- Finding matching with CVE ID and PURL combinations
- Filtering findings based on VEX statements
- Summary statistics generation
- Malformed input handling and edge cases
"""

import json
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from vex_processor import (
    VEXProcessor,
    VEXStatement,
    VEXStatus,
    VEXJustification,
)


# ---------------------------------------------------------------------------
# Sample documents used across multiple tests
# ---------------------------------------------------------------------------

SAMPLE_OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "timestamp": "2024-06-01T00:00:00Z",
    "statements": [
        {
            "vulnerability": {"name": "CVE-2023-44487"},
            "status": "not_affected",
            "justification": "component_not_present",
            "products": [
                {"@id": "product-a", "purl": "pkg:npm/express@4.18.2"}
            ],
            "statement": "gRPC not used in this product",
        },
        {
            "vulnerability": {"name": "CVE-2024-0001"},
            "status": "affected",
            "products": [{"@id": "product-b"}],
        },
    ],
}

SAMPLE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "vulnerabilities": [
        {
            "id": "CVE-2023-44487",
            "analysis": {
                "state": "not_affected",
                "justification": "vulnerable_code_not_present",
                "detail": "HTTP/2 rapid reset does not apply",
            },
            "affects": [{"ref": "comp-uuid-1"}],
        },
        {
            "id": "CVE-2024-0002",
            "analysis": {
                "state": "exploitable",
            },
            "affects": [{"ref": "comp-uuid-2"}],
        },
    ],
}

SAMPLE_CSAF = {
    "document": {
        "category": "csaf_vex",
        "title": "Test CSAF Advisory",
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2023-44487",
            "product_status": {
                "known_not_affected": ["product-x"],
                "known_affected": ["product-y"],
            },
            "remediations": [
                {"details": "Upgrade to v2", "product_ids": ["product-y"]}
            ],
            "threats": [
                {"details": "Low impact", "product_ids": ["product-x"]}
            ],
        },
    ],
}


# ===================================================================
# Enum tests
# ===================================================================

class TestVEXStatusEnum:
    """Tests for VEXStatus enum members and values."""

    def test_not_affected_value(self):
        assert VEXStatus.NOT_AFFECTED.value == "not_affected"

    def test_affected_value(self):
        assert VEXStatus.AFFECTED.value == "affected"

    def test_fixed_value(self):
        assert VEXStatus.FIXED.value == "fixed"

    def test_under_investigation_value(self):
        assert VEXStatus.UNDER_INVESTIGATION.value == "under_investigation"

    def test_member_count(self):
        assert len(VEXStatus) == 4


class TestVEXJustificationEnum:
    """Tests for VEXJustification enum members and values."""

    def test_component_not_present(self):
        assert VEXJustification.COMPONENT_NOT_PRESENT.value == "component_not_present"

    def test_vulnerable_code_not_present(self):
        assert VEXJustification.VULNERABLE_CODE_NOT_PRESENT.value == "vulnerable_code_not_present"

    def test_vulnerable_code_not_in_execute_path(self):
        assert (
            VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value
            == "vulnerable_code_not_in_execute_path"
        )

    def test_vulnerable_code_cannot_be_controlled(self):
        assert (
            VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY.value
            == "vulnerable_code_cannot_be_controlled_by_adversary"
        )

    def test_inline_mitigations(self):
        assert (
            VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value
            == "inline_mitigations_already_exist"
        )

    def test_none_value(self):
        assert VEXJustification.NONE.value == "none"

    def test_member_count(self):
        assert len(VEXJustification) == 6


# ===================================================================
# Format detection tests
# ===================================================================

class TestDetectFormat:
    """Tests for VEXProcessor._detect_format."""

    def test_detect_openvex(self):
        assert VEXProcessor._detect_format(SAMPLE_OPENVEX) == "openvex"

    def test_detect_openvex_context_as_list(self):
        doc = {"@context": ["https://openvex.dev/ns/v0.2.0", "extra"]}
        assert VEXProcessor._detect_format(doc) == "openvex"

    def test_detect_cyclonedx_vex(self):
        assert VEXProcessor._detect_format(SAMPLE_CYCLONEDX) == "cyclonedx_vex"

    def test_detect_csaf(self):
        assert VEXProcessor._detect_format(SAMPLE_CSAF) == "csaf"

    def test_detect_unknown_empty(self):
        assert VEXProcessor._detect_format({}) == "unknown"

    def test_detect_unknown_random_keys(self):
        assert VEXProcessor._detect_format({"foo": "bar"}) == "unknown"


# ===================================================================
# Parser tests
# ===================================================================

class TestParseOpenVEX:
    """Tests for VEXProcessor._parse_openvex."""

    def test_parses_statements(self):
        stmts = VEXProcessor._parse_openvex(SAMPLE_OPENVEX, "test.json")
        assert len(stmts) == 2

    def test_first_statement_fields(self):
        stmts = VEXProcessor._parse_openvex(SAMPLE_OPENVEX, "test.json")
        s = stmts[0]
        assert s.vulnerability_id == "CVE-2023-44487"
        assert s.status == VEXStatus.NOT_AFFECTED
        assert s.justification == VEXJustification.COMPONENT_NOT_PRESENT
        assert s.purl == "pkg:npm/express@4.18.2"
        assert s.product_id == "product-a"
        assert s.source_format == "openvex"
        assert s.source_file == "test.json"
        assert s.statement_text == "gRPC not used in this product"

    def test_affected_statement(self):
        stmts = VEXProcessor._parse_openvex(SAMPLE_OPENVEX, "test.json")
        s = stmts[1]
        assert s.vulnerability_id == "CVE-2024-0001"
        assert s.status == VEXStatus.AFFECTED
        assert s.justification == VEXJustification.NONE

    def test_empty_statements_list(self):
        doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
        stmts = VEXProcessor._parse_openvex(doc, "empty.json")
        assert stmts == []

    def test_statement_without_products(self):
        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2099-0001"},
                    "status": "fixed",
                }
            ],
        }
        stmts = VEXProcessor._parse_openvex(doc, "noprod.json")
        assert len(stmts) == 1
        assert stmts[0].purl == ""
        assert stmts[0].status == VEXStatus.FIXED

    def test_skips_entry_without_vuln_id(self):
        doc = {
            "statements": [
                {"vulnerability": {}, "status": "not_affected"}
            ]
        }
        stmts = VEXProcessor._parse_openvex(doc, "bad.json")
        assert stmts == []


class TestParseCycloneDXVEX:
    """Tests for VEXProcessor._parse_cyclonedx_vex."""

    def test_parses_vulnerabilities(self):
        stmts = VEXProcessor._parse_cyclonedx_vex(SAMPLE_CYCLONEDX, "cdx.json")
        assert len(stmts) == 2

    def test_not_affected_entry(self):
        stmts = VEXProcessor._parse_cyclonedx_vex(SAMPLE_CYCLONEDX, "cdx.json")
        s = stmts[0]
        assert s.vulnerability_id == "CVE-2023-44487"
        assert s.status == VEXStatus.NOT_AFFECTED
        assert s.justification == VEXJustification.VULNERABLE_CODE_NOT_PRESENT
        assert s.product_id == "comp-uuid-1"
        assert s.source_format == "cyclonedx_vex"
        assert s.statement_text == "HTTP/2 rapid reset does not apply"

    def test_exploitable_maps_to_affected(self):
        stmts = VEXProcessor._parse_cyclonedx_vex(SAMPLE_CYCLONEDX, "cdx.json")
        s = stmts[1]
        assert s.vulnerability_id == "CVE-2024-0002"
        assert s.status == VEXStatus.AFFECTED

    def test_empty_vulnerabilities(self):
        doc = {"bomFormat": "CycloneDX", "vulnerabilities": []}
        stmts = VEXProcessor._parse_cyclonedx_vex(doc, "empty.json")
        assert stmts == []

    def test_skips_entry_without_id(self):
        doc = {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{"analysis": {"state": "not_affected"}}],
        }
        stmts = VEXProcessor._parse_cyclonedx_vex(doc, "noid.json")
        assert stmts == []


class TestParseCSAF:
    """Tests for VEXProcessor._parse_csaf."""

    def test_parses_product_statuses(self):
        stmts = VEXProcessor._parse_csaf(SAMPLE_CSAF, "csaf.json")
        # known_not_affected: 1 product, known_affected: 1 product
        assert len(stmts) == 2

    def test_not_affected_product(self):
        stmts = VEXProcessor._parse_csaf(SAMPLE_CSAF, "csaf.json")
        not_affected = [s for s in stmts if s.status == VEXStatus.NOT_AFFECTED]
        assert len(not_affected) == 1
        s = not_affected[0]
        assert s.vulnerability_id == "CVE-2023-44487"
        assert s.product_id == "product-x"
        assert s.source_format == "csaf"
        # threat detail for product-x
        assert s.statement_text == "Low impact"

    def test_affected_product(self):
        stmts = VEXProcessor._parse_csaf(SAMPLE_CSAF, "csaf.json")
        affected = [s for s in stmts if s.status == VEXStatus.AFFECTED]
        assert len(affected) == 1
        assert affected[0].product_id == "product-y"
        # remediation detail for product-y
        assert affected[0].statement_text == "Upgrade to v2"

    def test_empty_vulnerabilities(self):
        doc = {"document": {"category": "csaf_vex"}, "vulnerabilities": []}
        assert VEXProcessor._parse_csaf(doc, "e.json") == []

    def test_skips_entry_without_cve(self):
        doc = {
            "document": {"category": "csaf_vex"},
            "vulnerabilities": [{"product_status": {"fixed": ["p1"]}}],
        }
        stmts = VEXProcessor._parse_csaf(doc, "nocve.json")
        assert stmts == []


# ===================================================================
# File loading & auto-discovery tests
# ===================================================================

class TestLoadStatements:
    """Tests for VEXProcessor.load_statements with real files."""

    def test_load_from_explicit_path(self, tmp_path):
        vex_file = tmp_path / "my.vex.json"
        vex_file.write_text(json.dumps(SAMPLE_OPENVEX))

        proc = VEXProcessor(
            vex_paths=[str(vex_file)], auto_discover_dir=str(tmp_path / "nonexistent")
        )
        stmts = proc.load_statements()
        assert len(stmts) == 2
        assert stmts[0].vulnerability_id == "CVE-2023-44487"

    def test_auto_discovery(self, tmp_path):
        vex_dir = tmp_path / ".argus" / "vex"
        vex_dir.mkdir(parents=True)
        (vex_dir / "a.json").write_text(json.dumps(SAMPLE_OPENVEX))
        (vex_dir / "b.json").write_text(json.dumps(SAMPLE_CYCLONEDX))

        proc = VEXProcessor(auto_discover_dir=str(vex_dir))
        stmts = proc.load_statements()
        # SAMPLE_OPENVEX: 2 statements, SAMPLE_CYCLONEDX: 2 statements
        assert len(stmts) == 4

    def test_caching(self, tmp_path):
        vex_file = tmp_path / "cache_test.json"
        vex_file.write_text(json.dumps(SAMPLE_OPENVEX))

        proc = VEXProcessor(
            vex_paths=[str(vex_file)], auto_discover_dir=str(tmp_path / "none")
        )
        first = proc.load_statements()
        second = proc.load_statements()
        assert first is second  # same object -- cached

    def test_missing_explicit_path(self, tmp_path):
        proc = VEXProcessor(
            vex_paths=[str(tmp_path / "does_not_exist.json")],
            auto_discover_dir=str(tmp_path / "none"),
        )
        stmts = proc.load_statements()
        assert stmts == []

    def test_no_auto_discover_dir(self, tmp_path):
        proc = VEXProcessor(
            vex_paths=[], auto_discover_dir=str(tmp_path / "nonexistent")
        )
        stmts = proc.load_statements()
        assert stmts == []


# ===================================================================
# Matching tests
# ===================================================================

class TestMatchesFinding:
    """Tests for VEXProcessor.matches_finding."""

    def test_cve_match(self):
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
        )
        finding = {"cve_id": "CVE-2023-44487"}
        assert VEXProcessor.matches_finding(stmt, finding) is True

    def test_cve_match_case_insensitive(self):
        stmt = VEXStatement(
            vulnerability_id="cve-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
        )
        finding = {"cve_id": "CVE-2023-44487"}
        assert VEXProcessor.matches_finding(stmt, finding) is True

    def test_cve_and_purl_match(self):
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
            purl="pkg:npm/express@4.18.2",
        )
        finding = {"cve_id": "CVE-2023-44487", "purl": "pkg:npm/express@4.18.2"}
        assert VEXProcessor.matches_finding(stmt, finding) is True

    def test_cve_match_purl_mismatch(self):
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
            purl="pkg:npm/express@4.18.2",
        )
        finding = {"cve_id": "CVE-2023-44487", "purl": "pkg:npm/fastify@3.0.0"}
        assert VEXProcessor.matches_finding(stmt, finding) is False

    def test_cve_mismatch(self):
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
        )
        finding = {"cve_id": "CVE-9999-0000"}
        assert VEXProcessor.matches_finding(stmt, finding) is False

    def test_finding_without_cve_id(self):
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
        )
        finding = {"title": "Something without CVE"}
        assert VEXProcessor.matches_finding(stmt, finding) is False

    def test_statement_purl_only_finding_no_purl(self):
        """When statement has PURL but finding does not, CVE match suffices."""
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
            purl="pkg:npm/express@4.18.2",
        )
        finding = {"cve_id": "CVE-2023-44487"}
        assert VEXProcessor.matches_finding(stmt, finding) is True

    def test_finding_purl_only_statement_no_purl(self):
        """When finding has PURL but statement does not, CVE match suffices."""
        stmt = VEXStatement(
            vulnerability_id="CVE-2023-44487",
            status=VEXStatus.NOT_AFFECTED,
        )
        finding = {"cve_id": "CVE-2023-44487", "purl": "pkg:npm/express@4.18.2"}
        assert VEXProcessor.matches_finding(stmt, finding) is True


# ===================================================================
# Filtering tests
# ===================================================================

class TestFilterFindings:
    """Tests for VEXProcessor.filter_findings."""

    def _make_processor(self):
        return VEXProcessor(vex_paths=[], auto_discover_dir="/nonexistent")

    def test_suppresses_not_affected(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-44487",
                status=VEXStatus.NOT_AFFECTED,
                justification=VEXJustification.COMPONENT_NOT_PRESENT,
            )
        ]
        findings = [{"cve_id": "CVE-2023-44487", "severity": "high"}]
        remaining, suppressed = proc.filter_findings(findings, stmts)

        assert len(remaining) == 0
        assert len(suppressed) == 1

    def test_keeps_affected(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-44487",
                status=VEXStatus.AFFECTED,
            )
        ]
        findings = [{"cve_id": "CVE-2023-44487", "severity": "high"}]
        remaining, suppressed = proc.filter_findings(findings, stmts)

        assert len(remaining) == 1
        assert len(suppressed) == 0

    def test_keeps_under_investigation(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-44487",
                status=VEXStatus.UNDER_INVESTIGATION,
            )
        ]
        findings = [{"cve_id": "CVE-2023-44487"}]
        remaining, suppressed = proc.filter_findings(findings, stmts)
        assert len(remaining) == 1
        assert len(suppressed) == 0

    def test_suppresses_fixed(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-44487",
                status=VEXStatus.FIXED,
            )
        ]
        findings = [{"cve_id": "CVE-2023-44487"}]
        remaining, suppressed = proc.filter_findings(findings, stmts)
        assert len(remaining) == 0
        assert len(suppressed) == 1

    def test_sets_vex_status_on_suppressed(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-44487",
                status=VEXStatus.NOT_AFFECTED,
                justification=VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                source_file="my.vex.json",
                statement_text="Code path not reachable",
            )
        ]
        findings = [{"cve_id": "CVE-2023-44487"}]
        _, suppressed = proc.filter_findings(findings, stmts)

        s = suppressed[0]
        assert s["vex_status"] == "not_affected"
        assert s["vex_justification"] == "vulnerable_code_not_in_execute_path"
        assert s["vex_source"] == "my.vex.json"
        assert s["vex_statement"] == "Code path not reachable"

    def test_mixed_findings(self):
        proc = self._make_processor()
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-2023-0001",
                status=VEXStatus.NOT_AFFECTED,
            ),
        ]
        findings = [
            {"cve_id": "CVE-2023-0001", "title": "Suppressed"},
            {"cve_id": "CVE-2023-0002", "title": "Kept"},
            {"cve_id": "CVE-2023-0003", "title": "Also kept"},
        ]
        remaining, suppressed = proc.filter_findings(findings, stmts)
        assert len(remaining) == 2
        assert len(suppressed) == 1
        assert suppressed[0]["title"] == "Suppressed"

    def test_empty_findings(self):
        proc = self._make_processor()
        remaining, suppressed = proc.filter_findings([], [])
        assert remaining == []
        assert suppressed == []

    def test_empty_statements(self):
        proc = self._make_processor()
        findings = [{"cve_id": "CVE-2023-0001"}]
        remaining, suppressed = proc.filter_findings(findings, [])
        assert len(remaining) == 1
        assert len(suppressed) == 0


# ===================================================================
# Summary tests
# ===================================================================

class TestGetSummary:
    """Tests for VEXProcessor.get_summary."""

    def test_summary_statistics(self):
        stmts = [
            VEXStatement(
                vulnerability_id="CVE-1",
                status=VEXStatus.NOT_AFFECTED,
                source_format="openvex",
                source_file="a.json",
            ),
            VEXStatement(
                vulnerability_id="CVE-2",
                status=VEXStatus.NOT_AFFECTED,
                source_format="openvex",
                source_file="a.json",
            ),
            VEXStatement(
                vulnerability_id="CVE-3",
                status=VEXStatus.AFFECTED,
                source_format="cyclonedx_vex",
                source_file="b.json",
            ),
            VEXStatement(
                vulnerability_id="CVE-4",
                status=VEXStatus.FIXED,
                source_format="csaf",
                source_file="c.json",
            ),
        ]
        summary = VEXProcessor.get_summary(stmts)

        assert summary["total_statements"] == 4
        assert summary["by_status"]["not_affected"] == 2
        assert summary["by_status"]["affected"] == 1
        assert summary["by_status"]["fixed"] == 1
        assert summary["by_format"]["openvex"] == 2
        assert summary["by_format"]["cyclonedx_vex"] == 1
        assert summary["by_format"]["csaf"] == 1
        assert sorted(summary["sources"]) == ["a.json", "b.json", "c.json"]

    def test_summary_empty(self):
        summary = VEXProcessor.get_summary([])
        assert summary["total_statements"] == 0
        assert summary["by_status"] == {}
        assert summary["by_format"] == {}
        assert summary["sources"] == []


# ===================================================================
# Error handling / edge cases
# ===================================================================

class TestMalformedInputs:
    """Tests that malformed VEX files are handled gracefully."""

    def test_malformed_json_file(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json at all!!!")

        proc = VEXProcessor(
            vex_paths=[str(bad_file)], auto_discover_dir=str(tmp_path / "none")
        )
        stmts = proc.load_statements()
        assert stmts == []

    def test_json_array_instead_of_object(self, tmp_path):
        arr_file = tmp_path / "array.json"
        arr_file.write_text(json.dumps([1, 2, 3]))

        proc = VEXProcessor(
            vex_paths=[str(arr_file)], auto_discover_dir=str(tmp_path / "none")
        )
        stmts = proc.load_statements()
        assert stmts == []

    def test_unknown_format_file(self, tmp_path):
        unk_file = tmp_path / "unknown.json"
        unk_file.write_text(json.dumps({"random": "data"}))

        proc = VEXProcessor(
            vex_paths=[str(unk_file)], auto_discover_dir=str(tmp_path / "none")
        )
        stmts = proc.load_statements()
        assert stmts == []

    def test_openvex_with_missing_vulnerability_key(self):
        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"status": "not_affected"}  # no vulnerability key at all
            ],
        }
        stmts = VEXProcessor._parse_openvex(doc, "missing_vuln.json")
        assert stmts == []

    def test_cyclonedx_missing_analysis(self):
        doc = {
            "bomFormat": "CycloneDX",
            "vulnerabilities": [
                {"id": "CVE-2099-0001"}  # no analysis block
            ],
        }
        stmts = VEXProcessor._parse_cyclonedx_vex(doc, "noanalysis.json")
        assert len(stmts) == 1
        assert stmts[0].status == VEXStatus.UNDER_INVESTIGATION

    def test_empty_vex_paths_and_no_dir(self):
        proc = VEXProcessor(vex_paths=[], auto_discover_dir="/nonexistent/path")
        stmts = proc.load_statements()
        assert stmts == []
