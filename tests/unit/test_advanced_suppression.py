#!/usr/bin/env python3
"""
Unit tests for Advanced Finding Suppression.

Tests cover rule loading/saving, expiration logic, all six match types,
VEX integration, EPSS auto-suppression, filtering, and summary statistics.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../scripts"))

from advanced_suppression import (
    AdvancedSuppressionManager,
    MatchType,
    SuppressionResult,
    SuppressionRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manager():
    """Return an AdvancedSuppressionManager with default settings."""
    return AdvancedSuppressionManager()


@pytest.fixture
def sample_rules():
    """Return a small set of rules covering all match types."""
    return [
        SuppressionRule(
            id="cve-rule",
            match_type=MatchType.CVE,
            match_value="CVE-2023-12345",
            reason="Not exploitable",
            approved_by="security-team",
        ),
        SuppressionRule(
            id="rule-id-rule",
            match_type=MatchType.RULE_ID,
            match_value="semgrep.python.xss-reflected",
            reason="False positive in test code",
        ),
        SuppressionRule(
            id="purl-rule",
            match_type=MatchType.PURL,
            match_value="pkg:npm/lodash@*",
            reason="Lodash is vendored and patched",
        ),
        SuppressionRule(
            id="path-rule",
            match_type=MatchType.PATH_PATTERN,
            match_value="tests/**",
            reason="Test code not deployed",
        ),
        SuppressionRule(
            id="cwe-rule",
            match_type=MatchType.CWE,
            match_value="CWE-79",
            reason="XSS mitigated by CSP",
        ),
        SuppressionRule(
            id="severity-rule",
            match_type=MatchType.SEVERITY,
            match_value="low",
            reason="Low severity accepted",
        ),
    ]


@pytest.fixture
def sample_yaml_content():
    """Return valid YAML content for an .argus-ignore.yml file."""
    return (
        "version: 1\n"
        "rules:\n"
        "  - id: suppress-001\n"
        "    match_type: cve\n"
        '    match_value: "CVE-2023-12345"\n'
        '    reason: "Not exploitable in our config"\n'
        '    expires_at: "2099-06-01"\n'
        '    approved_by: "security-team"\n'
        "  - id: suppress-002\n"
        "    match_type: rule_id\n"
        '    match_value: "semgrep.python.xss"\n'
        '    reason: "Test code"\n'
    )


# ---------------------------------------------------------------------------
# SuppressionRule creation
# ---------------------------------------------------------------------------


class TestSuppressionRuleCreation:
    """Tests for the SuppressionRule dataclass."""

    def test_create_rule_with_defaults(self):
        """Rule creation with only required fields uses sensible defaults."""
        rule = SuppressionRule(
            id="test-1",
            match_type=MatchType.CVE,
            match_value="CVE-2024-0001",
        )
        assert rule.id == "test-1"
        assert rule.match_type == MatchType.CVE
        assert rule.match_value == "CVE-2024-0001"
        assert rule.reason == ""
        assert rule.expires_at == ""
        assert rule.approved_by == ""
        assert rule.source == "manual"
        assert rule.is_active is True

    def test_create_rule_with_all_fields(self):
        """Rule creation with all fields preserves each value."""
        rule = SuppressionRule(
            id="test-2",
            match_type=MatchType.PURL,
            match_value="pkg:pypi/requests@*",
            reason="Vendored copy",
            expires_at="2099-12-31",
            approved_by="alice",
            created_at="2024-01-01",
            source="vex",
            is_active=False,
        )
        assert rule.source == "vex"
        assert rule.is_active is False
        assert rule.approved_by == "alice"

    def test_match_type_enum_values(self):
        """All MatchType members have the expected string values."""
        assert MatchType.CVE.value == "cve"
        assert MatchType.RULE_ID.value == "rule_id"
        assert MatchType.PURL.value == "purl"
        assert MatchType.PATH_PATTERN.value == "path_pattern"
        assert MatchType.CWE.value == "cwe"
        assert MatchType.SEVERITY.value == "severity"


# ---------------------------------------------------------------------------
# Rule loading from YAML
# ---------------------------------------------------------------------------


class TestLoadRules:
    """Tests for loading rules from YAML files."""

    def test_load_rules_from_valid_file(self, tmp_path, manager, sample_yaml_content):
        """Valid YAML produces the correct number of rules."""
        config = tmp_path / ".argus-ignore.yml"
        config.write_text(sample_yaml_content)

        rules = manager.load_rules(str(config))

        assert len(rules) == 2
        assert rules[0].id == "suppress-001"
        assert rules[0].match_type == MatchType.CVE
        assert rules[0].match_value == "CVE-2023-12345"
        assert rules[0].approved_by == "security-team"

    def test_load_rules_missing_file_returns_empty(self, tmp_path, manager):
        """Loading from a non-existent file returns an empty list."""
        rules = manager.load_rules(str(tmp_path / "nonexistent.yml"))
        assert rules == []

    def test_load_rules_populates_manager_rules(self, tmp_path, manager, sample_yaml_content):
        """Loading rules also stores them on the manager instance."""
        config = tmp_path / ".argus-ignore.yml"
        config.write_text(sample_yaml_content)

        manager.load_rules(str(config))

        assert len(manager.rules) == 2

    def test_load_rules_skips_malformed_entries(self, tmp_path, manager):
        """Entries missing match_type are skipped without crashing."""
        content = (
            "version: 1\n"
            "rules:\n"
            "  - id: good\n"
            "    match_type: cve\n"
            '    match_value: "CVE-2024-0001"\n'
            "  - id: bad\n"
            '    match_value: "missing-type"\n'
        )
        config = tmp_path / ".argus-ignore.yml"
        config.write_text(content)

        rules = manager.load_rules(str(config))

        assert len(rules) == 1
        assert rules[0].id == "good"

    def test_load_rules_empty_file(self, tmp_path, manager):
        """An empty YAML file returns an empty list."""
        config = tmp_path / ".argus-ignore.yml"
        config.write_text("")

        rules = manager.load_rules(str(config))
        assert rules == []


# ---------------------------------------------------------------------------
# Expiration logic
# ---------------------------------------------------------------------------


class TestExpiration:
    """Tests for rule expiration checks."""

    def test_future_date_not_expired(self, manager):
        """A rule expiring in the future is not expired."""
        rule = SuppressionRule(
            id="future",
            match_type=MatchType.CVE,
            match_value="CVE-2099-0001",
            expires_at="2099-12-31",
        )
        assert manager._is_expired(rule) is False

    def test_past_date_is_expired(self, manager):
        """A rule expiring in the past is expired."""
        rule = SuppressionRule(
            id="past",
            match_type=MatchType.CVE,
            match_value="CVE-2020-0001",
            expires_at="2020-01-01",
        )
        assert manager._is_expired(rule) is True

    def test_no_expiry_never_expires(self, manager):
        """A rule with no expires_at is never expired."""
        rule = SuppressionRule(
            id="no-expiry",
            match_type=MatchType.CVE,
            match_value="CVE-2024-0001",
        )
        assert manager._is_expired(rule) is False

    def test_empty_string_expiry_never_expires(self, manager):
        """A rule with empty string expires_at is never expired."""
        rule = SuppressionRule(
            id="empty-expiry",
            match_type=MatchType.CVE,
            match_value="CVE-2024-0001",
            expires_at="",
        )
        assert manager._is_expired(rule) is False

    def test_invalid_expiry_format_not_expired(self, manager):
        """A rule with an invalid date string is treated as not expired."""
        rule = SuppressionRule(
            id="bad-date",
            match_type=MatchType.CVE,
            match_value="CVE-2024-0001",
            expires_at="not-a-date",
        )
        assert manager._is_expired(rule) is False


# ---------------------------------------------------------------------------
# Matching logic for each MatchType
# ---------------------------------------------------------------------------


class TestMatchesFinding:
    """Tests for _matches_finding across all match types."""

    def test_cve_match(self, manager):
        """CVE match type uses exact match on cve_id."""
        rule = SuppressionRule(
            id="r1", match_type=MatchType.CVE, match_value="CVE-2023-12345"
        )
        finding = {"cve_id": "CVE-2023-12345"}
        assert manager._matches_finding(rule, finding) is True

    def test_cve_no_match(self, manager):
        """CVE match type rejects different cve_id."""
        rule = SuppressionRule(
            id="r1", match_type=MatchType.CVE, match_value="CVE-2023-12345"
        )
        finding = {"cve_id": "CVE-2023-99999"}
        assert manager._matches_finding(rule, finding) is False

    def test_rule_id_match(self, manager):
        """RULE_ID match type uses exact match on rule_id."""
        rule = SuppressionRule(
            id="r2", match_type=MatchType.RULE_ID, match_value="semgrep.xss"
        )
        finding = {"rule_id": "semgrep.xss"}
        assert manager._matches_finding(rule, finding) is True

    def test_rule_id_no_match(self, manager):
        """RULE_ID match type rejects a different rule_id."""
        rule = SuppressionRule(
            id="r2", match_type=MatchType.RULE_ID, match_value="semgrep.xss"
        )
        finding = {"rule_id": "semgrep.sqli"}
        assert manager._matches_finding(rule, finding) is False

    def test_purl_wildcard_match(self, manager):
        """PURL matching supports fnmatch wildcards."""
        rule = SuppressionRule(
            id="r3", match_type=MatchType.PURL, match_value="pkg:npm/lodash@*"
        )
        finding = {"purl": "pkg:npm/lodash@4.17.21"}
        assert manager._matches_finding(rule, finding) is True

    def test_purl_no_match(self, manager):
        """PURL wildcard does not match a different package."""
        rule = SuppressionRule(
            id="r3", match_type=MatchType.PURL, match_value="pkg:npm/lodash@*"
        )
        finding = {"purl": "pkg:npm/express@4.18.0"}
        assert manager._matches_finding(rule, finding) is False

    def test_path_pattern_glob_match(self, manager):
        """PATH_PATTERN supports glob-style matching on file_path."""
        rule = SuppressionRule(
            id="r4", match_type=MatchType.PATH_PATTERN, match_value="tests/**"
        )
        finding = {"file_path": "tests/unit/test_foo.py"}
        assert manager._matches_finding(rule, finding) is True

    def test_path_pattern_uses_path_fallback(self, manager):
        """PATH_PATTERN falls back to 'path' key when 'file_path' is absent."""
        rule = SuppressionRule(
            id="r4", match_type=MatchType.PATH_PATTERN, match_value="vendor/*"
        )
        finding = {"path": "vendor/lib.js"}
        assert manager._matches_finding(rule, finding) is True

    def test_path_pattern_no_match(self, manager):
        """PATH_PATTERN rejects files outside the pattern."""
        rule = SuppressionRule(
            id="r4", match_type=MatchType.PATH_PATTERN, match_value="tests/**"
        )
        finding = {"file_path": "src/main.py"}
        assert manager._matches_finding(rule, finding) is False

    def test_cwe_match_single(self, manager):
        """CWE matches on the cwe_id field."""
        rule = SuppressionRule(
            id="r5", match_type=MatchType.CWE, match_value="CWE-79"
        )
        finding = {"cwe_id": "CWE-79"}
        assert manager._matches_finding(rule, finding) is True

    def test_cwe_match_in_list(self, manager):
        """CWE matches when value is in the cwe_ids list."""
        rule = SuppressionRule(
            id="r5", match_type=MatchType.CWE, match_value="CWE-79"
        )
        finding = {"cwe_ids": ["CWE-79", "CWE-89"]}
        assert manager._matches_finding(rule, finding) is True

    def test_cwe_no_match(self, manager):
        """CWE rejects when neither cwe_id nor cwe_ids matches."""
        rule = SuppressionRule(
            id="r5", match_type=MatchType.CWE, match_value="CWE-79"
        )
        finding = {"cwe_id": "CWE-89", "cwe_ids": ["CWE-89"]}
        assert manager._matches_finding(rule, finding) is False

    def test_severity_match_case_insensitive(self, manager):
        """SEVERITY matching is case-insensitive."""
        rule = SuppressionRule(
            id="r6", match_type=MatchType.SEVERITY, match_value="Low"
        )
        finding = {"severity": "low"}
        assert manager._matches_finding(rule, finding) is True

    def test_severity_no_match(self, manager):
        """SEVERITY rejects different severity levels."""
        rule = SuppressionRule(
            id="r6", match_type=MatchType.SEVERITY, match_value="low"
        )
        finding = {"severity": "high"}
        assert manager._matches_finding(rule, finding) is False

    def test_missing_finding_field_returns_false(self, manager):
        """Matching against a finding missing the relevant key returns False."""
        rule = SuppressionRule(
            id="r1", match_type=MatchType.CVE, match_value="CVE-2023-12345"
        )
        finding = {"rule_id": "some-rule"}  # No cve_id
        assert manager._matches_finding(rule, finding) is False


# ---------------------------------------------------------------------------
# evaluate_finding
# ---------------------------------------------------------------------------


class TestEvaluateFinding:
    """Tests for the evaluate_finding method."""

    def test_returns_match_when_rule_applies(self, manager, sample_rules):
        """Returns suppressed=True when a matching rule is found."""
        finding = {"cve_id": "CVE-2023-12345"}
        result = manager.evaluate_finding(finding, sample_rules)

        assert result.suppressed is True
        assert result.rule is not None
        assert result.rule.id == "cve-rule"
        assert "Not exploitable" in result.reason

    def test_skips_expired_rules(self, manager):
        """Expired rules are skipped during evaluation."""
        expired_rule = SuppressionRule(
            id="expired",
            match_type=MatchType.CVE,
            match_value="CVE-2023-12345",
            expires_at="2020-01-01",
            reason="Old exemption",
        )
        finding = {"cve_id": "CVE-2023-12345"}
        result = manager.evaluate_finding(finding, [expired_rule])

        assert result.suppressed is False
        assert result.rule is None

    def test_returns_no_match_when_no_rules_apply(self, manager, sample_rules):
        """Returns suppressed=False when no rule matches the finding."""
        finding = {"cve_id": "CVE-9999-0000", "severity": "critical"}
        result = manager.evaluate_finding(finding, sample_rules)

        assert result.suppressed is False
        assert result.rule is None
        assert "No matching" in result.reason

    def test_skips_inactive_rules(self, manager):
        """Inactive rules are skipped during evaluation."""
        inactive_rule = SuppressionRule(
            id="inactive",
            match_type=MatchType.CVE,
            match_value="CVE-2023-12345",
            is_active=False,
        )
        finding = {"cve_id": "CVE-2023-12345"}
        result = manager.evaluate_finding(finding, [inactive_rule])

        assert result.suppressed is False

    def test_uses_manager_rules_when_none_passed(self, manager):
        """Uses self.rules when no explicit rules are provided."""
        manager.rules = [
            SuppressionRule(
                id="from-manager",
                match_type=MatchType.SEVERITY,
                match_value="info",
                reason="Info findings ignored",
            )
        ]
        finding = {"severity": "info"}
        result = manager.evaluate_finding(finding)

        assert result.suppressed is True
        assert result.rule.id == "from-manager"


# ---------------------------------------------------------------------------
# filter_findings
# ---------------------------------------------------------------------------


class TestFilterFindings:
    """Tests for the filter_findings method."""

    def test_separates_suppressed_from_remaining(self, manager, sample_rules):
        """Suppressed and remaining findings are correctly partitioned."""
        findings = [
            {"cve_id": "CVE-2023-12345", "title": "Known vuln"},
            {"cve_id": "CVE-2024-9999", "severity": "critical", "title": "Real vuln"},
            {"severity": "low", "title": "Low sev"},
        ]

        remaining, suppressed = manager.filter_findings(findings, sample_rules)

        assert len(suppressed) == 2  # CVE match + severity match
        assert len(remaining) == 1
        assert remaining[0]["title"] == "Real vuln"

    def test_adds_suppression_metadata_to_findings(self, manager, sample_rules):
        """Suppressed findings receive suppression_rule_id and suppression_reason."""
        findings = [{"cve_id": "CVE-2023-12345"}]

        _, suppressed = manager.filter_findings(findings, sample_rules)

        assert len(suppressed) == 1
        assert suppressed[0]["suppression_rule_id"] == "cve-rule"
        assert "Not exploitable" in suppressed[0]["suppression_reason"]

    def test_original_finding_not_mutated(self, manager, sample_rules):
        """The original finding dict is not mutated by filter_findings."""
        finding = {"cve_id": "CVE-2023-12345"}
        findings = [finding]

        manager.filter_findings(findings, sample_rules)

        assert "suppression_rule_id" not in finding

    def test_empty_findings_list(self, manager, sample_rules):
        """Empty findings list returns two empty lists."""
        remaining, suppressed = manager.filter_findings([], sample_rules)
        assert remaining == []
        assert suppressed == []

    def test_empty_rules_list(self, manager):
        """No rules means no findings are suppressed."""
        findings = [{"cve_id": "CVE-2023-12345"}]
        remaining, suppressed = manager.filter_findings(findings, [])

        assert len(remaining) == 1
        assert len(suppressed) == 0


# ---------------------------------------------------------------------------
# VEX integration
# ---------------------------------------------------------------------------


class TestVexRules:
    """Tests for add_vex_rules."""

    def test_converts_not_affected_statements(self, manager):
        """VEX not_affected statements become CVE suppression rules."""
        statements = [
            {
                "vulnerability": "CVE-2023-44487",
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "HTTP/2 not enabled",
            }
        ]

        rules = manager.add_vex_rules(statements)

        assert len(rules) == 1
        assert rules[0].id == "vex-CVE-2023-44487"
        assert rules[0].match_type == MatchType.CVE
        assert rules[0].match_value == "CVE-2023-44487"
        assert rules[0].source == "vex"
        assert "component_not_present" in rules[0].reason

    def test_skips_affected_statements(self, manager):
        """VEX statements with status != not_affected are ignored."""
        statements = [
            {
                "vulnerability": "CVE-2024-0001",
                "status": "affected",
            }
        ]

        rules = manager.add_vex_rules(statements)
        assert len(rules) == 0

    def test_appends_to_manager_rules(self, manager):
        """VEX rules are appended to the manager's internal rule list."""
        statements = [
            {
                "vulnerability": "CVE-2023-44487",
                "status": "not_affected",
                "justification": "inline mitigation",
            }
        ]
        manager.add_vex_rules(statements)
        assert len(manager.rules) == 1

    def test_empty_statements(self, manager):
        """Empty VEX statement list produces no rules."""
        rules = manager.add_vex_rules([])
        assert rules == []

    def test_skips_statements_without_vulnerability(self, manager):
        """VEX statements missing vulnerability field are skipped."""
        statements = [
            {"status": "not_affected", "justification": "reason"},
        ]
        rules = manager.add_vex_rules(statements)
        assert len(rules) == 0


# ---------------------------------------------------------------------------
# EPSS auto-suppression
# ---------------------------------------------------------------------------


class TestEpssAutoSuppress:
    """Tests for add_epss_auto_suppress."""

    def test_creates_rules_for_low_score_findings(self, manager):
        """Findings with EPSS below threshold produce suppression rules."""
        findings = [
            {"cve_id": "CVE-2023-0001", "epss_score": 0.005},
            {"cve_id": "CVE-2023-0002", "epss_score": 0.001},
        ]

        rules = manager.add_epss_auto_suppress(findings, threshold=0.01)

        assert len(rules) == 2
        assert all(r.source == "epss_auto" for r in rules)
        assert all(r.match_type == MatchType.CVE for r in rules)

    def test_skips_high_score_findings(self, manager):
        """Findings with EPSS at or above threshold are not suppressed."""
        findings = [
            {"cve_id": "CVE-2023-0001", "epss_score": 0.5},
        ]

        rules = manager.add_epss_auto_suppress(findings, threshold=0.01)
        assert len(rules) == 0

    def test_skips_findings_without_epss(self, manager):
        """Findings without epss_score are skipped."""
        findings = [{"cve_id": "CVE-2023-0001"}]

        rules = manager.add_epss_auto_suppress(findings)
        assert len(rules) == 0

    def test_skips_findings_without_identifier(self, manager):
        """Findings with low EPSS but no cve_id or rule_id are skipped."""
        findings = [{"epss_score": 0.001}]

        rules = manager.add_epss_auto_suppress(findings)
        assert len(rules) == 0

    def test_rules_have_expiration(self, manager):
        """EPSS auto-suppression rules have an expiration date set."""
        findings = [{"cve_id": "CVE-2023-0001", "epss_score": 0.005}]

        rules = manager.add_epss_auto_suppress(findings)

        assert len(rules) == 1
        assert rules[0].expires_at != ""

    def test_uses_rule_id_fallback(self, manager):
        """Findings with rule_id but no cve_id use RULE_ID match type."""
        findings = [{"rule_id": "semgrep.xss.reflected", "epss_score": 0.002}]

        rules = manager.add_epss_auto_suppress(findings, threshold=0.01)

        assert len(rules) == 1
        assert rules[0].match_type == MatchType.RULE_ID
        assert rules[0].match_value == "semgrep.xss.reflected"


# ---------------------------------------------------------------------------
# get_expired_rules
# ---------------------------------------------------------------------------


class TestGetExpiredRules:
    """Tests for the get_expired_rules audit helper."""

    def test_returns_only_expired(self, manager):
        """Only rules past their expiration date are returned."""
        rules = [
            SuppressionRule(
                id="old",
                match_type=MatchType.CVE,
                match_value="CVE-2020-0001",
                expires_at="2020-01-01",
            ),
            SuppressionRule(
                id="current",
                match_type=MatchType.CVE,
                match_value="CVE-2024-0001",
                expires_at="2099-12-31",
            ),
            SuppressionRule(
                id="no-expiry",
                match_type=MatchType.CVE,
                match_value="CVE-2024-0002",
            ),
        ]

        expired = manager.get_expired_rules(rules)

        assert len(expired) == 1
        assert expired[0].id == "old"

    def test_empty_rules(self, manager):
        """Empty rule list yields empty expired list."""
        assert manager.get_expired_rules([]) == []

    def test_uses_manager_rules_by_default(self, manager):
        """Falls back to self.rules when no argument is provided."""
        manager.rules = [
            SuppressionRule(
                id="expired-on-manager",
                match_type=MatchType.CVE,
                match_value="CVE-2020-0001",
                expires_at="2020-01-01",
            ),
        ]
        expired = manager.get_expired_rules()
        assert len(expired) == 1


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------


class TestGetSummary:
    """Tests for the get_summary statistics method."""

    def test_summary_statistics(self, manager):
        """Summary accurately counts evaluated, suppressed, and breakdowns."""
        cve_rule = SuppressionRule(
            id="r1", match_type=MatchType.CVE, match_value="CVE-2023-0001",
            source="manual",
        )
        vex_rule = SuppressionRule(
            id="r2", match_type=MatchType.CVE, match_value="CVE-2023-0002",
            source="vex",
        )
        results = [
            SuppressionResult(
                finding={"cve_id": "CVE-2023-0001"},
                rule=cve_rule,
                suppressed=True,
                reason="Match",
            ),
            SuppressionResult(
                finding={"cve_id": "CVE-2023-0002"},
                rule=vex_rule,
                suppressed=True,
                reason="VEX",
            ),
            SuppressionResult(
                finding={"cve_id": "CVE-2024-9999"},
                rule=None,
                suppressed=False,
                reason="No match",
            ),
        ]

        summary = manager.get_summary(results)

        assert summary["total_evaluated"] == 3
        assert summary["suppressed_count"] == 2
        assert summary["by_match_type"]["cve"] == 2
        assert summary["by_source"]["manual"] == 1
        assert summary["by_source"]["vex"] == 1
        assert summary["expired_rules_used"] == 0

    def test_empty_results(self, manager):
        """Summary of empty results is all zeros."""
        summary = manager.get_summary([])

        assert summary["total_evaluated"] == 0
        assert summary["suppressed_count"] == 0
        assert summary["by_match_type"] == {}
        assert summary["by_source"] == {}
        assert summary["expired_rules_used"] == 0


# ---------------------------------------------------------------------------
# save_rules
# ---------------------------------------------------------------------------


class TestSaveRules:
    """Tests for the save_rules YAML writer."""

    def test_save_and_reload_roundtrip(self, tmp_path, manager):
        """Rules survive a save/load roundtrip without data loss."""
        rules = [
            SuppressionRule(
                id="roundtrip-1",
                match_type=MatchType.CVE,
                match_value="CVE-2023-12345",
                reason="Test reason",
                expires_at="2099-12-31",
                approved_by="tester",
            ),
            SuppressionRule(
                id="roundtrip-2",
                match_type=MatchType.PURL,
                match_value="pkg:npm/lodash@*",
                source="vex",
            ),
        ]
        path = str(tmp_path / "output.yml")

        manager.save_rules(rules, path)

        # Reload and verify
        loaded = manager.load_rules(path)

        assert len(loaded) == 2
        assert loaded[0].id == "roundtrip-1"
        assert loaded[0].match_type == MatchType.CVE
        assert loaded[0].match_value == "CVE-2023-12345"
        assert loaded[0].reason == "Test reason"
        assert loaded[0].expires_at == "2099-12-31"
        assert loaded[1].id == "roundtrip-2"
        assert loaded[1].match_type == MatchType.PURL
        assert loaded[1].source == "vex"

    def test_save_creates_valid_yaml(self, tmp_path, manager):
        """Saved file is valid YAML with the expected structure."""
        import yaml

        rules = [
            SuppressionRule(
                id="yaml-check",
                match_type=MatchType.SEVERITY,
                match_value="info",
            ),
        ]
        path = str(tmp_path / "check.yml")
        manager.save_rules(rules, path)

        with open(path, "r") as fh:
            data = yaml.safe_load(fh)

        assert data["version"] == 1
        assert len(data["rules"]) == 1
        assert data["rules"][0]["match_type"] == "severity"

    def test_save_empty_rules(self, tmp_path, manager):
        """Saving an empty rule list produces a valid YAML with empty rules."""
        path = str(tmp_path / "empty.yml")
        manager.save_rules([], path)

        loaded = manager.load_rules(path)
        assert loaded == []
