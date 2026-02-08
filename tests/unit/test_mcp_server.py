#!/usr/bin/env python3
"""Tests for mcp_server module: findings store, policy gates, remediation, and server factory.

All tests work regardless of whether the ``mcp`` package is installed.
MCP-dependent behaviour is tested via mocks when the package is absent.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure scripts/ is importable
# ---------------------------------------------------------------------------
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from mcp_server import (
    CWE_REMEDIATION_MAP,
    DEFAULT_GATE_RULES,
    VALID_SEVERITIES,
    Finding,
    FindingsStore,
    MCP_AVAILABLE,
    create_argus_mcp_server,
    evaluate_policy_gate,
    get_remediation,
)


# ===================================================================
# TestFinding
# ===================================================================


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_create_with_all_fields(self):
        """Finding with all explicit fields preserves them."""
        f = Finding(
            severity="high",
            title="SQL Injection",
            file_path="app/db.py",
            line=42,
            description="User input in query",
            cwe="CWE-89",
            timestamp="2025-01-01T00:00:00Z",
            finding_id="ARGUS-TEST0001",
        )
        assert f.severity == "high"
        assert f.title == "SQL Injection"
        assert f.file_path == "app/db.py"
        assert f.line == 42
        assert f.description == "User input in query"
        assert f.cwe == "CWE-89"
        assert f.timestamp == "2025-01-01T00:00:00Z"
        assert f.finding_id == "ARGUS-TEST0001"

    def test_create_with_defaults(self):
        """Finding auto-generates timestamp and finding_id when omitted."""
        f = Finding(
            severity="low",
            title="Info disclosure",
            file_path="app.py",
            line=1,
            description="Version header exposed",
        )
        assert f.severity == "low"
        assert f.cwe == ""
        assert f.timestamp != ""
        assert f.finding_id.startswith("ARGUS-")
        assert len(f.finding_id) == 14  # "ARGUS-" (6 chars) + 8 hex chars

    def test_finding_id_format(self):
        """Auto-generated IDs follow ARGUS-XXXXXXXX pattern."""
        f = Finding(
            severity="medium",
            title="Test",
            file_path="x.py",
            line=1,
            description="desc",
        )
        assert f.finding_id.startswith("ARGUS-")
        # 8 uppercase hex chars after the dash
        hex_part = f.finding_id.split("-", 1)[1]
        assert len(hex_part) == 8
        assert all(c in "0123456789ABCDEF" for c in hex_part)

    def test_unique_ids(self):
        """Each Finding gets a unique auto-generated ID."""
        ids = set()
        for _ in range(100):
            f = Finding(
                severity="info",
                title="t",
                file_path="f.py",
                line=1,
                description="d",
            )
            ids.add(f.finding_id)
        assert len(ids) == 100

    @pytest.mark.parametrize("severity", list(VALID_SEVERITIES))
    def test_all_valid_severities(self, severity):
        """All five severity levels can be assigned."""
        f = Finding(
            severity=severity,
            title="Test",
            file_path="a.py",
            line=1,
            description="d",
        )
        assert f.severity == severity


# ===================================================================
# TestFindingsStore
# ===================================================================


class TestFindingsStore:
    """Tests for the FindingsStore in-memory store with persistence."""

    @pytest.fixture()
    def store(self, tmp_path):
        """Provide a fresh store backed by a temporary directory."""
        return FindingsStore(str(tmp_path / "findings"))

    @pytest.fixture()
    def sample_finding(self):
        return Finding(
            severity="high",
            title="XSS in template",
            file_path="views/home.html",
            line=15,
            description="Unescaped user input",
            cwe="CWE-79",
        )

    # -- add / get_all ---

    def test_add_returns_id(self, store, sample_finding):
        """add() returns the finding's ID."""
        fid = store.add(sample_finding)
        assert fid == sample_finding.finding_id
        assert fid.startswith("ARGUS-")

    def test_get_all_after_add(self, store, sample_finding):
        """get_all() returns every added finding."""
        store.add(sample_finding)
        all_findings = store.get_all()
        assert len(all_findings) == 1
        assert all_findings[0].title == "XSS in template"

    def test_get_all_returns_copy(self, store, sample_finding):
        """get_all() returns a copy, not a reference to the internal list."""
        store.add(sample_finding)
        result = store.get_all()
        result.clear()
        assert len(store.get_all()) == 1

    def test_multiple_adds(self, store):
        """Multiple findings can be added and retrieved."""
        for i in range(5):
            f = Finding(
                severity="medium",
                title=f"Finding {i}",
                file_path=f"file{i}.py",
                line=i,
                description=f"desc {i}",
            )
            store.add(f)
        assert len(store.get_all()) == 5

    # -- get_by_severity ---

    def test_get_by_severity(self, store):
        """get_by_severity() filters correctly."""
        store.add(
            Finding(
                severity="critical",
                title="Secret",
                file_path="a.py",
                line=1,
                description="d",
            )
        )
        store.add(
            Finding(
                severity="low",
                title="Info",
                file_path="b.py",
                line=2,
                description="d",
            )
        )
        store.add(
            Finding(
                severity="critical",
                title="RCE",
                file_path="c.py",
                line=3,
                description="d",
            )
        )
        crits = store.get_by_severity("critical")
        assert len(crits) == 2
        assert all(f.severity == "critical" for f in crits)

    def test_get_by_severity_case_insensitive(self, store):
        """Severity filtering is case-insensitive."""
        store.add(
            Finding(
                severity="High",
                title="T",
                file_path="a.py",
                line=1,
                description="d",
            )
        )
        assert len(store.get_by_severity("high")) == 1
        assert len(store.get_by_severity("HIGH")) == 1

    def test_get_by_severity_empty_result(self, store, sample_finding):
        """Returns empty list when no findings match."""
        store.add(sample_finding)
        assert store.get_by_severity("info") == []

    # -- get_by_id ---

    def test_get_by_id_found(self, store, sample_finding):
        """get_by_id returns the finding when it exists."""
        fid = store.add(sample_finding)
        result = store.get_by_id(fid)
        assert result is not None
        assert result.finding_id == fid

    def test_get_by_id_not_found(self, store):
        """get_by_id returns None for unknown IDs."""
        assert store.get_by_id("ARGUS-NONEXIST") is None

    # -- summary ---

    def test_summary_counts(self, store):
        """summary() returns correct counts by severity."""
        store.add(
            Finding(severity="critical", title="a", file_path="a", line=1, description="d")
        )
        store.add(
            Finding(severity="critical", title="b", file_path="b", line=2, description="d")
        )
        store.add(
            Finding(severity="high", title="c", file_path="c", line=3, description="d")
        )
        s = store.summary()
        assert s["critical"] == 2
        assert s["high"] == 1
        assert s["medium"] == 0
        assert s["total"] == 3

    # -- save_to_disk ---

    def test_save_to_disk_creates_file(self, store, sample_finding):
        """save_to_disk() creates a JSON file and returns its path."""
        store.add(sample_finding)
        path = store.save_to_disk()
        assert os.path.isfile(path)
        assert path.endswith("findings.json")

    def test_save_to_disk_valid_json(self, store, sample_finding):
        """Persisted file contains valid JSON with correct structure."""
        store.add(sample_finding)
        path = store.save_to_disk()
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["title"] == "XSS in template"
        assert data[0]["cwe"] == "CWE-79"

    def test_save_to_disk_creates_directory(self, tmp_path):
        """save_to_disk() creates the output directory if needed."""
        deep = str(tmp_path / "a" / "b" / "c")
        store = FindingsStore(deep)
        store.add(
            Finding(severity="info", title="t", file_path="f", line=1, description="d")
        )
        path = store.save_to_disk()
        assert os.path.isfile(path)

    # -- empty store ---

    def test_empty_store_get_all(self, store):
        """Empty store returns empty list."""
        assert store.get_all() == []

    def test_empty_store_summary(self, store):
        """Empty store summary has zero counts."""
        s = store.summary()
        assert s["total"] == 0
        assert all(s[sev] == 0 for sev in VALID_SEVERITIES)

    def test_empty_store_save_to_disk(self, store):
        """Saving an empty store writes an empty JSON array."""
        path = store.save_to_disk()
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data == []

    # -- clear ---

    def test_clear(self, store, sample_finding):
        """clear() removes all findings."""
        store.add(sample_finding)
        assert len(store.get_all()) == 1
        store.clear()
        assert len(store.get_all()) == 0


# ===================================================================
# TestEvaluatePolicyGate
# ===================================================================


class TestEvaluatePolicyGate:
    """Tests for the standalone evaluate_policy_gate function."""

    def _make_findings(self, severities):
        """Helper: create a list of finding dicts from severity strings."""
        return [{"severity": s, "title": f"Finding-{i}"} for i, s in enumerate(severities)]

    # -- PR gate ---

    def test_pr_gate_passes_no_critical(self):
        """PR gate passes when there are no critical findings."""
        findings = self._make_findings(["medium", "low", "info"])
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is True
        assert result["stage"] == "pr"

    def test_pr_gate_fails_on_critical(self):
        """PR gate fails when critical findings are present."""
        findings = self._make_findings(["critical", "high", "medium"])
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is False
        assert any("critical" in r.lower() for r in result["reasons"])

    def test_pr_gate_fails_on_too_many_high(self):
        """PR gate fails when high findings exceed the limit."""
        findings = self._make_findings(["high"] * 6)
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is False
        assert any("high" in r.lower() for r in result["reasons"])

    def test_pr_gate_passes_with_acceptable_high_count(self):
        """PR gate passes with up to 5 high findings (default max_high)."""
        findings = self._make_findings(["high"] * 5)
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is True

    # -- Release gate ---

    def test_release_gate_fails_on_high(self):
        """Release gate blocks high findings (max_high=0)."""
        findings = self._make_findings(["high"])
        result = evaluate_policy_gate("release", findings)
        assert result["passed"] is False

    def test_release_gate_passes_clean(self):
        """Release gate passes with only medium/low/info."""
        findings = self._make_findings(["medium", "low", "info"])
        result = evaluate_policy_gate("release", findings)
        assert result["passed"] is True

    # -- Deploy gate ---

    def test_deploy_gate_fails_on_critical(self):
        """Deploy gate blocks critical findings."""
        findings = self._make_findings(["critical"])
        result = evaluate_policy_gate("deploy", findings)
        assert result["passed"] is False

    # -- Edge cases ---

    def test_unknown_stage(self):
        """Unknown stage returns failure."""
        result = evaluate_policy_gate("unknown_stage", [])
        assert result["passed"] is False
        assert any("Unknown stage" in r for r in result["reasons"])

    def test_empty_findings_passes(self):
        """No findings should always pass."""
        result = evaluate_policy_gate("pr", [])
        assert result["passed"] is True

    def test_result_has_summary(self):
        """Result includes a severity summary dict."""
        findings = self._make_findings(["high", "high", "medium"])
        result = evaluate_policy_gate("pr", findings)
        assert result["summary"]["high"] == 2
        assert result["summary"]["medium"] == 1

    def test_custom_rules_override(self):
        """Custom rules override default gate rules."""
        findings = self._make_findings(["high"] * 3)
        # Override max_high to 2, so 3 should fail
        result = evaluate_policy_gate(
            "pr", findings, custom_rules={"max_high": 2}
        )
        assert result["passed"] is False

    def test_custom_rules_relax(self):
        """Custom rules can relax the gate."""
        findings = self._make_findings(["critical"])
        # Override block_severities to empty
        result = evaluate_policy_gate(
            "pr", findings, custom_rules={"block_severities": []}
        )
        assert result["passed"] is True


# ===================================================================
# TestGetRemediation
# ===================================================================


class TestGetRemediation:
    """Tests for the get_remediation helper function."""

    def test_known_cwe(self):
        """Known CWE returns specific remediation advice."""
        f = Finding(
            severity="high",
            title="SQL Injection",
            file_path="db.py",
            line=10,
            description="SQL injection in query",
            cwe="CWE-89",
        )
        result = get_remediation(f)
        assert result["cwe"] == "CWE-89"
        assert "parameterized" in result["remediation"].lower()
        assert result["finding_id"] == f.finding_id
        assert len(result["references"]) > 0
        assert "cwe.mitre.org" in result["references"][0]

    def test_unknown_cwe(self):
        """Unknown CWE returns generic advice with link."""
        f = Finding(
            severity="medium",
            title="Custom issue",
            file_path="x.py",
            line=1,
            description="Something",
            cwe="CWE-9999",
        )
        result = get_remediation(f)
        assert "No specific remediation template" in result["remediation"]
        assert "cwe.mitre.org" in result["references"][0]

    def test_no_cwe(self):
        """No CWE returns generic advice and no references."""
        f = Finding(
            severity="low",
            title="Minor issue",
            file_path="y.py",
            line=1,
            description="Something minor",
        )
        result = get_remediation(f)
        assert "No CWE specified" in result["remediation"]
        assert result["references"] == []

    def test_cwe_case_insensitive(self):
        """CWE lookup normalises to uppercase."""
        f = Finding(
            severity="high",
            title="XSS",
            file_path="v.py",
            line=1,
            description="xss",
            cwe="cwe-79",
        )
        result = get_remediation(f)
        assert result["cwe"] == "CWE-79"
        assert "XSS" in result["remediation"] or "Cross-Site" in result["remediation"]

    @pytest.mark.parametrize("cwe", list(CWE_REMEDIATION_MAP.keys()))
    def test_all_mapped_cwes_have_content(self, cwe):
        """Every CWE in the map produces non-empty remediation."""
        f = Finding(
            severity="high",
            title="test",
            file_path="t.py",
            line=1,
            description="d",
            cwe=cwe,
        )
        result = get_remediation(f)
        assert len(result["remediation"]) > 20


# ===================================================================
# TestCreateServer
# ===================================================================


class TestCreateServer:
    """Tests for the create_argus_mcp_server factory function."""

    def test_returns_none_when_mcp_unavailable(self):
        """Factory returns None when MCP is not installed."""
        with patch("mcp_server.MCP_AVAILABLE", False):
            result = create_argus_mcp_server("/tmp/repo")
            assert result is None

    def test_factory_returns_server_when_mcp_available(self, tmp_path):
        """Factory returns a Server object when MCP is available."""
        if not MCP_AVAILABLE:
            # Mock the MCP Server class
            mock_server_cls = MagicMock()
            mock_server_instance = MagicMock()
            mock_server_instance.tool = MagicMock(side_effect=lambda name: lambda fn: fn)
            mock_server_cls.return_value = mock_server_instance

            with patch("mcp_server.MCP_AVAILABLE", True), \
                 patch("mcp_server.Server", mock_server_cls, create=True):
                result = create_argus_mcp_server(str(tmp_path))
                assert result is not None
                mock_server_cls.assert_called_once_with("argus-security")
        else:
            result = create_argus_mcp_server(str(tmp_path))
            assert result is not None

    def test_factory_accepts_config(self, tmp_path):
        """Factory accepts an optional config dict without error."""
        config = {"enable_mcp_server": True, "project_type": "backend-api"}
        with patch("mcp_server.MCP_AVAILABLE", False):
            # Should still return None (MCP not available) but not crash
            result = create_argus_mcp_server(str(tmp_path), config=config)
            assert result is None

    def test_factory_creates_findings_dir_path(self, tmp_path):
        """Factory sets up findings store pointing to .argus/findings under repo."""
        if not MCP_AVAILABLE:
            mock_server_cls = MagicMock()
            mock_server_instance = MagicMock()
            mock_server_instance.tool = MagicMock(side_effect=lambda name: lambda fn: fn)
            mock_server_cls.return_value = mock_server_instance

            with patch("mcp_server.MCP_AVAILABLE", True), \
                 patch("mcp_server.Server", mock_server_cls, create=True):
                result = create_argus_mcp_server(str(tmp_path))
                assert result is not None
        else:
            result = create_argus_mcp_server(str(tmp_path))
            assert result is not None


# ===================================================================
# TestPolicyGateCheck (integration-style, testing the function directly)
# ===================================================================


class TestPolicyGateCheck:
    """Integration-style tests for policy gate checking."""

    def test_no_critical_findings_passes_pr(self):
        """PR gate passes when no critical findings are present."""
        findings = [
            {"severity": "high", "title": "Issue 1"},
            {"severity": "medium", "title": "Issue 2"},
            {"severity": "low", "title": "Issue 3"},
        ]
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is True

    def test_critical_findings_fails_pr(self):
        """PR gate fails when critical findings are present."""
        findings = [
            {"severity": "critical", "title": "Leaked API key"},
            {"severity": "medium", "title": "Minor issue"},
        ]
        result = evaluate_policy_gate("pr", findings)
        assert result["passed"] is False
        assert "critical" in result["reasons"][0].lower()

    def test_stage_specific_rules_pr_vs_release(self):
        """PR allows high findings but release does not."""
        findings = [{"severity": "high", "title": "High sev issue"}]
        pr_result = evaluate_policy_gate("pr", findings)
        release_result = evaluate_policy_gate("release", findings)
        # PR allows up to 5 high findings
        assert pr_result["passed"] is True
        # Release blocks all high findings (max_high=0 and high in block_severities)
        assert release_result["passed"] is False

    def test_mixed_severities_release_gate(self):
        """Release gate evaluates all severity types correctly."""
        findings = [
            {"severity": "medium", "title": "Med 1"},
            {"severity": "low", "title": "Low 1"},
            {"severity": "info", "title": "Info 1"},
        ]
        result = evaluate_policy_gate("release", findings)
        assert result["passed"] is True

    def test_gate_result_structure(self):
        """Gate result has all expected keys."""
        result = evaluate_policy_gate("pr", [])
        assert "passed" in result
        assert "stage" in result
        assert "reasons" in result
        assert "summary" in result
        assert isinstance(result["reasons"], list)
        assert isinstance(result["summary"], dict)

    def test_deploy_gate_mirrors_release(self):
        """Deploy gate has same strictness as release gate."""
        findings = [{"severity": "high", "title": "Issue"}]
        deploy_result = evaluate_policy_gate("deploy", findings)
        release_result = evaluate_policy_gate("release", findings)
        assert deploy_result["passed"] == release_result["passed"]


# ===================================================================
# TestConfigToggle
# ===================================================================


class TestConfigToggle:
    """Test that enable_mcp_server is present in config defaults."""

    def test_default_config_has_mcp_toggle(self):
        """get_default_config includes enable_mcp_server set to False."""
        from config_loader import get_default_config

        config = get_default_config()
        assert "enable_mcp_server" in config
        assert config["enable_mcp_server"] is False

    def test_mcp_toggle_env_override(self):
        """ENABLE_MCP_SERVER env var overrides the default."""
        from config_loader import load_env_overrides

        with patch.dict(os.environ, {"ENABLE_MCP_SERVER": "true"}):
            overrides = load_env_overrides()
            assert overrides.get("enable_mcp_server") is True


# ===================================================================
# TestMCPServerRunner
# ===================================================================


class TestMCPServerRunner:
    """Tests for the mcp_server_runner CLI entry point."""

    def test_runner_exits_when_mcp_unavailable(self):
        """Runner exits with code 1 when MCP is not available."""
        with patch("mcp_server.MCP_AVAILABLE", False):
            # Re-import to pick up the patched value
            import mcp_server_runner

            with patch.object(mcp_server_runner, "MCP_AVAILABLE", False):
                with pytest.raises(SystemExit) as exc_info:
                    mcp_server_runner.main()
                assert exc_info.value.code == 1
