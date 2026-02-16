"""Tests for the Chain Visualizer module.

Covers ChainVisualizer: initialization, markdown report generation,
console output, ASCII graph, JSON summary, and edge cases.

All file I/O is mocked or uses tmp_path.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.chain_visualizer import ChainVisualizer


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

def _make_chain(
    risk_score=8.5,
    exploitability="high",
    complexity="low",
    chain_id="chain-001",
    chain_length=2,
    final_impact="Full system compromise",
):
    return {
        "chain_id": chain_id,
        "risk_score": risk_score,
        "exploitability": exploitability,
        "complexity": complexity,
        "chain_length": chain_length,
        "base_risk": 5.0,
        "amplification_factor": risk_score / 5.0,
        "estimated_exploit_time": "2 hours",
        "final_impact": final_impact,
        "mitigation_priority": 8,
        "vulnerabilities": [
            {
                "category": "sql_injection",
                "severity": "critical",
                "file_path": "app/models.py",
                "title": "SQL Injection in user query",
            },
            {
                "category": "privilege_escalation",
                "severity": "high",
                "file_path": "app/auth.py",
                "title": "Privilege escalation via role bypass",
            },
        ],
    }


def _make_chains_data(n_chains=3):
    chains = [_make_chain(chain_id=f"chain-{i:03d}", risk_score=9.0 - i) for i in range(n_chains)]
    return {
        "timestamp": "2026-02-16T12:00:00Z",
        "duration_seconds": 42.5,
        "total_vulnerabilities": 15,
        "total_chains": n_chains,
        "statistics": {
            "critical_chains": 1,
            "high_chains": 2,
            "avg_chain_length": 2.3,
            "avg_risk_score": 7.5,
            "max_risk_score": 9.0,
            "by_exploitability": {"high": 2, "medium": 1},
        },
        "chains": chains,
    }


@pytest.fixture
def visualizer():
    return ChainVisualizer()


@pytest.fixture
def chains_data():
    return _make_chains_data()


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

class TestInit:
    def test_color_map_populated(self, visualizer):
        assert "critical" in visualizer.color_map
        assert "reset" in visualizer.color_map
        assert len(visualizer.color_map) == 6

    def test_color_map_has_ansi_codes(self, visualizer):
        for key, value in visualizer.color_map.items():
            assert value.startswith("\033["), f"Missing ANSI code for {key}"


# ---------------------------------------------------------------------------
# 2. generate_markdown_report
# ---------------------------------------------------------------------------

class TestGenerateMarkdownReport:
    def test_creates_file(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "report.md")
        visualizer.generate_markdown_report(chains_data, out)
        assert Path(out).exists()

    def test_report_contains_header(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "report.md")
        visualizer.generate_markdown_report(chains_data, out)
        content = Path(out).read_text()
        assert "Vulnerability Chaining Analysis Report" in content

    def test_report_contains_statistics(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "report.md")
        visualizer.generate_markdown_report(chains_data, out)
        content = Path(out).read_text()
        assert "Total Vulnerabilities Analyzed" in content
        assert str(chains_data["total_vulnerabilities"]) in content

    def test_report_contains_chain_details(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "report.md")
        visualizer.generate_markdown_report(chains_data, out)
        content = Path(out).read_text()
        assert "Chain #1" in content
        assert "Attack Scenario" in content

    def test_creates_parent_dirs(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "deep" / "nested" / "report.md")
        visualizer.generate_markdown_report(chains_data, out)
        assert Path(out).exists()

    def test_limits_to_top_10_chains(self, visualizer, tmp_path):
        data = _make_chains_data(n_chains=15)
        out = str(tmp_path / "report.md")
        visualizer.generate_markdown_report(data, out)
        content = Path(out).read_text()
        assert "Chain #10" in content
        assert "Chain #11" not in content


# ---------------------------------------------------------------------------
# 3. print_console_report
# ---------------------------------------------------------------------------

class TestPrintConsoleReport:
    def test_prints_without_error(self, visualizer, chains_data, capsys):
        visualizer.print_console_report(chains_data, max_chains=2)
        captured = capsys.readouterr()
        assert "VULNERABILITY CHAINING ANALYSIS REPORT" in captured.out

    def test_respects_max_chains(self, visualizer, chains_data, capsys):
        visualizer.print_console_report(chains_data, max_chains=1)
        captured = capsys.readouterr()
        assert "Chain #1" in captured.out
        # Chain #2 should not appear
        assert "Chain #2" not in captured.out

    def test_shows_statistics(self, visualizer, chains_data, capsys):
        visualizer.print_console_report(chains_data)
        captured = capsys.readouterr()
        assert "Total Vulnerabilities" in captured.out
        assert "Attack Chains Found" in captured.out


# ---------------------------------------------------------------------------
# 4. _print_chain
# ---------------------------------------------------------------------------

class TestPrintChain:
    def test_prints_chain_info(self, visualizer, capsys):
        chain = _make_chain()
        visualizer._print_chain(1, chain)
        captured = capsys.readouterr()
        assert "Chain #1" in captured.out
        assert "Full system compromise" in captured.out

    def test_chain_without_final_impact(self, visualizer, capsys):
        chain = _make_chain()
        del chain["final_impact"]
        visualizer._print_chain(1, chain)
        captured = capsys.readouterr()
        assert "Chain #1" in captured.out


# ---------------------------------------------------------------------------
# 5. Color helpers
# ---------------------------------------------------------------------------

class TestColorHelpers:
    def test_color_wraps_text(self, visualizer):
        result = visualizer._color("critical", "ALERT")
        assert "ALERT" in result
        assert "\033[" in result

    def test_color_unknown_severity(self, visualizer):
        result = visualizer._color("unknown", "text")
        assert "text" in result

    def test_get_risk_color_critical(self, visualizer):
        assert visualizer._get_risk_color(9.5) == visualizer.color_map["critical"]

    def test_get_risk_color_high(self, visualizer):
        assert visualizer._get_risk_color(7.5) == visualizer.color_map["high"]

    def test_get_risk_color_medium(self, visualizer):
        assert visualizer._get_risk_color(6.0) == visualizer.color_map["medium"]

    def test_get_risk_color_low(self, visualizer):
        assert visualizer._get_risk_color(3.0) == visualizer.color_map["low"]

    def test_get_severity_color(self, visualizer):
        assert visualizer._get_severity_color("critical") == visualizer.color_map["critical"]

    def test_get_severity_color_unknown(self, visualizer):
        assert visualizer._get_severity_color("unknown") == visualizer.color_map["reset"]


# ---------------------------------------------------------------------------
# 6. generate_ascii_graph
# ---------------------------------------------------------------------------

class TestGenerateAsciiGraph:
    def test_returns_string(self, visualizer):
        chain = _make_chain()
        result = visualizer.generate_ascii_graph(chain)
        assert isinstance(result, str)

    def test_contains_severity(self, visualizer):
        chain = _make_chain()
        result = visualizer.generate_ascii_graph(chain)
        assert "[CRITICAL]" in result
        assert "[HIGH]" in result

    def test_contains_final_impact(self, visualizer):
        chain = _make_chain()
        result = visualizer.generate_ascii_graph(chain)
        assert "Full system compromise" in result

    def test_default_impact_when_missing(self, visualizer):
        chain = _make_chain()
        del chain["final_impact"]
        result = visualizer.generate_ascii_graph(chain)
        assert "High Impact" in result

    def test_contains_arrows_for_multi_step(self, visualizer):
        chain = _make_chain()
        result = visualizer.generate_ascii_graph(chain)
        # Should contain down arrow between steps
        assert "\u25bc" in result  # ▼ character


# ---------------------------------------------------------------------------
# 7. generate_json_summary
# ---------------------------------------------------------------------------

class TestGenerateJsonSummary:
    def test_creates_valid_json(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "summary.json")
        visualizer.generate_json_summary(chains_data, out)
        with open(out) as f:
            data = json.load(f)
        assert "metadata" in data
        assert "summary" in data
        assert "top_chains" in data

    def test_summary_fields(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "summary.json")
        visualizer.generate_json_summary(chains_data, out)
        with open(out) as f:
            data = json.load(f)
        assert data["summary"]["total_vulnerabilities"] == 15
        assert data["summary"]["total_chains"] == 3

    def test_limits_to_10_chains(self, visualizer, tmp_path):
        data = _make_chains_data(n_chains=15)
        out = str(tmp_path / "summary.json")
        visualizer.generate_json_summary(data, out)
        with open(out) as f:
            parsed = json.load(f)
        assert len(parsed["top_chains"]) == 10

    def test_creates_parent_dirs(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "a" / "b" / "summary.json")
        visualizer.generate_json_summary(chains_data, out)
        assert Path(out).exists()


# ---------------------------------------------------------------------------
# 8. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_chains(self, visualizer, tmp_path):
        data = _make_chains_data(n_chains=0)
        out = str(tmp_path / "empty.md")
        visualizer.generate_markdown_report(data, out)
        assert Path(out).exists()

    def test_chain_with_no_estimated_time(self, visualizer, capsys):
        chain = _make_chain()
        del chain["estimated_exploit_time"]
        visualizer._print_chain(1, chain)
        captured = capsys.readouterr()
        assert "Unknown" in captured.out

    def test_json_summary_preserves_statistics(self, visualizer, chains_data, tmp_path):
        out = str(tmp_path / "summary.json")
        visualizer.generate_json_summary(chains_data, out)
        with open(out) as f:
            data = json.load(f)
        assert data["statistics"] == chains_data["statistics"]
