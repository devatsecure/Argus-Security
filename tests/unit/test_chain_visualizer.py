#!/usr/bin/env python3
"""
Unit Tests for Chain Visualizer

Tests cover:
- ChainVisualizer initialization (color map)
- generate_markdown_report
- print_console_report
- generate_ascii_graph
- generate_json_summary
- Helper methods (_color, _get_risk_color, _get_severity_color)
- Edge cases (empty chains, missing fields)
"""

import json
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from chain_visualizer import ChainVisualizer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def visualizer():
    return ChainVisualizer()


@pytest.fixture
def sample_chains_data():
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "duration_seconds": 12.5,
        "total_vulnerabilities": 10,
        "total_chains": 2,
        "statistics": {
            "critical_chains": 1,
            "high_chains": 1,
            "avg_chain_length": 3.0,
            "avg_risk_score": 7.5,
            "max_risk_score": 9.2,
            "by_exploitability": {"trivial": 1, "moderate": 1},
        },
        "chains": [
            {
                "chain_id": "chain-001",
                "risk_score": 9.2,
                "exploitability": "trivial",
                "complexity": "low",
                "estimated_exploit_time": "1 hour",
                "base_risk": 7.0,
                "amplification_factor": 1.31,
                "chain_length": 3,
                "final_impact": "Full data breach via SQL injection chain",
                "mitigation_priority": 9,
                "vulnerabilities": [
                    {
                        "category": "SAST",
                        "severity": "high",
                        "file_path": "src/api/users.py",
                        "title": "SQL injection in user query",
                    },
                    {
                        "category": "SAST",
                        "severity": "high",
                        "file_path": "src/api/auth.py",
                        "title": "Missing authentication check",
                    },
                    {
                        "category": "SAST",
                        "severity": "critical",
                        "file_path": "src/db/connection.py",
                        "title": "Unrestricted database access",
                    },
                ],
            },
            {
                "chain_id": "chain-002",
                "risk_score": 5.8,
                "exploitability": "moderate",
                "complexity": "medium",
                "estimated_exploit_time": "4 hours",
                "base_risk": 4.5,
                "amplification_factor": 1.29,
                "chain_length": 2,
                "final_impact": "XSS escalation to session hijack",
                "mitigation_priority": 6,
                "vulnerabilities": [
                    {
                        "category": "SAST",
                        "severity": "medium",
                        "file_path": "src/views/profile.py",
                        "title": "Reflected XSS in profile page",
                    },
                    {
                        "category": "SAST",
                        "severity": "high",
                        "file_path": "src/session/manager.py",
                        "title": "Session cookie without HttpOnly",
                    },
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestChainVisualizerInit:
    """Test ChainVisualizer initialization"""

    def test_color_map_defined(self, visualizer):
        assert "critical" in visualizer.color_map
        assert "high" in visualizer.color_map
        assert "medium" in visualizer.color_map
        assert "low" in visualizer.color_map
        assert "info" in visualizer.color_map
        assert "reset" in visualizer.color_map

    def test_color_map_has_ansi_codes(self, visualizer):
        for _key, value in visualizer.color_map.items():
            assert "\033[" in value


# ---------------------------------------------------------------------------
# Markdown Report
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    """Test generate_markdown_report"""

    def test_creates_file(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "report.md"
        visualizer.generate_markdown_report(sample_chains_data, str(output_file))
        assert output_file.exists()

    def test_contains_header(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "report.md"
        visualizer.generate_markdown_report(sample_chains_data, str(output_file))
        content = output_file.read_text()
        assert "Vulnerability Chaining Analysis Report" in content

    def test_contains_statistics(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "report.md"
        visualizer.generate_markdown_report(sample_chains_data, str(output_file))
        content = output_file.read_text()
        assert "10" in content  # total vulnerabilities
        assert "2" in content  # total chains
        assert "9.2" in content  # max risk score

    def test_contains_chain_details(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "report.md"
        visualizer.generate_markdown_report(sample_chains_data, str(output_file))
        content = output_file.read_text()
        assert "Chain #1" in content
        assert "Chain #2" in content
        assert "SQL injection" in content
        assert "Full data breach" in content

    def test_creates_parent_directories(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "subdir" / "nested" / "report.md"
        visualizer.generate_markdown_report(sample_chains_data, str(output_file))
        assert output_file.exists()

    def test_limits_to_10_chains(self, visualizer, tmp_path):
        chains_data = {
            "timestamp": "2026-01-01T00:00:00Z",
            "duration_seconds": 1.0,
            "total_vulnerabilities": 50,
            "total_chains": 15,
            "statistics": {
                "critical_chains": 5,
                "high_chains": 5,
                "avg_chain_length": 2.0,
                "avg_risk_score": 5.0,
                "max_risk_score": 9.0,
                "by_exploitability": {},
            },
            "chains": [
                {
                    "chain_id": f"chain-{i:03d}",
                    "risk_score": 9.0 - i * 0.5,
                    "exploitability": "moderate",
                    "complexity": "medium",
                    "base_risk": 5.0,
                    "amplification_factor": 1.5,
                    "chain_length": 2,
                    "vulnerabilities": [
                        {"category": "SAST", "severity": "high", "file_path": f"file{i}.py", "title": f"Vuln {i}"},
                    ],
                }
                for i in range(15)
            ],
        }

        output_file = tmp_path / "report.md"
        visualizer.generate_markdown_report(chains_data, str(output_file))
        content = output_file.read_text()
        # Should have chains 1 through 10, not 11+
        assert "Chain #10" in content
        assert "Chain #11" not in content


# ---------------------------------------------------------------------------
# Console Report
# ---------------------------------------------------------------------------


class TestConsoleReport:
    """Test print_console_report"""

    def test_prints_without_error(self, visualizer, sample_chains_data, capsys):
        visualizer.print_console_report(sample_chains_data, max_chains=2)
        captured = capsys.readouterr()
        assert "VULNERABILITY CHAINING ANALYSIS REPORT" in captured.out

    def test_prints_statistics(self, visualizer, sample_chains_data, capsys):
        visualizer.print_console_report(sample_chains_data, max_chains=1)
        captured = capsys.readouterr()
        assert "Total Vulnerabilities: 10" in captured.out
        assert "Attack Chains Found: 2" in captured.out

    def test_prints_chain_details(self, visualizer, sample_chains_data, capsys):
        visualizer.print_console_report(sample_chains_data, max_chains=1)
        captured = capsys.readouterr()
        assert "Chain #1" in captured.out
        assert "9.2" in captured.out

    def test_respects_max_chains(self, visualizer, sample_chains_data, capsys):
        visualizer.print_console_report(sample_chains_data, max_chains=1)
        captured = capsys.readouterr()
        assert "Chain #1" in captured.out
        # Should NOT contain chain #2
        assert "Chain #2" not in captured.out


# ---------------------------------------------------------------------------
# ASCII Graph
# ---------------------------------------------------------------------------


class TestAsciiGraph:
    """Test generate_ascii_graph"""

    def test_generates_graph(self, visualizer, sample_chains_data):
        chain = sample_chains_data["chains"][0]
        graph = visualizer.generate_ascii_graph(chain)
        assert isinstance(graph, str)
        assert "Attack Chain" in graph
        assert "9.2" in graph

    def test_graph_contains_vulnerabilities(self, visualizer, sample_chains_data):
        chain = sample_chains_data["chains"][0]
        graph = visualizer.generate_ascii_graph(chain)
        assert "SAST" in graph
        assert "HIGH" in graph or "CRITICAL" in graph

    def test_graph_contains_impact(self, visualizer, sample_chains_data):
        chain = sample_chains_data["chains"][0]
        graph = visualizer.generate_ascii_graph(chain)
        assert "Full data breach" in graph

    def test_graph_single_vulnerability(self, visualizer):
        chain = {
            "risk_score": 5.0,
            "vulnerabilities": [
                {"category": "SAST", "severity": "medium", "file_path": "test.py", "title": "Issue"},
            ],
            "final_impact": "Minor impact",
        }
        graph = visualizer.generate_ascii_graph(chain)
        assert "MEDIUM" in graph
        assert "Minor impact" in graph

    def test_graph_no_final_impact(self, visualizer):
        chain = {
            "risk_score": 3.0,
            "vulnerabilities": [
                {"category": "SAST", "severity": "low", "file_path": "test.py", "title": "Issue"},
            ],
        }
        graph = visualizer.generate_ascii_graph(chain)
        assert "High Impact" in graph  # Default fallback


# ---------------------------------------------------------------------------
# JSON Summary
# ---------------------------------------------------------------------------


class TestJsonSummary:
    """Test generate_json_summary"""

    def test_creates_file(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        assert output_file.exists()

    def test_valid_json(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        data = json.loads(output_file.read_text())
        assert isinstance(data, dict)

    def test_contains_metadata(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        data = json.loads(output_file.read_text())
        assert "metadata" in data
        assert data["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"

    def test_contains_summary(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        data = json.loads(output_file.read_text())
        assert data["summary"]["total_vulnerabilities"] == 10
        assert data["summary"]["total_chains"] == 2
        assert data["summary"]["critical_chains"] == 1

    def test_contains_top_chains(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        data = json.loads(output_file.read_text())
        assert len(data["top_chains"]) == 2
        assert data["top_chains"][0]["chain_id"] == "chain-001"
        assert data["top_chains"][0]["risk_score"] == 9.2

    def test_creates_parent_directories(self, visualizer, sample_chains_data, tmp_path):
        output_file = tmp_path / "deep" / "nested" / "summary.json"
        visualizer.generate_json_summary(sample_chains_data, str(output_file))
        assert output_file.exists()


# ---------------------------------------------------------------------------
# Helper Methods
# ---------------------------------------------------------------------------


class TestHelperMethods:
    """Test _color, _get_risk_color, _get_severity_color"""

    def test_color_with_known_severity(self, visualizer):
        result = visualizer._color("critical", "42")
        assert "42" in result
        assert "\033[" in result

    def test_color_with_unknown_severity(self, visualizer):
        result = visualizer._color("unknown", "text")
        assert "text" in result

    def test_get_risk_color_critical(self, visualizer):
        color = visualizer._get_risk_color(9.5)
        assert color == visualizer.color_map["critical"]

    def test_get_risk_color_high(self, visualizer):
        color = visualizer._get_risk_color(7.5)
        assert color == visualizer.color_map["high"]

    def test_get_risk_color_medium(self, visualizer):
        color = visualizer._get_risk_color(5.5)
        assert color == visualizer.color_map["medium"]

    def test_get_risk_color_low(self, visualizer):
        color = visualizer._get_risk_color(3.0)
        assert color == visualizer.color_map["low"]

    def test_get_severity_color_known(self, visualizer):
        assert visualizer._get_severity_color("critical") == visualizer.color_map["critical"]
        assert visualizer._get_severity_color("high") == visualizer.color_map["high"]
        assert visualizer._get_severity_color("MEDIUM") == visualizer.color_map["medium"]

    def test_get_severity_color_unknown(self, visualizer):
        result = visualizer._get_severity_color("unknown")
        assert result == visualizer.color_map["reset"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
