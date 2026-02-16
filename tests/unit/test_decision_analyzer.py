#!/usr/bin/env python3
"""
Unit Tests for Decision Analyzer

Tests cover:
- DecisionPattern creation and to_dict
- DecisionAnalyzer initialization
- load_decisions with filtering (date, scanner)
- analyze_decisions (rates, confidence, breakdowns)
- identify_patterns (test file, documentation, finding type, reasoning)
- suggest_improvements
- generate_report (text and JSON)
- Edge cases (empty decisions, missing log file, corrupt data)
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from decision_analyzer import DecisionAnalyzer, DecisionPattern

# ---------------------------------------------------------------------------
# DecisionPattern
# ---------------------------------------------------------------------------


class TestDecisionPattern:
    """Test DecisionPattern class"""

    def test_creation(self):
        pattern = DecisionPattern(
            pattern_type="test_suppression",
            description="Suppresses test files",
            frequency=15,
            confidence=0.92,
            examples=[{"finding_id": "f1"}],
        )
        assert pattern.pattern_type == "test_suppression"
        assert pattern.frequency == 15
        assert pattern.confidence == 0.92
        assert len(pattern.examples) == 1

    def test_to_dict(self):
        pattern = DecisionPattern(
            pattern_type="test_suppression",
            description="Suppresses test files",
            frequency=10,
            confidence=0.85,
            examples=[{"id": i} for i in range(5)],
        )
        d = pattern.to_dict()
        assert d["pattern_type"] == "test_suppression"
        assert d["frequency"] == 10
        assert d["confidence"] == 0.85
        assert d["example_count"] == 5
        assert len(d["examples"]) == 3  # Max 3 examples in output

    def test_to_dict_few_examples(self):
        pattern = DecisionPattern(
            pattern_type="t",
            description="d",
            frequency=1,
            confidence=0.5,
            examples=[{"id": 1}],
        )
        d = pattern.to_dict()
        assert d["example_count"] == 1
        assert len(d["examples"]) == 1


# ---------------------------------------------------------------------------
# DecisionAnalyzer Initialization
# ---------------------------------------------------------------------------


class TestDecisionAnalyzerInit:
    """Test DecisionAnalyzer initialization"""

    def test_default_path(self):
        analyzer = DecisionAnalyzer()
        assert analyzer.decision_log_path == Path(".argus-cache/decisions.jsonl")

    def test_custom_path(self):
        analyzer = DecisionAnalyzer("/tmp/custom.jsonl")
        assert analyzer.decision_log_path == Path("/tmp/custom.jsonl")


# ---------------------------------------------------------------------------
# load_decisions
# ---------------------------------------------------------------------------


class TestLoadDecisions:
    """Test load_decisions"""

    def test_missing_file_returns_empty(self, tmp_path):
        analyzer = DecisionAnalyzer(str(tmp_path / "nonexistent.jsonl"))
        decisions = analyzer.load_decisions()
        assert decisions == []

    def test_load_all_decisions(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {
                "finding_id": "f1",
                "decision": "suppress",
                "confidence": 0.9,
                "scanner": "semgrep",
                "timestamp": "2026-01-15T10:00:00",
            },
            {
                "finding_id": "f2",
                "decision": "escalate",
                "confidence": 0.8,
                "scanner": "trivy",
                "timestamp": "2026-01-15T11:00:00",
            },
        ]
        log_file.write_text("\n".join(json.dumps(d) for d in decisions_data))

        analyzer = DecisionAnalyzer(str(log_file))
        decisions = analyzer.load_decisions()
        assert len(decisions) == 2

    def test_filter_by_scanner(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {"finding_id": "f1", "decision": "suppress", "scanner": "semgrep", "timestamp": "2026-01-15T10:00:00"},
            {"finding_id": "f2", "decision": "escalate", "scanner": "trivy", "timestamp": "2026-01-15T11:00:00"},
            {"finding_id": "f3", "decision": "suppress", "scanner": "semgrep", "timestamp": "2026-01-15T12:00:00"},
        ]
        log_file.write_text("\n".join(json.dumps(d) for d in decisions_data))

        analyzer = DecisionAnalyzer(str(log_file))
        decisions = analyzer.load_decisions(scanner="semgrep")
        assert len(decisions) == 2
        assert all(d["scanner"] == "semgrep" for d in decisions)

    def test_filter_by_start_date(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {"finding_id": "f1", "decision": "suppress", "timestamp": "2026-01-10T10:00:00"},
            {"finding_id": "f2", "decision": "escalate", "timestamp": "2026-01-20T10:00:00"},
        ]
        log_file.write_text("\n".join(json.dumps(d) for d in decisions_data))

        analyzer = DecisionAnalyzer(str(log_file))
        start = datetime(2026, 1, 15)
        decisions = analyzer.load_decisions(start_date=start)
        assert len(decisions) == 1
        assert decisions[0]["finding_id"] == "f2"

    def test_filter_by_end_date(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {"finding_id": "f1", "decision": "suppress", "timestamp": "2026-01-10T10:00:00"},
            {"finding_id": "f2", "decision": "escalate", "timestamp": "2026-01-20T10:00:00"},
        ]
        log_file.write_text("\n".join(json.dumps(d) for d in decisions_data))

        analyzer = DecisionAnalyzer(str(log_file))
        end = datetime(2026, 1, 15)
        decisions = analyzer.load_decisions(end_date=end)
        assert len(decisions) == 1
        assert decisions[0]["finding_id"] == "f1"

    def test_corrupt_lines_skipped(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        log_file.write_text(
            '{"finding_id": "f1", "decision": "suppress", "timestamp": "2026-01-15T10:00:00"}\n'
            "not json at all\n"
            '{"finding_id": "f2", "decision": "escalate", "timestamp": "2026-01-15T11:00:00"}\n'
        )
        analyzer = DecisionAnalyzer(str(log_file))
        decisions = analyzer.load_decisions()
        assert len(decisions) == 2


# ---------------------------------------------------------------------------
# analyze_decisions
# ---------------------------------------------------------------------------


class TestAnalyzeDecisions:
    """Test analyze_decisions"""

    def test_empty_decisions(self):
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions([])
        assert result == {}

    def test_basic_metrics(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "scanner": "semgrep", "finding_type": "sql_injection"},
            {"decision": "suppress", "confidence": 0.8, "scanner": "semgrep", "finding_type": "xss"},
            {"decision": "escalate", "confidence": 0.95, "scanner": "trivy", "finding_type": "cve"},
            {"decision": "suppress", "confidence": 0.3, "scanner": "checkov", "finding_type": "iac"},
        ]
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions(decisions)

        assert result["total_decisions"] == 4
        assert result["suppression_rate"] == 75.0
        assert result["escalation_rate"] == 25.0
        assert 0.7 < result["avg_confidence"] < 0.75

    def test_confidence_distribution(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.1},
            {"decision": "suppress", "confidence": 0.3},
            {"decision": "suppress", "confidence": 0.5},
            {"decision": "escalate", "confidence": 0.7},
            {"decision": "escalate", "confidence": 0.95},
        ]
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions(decisions)

        dist = result["confidence_distribution"]
        assert dist["0.0-0.2"] == 1
        assert dist["0.2-0.4"] == 1
        assert dist["0.4-0.6"] == 1
        assert dist["0.6-0.8"] == 1
        assert dist["0.8-1.0"] == 1

    def test_by_scanner_breakdown(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "scanner": "semgrep"},
            {"decision": "escalate", "confidence": 0.8, "scanner": "semgrep"},
            {"decision": "suppress", "confidence": 0.7, "scanner": "trivy"},
        ]
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions(decisions)

        assert "semgrep" in result["by_scanner"]
        assert result["by_scanner"]["semgrep"]["total"] == 2
        assert "trivy" in result["by_scanner"]

    def test_low_confidence_decisions(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.3, "finding_id": "f1", "finding_type": "test", "scanner": "s"},
            {"decision": "suppress", "confidence": 0.9, "finding_id": "f2"},
            {"decision": "suppress", "confidence": 0.5, "finding_id": "f3", "finding_type": "iac", "scanner": "c"},
        ]
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions(decisions)

        assert result["low_confidence_count"] == 2  # 0.3 and 0.5 are < 0.6

    def test_model_usage_tracking(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "model": "claude-3"},
            {"decision": "suppress", "confidence": 0.8, "model": "claude-3"},
            {"decision": "escalate", "confidence": 0.7, "model": "gpt-4"},
        ]
        analyzer = DecisionAnalyzer()
        result = analyzer.analyze_decisions(decisions)

        assert result["model_usage"]["claude-3"] == 2
        assert result["model_usage"]["gpt-4"] == 1


# ---------------------------------------------------------------------------
# identify_patterns
# ---------------------------------------------------------------------------


class TestIdentifyPatterns:
    """Test identify_patterns"""

    def test_no_patterns_in_empty_decisions(self):
        analyzer = DecisionAnalyzer()
        patterns = analyzer.identify_patterns([])
        assert patterns == []

    def test_detect_test_file_suppression(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "reasoning": "This is in a test file, low risk"},
            {"decision": "suppress", "confidence": 0.85, "reasoning": "Test fixture, not production code"},
            {"decision": "escalate", "confidence": 0.95, "reasoning": "Critical SQL injection"},
        ]
        analyzer = DecisionAnalyzer()
        patterns = analyzer.identify_patterns(decisions)

        test_patterns = [p for p in patterns if p.pattern_type == "test_file_suppression"]
        assert len(test_patterns) == 1
        assert test_patterns[0].frequency == 2

    def test_detect_documentation_suppression(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "reasoning": "Found in documentation example"},
            {"decision": "suppress", "confidence": 0.8, "reasoning": "Readme code snippet, not executable"},
        ]
        analyzer = DecisionAnalyzer()
        patterns = analyzer.identify_patterns(decisions)

        doc_patterns = [p for p in patterns if p.pattern_type == "documentation_suppression"]
        assert len(doc_patterns) == 1

    def test_detect_high_confidence_type_suppression(self):
        decisions = [{"decision": "suppress", "confidence": 0.9, "finding_type": "info_leak"} for _ in range(6)]
        analyzer = DecisionAnalyzer()
        patterns = analyzer.identify_patterns(decisions)

        type_patterns = [p for p in patterns if p.pattern_type == "high_confidence_type_suppression"]
        assert len(type_patterns) >= 1

    def test_detect_reasoning_phrases(self):
        decisions = [
            {"decision": "suppress", "confidence": 0.9, "reasoning": "This is a false positive"},
            {"decision": "suppress", "confidence": 0.85, "reasoning": "Known false positive pattern"},
            {"decision": "suppress", "confidence": 0.8, "reasoning": "Clearly a false positive"},
        ]
        analyzer = DecisionAnalyzer()
        patterns = analyzer.identify_patterns(decisions)

        fp_patterns = [p for p in patterns if "false_positive" in p.pattern_type]
        assert len(fp_patterns) >= 1


# ---------------------------------------------------------------------------
# suggest_improvements
# ---------------------------------------------------------------------------


class TestSuggestImprovements:
    """Test suggest_improvements"""

    def test_no_suggestions_for_good_analysis(self):
        analysis = {
            "total_decisions": 100,
            "low_confidence_count": 2,
            "by_scanner": {"semgrep": {"suppress": 30, "escalate": 70, "total": 100}},
            "by_finding_type": {},
        }
        patterns = []
        analyzer = DecisionAnalyzer()
        suggestions = analyzer.suggest_improvements(analysis, patterns)
        assert isinstance(suggestions, list)

    def test_suggest_heuristic_for_strong_pattern(self):
        analysis = {"total_decisions": 100, "low_confidence_count": 0, "by_scanner": {}, "by_finding_type": {}}
        patterns = [
            DecisionPattern(
                pattern_type="test_file_suppression",
                description="Test files",
                frequency=15,
                confidence=0.90,
                examples=[],
            )
        ]
        analyzer = DecisionAnalyzer()
        suggestions = analyzer.suggest_improvements(analysis, patterns)
        assert any("heuristic" in s.lower() for s in suggestions)

    def test_suggest_investigation_for_low_confidence(self):
        analysis = {
            "total_decisions": 100,
            "low_confidence_count": 20,
            "by_scanner": {},
            "by_finding_type": {},
        }
        patterns = []
        analyzer = DecisionAnalyzer()
        suggestions = analyzer.suggest_improvements(analysis, patterns)
        assert any("investigate" in s.lower() for s in suggestions)

    def test_suggest_scanner_adjustment(self):
        analysis = {
            "total_decisions": 100,
            "low_confidence_count": 0,
            "by_scanner": {"noisy_scanner": {"suppress": 90, "escalate": 10, "total": 100}},
            "by_finding_type": {},
        }
        patterns = []
        analyzer = DecisionAnalyzer()
        suggestions = analyzer.suggest_improvements(analysis, patterns)
        assert any("noisy_scanner" in s for s in suggestions)

    def test_suggest_finding_type_allowlist(self):
        analysis = {
            "total_decisions": 100,
            "low_confidence_count": 0,
            "by_scanner": {},
            "by_finding_type": {"info_leak": {"suppress": 10, "escalate": 0, "total": 10}},
        }
        patterns = []
        analyzer = DecisionAnalyzer()
        suggestions = analyzer.suggest_improvements(analysis, patterns)
        assert any("info_leak" in s for s in suggestions)


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    """Test generate_report"""

    def test_no_decisions_returns_message(self):
        analyzer = DecisionAnalyzer("/nonexistent/path.jsonl")
        report = analyzer.generate_report()
        assert "No decisions found" in report

    def test_text_format(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {
                "finding_id": "f1",
                "decision": "suppress",
                "confidence": 0.9,
                "scanner": "semgrep",
                "finding_type": "xss",
                "timestamp": "2026-01-15T10:00:00",
            },
            {
                "finding_id": "f2",
                "decision": "escalate",
                "confidence": 0.95,
                "scanner": "trivy",
                "finding_type": "cve",
                "timestamp": "2026-01-15T11:00:00",
            },
        ]
        log_file.write_text("\n".join(json.dumps(d) for d in decisions_data))

        analyzer = DecisionAnalyzer(str(log_file))
        report = analyzer.generate_report(output_format="text")
        assert "AI DECISION QUALITY ANALYSIS" in report
        assert "SUMMARY METRICS" in report
        assert "Total Decisions:" in report

    def test_json_format(self, tmp_path):
        log_file = tmp_path / "decisions.jsonl"
        decisions_data = [
            {
                "finding_id": "f1",
                "decision": "suppress",
                "confidence": 0.9,
                "scanner": "semgrep",
                "finding_type": "xss",
                "timestamp": "2026-01-15T10:00:00",
            },
        ]
        log_file.write_text(json.dumps(decisions_data[0]))

        analyzer = DecisionAnalyzer(str(log_file))
        report = analyzer.generate_report(output_format="json")
        data = json.loads(report)
        assert "analysis" in data
        assert "patterns" in data
        assert "suggestions" in data
        assert "generated_at" in data

    def test_report_with_provided_decisions(self):
        decisions = [
            {
                "finding_id": "f1",
                "decision": "suppress",
                "confidence": 0.9,
                "scanner": "semgrep",
                "finding_type": "xss",
            },
        ]
        analyzer = DecisionAnalyzer()
        report = analyzer.generate_report(decisions=decisions, output_format="text")
        assert "Total Decisions:" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
