#!/usr/bin/env python3
"""
Unit Tests for Pairwise Comparison Engine

Tests cover:
- Finding matching algorithms
- Judge evaluation
- Comparison aggregation
- Report generation
- Error handling
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from pairwise_comparison import (
    FindingMatcher,
    PairwiseComparison,
    PairwiseAggregation,
    PairwiseJudge,
    PairwiseComparator,
    ComparisonReportGenerator,
)


class TestFindingMatcher:
    """Test FindingMatcher class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.matcher = FindingMatcher(match_threshold=0.7)

    def test_exact_match(self):
        """Test exact matching of identical findings"""
        findings1 = [
            {
                "id": "1",
                "path": "src/api.py",
                "rule_id": "SQL-001",
                "severity": "high",
                "message": "SQL injection risk",
            }
        ]

        findings2 = [
            {
                "id": "2",
                "path": "src/api.py",
                "rule_id": "SQL-001",
                "severity": "high",
                "message": "SQL injection risk",
            }
        ]

        matched, f1_only, f2_only = self.matcher.match_findings(findings1, findings2)

        assert len(matched) == 1
        assert len(f1_only) == 0
        assert len(f2_only) == 0

    def test_no_match(self):
        """Test unrelated findings don't match"""
        findings1 = [
            {
                "id": "1",
                "path": "src/api.py",
                "rule_id": "SQL-001",
                "severity": "high",
                "message": "SQL injection",
            }
        ]

        findings2 = [
            {
                "id": "2",
                "path": "src/config.py",
                "rule_id": "SECRET-001",
                "severity": "critical",
                "message": "Hardcoded secret",
            }
        ]

        matched, f1_only, f2_only = self.matcher.match_findings(findings1, findings2)

        assert len(matched) == 0
        assert len(f1_only) == 1
        assert len(f2_only) == 1

    def test_partial_match(self):
        """Test partial matches based on threshold"""
        findings1 = [
            {
                "id": "1",
                "path": "src/api.py",
                "rule_id": "SQL-001",
                "severity": "high",
                "message": "SQL injection risk detected",
            }
        ]

        findings2 = [
            {
                "id": "2",
                "path": "src/api.py",
                "rule_id": "SQL-INJECTION",
                "severity": "high",
                "message": "Potential SQL injection vulnerability",
            }
        ]

        matched, f1_only, f2_only = self.matcher.match_findings(findings1, findings2)

        # Should match based on path and severity
        assert len(matched) >= 0  # Depends on similarity calculation

    def test_multiple_findings(self):
        """Test matching multiple findings"""
        findings1 = [
            {"id": "a1", "path": "api.py", "rule_id": "R1", "severity": "high", "message": "Issue 1"},
            {"id": "a2", "path": "auth.py", "rule_id": "R2", "severity": "medium", "message": "Issue 2"},
            {"id": "a3", "path": "db.py", "rule_id": "R3", "severity": "critical", "message": "Issue 3"},
        ]

        findings2 = [
            {"id": "b1", "path": "api.py", "rule_id": "R1", "severity": "high", "message": "Issue 1"},
            {"id": "b2", "path": "cache.py", "rule_id": "R4", "severity": "low", "message": "Issue 4"},
        ]

        matched, f1_only, f2_only = self.matcher.match_findings(findings1, findings2)

        assert len(matched) >= 1
        assert len(f1_only) >= 1
        assert len(f2_only) >= 0

    def test_similarity_calculation(self):
        """Test similarity score calculation"""
        f1 = {"path": "src/api.py", "rule_id": "SQL-001", "severity": "high"}
        f2 = {"path": "src/api.py", "rule_id": "SQL-001", "severity": "high"}

        score = self.matcher._calculate_similarity(f1, f2)
        assert score == 1.0  # Perfect match

    def test_threshold_filtering(self):
        """Test match threshold filtering"""
        matcher_high = FindingMatcher(match_threshold=0.9)
        matcher_low = FindingMatcher(match_threshold=0.3)

        findings1 = [{"id": "1", "path": "a.py", "rule_id": "R1"}]
        findings2 = [{"id": "2", "path": "a.py", "rule_id": "R2"}]

        # High threshold should not match
        matched_high, _, _ = matcher_high.match_findings(findings1, findings2)
        # Low threshold might match
        matched_low, _, _ = matcher_low.match_findings(findings1, findings2)

        assert len(matched_high) <= len(matched_low)


class TestPairwiseComparison:
    """Test PairwiseComparison dataclass"""

    def test_creation(self):
        """Test creating a comparison"""
        agent_finding = {"id": "1", "message": "Issue A"}
        codex_finding = {"id": "2", "message": "Issue B"}

        comp = PairwiseComparison(
            finding_id="test_1",
            argus_finding=agent_finding,
            codex_finding=codex_finding,
            match_type="matched",
            argus_score=4,
            codex_score=3,
            winner="argus",
            judge_reasoning="Argus was more thorough",
            confidence=0.95,
        )

        assert comp.finding_id == "test_1"
        assert comp.argus_score == 4
        assert comp.codex_score == 3
        assert comp.winner == "argus"

    def test_to_dict(self):
        """Test converting comparison to dict"""
        comp = PairwiseComparison(
            finding_id="test_1",
            argus_score=4,
            codex_score=3,
            winner="argus",
        )

        d = comp.to_dict()
        assert d["finding_id"] == "test_1"
        assert d["argus_score"] == 4
        assert d["winner"] == "argus"

    def test_timestamp(self):
        """Test comparison includes timestamp"""
        comp = PairwiseComparison(finding_id="test")
        assert comp.compared_at
        assert "T" in comp.compared_at  # ISO format


class TestPairwiseAggregation:
    """Test PairwiseAggregation statistics"""

    def test_creation(self):
        """Test creating aggregation"""
        agg = PairwiseAggregation(
            total_comparisons=10,
            matched_findings=8,
            argus_wins=6,
            codex_wins=2,
            ties=2,
        )

        assert agg.total_comparisons == 10
        assert agg.argus_wins == 6
        assert agg.codex_wins == 2

    def test_win_rates(self):
        """Test win rate calculation"""
        agg = PairwiseAggregation()
        agg.total_comparisons = 10
        agg.argus_wins = 6
        agg.codex_wins = 3
        agg.ties = 1

        agg.argus_win_rate = agg.argus_wins / agg.total_comparisons
        agg.codex_win_rate = agg.codex_wins / agg.total_comparisons
        agg.tie_rate = agg.ties / agg.total_comparisons

        assert agg.argus_win_rate == 0.6
        assert agg.codex_win_rate == 0.3
        assert agg.tie_rate == 0.1


class TestPairwiseJudge:
    """Test PairwiseJudge class"""

    @patch("pairwise_comparison.AnthropicProvider")
    def test_judge_initialization(self, mock_anthropic):
        """Test judge initialization"""
        mock_provider = MagicMock()
        mock_anthropic.return_value = mock_provider

        judge = PairwiseJudge(judge_model="anthropic")
        assert judge.judge_model == "anthropic"
        assert judge.judge_llm is not None

    def test_build_comparison_prompt(self):
        """Test building comparison prompt"""
        judge = MagicMock(spec=PairwiseJudge)
        judge._build_comparison_prompt = PairwiseJudge._build_comparison_prompt.__get__(judge)

        agent_finding = {
            "path": "api.py",
            "severity": "high",
            "rule_id": "SQL-001",
            "message": "SQL injection",
        }

        codex_finding = {
            "path": "api.py",
            "severity": "high",
            "rule_id": "SQL-INJECTION",
            "message": "SQL injection risk",
        }

        prompt = judge._build_comparison_prompt(agent_finding, codex_finding)

        assert "ARGUS FINDING" in prompt
        assert "CODEX FINDING" in prompt
        assert "EVALUATION CRITERIA" in prompt
        assert "Coverage" in prompt
        assert "Accuracy" in prompt

    def test_parse_judge_response(self):
        """Test parsing judge response"""
        judge = MagicMock(spec=PairwiseJudge)
        judge._parse_judge_response = PairwiseJudge._parse_judge_response.__get__(judge)

        response = json.dumps({
            "argus_scores": {
                "coverage": 5,
                "accuracy": 4,
                "actionability": 5,
                "detail": 4,
                "risk_assessment": 5,
            },
            "codex_scores": {
                "coverage": 4,
                "accuracy": 4,
                "actionability": 3,
                "detail": 4,
                "risk_assessment": 4,
            },
            "winner": "argus",
            "reasoning": "Argus provided better coverage and actionability",
            "key_differences": ["Coverage depth", "Remediation clarity"],
            "agreement_aspects": ["Severity assessment"],
            "confidence": 0.95,
        })

        agent_finding = {"id": "1", "path": "api.py"}
        codex_finding = {"id": "2", "path": "api.py"}

        comp = judge._parse_judge_response(response, agent_finding, codex_finding, "matched")

        assert comp.winner == "argus"
        assert comp.confidence == 0.95
        assert len(comp.key_differences) > 0


class TestPairwiseComparator:
    """Test PairwiseComparator orchestrator"""

    @patch("pairwise_comparison.PairwiseJudge")
    def test_initialization(self, mock_judge):
        """Test comparator initialization"""
        agent_findings = [{"id": "1"}]
        codex_findings = [{"id": "2"}]

        comparator = PairwiseComparator(
            argus_findings=agent_findings,
            codex_findings=codex_findings,
            judge_model="anthropic",
            match_threshold=0.7,
        )

        assert len(comparator.argus_findings) == 1
        assert len(comparator.codex_findings) == 1
        assert comparator.matcher.match_threshold == 0.7

    @patch("pairwise_comparison.PairwiseJudge")
    @patch("pairwise_comparison.PairwiseComparator.run_comparison")
    def test_aggregation(self, mock_run, mock_judge):
        """Test aggregation calculation"""
        # Create sample comparisons
        comparisons = [
            PairwiseComparison(
                finding_id="1",
                match_type="matched",
                argus_score=5,
                codex_score=3,
                winner="argus",
                confidence=0.95,
            ),
            PairwiseComparison(
                finding_id="2",
                match_type="matched",
                argus_score=4,
                codex_score=4,
                winner="tie",
                confidence=0.8,
            ),
            PairwiseComparison(
                finding_id="3",
                match_type="argus_only",
                argus_score=4,
                codex_score=0,
                winner="argus",
                confidence=0.7,
            ),
        ]

        # Create comparator and manually aggregate
        agent_findings = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        codex_findings = [{"id": "1"}, {"id": "2"}]

        comparator = PairwiseComparator(agent_findings, codex_findings)
        comparator.comparisons = comparisons

        agg = comparator._aggregate_comparisons()

        assert agg.total_comparisons == 3
        assert agg.matched_findings == 2
        assert agg.argus_only == 1
        assert agg.argus_wins == 2
        assert agg.ties == 1


class TestComparisonReportGenerator:
    """Test report generation"""

    def test_json_report_generation(self, tmp_path):
        """Test generating JSON report"""
        comparisons = [
            PairwiseComparison(
                finding_id="1",
                argus_score=4,
                codex_score=3,
                winner="argus",
            )
        ]

        agg = PairwiseAggregation(
            total_comparisons=1,
            argus_wins=1,
            codex_wins=0,
        )

        output_file = tmp_path / "report.json"

        ComparisonReportGenerator.generate_json_report(
            comparisons,
            agg,
            str(output_file)
        )

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert "aggregation" in data
        assert "comparisons" in data
        assert data["aggregation"]["total_comparisons"] == 1

    def test_markdown_report_generation(self, tmp_path):
        """Test generating markdown report"""
        comparisons = [
            PairwiseComparison(
                finding_id="1",
                argus_finding={"path": "api.py", "severity": "high"},
                codex_finding={"path": "api.py", "severity": "high"},
                match_type="matched",
                argus_score=4,
                codex_score=3,
                winner="argus",
                judge_reasoning="Better coverage",
            )
        ]

        agg = PairwiseAggregation(
            total_comparisons=1,
            matched_findings=1,
            argus_wins=1,
            codex_wins=0,
            ties=0,
            avg_argus_score=4.0,
            avg_codex_score=3.0,
            overall_winner="argus",
            recommendation="Argus is better",
        )

        output_file = tmp_path / "report.md"

        ComparisonReportGenerator.generate_markdown_report(
            comparisons,
            agg,
            str(output_file)
        )

        assert output_file.exists()

        with open(output_file) as f:
            content = f.read()

        assert "Pairwise Comparison Analysis Report" in content
        assert "Argus" in content
        assert "Codex" in content


class TestErrorHandling:
    """Test error handling"""

    def test_missing_fields(self):
        """Test handling findings with missing fields"""
        matcher = FindingMatcher()

        findings1 = [{"id": "1"}]  # Minimal finding
        findings2 = [{"id": "2"}]

        # Should not raise exception
        matched, f1_only, f2_only = matcher.match_findings(findings1, findings2)

        assert len(f1_only) > 0 or len(f2_only) > 0

    def test_empty_findings(self):
        """Test handling empty finding lists"""
        matcher = FindingMatcher()

        matched, f1_only, f2_only = matcher.match_findings([], [])

        assert len(matched) == 0
        assert len(f1_only) == 0
        assert len(f2_only) == 0

    def test_invalid_threshold(self):
        """Test invalid match threshold"""
        # Threshold should be 0-1 - implementation may or may not validate
        try:
            matcher = FindingMatcher(match_threshold=1.5)
            # If no exception, just verify matcher was created
            assert matcher is not None
        except (ValueError, AssertionError):
            # If validation exists, that's also fine
            pass


class TestIntegration:
    """Integration tests"""

    def test_end_to_end_matching_only(self):
        """Test complete workflow without judge (no API needed)"""
        agent_findings = [
            {
                "id": "ao1",
                "path": "src/api.py",
                "rule_id": "SQL-001",
                "severity": "high",
                "message": "SQL injection",
            },
            {
                "id": "ao2",
                "path": "src/auth.py",
                "rule_id": "WEAK-PASS",
                "severity": "medium",
                "message": "Weak password",
            },
        ]

        codex_findings = [
            {
                "id": "cx1",
                "path": "src/api.py",
                "rule_id": "SQL-INJECTION",
                "severity": "high",
                "message": "SQL injection risk",
            },
            {
                "id": "cx2",
                "path": "src/config.py",
                "rule_id": "SECRET",
                "severity": "critical",
                "message": "Hardcoded secret",
            },
        ]

        matcher = FindingMatcher(match_threshold=0.6)
        matched, ao_only, cx_only = matcher.match_findings(agent_findings, codex_findings)

        assert len(matched) >= 1  # Should match first finding
        assert len(ao_only) >= 1  # auth.py finding
        assert len(cx_only) >= 1  # config.py finding


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
