#!/usr/bin/env python3
"""
Unit tests for metrics_calculator.py

Tests Cohen's Kappa, Precision/Recall, Agreement calculations, and statistical analysis.
"""

import json
import tempfile
from pathlib import Path

import pytest

from metrics_calculator import (
    CategoryAgreement,
    ConfusionMatrix,
    CohenKappaResult,
    FindingMatch,
    MetricsCalculator,
    MetricsReport,
    PrecisionRecallMetrics,
    SeverityAgreement,
    load_findings_from_file,
    save_metrics_report,
)


class TestCohenKappaInterpretion:
    """Test Cohen's Kappa interpretation scale."""

    def test_interpret_perfect_agreement(self):
        """Test perfect agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(0.95)
        assert interpretation == "Almost Perfect"

    def test_interpret_substantial_agreement(self):
        """Test substantial agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(0.75)
        assert interpretation == "Substantial"

    def test_interpret_moderate_agreement(self):
        """Test moderate agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(0.55)
        assert interpretation == "Moderate"

    def test_interpret_fair_agreement(self):
        """Test fair agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(0.35)
        assert interpretation == "Fair"

    def test_interpret_slight_agreement(self):
        """Test slight agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(0.15)
        assert interpretation == "Slight"

    def test_interpret_poor_agreement(self):
        """Test poor agreement interpretation."""
        interpretation = CohenKappaResult.interpret_kappa(-0.05)
        assert interpretation == "Poor"


class TestConfusionMatrix:
    """Test confusion matrix creation and conversion."""

    def test_confusion_matrix_creation(self):
        """Test creating confusion matrix."""
        cm = ConfusionMatrix(true_positive=10, false_positive=2, false_negative=1, true_negative=87)

        assert cm.true_positive == 10
        assert cm.false_positive == 2
        assert cm.false_negative == 1
        assert cm.true_negative == 87

    def test_confusion_matrix_to_dict(self):
        """Test confusion matrix to dict conversion."""
        cm = ConfusionMatrix(true_positive=10, false_positive=2, false_negative=1, true_negative=87)
        cm_dict = cm.to_dict()

        assert cm_dict["true_positive"] == 10
        assert cm_dict["false_positive"] == 2
        assert cm_dict["false_negative"] == 1
        assert cm_dict["true_negative"] == 87


class TestPrecisionRecallMetrics:
    """Test Precision and Recall calculations."""

    def test_precision_calculation(self):
        """Test precision calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=20, false_negative=5, true_negative=95)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # Precision = TP / (TP + FP) = 80 / 100 = 0.8
        assert abs(metrics.precision - 0.8) < 0.01

    def test_recall_calculation(self):
        """Test recall calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=20, false_negative=20, true_negative=80)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # Recall = TP / (TP + FN) = 80 / 100 = 0.8
        assert abs(metrics.recall - 0.8) < 0.01

    def test_f1_score_calculation(self):
        """Test F1-Score calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=20, false_negative=20, true_negative=80)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # Precision = 0.8, Recall = 0.8, F1 = 2 * 0.8 * 0.8 / (0.8 + 0.8) = 0.8
        assert abs(metrics.f1_score - 0.8) < 0.01

    def test_accuracy_calculation(self):
        """Test accuracy calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=20, false_negative=20, true_negative=80)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # Accuracy = (TP + TN) / (TP + TN + FP + FN) = 160 / 200 = 0.8
        assert abs(metrics.accuracy - 0.8) < 0.01

    def test_specificity_calculation(self):
        """Test specificity calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=10, false_negative=20, true_negative=90)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # Specificity = TN / (TN + FP) = 90 / 100 = 0.9
        assert abs(metrics.specificity - 0.9) < 0.01

    def test_false_positive_rate_calculation(self):
        """Test false positive rate calculation."""
        cm = ConfusionMatrix(true_positive=80, false_positive=20, false_negative=20, true_negative=80)

        calculator = MetricsCalculator()
        metrics = calculator._calculate_precision_recall(cm)

        # FPR = FP / (FP + TN) = 20 / 100 = 0.2
        assert abs(metrics.false_positive_rate - 0.2) < 0.01


class TestMatchFinding:
    """Test finding matching logic."""

    def test_exact_path_match_score(self):
        """Test matching score for same path."""
        calculator = MetricsCalculator()

        finding1 = {"path": "src/main.py", "line": 10, "rule_id": "SEC001", "severity": "high",
                    "category": "SAST"}
        finding2 = {"path": "src/main.py", "line": 10, "rule_id": "SEC001", "severity": "high",
                    "category": "SAST"}

        score = calculator._calculate_match_score(finding1, finding2)

        # All fields match: 0.4 + 0.2 + 0.2 + 0.1 + 0.1 = 1.0
        assert abs(score - 1.0) < 0.01

    def test_partial_match_score(self):
        """Test matching score for partial match."""
        calculator = MetricsCalculator()

        finding1 = {"path": "src/main.py", "line": 10, "rule_id": "SEC001", "severity": "high",
                    "category": "SAST"}
        finding2 = {"path": "src/main.py", "line": 20, "rule_id": "SEC001", "severity": "high",
                    "category": "SAST"}

        score = calculator._calculate_match_score(finding1, finding2)

        # Path + Rule ID + Severity + Category: 0.4 + 0.2 + 0.1 + 0.1 = 0.8
        assert abs(score - 0.8) < 0.01

    def test_no_match_score(self):
        """Test matching score for different findings."""
        calculator = MetricsCalculator()

        finding1 = {"path": "src/main.py", "line": 10, "rule_id": "SEC001", "severity": "high",
                    "category": "SAST"}
        finding2 = {"path": "src/other.py", "line": 20, "rule_id": "SEC999", "severity": "low",
                    "category": "DEPS"}

        score = calculator._calculate_match_score(finding1, finding2)

        assert abs(score - 0.0) < 0.01


class TestSimpleAgreement:
    """Test simple agreement calculation."""

    def test_perfect_agreement(self):
        """Test 100% agreement."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(argus_finding={"path": "a.py"}, codex_finding={"path": "a.py"}),
            FindingMatch(argus_finding={"path": "b.py"}, codex_finding={"path": "b.py"}),
        ]

        agreement = calculator._calculate_simple_agreement(matches)

        assert abs(agreement - 1.0) < 0.01

    def test_partial_agreement(self):
        """Test 50% agreement."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(argus_finding={"path": "a.py"}, codex_finding={"path": "a.py"}),
            FindingMatch(argus_finding={"path": "b.py"}, codex_finding=None),
        ]

        agreement = calculator._calculate_simple_agreement(matches)

        assert abs(agreement - 0.5) < 0.01

    def test_no_agreement(self):
        """Test 0% agreement."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(argus_finding={"path": "a.py"}, codex_finding=None),
            FindingMatch(argus_finding={"path": "b.py"}, codex_finding=None),
        ]

        agreement = calculator._calculate_simple_agreement(matches)

        assert abs(agreement - 0.0) < 0.01


class TestCohenKappaCalculation:
    """Test Cohen's Kappa calculation with different scenarios."""

    def test_perfect_agreement_kappa(self):
        """Test Cohen's Kappa for perfect agreement."""
        import numpy as np

        calculator = MetricsCalculator()

        # Perfect agreement contingency table
        contingency = np.array([[100, 0], [0, 100]])

        result = calculator._calculate_cohens_kappa(contingency)

        # Perfect agreement should yield kappa = 1.0
        assert abs(result.kappa - 1.0) < 0.01
        assert result.interpretation == "Almost Perfect"

    def test_no_agreement_kappa(self):
        """Test Cohen's Kappa for no agreement."""
        import numpy as np

        calculator = MetricsCalculator()

        # No agreement contingency table
        contingency = np.array([[0, 50], [50, 0]])

        result = calculator._calculate_cohens_kappa(contingency)

        # No agreement should yield kappa = -1.0 or close to it
        assert result.kappa < 0.0

    def test_chance_agreement_kappa(self):
        """Test Cohen's Kappa for chance agreement."""
        import numpy as np

        calculator = MetricsCalculator()

        # Moderate agreement contingency table
        contingency = np.array([[60, 20], [20, 100]])

        result = calculator._calculate_cohens_kappa(contingency)

        # Should have positive kappa
        assert result.kappa > 0.0
        assert result.std_error > 0.0

    def test_kappa_confidence_interval(self):
        """Test that confidence interval is calculated correctly."""
        import numpy as np

        calculator = MetricsCalculator()

        contingency = np.array([[80, 20], [20, 80]])

        result = calculator._calculate_cohens_kappa(contingency)

        # CI should be reasonable range around kappa
        assert result.confidence_interval_lower < result.kappa
        assert result.kappa < result.confidence_interval_upper


class TestSeverityAgreement:
    """Test severity-based agreement calculation."""

    def test_severity_agreement_critical(self):
        """Test agreement for critical severity findings."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(
                argus_finding={"severity": "critical"},
                codex_finding={"severity": "critical"},
                severity_agreement=True,
            ),
            FindingMatch(
                argus_finding={"severity": "critical"},
                codex_finding=None,
                severity_agreement=False,
            ),
        ]

        agreements = calculator._calculate_severity_agreements(matches)

        critical = [a for a in agreements if a.severity == "critical"]
        assert len(critical) > 0
        assert critical[0].argus_count == 2
        assert critical[0].both_agree == 1

    def test_severity_agreement_multiple_levels(self):
        """Test agreement across multiple severity levels."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(
                argus_finding={"severity": "critical"},
                codex_finding={"severity": "critical"},
                severity_agreement=True,
            ),
            FindingMatch(
                argus_finding={"severity": "high"},
                codex_finding={"severity": "high"},
                severity_agreement=True,
            ),
            FindingMatch(
                argus_finding={"severity": "medium"},
                codex_finding=None,
                severity_agreement=False,
            ),
        ]

        agreements = calculator._calculate_severity_agreements(matches)

        assert len(agreements) >= 2


class TestCategoryAgreement:
    """Test category-based agreement calculation."""

    def test_category_agreement_sast(self):
        """Test agreement for SAST category."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(
                argus_finding={"category": "SAST"},
                codex_finding={"category": "SAST"},
                category_agreement=True,
            ),
            FindingMatch(
                argus_finding={"category": "SAST"},
                codex_finding=None,
                category_agreement=False,
            ),
        ]

        agreements = calculator._calculate_category_agreements(matches)

        sast = [a for a in agreements if a.category == "SAST"]
        assert len(sast) > 0
        assert sast[0].argus_count == 2
        assert sast[0].both_agree == 1

    def test_category_agreement_multiple_categories(self):
        """Test agreement across multiple categories."""
        calculator = MetricsCalculator()

        matches = [
            FindingMatch(
                argus_finding={"category": "SAST"},
                codex_finding={"category": "SAST"},
                category_agreement=True,
            ),
            FindingMatch(
                argus_finding={"category": "SECRETS"},
                codex_finding={"category": "SECRETS"},
                category_agreement=True,
            ),
            FindingMatch(
                argus_finding={"category": "DEPS"},
                codex_finding=None,
                category_agreement=False,
            ),
        ]

        agreements = calculator._calculate_category_agreements(matches)

        assert len(agreements) >= 2


class TestMetricsReport:
    """Test metrics report generation and serialization."""

    def test_metrics_report_creation(self):
        """Test creating a metrics report."""
        report = MetricsReport(
            argus_finding_count=10,
            codex_finding_count=12,
            total_matches=8,
        )

        assert report.argus_finding_count == 10
        assert report.codex_finding_count == 12
        assert report.total_matches == 8

    def test_metrics_report_to_dict(self):
        """Test converting report to dictionary."""
        report = MetricsReport(
            argus_finding_count=10,
            codex_finding_count=12,
            total_matches=8,
        )

        report_dict = report.to_dict()

        assert isinstance(report_dict, dict)
        assert report_dict["argus_finding_count"] == 10
        assert report_dict["codex_finding_count"] == 12
        assert "timestamp" in report_dict

    def test_metrics_report_to_json(self):
        """Test converting report to JSON."""
        report = MetricsReport(
            argus_finding_count=10,
            codex_finding_count=12,
            total_matches=8,
        )

        json_str = report.to_json()

        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["argus_finding_count"] == 10


class TestCompleteWorkflow:
    """Test complete comparison workflow."""

    def test_full_comparison_workflow(self):
        """Test complete comparison from findings to report."""
        calculator = MetricsCalculator()

        argus_findings = [
            {
                "path": "src/api.py",
                "line": 10,
                "rule_id": "SEC-001",
                "severity": "high",
                "category": "SAST",
            },
            {
                "path": "src/auth.py",
                "line": 25,
                "rule_id": "SEC-002",
                "severity": "critical",
                "category": "SECRETS",
            },
            {
                "path": "src/utils.py",
                "line": 5,
                "rule_id": "SEC-003",
                "severity": "medium",
                "category": "DEPS",
            },
        ]

        codex_findings = [
            {
                "path": "src/api.py",
                "line": 10,
                "rule_id": "SEC-001",
                "severity": "high",
                "category": "SAST",
            },
            {
                "path": "src/auth.py",
                "line": 25,
                "rule_id": "SEC-002",
                "severity": "critical",
                "category": "SECRETS",
            },
        ]

        report = calculator.compare_findings(argus_findings, codex_findings)

        assert report.argus_finding_count == 3
        assert report.codex_finding_count == 2
        assert report.total_matches == 2
        assert report.total_unique_to_argus == 1
        assert report.simple_agreement_rate > 0.5
        assert report.cohens_kappa is not None
        assert report.precision_recall is not None
        assert report.confusion_matrix is not None

    def test_comparison_with_disagreement(self):
        """Test comparison with disagreement on severity."""
        calculator = MetricsCalculator()

        argus_findings = [
            {
                "path": "src/api.py",
                "line": 10,
                "rule_id": "SEC-001",
                "severity": "high",
                "category": "SAST",
            },
        ]

        codex_findings = [
            {
                "path": "src/api.py",
                "line": 10,
                "rule_id": "SEC-001",
                "severity": "critical",
                "category": "SAST",
            },
        ]

        report = calculator.compare_findings(argus_findings, codex_findings)

        # Should still match but severity_agreement should be False
        assert report.total_matches >= 1
        assert not report.finding_matches[0].severity_agreement


class TestFileIO:
    """Test file loading and saving operations."""

    def test_load_findings_from_json_list(self):
        """Test loading findings from JSON file with list format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            findings = [
                {"path": "a.py", "rule_id": "SEC001"},
                {"path": "b.py", "rule_id": "SEC002"},
            ]
            json.dump(findings, f)
            temp_file = f.name

        try:
            loaded = load_findings_from_file(temp_file)
            assert len(loaded) == 2
            assert loaded[0]["path"] == "a.py"
        finally:
            Path(temp_file).unlink()

    def test_load_findings_from_json_dict(self):
        """Test loading findings from JSON file with dict format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            data = {
                "findings": [
                    {"path": "a.py", "rule_id": "SEC001"},
                    {"path": "b.py", "rule_id": "SEC002"},
                ]
            }
            json.dump(data, f)
            temp_file = f.name

        try:
            loaded = load_findings_from_file(temp_file)
            assert len(loaded) == 2
            assert loaded[0]["path"] == "a.py"
        finally:
            Path(temp_file).unlink()

    def test_save_metrics_report(self):
        """Test saving metrics report to file."""
        report = MetricsReport(
            argus_finding_count=10,
            codex_finding_count=12,
            total_matches=8,
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_file = f.name

        try:
            save_metrics_report(report, temp_file)
            assert Path(temp_file).exists()

            with open(temp_file) as f:
                loaded = json.load(f)
                assert loaded["argus_finding_count"] == 10
        finally:
            Path(temp_file).unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
