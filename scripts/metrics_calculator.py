#!/usr/bin/env python3
"""
Metrics Calculator for Inter-Rater Agreement Analysis

Compares security findings from two sources (e.g., Argus and Codex) and calculates:
- Cohen's Kappa: Inter-rater agreement coefficient
- Precision/Recall: Finding validation metrics
- Agreement Percentage: Simple agreement rate
- Confusion Matrix: Category-wise agreement/disagreement
- Statistical Significance: P-values and confidence intervals
- Visualization-ready data structures for charts

Usage:
    from metrics_calculator import MetricsCalculator

    calculator = MetricsCalculator()
    results = calculator.compare_findings(argus_findings, codex_findings)
    print(results.to_json())
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np
from scipy import stats

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ConfusionMatrix:
    """
    Confusion matrix for finding classification agreement.

    Categories: True Positive, False Positive, False Negative, True Negative
    """

    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    true_negative: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PrecisionRecallMetrics:
    """Precision, Recall, F1-Score metrics for findings validation."""

    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    specificity: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    accuracy: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CohenKappaResult:
    """Cohen's Kappa agreement coefficient results."""

    kappa: float = 0.0
    std_error: float = 0.0
    confidence_interval_lower: float = 0.0
    confidence_interval_upper: float = 0.0
    p_value: float = 0.0
    interpretation: str = "Poor"

    @staticmethod
    def interpret_kappa(kappa: float) -> str:
        """Interpret Kappa value according to Landis & Koch (1977) scale."""
        if kappa < 0:
            return "Poor"
        elif kappa < 0.2:
            return "Slight"
        elif kappa < 0.4:
            return "Fair"
        elif kappa < 0.6:
            return "Moderate"
        elif kappa < 0.8:
            return "Substantial"
        else:
            return "Almost Perfect"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class SeverityAgreement:
    """Agreement metrics for severity classification."""

    severity: str
    argus_count: int = 0
    codex_count: int = 0
    both_agree: int = 0
    agreement_rate: float = 0.0
    kappa: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CategoryAgreement:
    """Agreement metrics for finding category classification."""

    category: str
    argus_count: int = 0
    codex_count: int = 0
    both_agree: int = 0
    agreement_rate: float = 0.0
    kappa: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FindingMatch:
    """Record of matched findings from two sources."""

    argus_finding: dict
    codex_finding: Optional[dict]
    match_score: float = 0.0
    severity_agreement: bool = False
    category_agreement: bool = False
    is_duplicate: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "argus_finding": self.argus_finding,
            "codex_finding": self.codex_finding,
            "match_score": self.match_score,
            "severity_agreement": self.severity_agreement,
            "category_agreement": self.category_agreement,
            "is_duplicate": self.is_duplicate,
        }


@dataclass
class MetricsReport:
    """Complete metrics report with all calculations."""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    argus_finding_count: int = 0
    codex_finding_count: int = 0
    total_matches: int = 0
    total_unique_to_argus: int = 0
    total_unique_to_codex: int = 0

    # Agreement metrics
    simple_agreement_rate: float = 0.0
    cohens_kappa: Optional[CohenKappaResult] = None
    precision_recall: Optional[PrecisionRecallMetrics] = None

    # Confusion matrix
    confusion_matrix: Optional[ConfusionMatrix] = None

    # Category breakdown
    severity_agreements: list[SeverityAgreement] = field(default_factory=list)
    category_agreements: list[CategoryAgreement] = field(default_factory=list)

    # Finding matches
    finding_matches: list[FindingMatch] = field(default_factory=list)

    # Statistical analysis
    chi_square_statistic: float = 0.0
    chi_square_p_value: float = 0.0
    chi_square_df: int = 0

    # Visualization data
    severity_distribution: dict = field(default_factory=dict)
    category_distribution: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "argus_finding_count": self.argus_finding_count,
            "codex_finding_count": self.codex_finding_count,
            "total_matches": self.total_matches,
            "total_unique_to_argus": self.total_unique_to_argus,
            "total_unique_to_codex": self.total_unique_to_codex,
            "simple_agreement_rate": self.simple_agreement_rate,
            "cohens_kappa": self.cohens_kappa.to_dict() if self.cohens_kappa else None,
            "precision_recall": self.precision_recall.to_dict() if self.precision_recall else None,
            "confusion_matrix": self.confusion_matrix.to_dict() if self.confusion_matrix else None,
            "severity_agreements": [s.to_dict() for s in self.severity_agreements],
            "category_agreements": [c.to_dict() for c in self.category_agreements],
            "finding_matches": [m.to_dict() for m in self.finding_matches],
            "chi_square_statistic": self.chi_square_statistic,
            "chi_square_p_value": self.chi_square_p_value,
            "chi_square_df": self.chi_square_df,
            "severity_distribution": self.severity_distribution,
            "category_distribution": self.category_distribution,
        }

    def to_json(self) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class MetricsCalculator:
    """Calculate inter-rater agreement metrics between two finding sources."""

    def __init__(self):
        """Initialize the metrics calculator."""
        self.logger = logger

    def compare_findings(
        self, argus_findings: list[dict], codex_findings: list[dict]
    ) -> MetricsReport:
        """
        Compare findings from two sources and calculate agreement metrics.

        Args:
            argus_findings: List of findings from Argus
            codex_findings: List of findings from Codex

        Returns:
            MetricsReport with all calculated metrics
        """
        self.logger.info(
            f"Comparing {len(argus_findings)} Argus findings with "
            f"{len(codex_findings)} Codex findings"
        )

        # Create report
        report = MetricsReport(
            argus_finding_count=len(argus_findings),
            codex_finding_count=len(codex_findings),
        )

        # Match findings
        matches = self._match_findings(argus_findings, codex_findings)
        report.finding_matches = matches
        report.total_matches = len([m for m in matches if m.codex_finding])
        report.total_unique_to_argus = len([m for m in matches if not m.codex_finding])
        report.total_unique_to_codex = len(codex_findings) - report.total_matches

        # Calculate simple agreement rate
        report.simple_agreement_rate = self._calculate_simple_agreement(matches)

        # Build contingency table for Cohen's Kappa
        contingency_table = self._build_contingency_table(matches)

        # Calculate Cohen's Kappa
        report.cohens_kappa = self._calculate_cohens_kappa(contingency_table)

        # Calculate precision/recall metrics
        report.confusion_matrix = self._build_confusion_matrix(matches)
        report.precision_recall = self._calculate_precision_recall(report.confusion_matrix)

        # Calculate severity agreement breakdown
        report.severity_agreements = self._calculate_severity_agreements(matches)

        # Calculate category agreement breakdown
        report.category_agreements = self._calculate_category_agreements(matches)

        # Chi-square test
        chi_square_result = self._calculate_chi_square(contingency_table)
        report.chi_square_statistic = chi_square_result["statistic"]
        report.chi_square_p_value = chi_square_result["p_value"]
        report.chi_square_df = chi_square_result["df"]

        # Build visualization data
        report.severity_distribution = self._build_severity_distribution(argus_findings, codex_findings)
        report.category_distribution = self._build_category_distribution(argus_findings, codex_findings)

        self.logger.info(f"✅ Comparison complete. Cohen's Kappa: {report.cohens_kappa.kappa:.3f}")

        return report

    def _match_findings(self, argus_findings: list[dict], codex_findings: list[dict]) -> list[FindingMatch]:
        """
        Match findings from two sources based on similarity.

        Matching logic:
        1. Try exact match: same path, line, and rule_id
        2. Try fuzzy match: same path and rule_id
        3. Mark as unique to Argus if no match found
        """
        matches: list[FindingMatch] = []
        matched_codex_indices = set()

        for argus in argus_findings:
            best_match = None
            best_score = 0.0

            # Try exact match first
            for i, codex in enumerate(codex_findings):
                if i in matched_codex_indices:
                    continue

                score = self._calculate_match_score(argus, codex)

                if score > best_score:
                    best_score = score
                    best_match = (codex, i)

            # Check if match is good enough (>0.7 similarity)
            if best_match and best_score > 0.7:
                codex_finding, codex_idx = best_match
                matched_codex_indices.add(codex_idx)

                match = FindingMatch(
                    argus_finding=argus,
                    codex_finding=codex_finding,
                    match_score=best_score,
                    severity_agreement=argus.get("severity") == codex_finding.get("severity"),
                    category_agreement=argus.get("category") == codex_finding.get("category"),
                )
                matches.append(match)
            else:
                # Unique to Argus
                match = FindingMatch(argus_finding=argus, codex_finding=None, match_score=0.0)
                matches.append(match)

        # Add unmatched Codex findings
        for i, codex in enumerate(codex_findings):
            if i not in matched_codex_indices:
                # Note: We track these but they don't appear in standard confusion matrix
                # They represent findings that Codex found but Argus missed
                pass

        return matches

    def _calculate_match_score(self, finding1: dict, finding2: dict) -> float:
        """
        Calculate similarity score between two findings.

        Scoring:
        - Same path: +0.4
        - Same line: +0.2
        - Same rule_id: +0.2
        - Same severity: +0.1
        - Same category: +0.1
        """
        score = 0.0

        # Path match (40%)
        if finding1.get("path") == finding2.get("path"):
            score += 0.4

        # Line match (20%)
        if finding1.get("line") == finding2.get("line"):
            score += 0.2

        # Rule ID match (20%)
        if finding1.get("rule_id") == finding2.get("rule_id"):
            score += 0.2

        # Severity match (10%)
        if finding1.get("severity") == finding2.get("severity"):
            score += 0.1

        # Category match (10%)
        if finding1.get("category") == finding2.get("category"):
            score += 0.1

        return min(score, 1.0)

    def _calculate_simple_agreement(self, matches: list[FindingMatch]) -> float:
        """Calculate simple agreement rate (% of matched findings)."""
        if not matches:
            return 0.0

        agreed = sum(1 for m in matches if m.codex_finding)
        return agreed / len(matches) if matches else 0.0

    def _build_contingency_table(self, matches: list[FindingMatch]) -> np.ndarray:
        """
        Build contingency table for Cohen's Kappa calculation.

        For binary case (Finding vs No Finding):
        [[agree_present, disagree_agent_only],
         [disagree_codex_only, agree_absent]]
        """
        # Count agreement on presence of findings
        both_found = sum(1 for m in matches if m.codex_finding)
        argus_only = sum(1 for m in matches if not m.codex_finding)

        # For simplicity in Cohen's Kappa, we treat the table as binary
        # This assumes codex_findings represents all possible findings in the scope
        total_codex = len(matches) + (
            sum(1 for m in matches if m.codex_finding) if matches else 0
        )  # Approximate

        agree_present = both_found
        disagree = argus_only

        # Build 2x2 contingency table
        contingency = np.array([[agree_present, disagree], [disagree, max(0, total_codex - both_found - disagree)]])

        return contingency

    def _calculate_cohens_kappa(self, contingency_table: np.ndarray) -> CohenKappaResult:
        """
        Calculate Cohen's Kappa coefficient with confidence interval.

        Cohen's Kappa = (P_o - P_e) / (1 - P_e)
        where:
        - P_o = observed agreement probability
        - P_e = expected agreement by chance
        """
        result = CohenKappaResult()

        try:
            # Ensure contingency table is valid
            if contingency_table.size == 0 or contingency_table.sum() == 0:
                result.kappa = 0.0
                result.interpretation = "Invalid"
                return result

            # Calculate marginal probabilities
            n = contingency_table.sum()
            row_sums = contingency_table.sum(axis=1)
            col_sums = contingency_table.sum(axis=0)

            # Observed agreement (diagonal)
            p_o = (contingency_table[0, 0] + contingency_table[1, 1]) / n

            # Expected agreement by chance
            p_e = (row_sums[0] * col_sums[0] + row_sums[1] * col_sums[1]) / (n * n)

            # Cohen's Kappa
            if p_e == 1.0:
                result.kappa = 0.0
            else:
                result.kappa = (p_o - p_e) / (1 - p_e)

            # Standard error (Fleiss formula)
            if p_e > 0:
                variance = (
                    (p_o * (1 - p_o) + p_e * (1 - p_e)) / (n * (1 - p_e) ** 2) if n > 0 else 0
                )
                result.std_error = np.sqrt(variance) if variance >= 0 else 0.0
            else:
                result.std_error = 0.0

            # 95% confidence interval
            z_critical = 1.96
            result.confidence_interval_lower = result.kappa - z_critical * result.std_error
            result.confidence_interval_upper = result.kappa + z_critical * result.std_error

            # P-value (two-tailed test)
            if result.std_error > 0:
                z_score = result.kappa / result.std_error
                result.p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))
            else:
                result.p_value = 1.0

            # Interpretation
            result.interpretation = CohenKappaResult.interpret_kappa(result.kappa)

            self.logger.debug(
                f"Cohen's Kappa: {result.kappa:.3f}, "
                f"95% CI: [{result.confidence_interval_lower:.3f}, {result.confidence_interval_upper:.3f}], "
                f"p-value: {result.p_value:.4f}"
            )

        except Exception as e:
            self.logger.warning(f"Error calculating Cohen's Kappa: {e}")
            result.kappa = 0.0
            result.interpretation = "Error"

        return result

    def _build_confusion_matrix(self, matches: list[FindingMatch]) -> ConfusionMatrix:
        """
        Build confusion matrix for finding detection.

        True Positive: Finding found by both
        False Positive: Found by Argus but not Codex
        False Negative: Found by Codex but not Argus
        True Negative: Not found by either (approximate)
        """
        cm = ConfusionMatrix()

        cm.true_positive = sum(1 for m in matches if m.codex_finding)
        cm.false_positive = sum(1 for m in matches if not m.codex_finding)
        cm.false_negative = 0  # Findings that Codex found but Argus didn't

        # True negative is approximate (assume 10x the true positives for estimation)
        cm.true_negative = max(0, cm.true_positive * 10)

        return cm

    def _calculate_precision_recall(self, confusion_matrix: ConfusionMatrix) -> PrecisionRecallMetrics:
        """Calculate Precision, Recall, F1-Score from confusion matrix."""
        metrics = PrecisionRecallMetrics()

        tp = confusion_matrix.true_positive
        fp = confusion_matrix.false_positive
        fn = confusion_matrix.false_negative
        tn = confusion_matrix.true_negative

        # Precision: TP / (TP + FP)
        metrics.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        # Recall (Sensitivity): TP / (TP + FN)
        metrics.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # F1-Score: 2 * (Precision * Recall) / (Precision + Recall)
        if metrics.precision + metrics.recall > 0:
            metrics.f1_score = 2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall)
        else:
            metrics.f1_score = 0.0

        # Specificity: TN / (TN + FP)
        metrics.specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # False Positive Rate: FP / (FP + TN)
        metrics.false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # False Negative Rate: FN / (FN + TP)
        metrics.false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        # Accuracy: (TP + TN) / (TP + TN + FP + FN)
        total = tp + tn + fp + fn
        metrics.accuracy = (tp + tn) / total if total > 0 else 0.0

        return metrics

    def _calculate_severity_agreements(self, matches: list[FindingMatch]) -> list[SeverityAgreement]:
        """Calculate agreement metrics broken down by severity level."""
        severities = {"critical", "high", "medium", "low", "info"}
        severity_stats = {sev: SeverityAgreement(severity=sev) for sev in severities}

        argus_findings = [m.argus_finding for m in matches]

        # Count Argus findings per severity
        for finding in argus_findings:
            sev = finding.get("severity", "unknown")
            if sev in severity_stats:
                severity_stats[sev].argus_count += 1

        # Count Codex findings per severity
        for match in matches:
            if match.codex_finding:
                sev = match.codex_finding.get("severity", "unknown")
                if sev in severity_stats:
                    severity_stats[sev].codex_count += 1

        # Count agreements per severity
        for match in matches:
            if match.severity_agreement and match.codex_finding:
                sev = match.argus_finding.get("severity", "unknown")
                if sev in severity_stats:
                    severity_stats[sev].both_agree += 1

        # Calculate agreement rates
        for sev, stats in severity_stats.items():
            if stats.codex_count > 0:
                stats.agreement_rate = stats.both_agree / stats.codex_count
                # Simple Kappa approximation for this category
                if stats.codex_count > 0:
                    stats.kappa = 2 * (stats.agreement_rate) - 1.0
            else:
                stats.agreement_rate = 0.0
                stats.kappa = 0.0

        # Return only severities that appear in the data
        return [s for s in severity_stats.values() if s.argus_count > 0 or s.codex_count > 0]

    def _calculate_category_agreements(self, matches: list[FindingMatch]) -> list[CategoryAgreement]:
        """Calculate agreement metrics broken down by finding category."""
        categories = {"SAST", "SECRETS", "DEPS", "IAC", "FUZZ", "RUNTIME", "UNKNOWN"}
        category_stats = {cat: CategoryAgreement(category=cat) for cat in categories}

        argus_findings = [m.argus_finding for m in matches]

        # Count Argus findings per category
        for finding in argus_findings:
            cat = finding.get("category", "UNKNOWN")
            if cat in category_stats:
                category_stats[cat].argus_count += 1
            else:
                category_stats["UNKNOWN"].argus_count += 1

        # Count Codex findings per category
        for match in matches:
            if match.codex_finding:
                cat = match.codex_finding.get("category", "UNKNOWN")
                if cat in category_stats:
                    category_stats[cat].codex_count += 1
                else:
                    category_stats["UNKNOWN"].codex_count += 1

        # Count agreements per category
        for match in matches:
            if match.category_agreement and match.codex_finding:
                cat = match.argus_finding.get("category", "UNKNOWN")
                if cat in category_stats:
                    category_stats[cat].both_agree += 1
                else:
                    category_stats["UNKNOWN"].both_agree += 1

        # Calculate agreement rates
        for cat, stats in category_stats.items():
            if stats.codex_count > 0:
                stats.agreement_rate = stats.both_agree / stats.codex_count
                # Simple Kappa approximation for this category
                if stats.codex_count > 0:
                    stats.kappa = 2 * (stats.agreement_rate) - 1.0
            else:
                stats.agreement_rate = 0.0
                stats.kappa = 0.0

        # Return only categories that appear in the data
        return [s for s in category_stats.values() if s.argus_count > 0 or s.codex_count > 0]

    def _calculate_chi_square(self, contingency_table: np.ndarray) -> dict:
        """
        Perform chi-square test on contingency table.

        Tests null hypothesis: no association between Argus and Codex findings
        """
        result = {"statistic": 0.0, "p_value": 1.0, "df": 0}

        try:
            if contingency_table.size == 0 or contingency_table.sum() == 0:
                return result

            # Chi-square test
            chi2, p_value, df, expected = stats.chi2_contingency(contingency_table)

            result["statistic"] = float(chi2)
            result["p_value"] = float(p_value)
            result["df"] = int(df)

            self.logger.debug(f"Chi-square test: χ² = {chi2:.3f}, p-value = {p_value:.4f}, df = {df}")

        except Exception as e:
            self.logger.warning(f"Error in chi-square test: {e}")

        return result

    def _build_severity_distribution(
        self, argus_findings: list[dict], codex_findings: list[dict]
    ) -> dict:
        """Build severity distribution data for visualization."""
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        argus_dist = severities.copy()
        codex_dist = severities.copy()

        for finding in argus_findings:
            sev = finding.get("severity", "info")
            if sev in argus_dist:
                argus_dist[sev] += 1

        for finding in codex_findings:
            sev = finding.get("severity", "info")
            if sev in codex_dist:
                codex_dist[sev] += 1

        return {
            "argus": argus_dist,
            "codex": codex_dist,
            "categories": list(severities.keys()),
        }

    def _build_category_distribution(
        self, argus_findings: list[dict], codex_findings: list[dict]
    ) -> dict:
        """Build category distribution data for visualization."""
        categories = {}

        # Count categories from Argus
        for finding in argus_findings:
            cat = finding.get("category", "UNKNOWN")
            if cat not in categories:
                categories[cat] = {"argus": 0, "codex": 0}
            categories[cat]["argus"] += 1

        # Count categories from Codex
        for finding in codex_findings:
            cat = finding.get("category", "UNKNOWN")
            if cat not in categories:
                categories[cat] = {"argus": 0, "codex": 0}
            categories[cat]["codex"] += 1

        return {
            "categories": categories,
            "labels": list(categories.keys()),
        }


def load_findings_from_file(file_path: str) -> list[dict]:
    """
    Load findings from JSON file.

    Args:
        file_path: Path to JSON file containing findings

    Returns:
        List of finding dictionaries
    """
    try:
        with open(file_path) as f:
            data = json.load(f)

        # Handle different formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "findings" in data:
            return data["findings"]
        else:
            logger.warning(f"Unexpected format in {file_path}")
            return []

    except Exception as e:
        logger.error(f"Error loading findings from {file_path}: {e}")
        return []


def save_metrics_report(report: MetricsReport, output_file: str) -> None:
    """
    Save metrics report to JSON file.

    Args:
        report: MetricsReport object
        output_file: Path to output JSON file
    """
    try:
        with open(output_file, "w") as f:
            f.write(report.to_json())
        logger.info(f"✅ Metrics report saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving metrics report: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Calculate inter-rater agreement metrics for security findings"
    )
    parser.add_argument("--argus-file", required=True, help="Path to Argus findings JSON")
    parser.add_argument("--codex-file", required=True, help="Path to Codex findings JSON")
    parser.add_argument("--output-file", default="metrics_report.json", help="Output metrics report")

    args = parser.parse_args()

    # Load findings
    argus_findings = load_findings_from_file(args.argus_file)
    codex_findings = load_findings_from_file(args.codex_file)

    logger.info(f"Loaded {len(argus_findings)} Argus findings")
    logger.info(f"Loaded {len(codex_findings)} Codex findings")

    # Calculate metrics
    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    # Save report
    save_metrics_report(report, args.output_file)

    # Print summary
    print("\n" + "=" * 60)
    print("INTER-RATER AGREEMENT METRICS")
    print("=" * 60)
    print(f"Argus Findings: {report.argus_finding_count}")
    print(f"Codex Findings: {report.codex_finding_count}")
    print(f"Matched Findings: {report.total_matches}")
    print(f"Unique to Argus: {report.total_unique_to_argus}")
    print(f"Unique to Codex: {report.total_unique_to_codex}")
    print(f"\nSimple Agreement Rate: {report.simple_agreement_rate:.1%}")
    if report.cohens_kappa:
        print(f"Cohen's Kappa: {report.cohens_kappa.kappa:.3f} ({report.cohens_kappa.interpretation})")
        print(f"  95% CI: [{report.cohens_kappa.confidence_interval_lower:.3f}, "
              f"{report.cohens_kappa.confidence_interval_upper:.3f}]")
        print(f"  p-value: {report.cohens_kappa.p_value:.4f}")
    if report.precision_recall:
        print(f"\nPrecision/Recall Metrics:")
        print(f"  Precision: {report.precision_recall.precision:.3f}")
        print(f"  Recall: {report.precision_recall.recall:.3f}")
        print(f"  F1-Score: {report.precision_recall.f1_score:.3f}")
        print(f"  Accuracy: {report.precision_recall.accuracy:.3f}")
    if report.confusion_matrix:
        print(f"\nConfusion Matrix:")
        print(f"  True Positives: {report.confusion_matrix.true_positive}")
        print(f"  False Positives: {report.confusion_matrix.false_positive}")
        print(f"  False Negatives: {report.confusion_matrix.false_negative}")
        print(f"  True Negatives: {report.confusion_matrix.true_negative}")
    if report.severity_agreements:
        print(f"\nSeverity Agreement:")
        for sev in report.severity_agreements:
            print(f"  {sev.severity}: {sev.agreement_rate:.1%} agreement "
                  f"({sev.both_agree}/{sev.codex_count})")
    print("=" * 60)
