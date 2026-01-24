#!/usr/bin/env python3
"""
Integration utilities for Metrics Calculator with Argus workflow

Provides convenience functions for:
- Loading findings from Argus output
- Comparing with external tools (Codex, Semgrep, Trivy, etc.)
- Generating comparison reports
- Publishing metrics to monitoring systems
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from metrics_calculator import MetricsCalculator, MetricsReport, save_metrics_report

logger = logging.getLogger(__name__)


class MetricsIntegration:
    """Convenience wrapper for metrics calculation in Argus workflow."""

    def __init__(self, cache_dir: str = ".argus"):
        """
        Initialize metrics integration.

        Args:
            cache_dir: Directory for caching metrics reports
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.calculator = MetricsCalculator()

    def compare_with_external_tool(
        self, argus_results_file: str, external_tool_results_file: str, tool_name: str = "external"
    ) -> MetricsReport:
        """
        Compare Argus findings with external security tool results.

        Args:
            argus_results_file: Path to Argus JSON findings
            external_tool_results_file: Path to external tool JSON findings
            tool_name: Name of external tool (codex, semgrep, trivy, etc.)

        Returns:
            MetricsReport with comparison results
        """
        logger.info(f"Comparing Argus with {tool_name}")

        # Load findings
        argus_findings = self._load_findings(argus_results_file)
        external_findings = self._load_findings(external_tool_results_file)

        logger.info(f"Loaded {len(argus_findings)} Argus findings")
        logger.info(f"Loaded {len(external_findings)} {tool_name} findings")

        # Run comparison
        report = self.calculator.compare_findings(argus_findings, external_findings)

        # Cache report
        report_file = self.cache_dir / f"metrics_{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_metrics_report(report, str(report_file))

        logger.info(f"Saved metrics report to {report_file}")
        logger.info(f"Cohen's Kappa: {report.cohens_kappa.kappa:.3f} ({report.cohens_kappa.interpretation})")

        return report

    def _load_findings(self, file_path: str) -> list[dict]:
        """
        Load findings from JSON file with format detection.

        Supports multiple formats:
        - Direct list of findings: [...]
        - Findings in 'findings' key: {"findings": [...]}
        - Argus output format with metadata

        Args:
            file_path: Path to JSON file

        Returns:
            List of finding dictionaries
        """
        try:
            with open(file_path) as f:
                data = json.load(f)

            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                if "findings" in data:
                    return data["findings"]
                elif "results" in data:
                    return data["results"]
                elif "vulnerabilities" in data:
                    return data["vulnerabilities"]
            return []

        except Exception as e:
            logger.error(f"Error loading findings from {file_path}: {e}")
            return []

    def publish_metrics_to_grafana(self, report: MetricsReport, grafana_url: str, api_token: str) -> bool:
        """
        Publish metrics to Grafana for visualization.

        Args:
            report: MetricsReport object
            grafana_url: Base URL of Grafana instance
            api_token: Grafana API token

        Returns:
            True if successful, False otherwise
        """
        try:
            import requests

            # Prepare metrics for Grafana
            metrics = {
                "timestamp": datetime.now().timestamp() * 1000,  # Milliseconds
                "metrics": {
                    "cohens_kappa": report.cohens_kappa.kappa,
                    "simple_agreement_rate": report.simple_agreement_rate,
                    "precision": report.precision_recall.precision,
                    "recall": report.precision_recall.recall,
                    "f1_score": report.precision_recall.f1_score,
                    "true_positives": report.confusion_matrix.true_positive,
                    "false_positives": report.confusion_matrix.false_positive,
                    "false_negatives": report.confusion_matrix.false_negative,
                },
            }

            # Send to Grafana
            response = requests.post(
                f"{grafana_url}/api/datasources/proxy/1/write",
                json=metrics,
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=10,
            )

            if response.status_code == 200:
                logger.info("✅ Metrics published to Grafana")
                return True
            else:
                logger.error(f"Failed to publish to Grafana: {response.status_code}")
                return False

        except ImportError:
            logger.warning("requests library not available; skipping Grafana publish")
            return False
        except Exception as e:
            logger.error(f"Error publishing to Grafana: {e}")
            return False

    def generate_comparison_report_markdown(self, report: MetricsReport, tool_name: str = "Codex") -> str:
        """
        Generate markdown report for GitHub comments/PRs.

        Args:
            report: MetricsReport object
            tool_name: Name of tool being compared with

        Returns:
            Markdown formatted report string
        """
        md = f"""## Metrics Comparison: Argus vs {tool_name}

### Summary
- **Argus Findings**: {report.argus_finding_count}
- **{tool_name} Findings**: {report.codex_finding_count}
- **Matched Findings**: {report.total_matches}
- **Agreement Rate**: {report.simple_agreement_rate:.1%}

### Agreement Analysis

#### Cohen's Kappa
| Metric | Value |
|--------|-------|
| **Kappa** | {report.cohens_kappa.kappa:.3f} |
| **Interpretation** | {report.cohens_kappa.interpretation} |
| **95% CI** | [{report.cohens_kappa.confidence_interval_lower:.3f}, {report.cohens_kappa.confidence_interval_upper:.3f}] |
| **P-Value** | {report.cohens_kappa.p_value:.4f} |

#### Precision & Recall
| Metric | Value |
|--------|-------|
| **Precision** | {report.precision_recall.precision:.1%} |
| **Recall** | {report.precision_recall.recall:.1%} |
| **F1-Score** | {report.precision_recall.f1_score:.3f} |
| **Accuracy** | {report.precision_recall.accuracy:.1%} |

#### Confusion Matrix
| | Argus Found | Argus Missed |
|---|---|---|
| **{tool_name} Found** | {report.confusion_matrix.true_positive} (TP) | {report.confusion_matrix.false_negative} (FN) |
| **{tool_name} Missed** | {report.confusion_matrix.false_positive} (FP) | {report.confusion_matrix.true_negative} (TN) |

### Severity Breakdown
"""

        for sev in report.severity_agreements:
            md += f"\n- **{sev.severity.upper()}**: {sev.agreement_rate:.1%} agreement ({sev.both_agree}/{sev.codex_count})"

        md += "\n\n### Category Breakdown\n"

        for cat in report.category_agreements:
            md += f"\n- **{cat.category}**: {cat.agreement_rate:.1%} agreement ({cat.both_agree}/{cat.codex_count})"

        md += f"""

### Statistical Significance
- **Chi-Square**: χ² = {report.chi_square_statistic:.3f}, p = {report.chi_square_p_value:.4f}
"""

        if report.cohens_kappa.p_value < 0.05:
            md += "- **Result**: Agreement is **STATISTICALLY SIGNIFICANT** (p < 0.05)\n"
        else:
            md += "- **Result**: Agreement is **NOT statistically significant** (p >= 0.05)\n"

        md += f"\n_Report generated: {report.timestamp}_\n"

        return md

    def generate_json_summary(self, report: MetricsReport, output_file: str) -> None:
        """
        Save metrics summary to JSON file.

        Args:
            report: MetricsReport object
            output_file: Path to output JSON file
        """
        summary = {
            "timestamp": report.timestamp,
            "metrics": {
                "argus_findings": report.argus_finding_count,
                "external_findings": report.codex_finding_count,
                "matched_findings": report.total_matches,
                "unique_to_argus": report.total_unique_to_argus,
                "unique_to_external": report.total_unique_to_codex,
            },
            "agreement": {
                "simple_agreement_rate": round(report.simple_agreement_rate, 4),
                "cohens_kappa": {
                    "value": round(report.cohens_kappa.kappa, 4),
                    "interpretation": report.cohens_kappa.interpretation,
                    "confidence_interval": [
                        round(report.cohens_kappa.confidence_interval_lower, 4),
                        round(report.cohens_kappa.confidence_interval_upper, 4),
                    ],
                    "p_value": round(report.cohens_kappa.p_value, 4),
                },
            },
            "detection_metrics": {
                "precision": round(report.precision_recall.precision, 4),
                "recall": round(report.precision_recall.recall, 4),
                "f1_score": round(report.precision_recall.f1_score, 4),
                "accuracy": round(report.precision_recall.accuracy, 4),
                "specificity": round(report.precision_recall.specificity, 4),
            },
            "severity_breakdown": [
                {
                    "severity": sev.severity,
                    "argus_count": sev.argus_count,
                    "external_count": sev.codex_count,
                    "agreement": round(sev.agreement_rate, 4),
                }
                for sev in report.severity_agreements
            ],
            "category_breakdown": [
                {
                    "category": cat.category,
                    "argus_count": cat.argus_count,
                    "external_count": cat.codex_count,
                    "agreement": round(cat.agreement_rate, 4),
                }
                for cat in report.category_agreements
            ],
        }

        with open(output_file, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Saved metrics summary to {output_file}")

    def compare_over_time(self, results_dir: str, pattern: str = "metrics_*.json") -> list[MetricsReport]:
        """
        Load and analyze multiple metric reports to track trends.

        Args:
            results_dir: Directory containing metric JSON reports
            pattern: Glob pattern for metric files

        Returns:
            List of MetricsReport objects sorted by timestamp
        """
        reports = []

        for report_file in Path(results_dir).glob(pattern):
            try:
                with open(report_file) as f:
                    data = json.load(f)
                    report = MetricsReport(**data)
                    reports.append(report)
            except Exception as e:
                logger.warning(f"Failed to load {report_file}: {e}")

        # Sort by timestamp
        reports.sort(key=lambda r: r.timestamp)

        logger.info(f"Loaded {len(reports)} metric reports")

        return reports

    def calculate_trend(self, reports: list[MetricsReport]) -> dict[str, Any]:
        """
        Analyze trends in metrics over multiple reports.

        Args:
            reports: List of MetricsReport objects

        Returns:
            Dictionary with trend analysis
        """
        if not reports:
            return {}

        kappas = [r.cohens_kappa.kappa for r in reports]
        agreements = [r.simple_agreement_rate for r in reports]
        precisions = [r.precision_recall.precision for r in reports]
        recalls = [r.precision_recall.recall for r in reports]

        def trend_direction(values):
            if len(values) < 2:
                return "stable"
            if values[-1] > values[-2]:
                return "improving"
            elif values[-1] < values[-2]:
                return "declining"
            return "stable"

        return {
            "total_comparisons": len(reports),
            "date_range": {
                "start": reports[0].timestamp,
                "end": reports[-1].timestamp,
            },
            "kappa": {
                "initial": round(kappas[0], 3),
                "current": round(kappas[-1], 3),
                "average": round(sum(kappas) / len(kappas), 3),
                "trend": trend_direction(kappas),
            },
            "agreement_rate": {
                "initial": round(agreements[0], 3),
                "current": round(agreements[-1], 3),
                "average": round(sum(agreements) / len(agreements), 3),
                "trend": trend_direction(agreements),
            },
            "precision": {
                "initial": round(precisions[0], 3),
                "current": round(precisions[-1], 3),
                "average": round(sum(precisions) / len(precisions), 3),
                "trend": trend_direction(precisions),
            },
            "recall": {
                "initial": round(recalls[0], 3),
                "current": round(recalls[-1], 3),
                "average": round(sum(recalls) / len(recalls), 3),
                "trend": trend_direction(recalls),
            },
        }


def example_integration():
    """Example of using metrics integration in a workflow."""
    import sys

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

    # Create integration instance
    integration = MetricsIntegration()

    # Example: Compare findings (requires actual files)
    # report = integration.compare_with_external_tool(
    #     "argus_findings.json",
    #     "codex_findings.json",
    #     tool_name="codex"
    # )

    # Generate markdown report
    # markdown = integration.generate_comparison_report_markdown(report)
    # print(markdown)

    # Generate JSON summary
    # integration.generate_json_summary(report, "metrics_summary.json")

    # Load historical metrics
    # reports = integration.compare_over_time(".argus", pattern="metrics_*.json")
    # trend = integration.calculate_trend(reports)
    # print(json.dumps(trend, indent=2))

    logger.info("Metrics integration available for use")


if __name__ == "__main__":
    example_integration()
