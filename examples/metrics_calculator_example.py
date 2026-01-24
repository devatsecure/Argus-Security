#!/usr/bin/env python3
"""
Example usage of the Metrics Calculator module

Demonstrates:
1. Comparing Argus and Codex findings
2. Calculating Cohen's Kappa agreement
3. Computing Precision/Recall metrics
4. Analyzing severity and category agreement
5. Generating JSON reports for visualization
"""

import json
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from metrics_calculator import MetricsCalculator, save_metrics_report


def example_1_basic_comparison():
    """Example 1: Basic comparison of Argus vs Codex findings."""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: BASIC COMPARISON")
    print("=" * 70)

    # Sample findings from Argus
    argus_findings = [
        {
            "path": "src/auth.py",
            "line": 42,
            "rule_id": "SEC-001",
            "rule_name": "SQL Injection",
            "severity": "critical",
            "category": "SAST",
            "cvss": 9.8,
        },
        {
            "path": "src/api.py",
            "line": 155,
            "rule_id": "SEC-002",
            "rule_name": "Hardcoded Password",
            "severity": "high",
            "category": "SECRETS",
            "cvss": 8.2,
        },
        {
            "path": "src/utils.py",
            "line": 8,
            "rule_id": "SEC-003",
            "rule_name": "Insecure Deserialization",
            "severity": "medium",
            "category": "SAST",
            "cvss": 6.5,
        },
        {
            "path": "requirements.txt",
            "line": 5,
            "rule_id": "CVE-2024-001",
            "rule_name": "Vulnerable Dependency",
            "severity": "high",
            "category": "DEPS",
            "cvss": 7.5,
        },
    ]

    # Sample findings from Codex (competitor tool)
    codex_findings = [
        {
            "path": "src/auth.py",
            "line": 42,
            "rule_id": "SQL-001",
            "rule_name": "SQL Injection Vulnerability",
            "severity": "critical",
            "category": "SAST",
            "cvss": 9.8,
        },
        {
            "path": "src/api.py",
            "line": 155,
            "rule_id": "SEC-PASS",
            "rule_name": "Hardcoded Secret",
            "severity": "critical",  # Different severity assessment
            "category": "SECRETS",
            "cvss": 8.2,
        },
        {
            "path": "src/utils.py",
            "line": 8,
            "rule_id": "SEC-SERIAL",
            "rule_name": "Unsafe Deserialization",
            "severity": "medium",
            "category": "SAST",
            "cvss": 6.5,
        },
        # Codex found an extra finding that Argus missed
        {
            "path": "src/logging.py",
            "line": 12,
            "rule_id": "SEC-LOG",
            "rule_name": "Sensitive Data in Logs",
            "severity": "medium",
            "category": "SAST",
            "cvss": 5.0,
        },
    ]

    # Run comparison
    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    # Display summary
    print(f"\nArgus Findings: {report.argus_finding_count}")
    print(f"Codex Findings: {report.codex_finding_count}")
    print(f"Matched: {report.total_matches}")
    print(f"Unique to Argus: {report.total_unique_to_argus}")
    print(f"Unique to Codex: {report.total_unique_to_codex}")

    print(f"\nSimple Agreement Rate: {report.simple_agreement_rate:.1%}")

    if report.cohens_kappa:
        print(f"\nCohen's Kappa: {report.cohens_kappa.kappa:.3f}")
        print(f"Interpretation: {report.cohens_kappa.interpretation}")
        print(
            f"95% Confidence Interval: [{report.cohens_kappa.confidence_interval_lower:.3f}, "
            f"{report.cohens_kappa.confidence_interval_upper:.3f}]"
        )
        print(f"P-value: {report.cohens_kappa.p_value:.4f}")

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

    return report


def example_2_severity_analysis():
    """Example 2: Analyze agreement broken down by severity level."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: SEVERITY-BASED AGREEMENT ANALYSIS")
    print("=" * 70)

    argus_findings = [
        {"severity": "critical", "category": "SAST", "path": "a.py", "rule_id": "A"},
        {"severity": "critical", "category": "SAST", "path": "b.py", "rule_id": "B"},
        {"severity": "high", "category": "SECRETS", "path": "c.py", "rule_id": "C"},
        {"severity": "high", "category": "SAST", "path": "d.py", "rule_id": "D"},
        {"severity": "medium", "category": "DEPS", "path": "e.py", "rule_id": "E"},
        {"severity": "low", "category": "SAST", "path": "f.py", "rule_id": "F"},
    ]

    codex_findings = [
        {"severity": "critical", "category": "SAST", "path": "a.py", "rule_id": "A"},
        {"severity": "critical", "category": "SAST", "path": "b.py", "rule_id": "B"},
        {"severity": "high", "category": "SECRETS", "path": "c.py", "rule_id": "C"},
        # Missing d.py
        # Missing e.py
        {"severity": "low", "category": "SAST", "path": "f.py", "rule_id": "F"},
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    print("\nSeverity-Based Agreement:")
    print("-" * 50)
    for sev_agreement in report.severity_agreements:
        print(
            f"\n{sev_agreement.severity.upper()}:"
            f"\n  Argus: {sev_agreement.argus_count}"
            f"\n  Codex: {sev_agreement.codex_count}"
            f"\n  Both Agree: {sev_agreement.both_agree}"
            f"\n  Agreement Rate: {sev_agreement.agreement_rate:.1%}"
            f"\n  Category Kappa: {sev_agreement.kappa:.3f}"
        )

    return report


def example_3_category_analysis():
    """Example 3: Analyze agreement broken down by finding category."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: CATEGORY-BASED AGREEMENT ANALYSIS")
    print("=" * 70)

    argus_findings = [
        {"category": "SAST", "severity": "critical", "path": "a.py", "rule_id": "A"},
        {"category": "SAST", "severity": "high", "path": "b.py", "rule_id": "B"},
        {"category": "SECRETS", "severity": "critical", "path": "c.py", "rule_id": "C"},
        {"category": "DEPS", "severity": "medium", "path": "d.py", "rule_id": "D"},
        {"category": "IAC", "severity": "high", "path": "e.py", "rule_id": "E"},
    ]

    codex_findings = [
        {"category": "SAST", "severity": "critical", "path": "a.py", "rule_id": "A"},
        {"category": "SAST", "severity": "high", "path": "b.py", "rule_id": "B"},
        {"category": "SECRETS", "severity": "critical", "path": "c.py", "rule_id": "C"},
        {"category": "DEPS", "severity": "medium", "path": "d.py", "rule_id": "D"},
        # Missing IAC finding
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    print("\nCategory-Based Agreement:")
    print("-" * 50)
    for cat_agreement in report.category_agreements:
        print(
            f"\n{cat_agreement.category}:"
            f"\n  Argus: {cat_agreement.argus_count}"
            f"\n  Codex: {cat_agreement.codex_count}"
            f"\n  Both Agree: {cat_agreement.both_agree}"
            f"\n  Agreement Rate: {cat_agreement.agreement_rate:.1%}"
            f"\n  Category Kappa: {cat_agreement.kappa:.3f}"
        )

    return report


def example_4_visualization_data():
    """Example 4: Extract data for visualization (charts/graphs)."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: VISUALIZATION-READY DATA")
    print("=" * 70)

    argus_findings = [
        {"severity": "critical", "category": "SAST", "path": "a.py", "rule_id": "A"},
        {"severity": "critical", "category": "SECRETS", "path": "b.py", "rule_id": "B"},
        {"severity": "high", "category": "SAST", "path": "c.py", "rule_id": "C"},
        {"severity": "high", "category": "DEPS", "path": "d.py", "rule_id": "D"},
        {"severity": "medium", "category": "SAST", "path": "e.py", "rule_id": "E"},
        {"severity": "low", "category": "IAC", "path": "f.py", "rule_id": "F"},
    ]

    codex_findings = [
        {"severity": "critical", "category": "SAST", "path": "a.py", "rule_id": "A"},
        {"severity": "high", "category": "SECRETS", "path": "b.py", "rule_id": "B"},  # Different severity
        {"severity": "high", "category": "SAST", "path": "c.py", "rule_id": "C"},
        {"severity": "medium", "category": "DEPS", "path": "d.py", "rule_id": "D"},  # Different severity
        {"severity": "medium", "category": "SAST", "path": "e.py", "rule_id": "E"},
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    # Severity distribution (for bar chart)
    print("\nSeverity Distribution (for bar chart):")
    print(json.dumps(report.severity_distribution, indent=2))

    # Category distribution (for pie/bar chart)
    print("\nCategory Distribution (for pie/bar chart):")
    print(json.dumps(report.category_distribution, indent=2))

    return report


def example_5_perfect_agreement():
    """Example 5: Perfect agreement scenario."""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: PERFECT AGREEMENT SCENARIO")
    print("=" * 70)

    shared_findings = [
        {"path": "a.py", "line": 1, "rule_id": "A", "severity": "critical", "category": "SAST"},
        {"path": "b.py", "line": 2, "rule_id": "B", "severity": "high", "category": "SECRETS"},
        {"path": "c.py", "line": 3, "rule_id": "C", "severity": "medium", "category": "DEPS"},
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(shared_findings, shared_findings)

    print(f"\nSimple Agreement Rate: {report.simple_agreement_rate:.1%}")
    print(f"Cohen's Kappa: {report.cohens_kappa.kappa:.3f} ({report.cohens_kappa.interpretation})")
    print(f"Precision: {report.precision_recall.precision:.3f}")
    print(f"Recall: {report.precision_recall.recall:.3f}")
    print(f"F1-Score: {report.precision_recall.f1_score:.3f}")

    return report


def example_6_statistical_significance():
    """Example 6: Statistical significance testing."""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: STATISTICAL SIGNIFICANCE TESTING")
    print("=" * 70)

    # Generate larger dataset for meaningful statistical test
    argus_findings = [
        {"path": f"file{i}.py", "line": i, "rule_id": f"R{i}", "severity": "high", "category": "SAST"}
        for i in range(1, 51)
    ]

    # Codex agrees on 80% of findings
    codex_findings = [
        {"path": f"file{i}.py", "line": i, "rule_id": f"R{i}", "severity": "high", "category": "SAST"}
        for i in range(1, 41)
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    print(f"\nSimple Agreement: {report.simple_agreement_rate:.1%}")
    print(f"\nCohen's Kappa Statistics:")
    print(f"  Kappa: {report.cohens_kappa.kappa:.4f}")
    print(f"  Standard Error: {report.cohens_kappa.std_error:.4f}")
    print(f"  P-value (two-tailed): {report.cohens_kappa.p_value:.4f}")

    if report.cohens_kappa.p_value < 0.05:
        print(f"  Result: STATISTICALLY SIGNIFICANT (p < 0.05)")
    else:
        print(f"  Result: NOT statistically significant (p >= 0.05)")

    print(f"\nChi-Square Test:")
    print(f"  χ² Statistic: {report.chi_square_statistic:.3f}")
    print(f"  P-value: {report.chi_square_p_value:.4f}")
    print(f"  Degrees of Freedom: {report.chi_square_df}")

    return report


def example_7_json_output():
    """Example 7: Generate JSON output for integration with other tools."""
    print("\n" + "=" * 70)
    print("EXAMPLE 7: JSON OUTPUT FOR INTEGRATION")
    print("=" * 70)

    argus_findings = [
        {"path": "a.py", "rule_id": "A", "severity": "high", "category": "SAST"},
        {"path": "b.py", "rule_id": "B", "severity": "critical", "category": "SECRETS"},
    ]

    codex_findings = [
        {"path": "a.py", "rule_id": "A", "severity": "high", "category": "SAST"},
    ]

    calculator = MetricsCalculator()
    report = calculator.compare_findings(argus_findings, codex_findings)

    # Convert to JSON
    json_report = report.to_json()

    print("\nJSON Report (first 500 chars):")
    print(json_report[:500])

    print("\n\nKey metrics in JSON:")
    report_dict = report.to_dict()
    print(
        json.dumps(
            {
                "simple_agreement_rate": report_dict["simple_agreement_rate"],
                "cohens_kappa": report_dict["cohens_kappa"],
                "precision_recall": report_dict["precision_recall"],
                "confusion_matrix": report_dict["confusion_matrix"],
            },
            indent=2,
        )
    )

    return report


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "METRICS CALCULATOR USAGE EXAMPLES" + " " * 21 + "║")
    print("╚" + "=" * 68 + "╝")

    try:
        # Run all examples
        report1 = example_1_basic_comparison()
        report2 = example_2_severity_analysis()
        report3 = example_3_category_analysis()
        report4 = example_4_visualization_data()
        report5 = example_5_perfect_agreement()
        report6 = example_6_statistical_significance()
        report7 = example_7_json_output()

        # Save final report to file
        print("\n" + "=" * 70)
        print("SAVING REPORTS TO FILES")
        print("=" * 70)

        save_metrics_report(report1, "/tmp/metrics_report_example1.json")
        save_metrics_report(report7, "/tmp/metrics_report_example7.json")

        print("\n✅ All examples completed successfully!")
        print("\nNext steps:")
        print("1. Use the JSON reports in visualization tools (Grafana, Tableau, etc.)")
        print("2. Track Cohen's Kappa over time to measure agreement improvement")
        print("3. Use precision/recall to optimize scanner configurations")
        print("4. Monitor category/severity breakdowns for pattern analysis")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
