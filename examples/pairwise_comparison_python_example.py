#!/usr/bin/env python3
"""
Example: Using Pairwise Comparison Engine Programmatically

This example demonstrates how to use the pairwise comparison components
in your own Python code.
"""

import json
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from pairwise_comparison import (
    PairwiseComparator,
    FindingMatcher,
    PairwiseJudge,
    ComparisonReportGenerator,
)


def example_1_basic_comparison():
    """Example 1: Run basic pairwise comparison"""
    print("\n" + "="*80)
    print("Example 1: Basic Pairwise Comparison")
    print("="*80 + "\n")

    # Sample findings (in real usage, these would come from files)
    argus_findings = [
        {
            "id": "finding_001",
            "path": "src/api/users.py",
            "rule_id": "SQL-INJECTION-001",
            "rule_name": "SQL Injection Risk",
            "severity": "high",
            "message": "User input concatenated directly into SQL query",
            "evidence": {"code": "query = f'SELECT * FROM users WHERE id={user_id}'"},
            "confidence": 0.95,
        },
        {
            "id": "finding_002",
            "path": "src/auth/login.py",
            "rule_id": "HARDCODED-SECRET",
            "rule_name": "Hardcoded API Key",
            "severity": "critical",
            "message": "API key hardcoded in source code",
            "evidence": {"code": "API_KEY = 'sk-1234567890abcdef'"},
            "confidence": 1.0,
        },
    ]

    codex_findings = [
        {
            "id": "codex_001",
            "path": "src/api/users.py",
            "rule_id": "SQL-INJECTION",
            "rule_name": "Potential SQL Injection",
            "severity": "high",
            "message": "String concatenation in SQL query could lead to injection",
            "evidence": {"code": "user_id is concatenated without parameterization"},
            "confidence": 0.92,
        },
        {
            "id": "codex_002",
            "path": "src/config.py",
            "rule_id": "EXPOSED-KEY",
            "rule_name": "Exposed Secret",
            "severity": "critical",
            "message": "Plaintext secret in configuration",
            "evidence": {"code": "SECRET = 'my-secret-key'"},
            "confidence": 0.98,
        },
    ]

    # Create comparator
    comparator = PairwiseComparator(
        argus_findings=argus_findings,
        codex_findings=codex_findings,
        judge_model="anthropic",
    )

    # Run comparison (limit to 2 for demo)
    aggregation = comparator.run_comparison(max_comparisons=2)

    # Print results
    print(f"\n📊 Results:")
    print(f"  Winner: {aggregation.overall_winner.upper()}")
    print(f"  Argus: {aggregation.avg_argus_score:.1f}/5")
    print(f"  Codex: {aggregation.avg_codex_score:.1f}/5")
    print(f"  Matched: {aggregation.matched_findings}")
    print(f"  Argus Only: {aggregation.argus_only}")
    print(f"  Codex Only: {aggregation.codex_only}")


def example_2_matching_only():
    """Example 2: Just match findings without judge comparison"""
    print("\n" + "="*80)
    print("Example 2: Finding Matching Only")
    print("="*80 + "\n")

    argus_findings = [
        {
            "id": "ao_1",
            "path": "src/api/users.py",
            "rule_id": "SQL-001",
            "severity": "high",
            "message": "SQL injection risk",
        },
        {
            "id": "ao_2",
            "path": "src/auth/token.py",
            "rule_id": "WEAK-CRYPTO",
            "severity": "medium",
            "message": "Weak cryptography",
        },
    ]

    codex_findings = [
        {
            "id": "cx_1",
            "path": "src/api/users.py",
            "rule_id": "SQL",
            "severity": "high",
            "message": "SQL injection",
        },
        {
            "id": "cx_2",
            "path": "src/logging/logger.py",
            "rule_id": "SENSITIVE-LOG",
            "severity": "medium",
            "message": "Sensitive data logged",
        },
    ]

    matcher = FindingMatcher(match_threshold=0.6)
    matched, ao_only, cx_only = matcher.match_findings(argus_findings, codex_findings)

    print(f"✅ Matched pairs: {len(matched)}")
    for ao, cx in matched:
        print(f"  - {ao['path']} ({ao['rule_id']} <-> {cx['rule_id']})")

    print(f"\n🆎 Argus only: {len(ao_only)}")
    for finding in ao_only:
        print(f"  - {finding['path']} ({finding['rule_id']})")

    print(f"\n🆎 Codex only: {len(cx_only)}")
    for finding in cx_only:
        print(f"  - {finding['path']} ({finding['rule_id']})")


def example_3_judge_evaluation():
    """Example 3: Use judge to evaluate specific findings"""
    print("\n" + "="*80)
    print("Example 3: Judge Evaluation of Specific Findings")
    print("="*80 + "\n")

    # Create judge
    judge = PairwiseJudge(judge_model="anthropic")

    # Sample matched findings
    argus_finding = {
        "id": "ao_1",
        "path": "src/api/endpoint.py",
        "rule_id": "INJECTION-001",
        "rule_name": "SQL Injection",
        "severity": "high",
        "message": "User input concatenated into SQL query without parameterization",
        "evidence": {"code": "query = f'SELECT * FROM users WHERE name={input}'"},
        "references": ["CWE-89", "OWASP-A03"],
        "confidence": 0.95,
    }

    codex_finding = {
        "id": "cx_1",
        "path": "src/api/endpoint.py",
        "rule_id": "SQL-INJECTION",
        "rule_name": "Potential SQL Injection",
        "severity": "high",
        "message": "String concatenation in SQL could allow injection attacks",
        "evidence": {"code": "Concatenating user input without parameterization"},
        "references": ["CWE-89"],
        "confidence": 0.92,
    }

    print("Evaluating matched findings...")
    print(f"  File: {argus_finding['path']}")
    print(f"  Argus: {argus_finding['rule_name']}")
    print(f"  Codex: {codex_finding['rule_name']}")
    print("\nWaiting for judge evaluation...\n")

    try:
        comparison = judge.compare_matched_findings(argus_finding, codex_finding)

        print(f"✅ Evaluation complete:")
        print(f"  Winner: {comparison.winner.upper()}")
        print(f"  Argus Score: {comparison.argus_score}/5")
        print(f"  Codex Score: {comparison.codex_score}/5")
        print(f"  Confidence: {comparison.confidence*100:.0f}%")
        print(f"\n📝 Reasoning:\n{comparison.judge_reasoning}")

        if comparison.key_differences:
            print(f"\n📊 Key Differences:")
            for diff in comparison.key_differences:
                print(f"  - {diff}")

    except Exception as e:
        print(f"⚠️ Judge evaluation failed (expected without API key): {e}")


def example_4_load_and_compare_files():
    """Example 4: Load findings from files and compare"""
    print("\n" + "="*80)
    print("Example 4: Load Findings from Files")
    print("="*80 + "\n")

    # Example code to load findings from JSON files
    def load_findings(file_path):
        """Load findings from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Handle different formats
            if isinstance(data, dict):
                if "findings" in data:
                    return data["findings"]
                elif "results" in data and isinstance(data["results"], dict):
                    if "findings" in data["results"]:
                        return data["results"]["findings"]

            if isinstance(data, list):
                return data

            print(f"⚠️ Unexpected findings format in {file_path}")
            return []
        except FileNotFoundError:
            print(f"⚠️ File not found: {file_path}")
            return []

    # Show how to use it
    print("Loading findings from files...")
    print("\nExample usage:")
    print("  argus_findings = load_findings('argus_results.json')")
    print("  codex_findings = load_findings('codex_results.json')")
    print("\n  comparator = PairwiseComparator(")
    print("      argus_findings=argus_findings,")
    print("      codex_findings=codex_findings")
    print("  )")
    print("  aggregation = comparator.run_comparison()")


def example_5_custom_matching():
    """Example 5: Use custom match threshold"""
    print("\n" + "="*80)
    print("Example 5: Custom Match Threshold")
    print("="*80 + "\n")

    findings1 = [
        {
            "id": "1",
            "path": "src/main.py",
            "rule_id": "RULE-A",
            "severity": "high",
            "message": "Issue A",
        }
    ]

    findings2 = [
        {
            "id": "2",
            "path": "src/main.py",
            "rule_id": "RULE-B",
            "severity": "high",
            "message": "Issue B",
        }
    ]

    # Test different thresholds
    thresholds = [0.5, 0.7, 0.9]

    for threshold in thresholds:
        matcher = FindingMatcher(match_threshold=threshold)
        matched, f1_only, f2_only = matcher.match_findings(findings1, findings2)

        print(f"Threshold {threshold}:")
        print(f"  Matched: {len(matched)}, F1 Only: {len(f1_only)}, F2 Only: {len(f2_only)}")


def example_6_cost_limiting():
    """Example 6: Limit cost by capping comparisons"""
    print("\n" + "="*80)
    print("Example 6: Cost-Limited Comparison")
    print("="*80 + "\n")

    print("When comparing many findings, limit costs:")
    print("")
    print("  # Only compare first 10 findings")
    print("  aggregation = comparator.run_comparison(max_comparisons=10)")
    print("")
    print("Cost estimate:")
    print("  - 1 comparison: ~$0.01")
    print("  - 10 comparisons: ~$0.10")
    print("  - 50 comparisons: ~$0.50")
    print("  - 100 comparisons: ~$1.00")


def main():
    """Run examples"""
    print("\n" + "="*80)
    print("Pairwise Comparison - Python Examples")
    print("="*80)

    print("\nThis script demonstrates how to use the pairwise comparison engine")
    print("in your own Python code.\n")

    print("Available examples:")
    print("  1. Basic pairwise comparison")
    print("  2. Finding matching only")
    print("  3. Judge evaluation")
    print("  4. Load findings from files")
    print("  5. Custom match threshold")
    print("  6. Cost-limited comparison")
    print("")

    # Run all examples (comment out those requiring API keys)
    print("\nRunning examples...\n")

    # These work without API keys
    example_2_matching_only()
    example_4_load_and_compare_files()
    example_5_custom_matching()
    example_6_cost_limiting()

    # These require API keys - commented out by default
    # example_1_basic_comparison()
    # example_3_judge_evaluation()

    print("\n" + "="*80)
    print("Examples Complete!")
    print("="*80)
    print("\nTo run examples that require API keys, uncomment them in the code")
    print("and set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variables.")
    print("")


if __name__ == "__main__":
    main()
