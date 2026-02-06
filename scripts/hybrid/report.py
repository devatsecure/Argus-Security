"""
Hybrid Security Analysis Report Generation.

This module contains report generation functions for the hybrid security analysis
pipeline. Extracted from hybrid_analyzer.py for better modularity.

Functions:
    get_enabled_tools: Get list of enabled scanning tools
    save_results: Save scan results in multiple formats (JSON, SARIF, Markdown)
    convert_to_sarif: Convert results to SARIF format for GitHub Code Scanning
    severity_to_sarif_level: Convert severity to SARIF level
    generate_markdown_report: Generate human-readable Markdown report
    print_summary: Print scan summary to console
"""

import json
import logging
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from hybrid.models import HybridFinding, HybridScanResult

logger = logging.getLogger(__name__)


def get_enabled_tools(flags: dict[str, Any]) -> list[str]:
    """Get list of enabled scanning tools.

    Args:
        flags: Dictionary containing enable_* boolean flags and ai_client

    Returns:
        List of enabled tool names
    """
    tools = []
    if flags.get("enable_semgrep"):
        tools.append("Semgrep")
    if flags.get("enable_trivy"):
        tools.append("Trivy")
    if flags.get("enable_checkov"):
        tools.append("Checkov")
    if flags.get("enable_api_security"):
        tools.append("API-Security")
    if flags.get("enable_dast"):
        tools.append("DAST")
    if flags.get("enable_supply_chain"):
        tools.append("Supply-Chain")
    if flags.get("enable_fuzzing"):
        tools.append("Fuzzing")
    if flags.get("enable_threat_intel"):
        tools.append("Threat-Intel")
    if flags.get("enable_remediation"):
        tools.append("Remediation")
    if flags.get("enable_runtime_security"):
        tools.append("Runtime-Security")
    if flags.get("enable_regression_testing"):
        tools.append("Regression-Testing")
    if flags.get("enable_ai_enrichment") and flags.get("ai_client"):
        ai_client = flags.get("ai_client")
        provider = getattr(ai_client, "provider", "AI")
        tools.append(f"AI-Enrichment ({provider})")
    if flags.get("enable_argus"):
        tools.append("Argus")
    if flags.get("enable_sandbox"):
        tools.append("Sandbox-Validator")
    return tools


def save_results(result: HybridScanResult, output_dir: str, target_path: str) -> None:
    """Save results in multiple formats.

    Args:
        result: The hybrid scan result to save
        output_dir: Directory to save results to
        target_path: Path to the scanned target (for SARIF conversion)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Save JSON
    json_file = output_path / f"hybrid-scan-{timestamp}.json"
    with open(json_file, "w") as f:
        json.dump(asdict(result), f, indent=2, default=str)
    logger.info(f"💾 JSON results: {json_file}")

    # QUALITY VALIDATION: Prevent pi-mono disaster incidents
    # Validate report quality before any external submission
    logger.info("🔍 Running report quality validation...")
    try:
        from report_quality_validator import ReportQualityValidator

        validator = ReportQualityValidator()
        validation_report = validator.validate_report_file(json_file)

        # Save validation report
        validation_output = output_path / f"quality-report-{timestamp}.json"
        validator.save_validation_report(validation_report, validation_output)

        # Print validation summary
        if not validation_report.overall_passed:
            logger.warning(f"⚠️  QUALITY CHECK FAILED: {validation_report.failed_findings}/{validation_report.total_findings} findings below quality threshold")
            logger.warning(f"⚠️  See {validation_output} for details")
            logger.warning("⚠️  DO NOT submit this report to external repositories without fixing quality issues!")
        else:
            logger.info(f"✅ Quality validation PASSED: All {validation_report.passed_findings} findings meet quality standards")
    except ImportError:
        logger.warning("⚠️  report_quality_validator not available - skipping quality check")
    except Exception as e:
        logger.warning(f"⚠️  Quality validation failed: {e}")

    # Save SARIF
    sarif_file = output_path / f"hybrid-scan-{timestamp}.sarif"
    sarif_data = convert_to_sarif(result, target_path)
    with open(sarif_file, "w") as f:
        json.dump(sarif_data, f, indent=2)
    logger.info(f"💾 SARIF results: {sarif_file}")

    # Save Markdown report
    md_file = output_path / f"hybrid-scan-{timestamp}.md"
    markdown_report = generate_markdown_report(result)
    with open(md_file, "w") as f:
        f.write(markdown_report)
    logger.info(f"💾 Markdown report: {md_file}")


def convert_to_sarif(result: HybridScanResult, target_path: str) -> dict:
    """Convert results to SARIF format for GitHub Code Scanning.

    Args:
        result: The hybrid scan result to convert
        target_path: Path to the scanned target

    Returns:
        Dictionary containing SARIF-formatted results
    """
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Hybrid Security Analyzer",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/securedotcom/argus",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.finding_id,
            "level": severity_to_sarif_level(finding.severity),
            "message": {"text": finding.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}}}],
        }

        if finding.line_number:
            sarif_result["locations"][0]["physicalLocation"]["region"] = {"startLine": finding.line_number}

        # Add properties
        properties = {}
        if finding.cwe_id:
            properties["cwe"] = finding.cwe_id
        if finding.cve_id:
            properties["cve"] = finding.cve_id
        if finding.exploitability:
            properties["exploitability"] = finding.exploitability
        if finding.source_tool:
            properties["source"] = finding.source_tool

        if properties:
            sarif_result["properties"] = properties

        sarif["runs"][0]["results"].append(sarif_result)

    return sarif


def severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level.

    Args:
        severity: Severity string (critical, high, medium, low)

    Returns:
        SARIF level string (error, warning, note)
    """
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return mapping.get(severity.lower(), "warning")


def generate_markdown_report(result: HybridScanResult) -> str:
    """Generate human-readable Markdown report.

    Args:
        result: The hybrid scan result to format

    Returns:
        Markdown-formatted report string
    """
    report = []

    report.append("# 🔒 Hybrid Security Analysis Report\n")
    report.append(f"**Generated**: {result.scan_timestamp}\n")
    report.append(f"**Target**: {result.target_path}\n")
    report.append(f"**Duration**: {result.scan_duration_seconds:.1f}s\n")
    report.append(f"**Cost**: ${result.cost_usd:.2f}\n")
    report.append(f"**Tools**: {', '.join(result.tools_used)}\n")
    report.append("\n---\n\n")

    report.append("## 📊 Summary\n\n")
    report.append(f"**Total Findings**: {result.total_findings}\n\n")

    report.append("### By Severity\n\n")
    for severity, count in result.findings_by_severity.items():
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        report.append(f"- {emoji.get(severity, '⚪')} **{severity.title()}**: {count}\n")

    report.append("\n### By Tool\n\n")
    for tool, count in result.findings_by_source.items():
        report.append(f"- **{tool}**: {count} findings\n")

    report.append("\n---\n\n")

    # Group findings by severity
    for severity in ["critical", "high", "medium", "low"]:
        severity_findings = [f for f in result.findings if f.severity.lower() == severity]

        if not severity_findings:
            continue

        report.append(f"## {severity.title()} Issues ({len(severity_findings)})\n\n")

        for i, finding in enumerate(severity_findings, 1):
            report.append(f"### {i}. {finding.title}\n\n")
            report.append(f"**Source**: {finding.source_tool}\n\n")
            report.append(f"**File**: `{finding.file_path}`")
            if finding.line_number:
                report.append(f" (line {finding.line_number})")
            report.append("\n\n")

            if finding.cve_id:
                report.append(f"**CVE**: {finding.cve_id}\n\n")
            if finding.cwe_id:
                report.append(f"**CWE**: {finding.cwe_id}\n\n")
            if finding.exploitability:
                report.append(f"**Exploitability**: {finding.exploitability}\n\n")

            report.append(f"**Description**: {finding.description}\n\n")

            if finding.recommendation:
                report.append(f"**Recommendation**: {finding.recommendation}\n\n")

            if finding.references:
                report.append("**References**:\n")
                for ref in finding.references[:3]:
                    report.append(f"- {ref}\n")
                report.append("\n")

            report.append("---\n\n")

    return "".join(report)


def print_summary(result: HybridScanResult) -> None:
    """Print scan summary to console.

    Args:
        result: The hybrid scan result to summarize
    """
    print("\n" + "=" * 80)
    print("🔒 HYBRID SECURITY ANALYSIS - FINAL RESULTS")
    print("=" * 80)
    print(f"📁 Target: {result.target_path}")
    print(f"🕐 Timestamp: {result.scan_timestamp}")
    print(f"⏱️  Total Duration: {result.scan_duration_seconds:.1f}s")
    print(f"💰 Cost: ${result.cost_usd:.2f}")
    print(f"🛠️  Tools Used: {', '.join(result.tools_used)}")
    print()
    print("📊 Findings by Severity:")
    print(f"   🔴 Critical: {result.findings_by_severity['critical']}")
    print(f"   🟠 High:     {result.findings_by_severity['high']}")
    print(f"   🟡 Medium:   {result.findings_by_severity['medium']}")
    print(f"   🟢 Low:      {result.findings_by_severity['low']}")
    print(f"   📈 Total:    {result.total_findings}")
    print()
    print("🔧 Findings by Tool:")
    for tool, count in result.findings_by_source.items():
        print(f"   {tool}: {count}")
    print()
    print("⏱️  Phase Timings:")
    for phase, duration in result.phase_timings.items():
        print(f"   {phase}: {duration:.1f}s")
    print("=" * 80)


__all__ = [
    "get_enabled_tools",
    "save_results",
    "convert_to_sarif",
    "severity_to_sarif_level",
    "generate_markdown_report",
    "print_summary",
]
