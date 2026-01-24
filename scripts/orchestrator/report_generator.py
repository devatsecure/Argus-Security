"""
Report Generator Module

Handles all report generation logic including SARIF, JSON, and Markdown formats.
Extracted from run_ai_audit.py to support modular report generation.

Features:
- SARIF 2.1.0 format for GitHub Code Scanning
- JSON structured output
- Markdown summaries
- GitHub PR comments
- Output file management
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate and save reports in multiple formats (SARIF, JSON, Markdown)"""

    # Tool information
    TOOL_NAME = "Agent OS Code Reviewer"
    TOOL_VERSION = "1.0.16"
    TOOL_URI = "https://github.com/devatsecure/Argus-Security"

    # SARIF schema
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, repo_path: str = "."):
        """Initialize the report generator

        Args:
            repo_path: Path to the repository being analyzed
        """
        self.repo_path = repo_path
        self.report_dir = Path(repo_path) / ".argus" / "reviews"

    def ensure_report_directory(self) -> Path:
        """Ensure the report directory exists

        Returns:
            Path to the report directory
        """
        self.report_dir.mkdir(parents=True, exist_ok=True)
        return self.report_dir

    @staticmethod
    def map_severity_to_sarif(severity: str) -> str:
        """Map severity to SARIF level

        Args:
            severity: String like 'critical', 'high', 'medium', 'low', 'info'

        Returns:
            SARIF level string ('error', 'warning', 'note')
        """
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity.lower(), "warning")

    @staticmethod
    def map_exploitability_to_score(exploitability: str) -> int:
        """Map exploitability level to numeric score for SARIF

        Args:
            exploitability: String like 'trivial', 'moderate', 'complex', 'theoretical'

        Returns:
            Numeric score (0-10)
        """
        mapping = {
            "trivial": 10,  # Highest exploitability
            "moderate": 7,
            "complex": 4,
            "theoretical": 1,  # Lowest exploitability
        }
        return mapping.get(exploitability.lower(), 5)

    def generate_sarif(
        self, findings: List[Dict[str, Any]], metrics: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate SARIF 2.1.0 format for GitHub Code Scanning with exploitability data

        Args:
            findings: List of vulnerability findings
            metrics: Optional metrics dictionary or ReviewMetrics instance

        Returns:
            SARIF dictionary
        """
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.TOOL_URI,
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        # Process findings and convert to SARIF results
        for finding in findings:
            result = {
                "ruleId": finding.get("rule_id", "ARGUS-001"),
                "level": self.map_severity_to_sarif(finding.get("severity", "medium")),
                "message": {"text": finding.get("message", "Issue found")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("file_path", "unknown")},
                            "region": {"startLine": finding.get("line_number", 1)},
                        }
                    }
                ],
            }

            # Add properties for additional finding metadata
            properties = {}

            if "cwe" in finding:
                properties["cwe"] = finding["cwe"]

            # Add exploitability as a property
            if "exploitability" in finding:
                properties["exploitability"] = finding["exploitability"]
                properties["exploitabilityScore"] = self.map_exploitability_to_score(
                    finding["exploitability"]
                )

            # Add exploit chain reference if part of a chain
            if "part_of_chain" in finding:
                properties["exploitChain"] = finding["part_of_chain"]

            # Add generated tests reference
            if "tests_generated" in finding:
                properties["testsGenerated"] = finding["tests_generated"]

            if properties:
                result["properties"] = properties

            sarif["runs"][0]["results"].append(result)

        # Add run properties with metrics
        if metrics:
            # Handle both dict and ReviewMetrics object
            metrics_dict = metrics.get("metrics", metrics) if isinstance(metrics, dict) else metrics.metrics
            sarif["runs"][0]["properties"] = {
                "exploitability": metrics_dict.get("exploitability", 0),
                "exploitChainsFound": metrics_dict.get("exploit_chains_found", 0),
                "testsGenerated": metrics_dict.get("tests_generated", 0),
                "agentsExecuted": metrics_dict.get("agents_executed", 0),
            }

        return sarif

    def save_sarif_report(
        self, findings: List[Dict[str, Any]], metrics: Optional[Dict[str, Any]] = None
    ) -> Path:
        """Generate and save SARIF report to file

        Args:
            findings: List of vulnerability findings
            metrics: Optional metrics dictionary or ReviewMetrics instance

        Returns:
            Path to the saved SARIF file
        """
        self.ensure_report_directory()

        # Generate SARIF
        sarif = self.generate_sarif(findings, metrics)

        # Save to file
        sarif_file = self.report_dir / "results.sarif"
        with open(sarif_file, "w") as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"SARIF report saved to {sarif_file}")
        return sarif_file

    def generate_json_report(
        self,
        findings: List[Dict[str, Any]],
        provider: str,
        model: str,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate structured JSON output

        Args:
            findings: List of vulnerability findings
            provider: AI provider used for analysis
            model: Model name used
            metrics: Optional metrics dictionary or ReviewMetrics instance

        Returns:
            JSON dictionary
        """
        # Handle both dict and ReviewMetrics object
        metrics_dict = metrics.get("metrics", metrics) if isinstance(metrics, dict) else metrics.metrics

        json_output = {
            "version": self.TOOL_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "provider": provider,
            "model": model,
            "summary": metrics_dict,
            "findings": findings,
        }

        return json_output

    def save_json_report(
        self,
        findings: List[Dict[str, Any]],
        provider: str,
        model: str,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Generate and save JSON report to file

        Args:
            findings: List of vulnerability findings
            provider: AI provider used for analysis
            model: Model name used
            metrics: Optional metrics dictionary or ReviewMetrics instance

        Returns:
            Path to the saved JSON file
        """
        self.ensure_report_directory()

        # Generate JSON
        json_output = self.generate_json_report(findings, provider, model, metrics)

        # Save to file
        json_file = self.report_dir / "results.json"
        with open(json_file, "w") as f:
            json.dump(json_output, f, indent=2)

        logger.info(f"JSON report saved to {json_file}")
        return json_file

    def save_markdown_report(self, markdown_content: str, review_type: str = "audit") -> Path:
        """Save markdown report to file

        Args:
            markdown_content: The markdown report content
            review_type: Type of review (e.g., 'audit', 'pr-review')

        Returns:
            Path to the saved markdown file
        """
        self.ensure_report_directory()

        # Save markdown report
        report_file = self.report_dir / f"{review_type}-report.md"
        with open(report_file, "w") as f:
            f.write(markdown_content)

        logger.info(f"Markdown report saved to {report_file}")
        return report_file

    @staticmethod
    def parse_findings_from_markdown(report_text: str) -> List[Dict[str, Any]]:
        """Parse findings from markdown report

        Args:
            report_text: Markdown report content

        Returns:
            List of parsed finding dictionaries
        """
        findings = []
        lines = report_text.split("\n")

        # Track current section for categorization
        current_section = None
        current_severity = None

        for i, line in enumerate(lines):
            # Detect severity sections
            if "## Critical Issues" in line or "## Critical" in line:
                current_severity = "critical"
                continue
            elif "## High Priority" in line or "## High" in line:
                current_severity = "high"
                continue
            elif "## Medium Priority" in line or "## Medium" in line:
                current_severity = "medium"
                continue
            elif "## Low Priority" in line or "## Low" in line:
                current_severity = "low"
                continue

            # Detect category subsections
            if "### Security" in line:
                current_section = "security"
                continue
            elif "### Performance" in line:
                current_section = "performance"
                continue
            elif "### Testing" in line or "### Test" in line:
                current_section = "testing"
                continue
            elif "### Code Quality" in line or "### Quality" in line:
                current_section = "quality"
                continue

            # Look for numbered findings (e.g., "1. **Issue Name**" or "14. **Issue Name**")
            numbered_match = re.match(
                r"^\d+\.\s+\*\*(.+?)\*\*\s*-?\s*`?([^`\n]+\.(?:ts|js|py|java|go|rs|rb|php|cs))?:?(\d+)?",
                line,
            )
            if numbered_match:
                issue_name = numbered_match.group(1)
                file_path = numbered_match.group(2) if numbered_match.group(2) else "unknown"
                line_num = int(numbered_match.group(3)) if numbered_match.group(3) else 1

                # Get description from next lines
                description_lines = []
                for j in range(i + 1, min(i + 5, len(lines))):
                    if (lines[j].strip() and not lines[j].startswith("#") and
                        not re.match(r"^\d+\.", lines[j])):
                        description_lines.append(lines[j].strip())
                    elif lines[j].startswith("#") or re.match(r"^\d+\.", lines[j]):
                        break

                description = " ".join(description_lines[:2]) if description_lines else issue_name

                # Determine category and severity
                category = current_section or "quality"
                severity = current_severity or "medium"

                # Override category based on keywords
                lower_text = (issue_name + " " + description).lower()
                if any(
                    kw in lower_text
                    for kw in ["security", "sql", "xss", "csrf", "auth", "jwt", "secret", "injection"]
                ):
                    category = "security"
                elif any(
                    kw in lower_text
                    for kw in ["performance", "n+1", "memory", "leak", "slow", "inefficient"]
                ):
                    category = "performance"
                elif any(kw in lower_text for kw in ["test", "coverage", "testing"]):
                    category = "testing"

                findings.append(
                    {
                        "severity": severity,
                        "category": category,
                        "message": f"{issue_name}: {description[:200]}",
                        "file_path": file_path,
                        "line_number": line_num,
                        "rule_id": f"{category.upper()}-{len([f for f in findings if f['category'] == category]) + 1:03d}",
                    }
                )

        return findings

    def write_output_files(
        self,
        markdown_content: str,
        findings: List[Dict[str, Any]],
        provider: str,
        model: str,
        metrics: Optional[Dict[str, Any]] = None,
        review_type: str = "audit",
    ) -> Dict[str, Path]:
        """Write all output files (Markdown, SARIF, JSON)

        Args:
            markdown_content: The markdown report content
            findings: List of vulnerability findings
            provider: AI provider used
            model: Model name used
            metrics: Optional metrics dictionary or ReviewMetrics instance
            review_type: Type of review

        Returns:
            Dictionary with file paths: {'markdown': Path, 'sarif': Path, 'json': Path}
        """
        self.ensure_report_directory()

        output_files = {}

        # Save markdown report
        markdown_path = self.save_markdown_report(markdown_content, review_type)
        output_files["markdown"] = markdown_path

        # Save SARIF report
        sarif_path = self.save_sarif_report(findings, metrics)
        output_files["sarif"] = sarif_path

        # Save JSON report
        json_path = self.save_json_report(findings, provider, model, metrics)
        output_files["json"] = json_path

        return output_files

    def create_pr_comment(
        self,
        findings: List[Dict[str, Any]],
        metrics: Optional[Dict[str, Any]] = None,
        max_issues: int = 10,
    ) -> str:
        """Create GitHub PR comment from findings

        Args:
            findings: List of vulnerability findings
            metrics: Optional metrics dictionary or ReviewMetrics instance
            max_issues: Maximum issues to include in comment

        Returns:
            Formatted PR comment markdown
        """
        # Handle both dict and ReviewMetrics object
        metrics_dict = metrics.get("metrics", metrics) if isinstance(metrics, dict) else metrics.metrics

        # Build comment
        comment = "# Code Review Summary\n\n"

        # Add summary stats
        critical_count = len([f for f in findings if f.get("severity") == "critical"])
        high_count = len([f for f in findings if f.get("severity") == "high"])
        medium_count = len([f for f in findings if f.get("severity") == "medium"])
        low_count = len([f for f in findings if f.get("severity") == "low"])

        comment += "## Summary\n\n"
        if critical_count > 0:
            comment += f"- **Critical**: {critical_count}\n"
        if high_count > 0:
            comment += f"- **High**: {high_count}\n"
        if medium_count > 0:
            comment += f"- **Medium**: {medium_count}\n"
        if low_count > 0:
            comment += f"- **Low**: {low_count}\n"

        # Add findings
        if findings:
            comment += "\n## Issues Found\n\n"

            # Group by severity
            for severity in ["critical", "high", "medium", "low"]:
                severity_findings = [f for f in findings if f.get("severity") == severity]
                if severity_findings:
                    comment += f"### {severity.capitalize()}\n\n"
                    for i, finding in enumerate(severity_findings[:max_issues], 1):
                        file_path = finding.get("file_path", "unknown")
                        line_num = finding.get("line_number", "?")
                        message = finding.get("message", "Issue found")
                        comment += f"{i}. **{finding.get('category', 'general').title()}** - {message}\n"
                        comment += f"   - Location: `{file_path}:{line_num}`\n\n"

                    if len(severity_findings) > max_issues:
                        comment += f"   ... and {len(severity_findings) - max_issues} more\n\n"
        else:
            comment += "\n✅ No issues found!\n\n"

        # Add metrics if available
        if metrics_dict:
            comment += "## Metrics\n\n"
            if "cost_usd" in metrics_dict:
                comment += f"- Cost: ${metrics_dict.get('cost_usd', 0):.2f}\n"
            if "duration_seconds" in metrics_dict:
                comment += f"- Duration: {metrics_dict.get('duration_seconds', 0)}s\n"
            comment += "\n"

        comment += "_Generated by Agent OS Code Reviewer_"

        return comment

    def write_github_output(
        self,
        findings: List[Dict[str, Any]],
        output_files: Dict[str, Path],
        metrics: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write GitHub Actions output variables

        Args:
            findings: List of vulnerability findings
            output_files: Dictionary with output file paths
            metrics: Optional metrics dictionary or ReviewMetrics instance
        """
        # Handle both dict and ReviewMetrics object
        metrics_dict = metrics.get("metrics", metrics) if isinstance(metrics, dict) else metrics.metrics

        # Count blockers and suggestions
        blocker_count = (
            len([f for f in findings if f.get("severity") in ["critical", "high"]])
            if findings
            else 0
        )
        suggestion_count = (
            len([f for f in findings if f.get("severity") in ["medium", "low"]])
            if findings
            else 0
        )

        # Try to write to GITHUB_OUTPUT
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"blockers={blocker_count}\n")
                f.write(f"suggestions={suggestion_count}\n")

                if "markdown" in output_files:
                    f.write(f"report-path={output_files['markdown']}\n")
                if "sarif" in output_files:
                    f.write(f"sarif-path={output_files['sarif']}\n")
                if "json" in output_files:
                    f.write(f"json-path={output_files['json']}\n")

                if metrics_dict:
                    f.write(f"cost-estimate={metrics_dict.get('cost_usd', 0):.2f}\n")
                    f.write(f"files-analyzed={metrics_dict.get('files_reviewed', 0)}\n")
                    f.write(f"duration-seconds={metrics_dict.get('duration_seconds', 0)}\n")

            logger.info("GitHub Actions outputs written")
        else:
            # Fallback for local testing
            logger.info(f"blockers={blocker_count}")
            logger.info(f"suggestions={suggestion_count}")

            if "markdown" in output_files:
                logger.info(f"report-path={output_files['markdown']}")
            if "sarif" in output_files:
                logger.info(f"sarif-path={output_files['sarif']}")
            if "json" in output_files:
                logger.info(f"json-path={output_files['json']}")

            if metrics_dict:
                logger.info(f"cost-estimate={metrics_dict.get('cost_usd', 0):.2f}")
                logger.info(f"files-analyzed={metrics_dict.get('files_reviewed', 0)}")
                logger.info(f"duration-seconds={metrics_dict.get('duration_seconds', 0)}")
