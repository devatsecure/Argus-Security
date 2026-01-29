#!/usr/bin/env python3
"""
Pre-Flight Checklist System for Argus Security External Reporting

Provides human-in-the-loop approval before submitting security reports externally.
Prevents automated spam and ensures high-quality submissions.

Features:
- Automated quality checks (file paths, line numbers, quality scores)
- Interactive manual confirmation prompts
- Generates audit trail of approval
- Blocks submission unless all checks pass
- Saves checklist results alongside reports

Usage:
    python preflight_checker.py --report findings.json
    python preflight_checker.py --report findings.json --checklist custom-checklist.yml
    python preflight_checker.py --report findings.json --non-interactive  # CI mode
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PreFlightChecker:
    """Pre-flight checklist system for external security report submission"""

    def __init__(self, report_path: str, checklist_path: Optional[str] = None, non_interactive: bool = False):
        """Initialize the pre-flight checker

        Args:
            report_path: Path to the JSON report file
            checklist_path: Optional path to custom checklist YAML (defaults to .argus/preflight-checklist.yml)
            non_interactive: Run in non-interactive mode (skip manual checks, only automated)
        """
        self.report_path = Path(report_path)
        self.non_interactive = non_interactive

        # Default checklist path
        if checklist_path:
            self.checklist_path = Path(checklist_path)
        else:
            # Look for checklist in .argus directory
            repo_root = self._find_repo_root()
            self.checklist_path = repo_root / ".argus" / "preflight-checklist.yml"

        # Load report
        self.report_data = self._load_report()

        # Load checklist
        self.checklist_config = self._load_checklist()

        # Track check results
        self.results = {
            "automated_checks": [],
            "manual_checks": [],
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "report_path": str(self.report_path),
            "user": os.environ.get("USER", "unknown"),
            "passed": False
        }

    def _find_repo_root(self) -> Path:
        """Find the repository root directory"""
        current = Path.cwd()
        while current != current.parent:
            if (current / ".git").exists() or (current / ".argus").exists():
                return current
            current = current.parent
        return Path.cwd()

    def _load_report(self) -> Dict[str, Any]:
        """Load the JSON report file"""
        if not self.report_path.exists():
            logger.error(f"Report file not found: {self.report_path}")
            sys.exit(1)

        try:
            with open(self.report_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in report file: {e}")
            sys.exit(1)

    def _load_checklist(self) -> Dict[str, Any]:
        """Load the checklist configuration"""
        if not self.checklist_path.exists():
            logger.warning(f"Checklist file not found: {self.checklist_path}")
            logger.info("Using default checklist configuration")
            return self._get_default_checklist()

        try:
            with open(self.checklist_path, "r") as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML in checklist file: {e}")
            sys.exit(1)

    def _get_default_checklist(self) -> Dict[str, Any]:
        """Get default checklist configuration"""
        return {
            "automated_checks": [
                {
                    "name": "Quality score ≥ 80",
                    "validator": "quality_score_validator"
                },
                {
                    "name": "All findings have file paths",
                    "validator": "file_path_validator"
                },
                {
                    "name": "All findings have line numbers",
                    "validator": "line_number_validator"
                }
            ],
            "manual_checks": [
                "Security contact identified?",
                "Disclosure method selected (email/private issue/HackerOne)?",
                "90-day timeline agreed with maintainers?",
                "Human reviewed report for quality and accuracy?",
                "Test report readability (can a developer action it)?",
                "Confirmed this is NOT a public security disclosure?"
            ]
        }

    # ===== AUTOMATED VALIDATORS =====

    def _validate_quality_score(self) -> Tuple[bool, str]:
        """Check if quality score is >= 80"""
        try:
            # Look for quality score in summary/metrics
            summary = self.report_data.get("summary", {})
            quality_score = summary.get("quality_score", 0)

            if quality_score >= 80:
                return True, f"Quality score: {quality_score}"
            else:
                return False, f"Quality score too low: {quality_score} (minimum: 80)"
        except Exception as e:
            return False, f"Error checking quality score: {e}"

    def _validate_file_paths(self) -> Tuple[bool, str]:
        """Check if all findings have file paths"""
        try:
            findings = self.report_data.get("findings", [])

            if not findings:
                return False, "No findings in report"

            missing_paths = []
            for i, finding in enumerate(findings):
                file_path = finding.get("file_path", "").strip()
                if not file_path or file_path == "unknown":
                    missing_paths.append(i + 1)

            if missing_paths:
                return False, f"Findings missing file paths: {missing_paths[:5]}" + \
                    (f" (+{len(missing_paths)-5} more)" if len(missing_paths) > 5 else "")

            return True, f"All {len(findings)} findings have file paths"
        except Exception as e:
            return False, f"Error checking file paths: {e}"

    def _validate_line_numbers(self) -> Tuple[bool, str]:
        """Check if all findings have line numbers"""
        try:
            findings = self.report_data.get("findings", [])

            if not findings:
                return False, "No findings in report"

            missing_lines = []
            for i, finding in enumerate(findings):
                line_number = finding.get("line_number", 0)
                if not line_number or line_number < 1:
                    missing_lines.append(i + 1)

            if missing_lines:
                return False, f"Findings missing line numbers: {missing_lines[:5]}" + \
                    (f" (+{len(missing_lines)-5} more)" if len(missing_lines) > 5 else "")

            return True, f"All {len(findings)} findings have line numbers"
        except Exception as e:
            return False, f"Error checking line numbers: {e}"

    def _validate_severity_assigned(self) -> Tuple[bool, str]:
        """Check if all findings have severity assigned"""
        try:
            findings = self.report_data.get("findings", [])

            if not findings:
                return False, "No findings in report"

            missing_severity = []
            for i, finding in enumerate(findings):
                severity = finding.get("severity", "").strip().lower()
                if not severity or severity not in ["critical", "high", "medium", "low", "info"]:
                    missing_severity.append(i + 1)

            if missing_severity:
                return False, f"Findings missing valid severity: {missing_severity[:5]}" + \
                    (f" (+{len(missing_severity)-5} more)" if len(missing_severity) > 5 else "")

            return True, f"All {len(findings)} findings have valid severity"
        except Exception as e:
            return False, f"Error checking severity: {e}"

    def _run_custom_command(self, command: str) -> Tuple[bool, str]:
        """Run a custom command validator"""
        try:
            # Replace {report} placeholder with actual report path
            cmd = command.replace("{report}", str(self.report_path))

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True, f"Command passed: {result.stdout.strip()}"
            else:
                return False, f"Command failed: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return False, "Command timed out (30s)"
        except Exception as e:
            return False, f"Error running command: {e}"

    def run_automated_checks(self) -> bool:
        """Run all automated checks

        Returns:
            True if all checks passed, False otherwise
        """
        logger.info("\n" + "="*70)
        logger.info("AUTOMATED CHECKS")
        logger.info("="*70 + "\n")

        all_passed = True

        for check in self.checklist_config.get("automated_checks", []):
            check_name = check.get("name", "Unknown check")

            # Determine validator
            if "validator" in check:
                validator_name = check["validator"]

                # Map validator name to method
                validators = {
                    "quality_score_validator": self._validate_quality_score,
                    "file_path_validator": self._validate_file_paths,
                    "line_number_validator": self._validate_line_numbers,
                    "severity_validator": self._validate_severity_assigned
                }

                if validator_name in validators:
                    passed, message = validators[validator_name]()
                else:
                    passed, message = False, f"Unknown validator: {validator_name}"

            elif "command" in check:
                passed, message = self._run_custom_command(check["command"])

            else:
                passed, message = False, "No validator or command specified"

            # Record result
            self.results["automated_checks"].append({
                "name": check_name,
                "passed": passed,
                "message": message
            })

            # Print result
            status = "✅ PASS" if passed else "❌ FAIL"
            logger.info(f"{status} - {check_name}")
            logger.info(f"      {message}\n")

            if not passed:
                all_passed = False

        return all_passed

    def run_manual_checks(self) -> bool:
        """Run all manual confirmation checks

        Returns:
            True if all checks confirmed, False otherwise
        """
        if self.non_interactive:
            logger.warning("Skipping manual checks (non-interactive mode)")
            return True

        logger.info("\n" + "="*70)
        logger.info("MANUAL CHECKS (Human Confirmation Required)")
        logger.info("="*70 + "\n")

        all_confirmed = True

        for check_question in self.checklist_config.get("manual_checks", []):
            logger.info(f"\n{check_question}")

            while True:
                response = input("  Confirm (yes/no): ").strip().lower()

                if response in ["yes", "y"]:
                    self.results["manual_checks"].append({
                        "question": check_question,
                        "confirmed": True
                    })
                    logger.info("  ✅ Confirmed\n")
                    break
                elif response in ["no", "n"]:
                    self.results["manual_checks"].append({
                        "question": check_question,
                        "confirmed": False
                    })
                    logger.warning("  ❌ NOT confirmed\n")
                    all_confirmed = False
                    break
                else:
                    logger.warning("  Please answer 'yes' or 'no'")

        return all_confirmed

    def save_checklist_results(self) -> Path:
        """Save checklist results to file

        Returns:
            Path to the saved checklist results
        """
        # Save results next to the report
        results_path = self.report_path.parent / f"{self.report_path.stem}_preflight_results.json"

        with open(results_path, "w") as f:
            json.dump(self.results, f, indent=2)

        logger.info(f"\nChecklist results saved to: {results_path}")
        return results_path

    def generate_markdown_report(self) -> str:
        """Generate markdown checklist report

        Returns:
            Markdown-formatted checklist report
        """
        md = "# Pre-Flight Checklist Results\n\n"
        md += f"**Report:** `{self.report_path}`\n"
        md += f"**Timestamp:** {self.results['timestamp']}\n"
        md += f"**User:** {self.results['user']}\n"
        md += f"**Status:** {'✅ PASSED' if self.results['passed'] else '❌ FAILED'}\n\n"

        md += "## Automated Checks\n\n"
        for check in self.results["automated_checks"]:
            status = "✅" if check["passed"] else "❌"
            md += f"- {status} **{check['name']}**\n"
            md += f"  - {check['message']}\n"

        if self.results["manual_checks"]:
            md += "\n## Manual Checks\n\n"
            for check in self.results["manual_checks"]:
                status = "✅" if check["confirmed"] else "❌"
                md += f"- {status} {check['question']}\n"

        md += f"\n---\n_Generated by Argus Security Pre-Flight Checker_\n"

        return md

    def save_markdown_report(self) -> Path:
        """Save markdown checklist report

        Returns:
            Path to the saved markdown report
        """
        md = self.generate_markdown_report()

        # Save results next to the report
        md_path = self.report_path.parent / f"{self.report_path.stem}_preflight_checklist.md"

        with open(md_path, "w") as f:
            f.write(md)

        logger.info(f"Markdown checklist saved to: {md_path}")
        return md_path

    def run(self) -> bool:
        """Run the complete pre-flight checklist

        Returns:
            True if all checks passed, False otherwise
        """
        logger.info("\n" + "="*70)
        logger.info("ARGUS SECURITY PRE-FLIGHT CHECKLIST")
        logger.info("="*70)
        logger.info(f"Report: {self.report_path}\n")

        # Run automated checks
        automated_passed = self.run_automated_checks()

        # If automated checks failed, don't proceed to manual checks
        if not automated_passed:
            logger.error("\n" + "="*70)
            logger.error("AUTOMATED CHECKS FAILED")
            logger.error("="*70)
            logger.error("Fix the automated check failures before proceeding.\n")

            self.results["passed"] = False
            self.save_checklist_results()
            self.save_markdown_report()
            return False

        # Run manual checks
        manual_passed = self.run_manual_checks()

        # Final result
        all_passed = automated_passed and manual_passed
        self.results["passed"] = all_passed

        # Print summary
        logger.info("\n" + "="*70)
        if all_passed:
            logger.info("✅ PRE-FLIGHT CHECKLIST PASSED")
            logger.info("="*70)
            logger.info("Report is approved for external submission.\n")
        else:
            logger.error("❌ PRE-FLIGHT CHECKLIST FAILED")
            logger.error("="*70)
            logger.error("Report is NOT approved for external submission.\n")

        # Save results
        self.save_checklist_results()
        self.save_markdown_report()

        return all_passed


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Pre-flight checklist for external security report submission",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python preflight_checker.py --report findings.json
  python preflight_checker.py --report findings.json --checklist custom.yml
  python preflight_checker.py --report findings.json --non-interactive
        """
    )

    parser.add_argument(
        "--report",
        required=True,
        help="Path to the JSON report file"
    )

    parser.add_argument(
        "--checklist",
        help="Path to custom checklist YAML (default: .argus/preflight-checklist.yml)"
    )

    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Run in non-interactive mode (skip manual checks)"
    )

    args = parser.parse_args()

    # Create and run checker
    checker = PreFlightChecker(
        report_path=args.report,
        checklist_path=args.checklist,
        non_interactive=args.non_interactive
    )

    passed = checker.run()

    # Exit with appropriate code
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
