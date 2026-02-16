#!/usr/bin/env python3
"""
Checkov IaC Scanner for Agent OS
Scans Infrastructure as Code files for security misconfigurations

Features:
- Terraform scanning
- Kubernetes YAML scanning
- Dockerfile scanning
- CloudFormation templates
- Helm charts
- ARM templates
- JSON output for LLM processing
"""

import json
import logging
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class CheckovFinding:
    """A single Checkov IaC misconfiguration finding"""

    check_id: str
    check_name: str
    check_class: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    resource: str
    resource_type: str
    file_line_range: list[int]
    guideline: str
    description: str
    code_block: list[str]
    check_result: dict[str, Any]
    framework: str  # terraform, kubernetes, dockerfile, cloudformation, etc.

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CheckovScanResult:
    """Results from a Checkov scan"""

    scan_type: str  # 'filesystem', 'file'
    target: str
    timestamp: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    skipped_checks: int
    parsing_errors: int
    findings: list[CheckovFinding]
    frameworks: list[str]
    scan_duration_seconds: float
    checkov_version: str

    def to_dict(self) -> dict:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "skipped_checks": self.skipped_checks,
            "parsing_errors": self.parsing_errors,
            "findings": [f.to_dict() for f in self.findings],
            "frameworks": self.frameworks,
            "scan_duration_seconds": self.scan_duration_seconds,
            "checkov_version": self.checkov_version,
        }


class CheckovScanner:
    """
    Checkov IaC Security Scanner

    Scans Infrastructure as Code for security misconfigurations:
    - Terraform/Tofu (HCL)
    - Kubernetes manifests (YAML)
    - Dockerfiles
    - CloudFormation templates (JSON/YAML)
    - Helm charts
    - ARM templates
    - Serverless framework

    Integrates with CheckovNormalizer for unified finding format
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize Checkov scanner

        Args:
            config: Optional configuration dictionary
                - frameworks: List of frameworks to scan (default: all)
                - checks: Specific checks to run (default: all)
                - skip_checks: Checks to skip
                - compact: Compact output mode
                - quiet: Suppress progress output
                - download_external_modules: Download external Terraform modules
        """
        self.config = config or {}
        self.frameworks = self.config.get("frameworks", [])  # Empty = all frameworks
        self.checks = self.config.get("checks", [])
        self.skip_checks = self.config.get("skip_checks", [])
        self.compact = self.config.get("compact", True)
        self.quiet = self.config.get("quiet", True)
        self.download_external_modules = self.config.get("download_external_modules", False)

        # Verify installation
        if not self._check_checkov_installed():
            logger.warning("Checkov not installed. Install with: pip install checkov")

    def _check_checkov_installed(self) -> bool:
        """Check if Checkov is available"""
        try:
            # Use 'which' for faster check (checkov --version can take 10+ seconds on first run)
            result = subprocess.run(["which", "checkov"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def install_checkov(self) -> bool:
        """
        Install Checkov via pip if not already installed

        Returns:
            True if Checkov is available after installation attempt
        """
        if self._check_checkov_installed():
            logger.info("Checkov is already installed")
            return True

        logger.info("Installing Checkov via pip...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "checkov"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                logger.info("Checkov installed successfully")
                return self._check_checkov_installed()
            else:
                logger.error(f"Failed to install Checkov: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Checkov installation timed out")
            return False
        except Exception as e:
            logger.error(f"Error installing Checkov: {e}")
            return False

    def scan(
        self,
        target_path: str,
        framework: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> CheckovScanResult:
        """
        Run Checkov scan on target path

        Args:
            target_path: Path to scan (file or directory)
            framework: Specific framework to scan (terraform, kubernetes, dockerfile, etc.)
            output_file: Optional path to save JSON results

        Returns:
            CheckovScanResult with all findings

        Raises:
            RuntimeError: If Checkov is not installed or scan fails
        """
        logger.info(f"Starting Checkov scan: {target_path}")

        # Runtime check for Checkov availability (non-fatal since we checked during init)
        if not self._check_checkov_installed():
            logger.warning("Checkov runtime check failed (but was available during init)")
            logger.info("Attempting scan anyway...")

        target_path_obj = Path(target_path).resolve()
        if not target_path_obj.exists():
            logger.error(f"Target path does not exist: {target_path}")
            raise RuntimeError(f"Target path not found: {target_path}")

        start_time = datetime.now()

        # Determine scan type
        scan_type = "file" if target_path_obj.is_file() else "filesystem"

        # Build Checkov command
        cmd = self._build_scan_command(str(target_path_obj), framework)

        try:
            logger.info(f"   Running: {' '.join(cmd[:4])}...")

            # Checkov returns:
            # - 0: No issues found
            # - 1: Issues found (this is normal!)
            # - 2+: Error
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            if result.returncode >= 2:
                logger.error(f"Checkov scan failed with exit code {result.returncode}")
                logger.error(f"STDERR: {result.stderr}")
                raise RuntimeError(f"Checkov scan failed: {result.stderr}")

            # Parse JSON output
            try:
                checkov_output = json.loads(result.stdout) if result.stdout else {}
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Checkov JSON output: {e}")
                logger.error(f"Raw output: {result.stdout[:500]}")
                raise RuntimeError(f"Failed to parse Checkov output: {e}")

            # Parse results
            findings = self.parse_output(checkov_output)

            # Calculate statistics — checkov_output may be a list (multi-framework) or dict
            summary = checkov_output.get("summary", {}) if isinstance(checkov_output, dict) else {}
            scan_duration = (datetime.now() - start_time).total_seconds()

            scan_result = CheckovScanResult(
                scan_type=scan_type,
                target=str(target_path_obj),
                timestamp=datetime.now().isoformat(),
                total_checks=summary.get("passed", 0)
                + summary.get("failed", 0)
                + summary.get("skipped", 0)
                + summary.get("parsing_errors", 0),
                passed_checks=summary.get("passed", 0),
                failed_checks=summary.get("failed", 0),
                skipped_checks=summary.get("skipped", 0),
                parsing_errors=summary.get("parsing_errors", 0),
                findings=findings,
                frameworks=self._extract_frameworks(checkov_output),
                scan_duration_seconds=scan_duration,
                checkov_version=self._get_checkov_version(),
            )

            logger.info(f"Checkov scan complete: {len(findings)} findings in {scan_duration:.1f}s")

            # Save to file if requested
            if output_file:
                self._save_results(scan_result, output_file)

            # Print summary
            self._print_summary(scan_result)

            return scan_result

        except subprocess.TimeoutExpired:
            logger.error("Checkov scan timed out after 10 minutes")
            raise RuntimeError("Checkov scan timed out")
        except Exception as e:
            logger.error(f"Checkov scan error: {e}")
            raise

    def scan_file(
        self,
        file_path: str,
        framework: Optional[str] = None,
    ) -> CheckovScanResult:
        """
        Scan a single IaC file

        Args:
            file_path: Path to the IaC file
            framework: Specific framework (auto-detected if not provided)

        Returns:
            CheckovScanResult with findings for this file
        """
        logger.info(f"Scanning single file: {file_path}")

        file_path_obj = Path(file_path).resolve()
        if not file_path_obj.is_file():
            raise RuntimeError(f"Not a file: {file_path}")

        # Auto-detect framework if not provided
        if not framework:
            framework = self._detect_framework(file_path_obj)
            logger.info(f"   Auto-detected framework: {framework}")

        return self.scan(str(file_path_obj), framework=framework)

    def parse_output(self, checkov_output: dict) -> list[CheckovFinding]:
        """
        Parse Checkov JSON output into CheckovFinding objects

        Args:
            checkov_output: Raw Checkov JSON output

        Returns:
            List of CheckovFinding objects
        """
        findings = []

        # Checkov can return either a list or dict format
        # Handle both cases
        if isinstance(checkov_output, list):
            # List format: directly iterate
            failed_checks = checkov_output
        elif isinstance(checkov_output, dict):
            # Dict format: results -> failed_checks (array)
            results = checkov_output.get("results", {})
            if isinstance(results, dict):
                failed_checks = results.get("failed_checks", [])
            elif isinstance(results, list):
                failed_checks = results
            else:
                failed_checks = []
        else:
            # Unexpected format
            logger.warning(f"Unexpected Checkov output format: {type(checkov_output)}")
            return findings

        for check in failed_checks:
            try:
                if not isinstance(check, dict):
                    continue
                # Extract severity (default to MEDIUM if not present)
                check_result = check.get("check_result", {})
                if not isinstance(check_result, dict):
                    check_result = {}
                severity = check_result.get("severity", "MEDIUM")

                # Normalize severity to standard levels
                severity = self._normalize_severity(severity)

                # Extract framework from check_class (e.g., "checkov.terraform.checks.aws" -> "terraform")
                check_class = check.get("check_class", "")
                framework = ""
                if check_class:
                    parts = check_class.split(".")
                    # Framework is typically the second part: checkov.<framework>.checks...
                    framework = parts[1].lower() if len(parts) > 1 else ""

                finding = CheckovFinding(
                    check_id=check.get("check_id", "UNKNOWN"),
                    check_name=check.get("check_name", "IaC Security Check"),
                    check_class=check_class,
                    severity=severity,
                    file_path=check.get("file_path", "unknown"),
                    resource=check.get("resource", ""),
                    resource_type=check.get("resource_type", ""),
                    file_line_range=check.get("file_line_range", [0, 0]),
                    guideline=check.get("guideline", ""),
                    description=check.get("description", ""),
                    code_block=check.get("code_block", []),
                    check_result=check_result,
                    framework=framework,
                )

                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue

        return findings

    def _build_scan_command(self, target_path: str, framework: Optional[str] = None) -> list[str]:
        """
        Build Checkov command with all options

        Args:
            target_path: Target to scan
            framework: Optional framework filter

        Returns:
            Command as list of strings
        """
        cmd = ["checkov"]

        # Target type - detect if file by existence or extension
        path = Path(target_path)
        # Check if it's an existing file, or if non-existent, check if it has a file extension
        is_file = path.is_file() or (not path.exists() and path.suffix)
        if is_file:
            cmd.extend(["--file", target_path])
        else:
            cmd.extend(["--directory", target_path])

        # Output format - always JSON for parsing
        cmd.extend(["--output", "json"])

        # Framework filter
        if framework:
            cmd.extend(["--framework", framework])
        elif self.frameworks:
            for fw in self.frameworks:
                cmd.extend(["--framework", fw])
        else:
            # Auto-detect frameworks from target directory to avoid scanning all 30+
            detected = self._detect_target_frameworks(target_path)
            if detected:
                for fw in detected:
                    cmd.extend(["--framework", fw])

        # Specific checks
        if self.checks:
            cmd.extend(["--check", ",".join(self.checks)])

        # Skip checks
        if self.skip_checks:
            cmd.extend(["--skip-check", ",".join(self.skip_checks)])

        # Compact mode
        if self.compact:
            cmd.append("--compact")

        # Quiet mode
        if self.quiet:
            cmd.append("--quiet")

        # External modules (Terraform)
        if self.download_external_modules:
            cmd.append("--download-external-modules")
            cmd.append("true")

        return cmd

    def _detect_target_frameworks(self, target_path: str) -> list[str]:
        """
        Walk the target directory to detect which IaC frameworks are present.

        Limits traversal to depth 3 and 500 files to stay fast.
        Reads at most 200 bytes of YAML/JSON files for pattern matching.

        Args:
            target_path: Root directory to scan

        Returns:
            List of detected framework names, or empty list if none found.
        """
        target = Path(target_path)
        if not target.is_dir():
            return []

        frameworks: set[str] = set()
        files_checked = 0
        max_files = 500
        max_depth = 3
        target_depth = len(target.parts)

        for dirpath, dirnames, filenames in os.walk(target):
            current = Path(dirpath)
            depth = len(current.parts) - target_depth
            if depth >= max_depth:
                dirnames.clear()
                continue

            for filename in filenames:
                if files_checked >= max_files:
                    break

                files_checked += 1
                name_lower = filename.lower()
                filepath = current / filename

                # Terraform
                if name_lower.endswith(".tf") or name_lower.endswith(".tf.json"):
                    frameworks.add("terraform")
                    continue

                # Bicep
                if name_lower.endswith(".bicep"):
                    frameworks.add("bicep")
                    continue

                # Dockerfile
                if name_lower.startswith("dockerfile") or name_lower == ".dockerignore":
                    frameworks.add("dockerfile")
                    continue

                # Helm
                if name_lower == "chart.yaml" or name_lower == "chart.yml":
                    frameworks.add("helm")
                    continue

                # Serverless
                if name_lower in ("serverless.yml", "serverless.yaml"):
                    frameworks.add("serverless")
                    continue

                # Bitbucket Pipelines
                if name_lower == "bitbucket-pipelines.yml":
                    frameworks.add("bitbucket_pipelines")
                    continue

                # GitHub Actions
                if name_lower.endswith((".yml", ".yaml")):
                    rel = filepath.relative_to(target)
                    rel_parts = rel.parts
                    if len(rel_parts) >= 3 and rel_parts[0] == ".github" and rel_parts[1] == "workflows":
                        frameworks.add("github_actions")
                        continue

                # YAML files - check for Kubernetes or CloudFormation patterns
                if name_lower.endswith((".yml", ".yaml")):
                    try:
                        with open(filepath, "rb") as f:
                            head = f.read(200)
                        if b"apiVersion:" in head or b"kind:" in head:
                            frameworks.add("kubernetes")
                        if b"AWSTemplateFormatVersion" in head:
                            frameworks.add("cloudformation")
                    except OSError:
                        pass
                    continue

                # JSON files - check for ARM or CloudFormation patterns
                if name_lower.endswith(".json"):
                    try:
                        with open(filepath, "rb") as f:
                            head = f.read(200)
                        if b"$schema" in head and b"deploymentTemplate" in head:
                            frameworks.add("arm")
                        if b"AWSTemplateFormatVersion" in head:
                            frameworks.add("cloudformation")
                    except OSError:
                        pass
                    continue

            if files_checked >= max_files:
                break

        # Check for Helm directory at top level
        helm_dir = target / "helm"
        if helm_dir.is_dir() and "helm" not in frameworks:
            frameworks.add("helm")

        detected = sorted(frameworks)
        if detected:
            logger.info(f"Auto-detected IaC frameworks: {', '.join(detected)}")
        return detected

    def _detect_framework(self, file_path: Path) -> str:
        """
        Auto-detect IaC framework from file extension and content

        Args:
            file_path: Path to file

        Returns:
            Framework name (terraform, kubernetes, dockerfile, etc.)
        """
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        # Dockerfile
        if "dockerfile" in name:
            return "dockerfile"

        # Terraform
        if suffix in [".tf", ".hcl"]:
            return "terraform"

        # Kubernetes/Helm
        if suffix in [".yaml", ".yml"]:
            try:
                with open(file_path) as f:
                    content = f.read(1024)  # Read first 1KB
                    if "apiVersion:" in content and "kind:" in content:
                        return "kubernetes"
            except Exception:
                pass
            return "kubernetes"  # Default YAML to k8s

        # ARM templates - check before CloudFormation
        if suffix == ".json" and "azure" in name:
            return "arm"

        # CloudFormation
        if suffix == ".json":
            try:
                with open(file_path) as f:
                    content = f.read(1024)
                    if "AWSTemplateFormatVersion" in content or "Resources:" in content:
                        return "cloudformation"
            except Exception:
                pass
            return "cloudformation"

        # Default
        return "terraform"

    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize severity to standard levels

        Args:
            severity: Raw severity string

        Returns:
            Normalized severity (CRITICAL, HIGH, MEDIUM, LOW)
        """
        severity_upper = severity.upper()

        # Map common variations
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "INFO": "LOW",
            "INFORMATIONAL": "LOW",
        }

        return mapping.get(severity_upper, "MEDIUM")

    def _extract_frameworks(self, checkov_output: dict) -> list[str]:
        """Extract list of frameworks that were scanned"""
        frameworks = set()

        # Handle both list and dict formats
        if isinstance(checkov_output, list):
            checks = checkov_output
        elif isinstance(checkov_output, dict):
            results = checkov_output.get("results", {})
            if isinstance(results, dict):
                checks = results.get("failed_checks", []) + results.get("passed_checks", [])
            elif isinstance(results, list):
                checks = results
            else:
                checks = []
        else:
            checks = []

        for check in checks:
            check_class = check.get("check_class", "") if isinstance(check, dict) else ""
            if check_class:
                # Extract framework from check_class (e.g., "checkov.terraform.checks...")
                parts = check_class.split(".")
                if len(parts) > 1:
                    frameworks.add(parts[1])

        return sorted(frameworks)

    def _get_checkov_version(self) -> str:
        """Get Checkov version"""
        try:
            result = subprocess.run(
                ["checkov", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Checkov outputs version on first line
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return "unknown"

    def _save_results(self, scan_result: CheckovScanResult, output_file: str) -> None:
        """
        Save scan results to JSON file

        Args:
            scan_result: Scan results
            output_file: Output file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(scan_result.to_dict(), f, indent=2)

        logger.info(f"Results saved to: {output_path}")

    def _print_summary(self, scan_result: CheckovScanResult) -> None:
        """
        Print scan summary to console

        Args:
            scan_result: Scan results
        """
        print("\n" + "=" * 80)
        print("CHECKOV IAC SCAN RESULTS")
        print("=" * 80)
        print(f"Target: {scan_result.target}")
        print(f"Timestamp: {scan_result.timestamp}")
        print(f"Duration: {scan_result.scan_duration_seconds:.1f}s")
        print(f"Checkov Version: {scan_result.checkov_version}")
        print(f"Frameworks: {', '.join(scan_result.frameworks) if scan_result.frameworks else 'auto-detected'}")
        print()
        print(f"Total Checks: {scan_result.total_checks}")
        print(f"Passed:       {scan_result.passed_checks}")
        print(f"Failed:       {scan_result.failed_checks}")
        print(f"Skipped:      {scan_result.skipped_checks}")
        print(f"Parse Errors: {scan_result.parsing_errors}")
        print()

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in scan_result.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        print("Findings by Severity:")
        print(f"  Critical: {severity_counts['CRITICAL']}")
        print(f"  High:     {severity_counts['HIGH']}")
        print(f"  Medium:   {severity_counts['MEDIUM']}")
        print(f"  Low:      {severity_counts['LOW']}")
        print("=" * 80)

        # Show top findings
        if scan_result.findings:
            print("\nTop Findings:")
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_findings = sorted(
                scan_result.findings,
                key=lambda f: severity_order.get(f.severity, 4),
            )

            for i, finding in enumerate(sorted_findings[:5], 1):
                print(f"\n{i}. [{finding.severity}] {finding.check_id}")
                print(f"   {finding.check_name}")
                print(f"   File: {finding.file_path}:{finding.file_line_range[0]}")
                print(f"   Resource: {finding.resource}")
                if finding.guideline:
                    print(f"   Guide: {finding.guideline}")

        print()


def main():
    """CLI entry point for Checkov scanner"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Checkov IaC Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory
  python checkov_scanner.py /path/to/terraform

  # Scan a specific file
  python checkov_scanner.py terraform/main.tf --framework terraform

  # Scan with specific checks only
  python checkov_scanner.py . --checks CKV_AWS_1,CKV_AWS_2

  # Skip certain checks
  python checkov_scanner.py . --skip-checks CKV_AWS_20

Supported Frameworks:
  - terraform (HCL files)
  - kubernetes (YAML manifests)
  - dockerfile
  - cloudformation
  - helm
  - arm (Azure)
  - serverless
        """,
    )

    parser.add_argument("target", help="Target path to scan (file or directory)")
    parser.add_argument(
        "--framework",
        "-f",
        choices=[
            "terraform",
            "kubernetes",
            "dockerfile",
            "cloudformation",
            "helm",
            "arm",
            "serverless",
        ],
        help="Specific framework to scan",
    )
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument(
        "--checks",
        help="Comma-separated list of specific checks to run",
    )
    parser.add_argument(
        "--skip-checks",
        help="Comma-separated list of checks to skip",
    )
    parser.add_argument(
        "--download-modules",
        action="store_true",
        help="Download external Terraform modules",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install Checkov if not present",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build config
    config = {
        "checks": args.checks.split(",") if args.checks else [],
        "skip_checks": args.skip_checks.split(",") if args.skip_checks else [],
        "download_external_modules": args.download_modules,
        "quiet": not args.verbose,
    }

    # Initialize scanner
    scanner = CheckovScanner(config)

    # Install if requested
    if args.install:
        if not scanner.install_checkov():
            logger.error("Failed to install Checkov")
            sys.exit(1)

    try:
        # Run scan
        result = scanner.scan(
            target_path=args.target,
            framework=args.framework,
            output_file=args.output,
        )

        # Exit with error code if critical or high severity findings
        critical_high = sum(1 for f in result.findings if f.severity in ["CRITICAL", "HIGH"])

        if critical_high > 0:
            logger.warning(f"Found {critical_high} critical/high severity issues")
            sys.exit(1)
        else:
            logger.info("No critical or high severity issues found")
            sys.exit(0)

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
