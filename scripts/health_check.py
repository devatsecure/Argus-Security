#!/usr/bin/env python3
"""
Argus Security Action - Health Check Script
Version: 1.1.0

Comprehensive environment validation that checks:
1. Python dependencies and versions
2. External security tools (semgrep, trivy, nuclei, falco, etc.)
3. API keys and environment variables
4. Docker availability and status
5. System requirements (memory, disk, etc.)

Exit codes:
    0: All required dependencies met
    1: Missing required dependencies
    2: Configuration errors
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Check if packaging is available
try:
    from packaging import version as pkg_version

    PACKAGING_AVAILABLE = True
except ImportError:
    PACKAGING_AVAILABLE = False
    print("Warning: 'packaging' module not found. Version checking will be limited.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a single health check"""

    name: str
    status: str  # 'passed', 'failed', 'warning', 'skipped'
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    required: bool = True


@dataclass
class HealthCheckReport:
    """Complete health check report"""

    timestamp: str
    platform: str
    python_version: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    checks: List[CheckResult] = field(default_factory=list)
    overall_status: str = "unknown"


class HealthChecker:
    """Comprehensive environment health checker"""

    def __init__(self, config_path: Optional[Path] = None, verbose: bool = False):
        """
        Initialize health checker

        Args:
            config_path: Path to external-tools.yml config file
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.config_path = config_path or Path(__file__).parent.parent / "external-tools.yml"
        self.results: List[CheckResult] = []

        # Load configuration
        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config from {self.config_path}: {e}")
            self.config = {"tools": [], "environment_variables": []}

    def _extract_version(self, output: str) -> Optional[str]:
        """Extract version number from command output"""
        # Try common version patterns
        patterns = [
            r"(\d+\.\d+\.\d+)",  # Standard semver
            r"v(\d+\.\d+\.\d+)",  # v-prefixed semver
            r"version[:\s]+(\d+\.\d+\.\d+)",  # "version: X.Y.Z"
            r"Version[:\s]+(\d+\.\d+\.\d+)",  # "Version: X.Y.Z"
        ]

        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)

        return None

    def _compare_versions(self, current: str, required: str) -> bool:
        """
        Compare version strings

        Args:
            current: Current version string
            required: Required version string (e.g., ">=1.0.0")

        Returns:
            True if current meets requirement, False otherwise
        """
        if not PACKAGING_AVAILABLE or not current or not required:
            return True  # Skip comparison if packaging unavailable or versions not provided

        try:
            # Parse requirement
            operator = ">="
            if required.startswith(">="):
                operator = ">="
                required_version = required[2:].strip()
            elif required.startswith(">"):
                operator = ">"
                required_version = required[1:].strip()
            elif required.startswith("<="):
                operator = "<="
                required_version = required[2:].strip()
            elif required.startswith("<"):
                operator = "<"
                required_version = required[1:].strip()
            elif required.startswith("=="):
                operator = "=="
                required_version = required[2:].strip()
            else:
                required_version = required.strip()

            # Compare versions
            current_ver = pkg_version.parse(current)
            required_ver = pkg_version.parse(required_version)

            if operator == ">=":
                return current_ver >= required_ver
            elif operator == ">":
                return current_ver > required_ver
            elif operator == "<=":
                return current_ver <= required_ver
            elif operator == "<":
                return current_ver < required_ver
            elif operator == "==":
                return current_ver == required_ver

            return True

        except Exception as e:
            logger.warning(f"Version comparison failed: {e}")
            return True  # Assume OK if comparison fails

    def check_python_dependencies(self) -> CheckResult:
        """Check all Python packages from requirements.txt"""
        try:
            requirements_file = Path(__file__).parent.parent / "requirements.txt"

            if not requirements_file.exists():
                return CheckResult(
                    name="Python Dependencies",
                    status="failed",
                    message="requirements.txt not found",
                    required=True,
                )

            missing = []
            outdated = []
            installed = []

            with open(requirements_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse requirement
                    pkg_name = line.split(">=")[0].split("==")[0].split("<")[0].strip()
                    required_version = None

                    if ">=" in line:
                        required_version = ">=" + line.split(">=")[1].split(",")[0].strip()

                    try:
                        import importlib.metadata

                        installed_version = importlib.metadata.version(pkg_name)
                        installed.append(f"{pkg_name}=={installed_version}")

                        # Check version if specified
                        if required_version and PACKAGING_AVAILABLE:
                            if not self._compare_versions(installed_version, required_version):
                                outdated.append(f"{pkg_name} ({installed_version} < {required_version})")

                    except importlib.metadata.PackageNotFoundError:
                        missing.append(pkg_name)

            if missing:
                return CheckResult(
                    name="Python Dependencies",
                    status="failed",
                    message=f"Missing {len(missing)} package(s): {', '.join(missing)}",
                    details={"missing": missing, "installed": installed, "outdated": outdated},
                    required=True,
                )
            elif outdated:
                return CheckResult(
                    name="Python Dependencies",
                    status="warning",
                    message=f"{len(outdated)} outdated package(s): {', '.join(outdated)}",
                    details={"missing": missing, "installed": installed, "outdated": outdated},
                    required=True,
                )
            else:
                return CheckResult(
                    name="Python Dependencies",
                    status="passed",
                    message=f"All {len(installed)} Python packages installed",
                    details={"missing": missing, "installed": installed, "outdated": outdated},
                    required=True,
                )

        except Exception as e:
            return CheckResult(
                name="Python Dependencies",
                status="failed",
                message=f"Error checking dependencies: {e}",
                required=True,
            )

    def check_external_tool(self, tool_config: Dict[str, Any]) -> CheckResult:
        """
        Check if external tool is installed and meets version requirements

        Args:
            tool_config: Tool configuration from external-tools.yml

        Returns:
            CheckResult with status and details
        """
        name = tool_config["name"]
        check_cmd = tool_config["check"]
        required_version = tool_config.get("version", "")
        optional = tool_config.get("optional", False)
        description = tool_config.get("description", "")

        # Check if tool exists
        tool_path = shutil.which(name)
        if not tool_path:
            if optional:
                return CheckResult(
                    name=f"Tool: {name}",
                    status="skipped",
                    message=f"{name} not installed (optional)",
                    details={"description": description},
                    required=False,
                )
            else:
                return CheckResult(
                    name=f"Tool: {name}",
                    status="failed",
                    message=f"{name} not found in PATH",
                    details={"description": description, "check_command": check_cmd},
                    required=True,
                )

        # Run version check
        try:
            result = subprocess.run(
                check_cmd.split(), capture_output=True, text=True, timeout=10, check=False
            )

            if result.returncode != 0:
                if optional:
                    return CheckResult(
                        name=f"Tool: {name}",
                        status="warning",
                        message=f"{name} found but version check failed",
                        details={
                            "path": tool_path,
                            "description": description,
                            "check_command": check_cmd,
                        },
                        required=False,
                    )
                else:
                    return CheckResult(
                        name=f"Tool: {name}",
                        status="failed",
                        message=f"{name} version check failed",
                        details={
                            "path": tool_path,
                            "description": description,
                            "check_command": check_cmd,
                            "error": result.stderr,
                        },
                        required=True,
                    )

            # Extract and compare version
            output = result.stdout + result.stderr
            current_version = self._extract_version(output)

            if current_version and required_version:
                if self._compare_versions(current_version, required_version):
                    return CheckResult(
                        name=f"Tool: {name}",
                        status="passed",
                        message=f"{name} {current_version} installed ({required_version})",
                        details={
                            "version": current_version,
                            "path": tool_path,
                            "description": description,
                        },
                        required=not optional,
                    )
                else:
                    return CheckResult(
                        name=f"Tool: {name}",
                        status="warning" if optional else "failed",
                        message=f"{name} {current_version} < required {required_version}",
                        details={
                            "version": current_version,
                            "required": required_version,
                            "path": tool_path,
                            "description": description,
                        },
                        required=not optional,
                    )
            else:
                # Version extraction failed, but tool exists
                return CheckResult(
                    name=f"Tool: {name}",
                    status="passed",
                    message=f"{name} installed (version unknown)",
                    details={"path": tool_path, "description": description},
                    required=not optional,
                )

        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"Tool: {name}",
                status="warning",
                message=f"{name} check timed out",
                details={"path": tool_path, "description": description},
                required=not optional,
            )
        except Exception as e:
            return CheckResult(
                name=f"Tool: {name}",
                status="warning" if optional else "failed",
                message=f"{name} check failed: {e}",
                details={"path": tool_path, "description": description, "error": str(e)},
                required=not optional,
            )

    def check_api_keys(self) -> List[CheckResult]:
        """Check if API keys are configured"""
        results = []
        env_vars = self.config.get("environment_variables", [])

        for var_config in env_vars:
            name = var_config["name"]
            description = var_config.get("description", "")
            required = var_config.get("required", False)
            provider = var_config.get("provider", "")

            value = os.getenv(name)

            if value:
                # Mask the key for security
                masked_value = value[:8] + "..." if len(value) > 8 else "***"
                results.append(
                    CheckResult(
                        name=f"API Key: {name}",
                        status="passed",
                        message=f"{name} is set ({masked_value})",
                        details={"provider": provider, "description": description},
                        required=required,
                    )
                )
            else:
                if required:
                    results.append(
                        CheckResult(
                            name=f"API Key: {name}",
                            status="failed",
                            message=f"{name} not set (required)",
                            details={"provider": provider, "description": description},
                            required=True,
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            name=f"API Key: {name}",
                            status="warning",
                            message=f"{name} not set (optional)",
                            details={"provider": provider, "description": description},
                            required=False,
                        )
                    )

        return results

    def check_docker(self) -> CheckResult:
        """Check Docker availability and status"""
        # Check if docker command exists
        docker_path = shutil.which("docker")
        if not docker_path:
            return CheckResult(
                name="Docker",
                status="failed",
                message="Docker not found in PATH",
                details={"required_for": "Sandbox validation"},
                required=True,
            )

        # Check if Docker daemon is running
        try:
            result = subprocess.run(
                ["docker", "ps"], capture_output=True, text=True, timeout=10, check=False
            )

            if result.returncode == 0:
                # Count running containers
                lines = result.stdout.strip().split("\n")
                container_count = len(lines) - 1 if len(lines) > 1 else 0

                # Get Docker version
                version_result = subprocess.run(
                    ["docker", "--version"], capture_output=True, text=True, timeout=5, check=False
                )
                docker_version = self._extract_version(version_result.stdout) or "unknown"

                return CheckResult(
                    name="Docker",
                    status="passed",
                    message=f"Docker {docker_version} running ({container_count} containers)",
                    details={
                        "version": docker_version,
                        "path": docker_path,
                        "running_containers": container_count,
                    },
                    required=True,
                )
            else:
                return CheckResult(
                    name="Docker",
                    status="failed",
                    message="Docker daemon not running",
                    details={"path": docker_path, "error": result.stderr},
                    required=True,
                )

        except subprocess.TimeoutExpired:
            return CheckResult(
                name="Docker",
                status="failed",
                message="Docker check timed out (daemon may be unresponsive)",
                details={"path": docker_path},
                required=True,
            )
        except Exception as e:
            return CheckResult(
                name="Docker",
                status="failed",
                message=f"Docker check failed: {e}",
                details={"path": docker_path, "error": str(e)},
                required=True,
            )

    def check_system_requirements(self) -> List[CheckResult]:
        """Check system requirements (memory, disk, etc.)"""
        results = []

        try:
            import psutil

            # Check memory
            memory = psutil.virtual_memory()
            memory_gb = memory.total / (1024**3)
            min_memory = self.config.get("system_requirements", {}).get("hardware", {}).get("min_memory_gb", 4)

            if memory_gb >= min_memory:
                results.append(
                    CheckResult(
                        name="System: Memory",
                        status="passed",
                        message=f"{memory_gb:.1f}GB RAM available (>= {min_memory}GB required)",
                        details={"total_gb": memory_gb, "required_gb": min_memory},
                        required=True,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="System: Memory",
                        status="warning",
                        message=f"{memory_gb:.1f}GB RAM < {min_memory}GB recommended",
                        details={"total_gb": memory_gb, "required_gb": min_memory},
                        required=True,
                    )
                )

            # Check disk space
            disk = psutil.disk_usage("/")
            disk_free_gb = disk.free / (1024**3)
            min_disk = self.config.get("system_requirements", {}).get("hardware", {}).get("min_disk_gb", 10)

            if disk_free_gb >= min_disk:
                results.append(
                    CheckResult(
                        name="System: Disk Space",
                        status="passed",
                        message=f"{disk_free_gb:.1f}GB free (>= {min_disk}GB required)",
                        details={"free_gb": disk_free_gb, "required_gb": min_disk},
                        required=True,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="System: Disk Space",
                        status="warning",
                        message=f"{disk_free_gb:.1f}GB free < {min_disk}GB recommended",
                        details={"free_gb": disk_free_gb, "required_gb": min_disk},
                        required=True,
                    )
                )

            # Check CPU
            cpu_count = psutil.cpu_count(logical=True)
            min_cpu = self.config.get("system_requirements", {}).get("hardware", {}).get("cpu_cores", 2)

            if cpu_count >= min_cpu:
                results.append(
                    CheckResult(
                        name="System: CPU",
                        status="passed",
                        message=f"{cpu_count} CPU cores (>= {min_cpu} required)",
                        details={"cores": cpu_count, "required": min_cpu},
                        required=True,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="System: CPU",
                        status="warning",
                        message=f"{cpu_count} CPU cores < {min_cpu} recommended",
                        details={"cores": cpu_count, "required": min_cpu},
                        required=True,
                    )
                )

        except ImportError:
            results.append(
                CheckResult(
                    name="System Requirements",
                    status="skipped",
                    message="psutil not installed, cannot check system resources",
                    required=False,
                )
            )

        return results

    def run_all_checks(self) -> HealthCheckReport:
        """Run all health checks and generate report"""
        import datetime

        print("=" * 80)
        print("Argus Security Action - Health Check")
        print("=" * 80)
        print()

        # Platform info
        platform_info = f"{platform.system()} {platform.release()}"
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.minor}"

        print(f"Platform:       {platform_info}")
        print(f"Python:         {python_version}")
        print(f"Config:         {self.config_path}")
        print()
        print("=" * 80)
        print()

        # Run checks
        self.results = []

        # 1. Python dependencies
        print("[1/5] Checking Python dependencies...")
        result = self.check_python_dependencies()
        self.results.append(result)
        self._print_result(result)

        # 2. External tools
        print("\n[2/5] Checking external security tools...")
        tools = self.config.get("tools", [])
        for tool in tools:
            result = self.check_external_tool(tool)
            self.results.append(result)
            self._print_result(result)

        # 3. API keys
        print("\n[3/5] Checking API keys and environment variables...")
        api_results = self.check_api_keys()
        self.results.extend(api_results)
        for result in api_results:
            self._print_result(result)

        # 4. Docker
        print("\n[4/5] Checking Docker...")
        result = self.check_docker()
        self.results.append(result)
        self._print_result(result)

        # 5. System requirements
        print("\n[5/5] Checking system requirements...")
        sys_results = self.check_system_requirements()
        self.results.extend(sys_results)
        for result in sys_results:
            self._print_result(result)

        # Generate summary
        passed = sum(1 for r in self.results if r.status == "passed")
        failed = sum(1 for r in self.results if r.status == "failed")
        warnings = sum(1 for r in self.results if r.status == "warning")
        skipped = sum(1 for r in self.results if r.status == "skipped")

        # Determine overall status
        if failed > 0:
            overall_status = "FAILED"
        elif warnings > 0:
            overall_status = "WARNING"
        else:
            overall_status = "PASSED"

        # Create report
        report = HealthCheckReport(
            timestamp=datetime.datetime.now().isoformat(),
            platform=platform_info,
            python_version=python_version,
            total_checks=len(self.results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            checks=self.results,
            overall_status=overall_status,
        )

        # Print summary
        print()
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Checks:   {report.total_checks}")
        print(f"Passed:         {passed}")
        print(f"Failed:         {failed}")
        print(f"Warnings:       {warnings}")
        print(f"Skipped:        {skipped}")
        print()
        print(f"Overall Status: {overall_status}")
        print("=" * 80)

        if failed > 0:
            print("\nFailed checks:")
            for result in self.results:
                if result.status == "failed":
                    print(f"  - {result.name}: {result.message}")

        if warnings > 0:
            print("\nWarnings:")
            for result in self.results:
                if result.status == "warning":
                    print(f"  - {result.name}: {result.message}")

        return report

    def _print_result(self, result: CheckResult):
        """Print check result with formatting"""
        status_symbols = {
            "passed": "✓",
            "failed": "✗",
            "warning": "⚠",
            "skipped": "○",
        }

        symbol = status_symbols.get(result.status, "?")
        print(f"  {symbol} {result.name}: {result.message}")

        if self.verbose and result.details:
            for key, value in result.details.items():
                print(f"      {key}: {value}")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Argus Security Action - Health Check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config", type=Path, help="Path to external-tools.yml config file", default=None
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--output", type=Path, help="Save report to JSON file", default=None
    )

    args = parser.parse_args()

    # Run health check
    checker = HealthChecker(config_path=args.config, verbose=args.verbose)
    report = checker.run_all_checks()

    # Save report if requested
    if args.output:
        report_dict = {
            "timestamp": report.timestamp,
            "platform": report.platform,
            "python_version": report.python_version,
            "total_checks": report.total_checks,
            "passed": report.passed,
            "failed": report.failed,
            "warnings": report.warnings,
            "skipped": report.skipped,
            "overall_status": report.overall_status,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "details": c.details,
                    "required": c.required,
                }
                for c in report.checks
            ],
        }

        with open(args.output, "w") as f:
            json.dump(report_dict, f, indent=2)
        print(f"\nReport saved to: {args.output}")

    # Exit with appropriate code
    if report.failed > 0:
        print("\n❌ Health check FAILED - missing required dependencies")
        print("💡 Run: python scripts/install_dependencies.py")
        sys.exit(1)
    elif report.warnings > 0:
        print("\n⚠️  Health check PASSED with warnings")
        sys.exit(0)
    else:
        print("\n✅ Health check PASSED - all dependencies met")
        sys.exit(0)


if __name__ == "__main__":
    main()
