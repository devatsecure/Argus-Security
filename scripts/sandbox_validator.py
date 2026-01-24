#!/usr/bin/env python3
"""
Sandbox Validator for Argus
Safe exploit validation in isolated Docker containers

Validates PoC exploits with:
- Multi-language support (Python, JavaScript, Java, Go)
- Result analysis and categorization
- Metrics tracking
- Safe execution environment
"""

import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from docker_manager import DockerManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExploitType(Enum):
    """Types of exploits that can be validated"""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "dos"
    CUSTOM = "custom"


class ValidationResult(Enum):
    """Result of exploit validation"""

    EXPLOITABLE = "exploitable"  # Exploit works as expected
    NOT_EXPLOITABLE = "not_exploitable"  # Exploit doesn't work
    PARTIAL = "partial"  # Exploit partially works
    ERROR = "error"  # Error during validation
    TIMEOUT = "timeout"  # Validation timed out
    UNSAFE = "unsafe"  # Exploit is too dangerous to run


@dataclass
class ExploitConfig:
    """Configuration for an exploit to validate"""

    name: str
    exploit_type: ExploitType
    language: str
    code: str
    expected_indicators: list[str]  # Indicators that exploit worked
    target_file: Optional[str] = None
    setup_commands: Optional[list[str]] = None
    cleanup_commands: Optional[list[str]] = None
    timeout: int = 30
    metadata: Optional[dict[str, Any]] = None


@dataclass
class ValidationMetrics:
    """Metrics from validation"""

    validation_id: str
    exploit_name: str
    exploit_type: str
    result: str
    execution_time_ms: int
    stdout: str
    stderr: str
    exit_code: int
    indicators_found: list[str]
    indicators_missing: list[str]
    container_id: str
    timestamp: str
    error_message: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class SandboxValidator:
    """Validates exploits safely in Docker containers"""

    def __init__(
        self,
        docker_manager: Optional[DockerManager] = None,
        results_dir: Optional[str] = None,
    ):
        """
        Initialize sandbox validator

        Args:
            docker_manager: DockerManager instance (creates new one if None)
            results_dir: Directory to save validation results
        """
        self.docker_manager = docker_manager or DockerManager()

        # Try default results location, fallback to /cache for Docker read-only workspaces
        default_results = Path(results_dir) if results_dir else Path(".argus/sandbox-results")
        try:
            default_results.mkdir(parents=True, exist_ok=True)
            # Test if writable
            test_file = default_results / ".write_test"
            test_file.touch()
            test_file.unlink()
            self.results_dir = default_results
        except (PermissionError, OSError):
            # Fallback to /cache for Docker read-only mounts
            self.results_dir = Path("/cache/sandbox-results")
            self.results_dir.mkdir(parents=True, exist_ok=True)
            logger.warning(f"Using fallback results directory: {self.results_dir}")

        self._validation_count = 0
        self._metrics: list[ValidationMetrics] = []

    def validate_exploit(
        self,
        exploit: ExploitConfig,
        create_new_container: bool = True,
        container_id: Optional[str] = None,
    ) -> ValidationMetrics:
        """
        Validate an exploit in a sandbox

        Args:
            exploit: Exploit configuration
            create_new_container: Create a new container for this validation
            container_id: Existing container ID to use (if create_new_container=False)

        Returns:
            ValidationMetrics with results
        """
        self._validation_count += 1
        validation_id = f"validation-{int(time.time())}-{self._validation_count}"

        logger.info(f"Starting validation {validation_id} for {exploit.name}")

        # Pre-validation safety checks
        safety_check = self._safety_check(exploit)
        if not safety_check["safe"]:
            logger.warning(f"Exploit {exploit.name} failed safety check: {safety_check['reason']}")
            return ValidationMetrics(
                validation_id=validation_id,
                exploit_name=exploit.name,
                exploit_type=exploit.exploit_type.value,
                result=ValidationResult.UNSAFE.value,
                execution_time_ms=0,
                stdout="",
                stderr="",
                exit_code=-1,
                indicators_found=[],
                indicators_missing=exploit.expected_indicators,
                container_id="",
                timestamp=datetime.utcnow().isoformat(),
                error_message=safety_check["reason"],
                metadata=exploit.metadata,
            )

        start_time = time.time()
        container_created = False

        try:
            # Create or reuse container
            if create_new_container:
                container_id = self.docker_manager.create_container(
                    name=f"sandbox-{validation_id}",
                    memory_limit="512m",
                    cpu_limit=1.0,
                    network_disabled=True,
                    timeout=exploit.timeout,
                )
                container_created = True
            elif not container_id:
                raise ValueError("container_id required when create_new_container=False")

            # Run setup commands if provided
            if exploit.setup_commands:
                for cmd in exploit.setup_commands:
                    setup_result = self.docker_manager.execute_code(
                        container_id,
                        cmd,
                        language="bash",
                        timeout=30,
                    )
                    if not setup_result["success"]:
                        logger.warning(f"Setup command failed: {cmd}")
                        logger.warning(f"stderr: {setup_result['stderr']}")

            # Copy target file if provided
            if exploit.target_file and Path(exploit.target_file).exists():
                self.docker_manager.copy_to_container(
                    container_id,
                    exploit.target_file,
                    "/workspace",
                )

            # Execute exploit code
            result = self.docker_manager.execute_code(
                container_id,
                exploit.code,
                language=exploit.language,
                timeout=exploit.timeout,
            )

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Analyze results
            indicators_found, indicators_missing = self._analyze_results(
                result["stdout"],
                result["stderr"],
                exploit.expected_indicators,
            )

            # Determine validation result
            validation_result = self._determine_result(
                result,
                indicators_found,
                indicators_missing,
            )

            # Run cleanup commands if provided
            if exploit.cleanup_commands:
                for cmd in exploit.cleanup_commands:
                    cleanup_result = self.docker_manager.execute_code(
                        container_id,
                        cmd,
                        language="bash",
                        timeout=30,
                    )
                    if not cleanup_result["success"]:
                        logger.warning(f"Cleanup command failed: {cmd}")

            # Create metrics
            metrics = ValidationMetrics(
                validation_id=validation_id,
                exploit_name=exploit.name,
                exploit_type=exploit.exploit_type.value,
                result=validation_result.value,
                execution_time_ms=execution_time_ms,
                stdout=result["stdout"],
                stderr=result["stderr"],
                exit_code=result["exit_code"],
                indicators_found=indicators_found,
                indicators_missing=indicators_missing,
                container_id=container_id,
                timestamp=datetime.utcnow().isoformat(),
                metadata=exploit.metadata,
            )

            self._metrics.append(metrics)
            self._save_results(metrics)

            logger.info(
                f"Validation {validation_id} completed: {validation_result.value} "
                f"({len(indicators_found)}/{len(exploit.expected_indicators)} indicators found)"
            )

            return metrics

        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            logger.exception(f"Validation {validation_id} failed with error")

            metrics = ValidationMetrics(
                validation_id=validation_id,
                exploit_name=exploit.name,
                exploit_type=exploit.exploit_type.value,
                result=ValidationResult.ERROR.value,
                execution_time_ms=execution_time_ms,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                indicators_found=[],
                indicators_missing=exploit.expected_indicators,
                container_id=container_id or "",
                timestamp=datetime.utcnow().isoformat(),
                error_message=str(e),
                metadata=exploit.metadata,
            )

            self._metrics.append(metrics)
            self._save_results(metrics)

            return metrics

        finally:
            # Clean up container if we created it
            if container_created and container_id:
                try:
                    self.docker_manager.stop_container(container_id, timeout=5)
                    self.docker_manager.remove_container(container_id, force=True)
                except Exception as e:
                    logger.warning(f"Failed to clean up container {container_id}: {e}")

    def validate_multiple(
        self,
        exploits: list[ExploitConfig],
        reuse_container: bool = False,
    ) -> list[ValidationMetrics]:
        """
        Validate multiple exploits

        Args:
            exploits: List of exploit configurations
            reuse_container: Reuse the same container for all exploits

        Returns:
            List of ValidationMetrics
        """
        results = []
        container_id = None

        try:
            if reuse_container:
                container_id = self.docker_manager.create_container(
                    name=f"sandbox-batch-{int(time.time())}",
                    memory_limit="1g",
                    cpu_limit=2.0,
                    network_disabled=True,
                )

            for exploit in exploits:
                result = self.validate_exploit(
                    exploit,
                    create_new_container=not reuse_container,
                    container_id=container_id,
                )
                results.append(result)

        finally:
            if reuse_container and container_id:
                try:
                    self.docker_manager.stop_container(container_id, timeout=5)
                    self.docker_manager.remove_container(container_id, force=True)
                except Exception as e:
                    logger.warning(f"Failed to clean up batch container: {e}")

        return results

    def _safety_check(self, exploit: ExploitConfig) -> dict[str, Any]:
        """
        Perform safety checks on exploit code

        Args:
            exploit: Exploit configuration

        Returns:
            Dict with 'safe' bool and 'reason' string
        """
        # Dangerous patterns that should not be executed
        dangerous_patterns = [
            (r"rm\s+-rf\s+/", "Attempting to delete root filesystem"),
            (r":()\{\s*:\|\:&\s*\};:", "Fork bomb detected"),
            (r"dd\s+if=/dev/zero", "Disk filling attack detected"),
            (r"wget.*\|.*sh", "Remote code execution via wget pipe"),
            (r"curl.*\|.*sh", "Remote code execution via curl pipe"),
            (r"mkfs\.", "Filesystem formatting detected"),
            (r"shutdown|reboot|halt", "System shutdown/reboot detected"),
        ]

        code_lower = exploit.code.lower()

        for pattern, reason in dangerous_patterns:
            if re.search(pattern, code_lower, re.IGNORECASE):
                return {"safe": False, "reason": reason}

        # Additional checks based on exploit type
        if exploit.exploit_type == ExploitType.DENIAL_OF_SERVICE and re.search(r"while\s+true", code_lower):
            return {"safe": False, "reason": "Infinite loop detected in DoS exploit"}

        return {"safe": True, "reason": ""}

    def _analyze_results(
        self,
        stdout: str,
        stderr: str,
        expected_indicators: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Analyze execution results for exploit indicators

        Args:
            stdout: Standard output
            stderr: Standard error
            expected_indicators: List of expected indicators

        Returns:
            Tuple of (indicators_found, indicators_missing)
        """
        combined_output = (stdout + "\n" + stderr).lower()
        indicators_found = []
        indicators_missing = []

        for indicator in expected_indicators:
            if indicator.lower() in combined_output:
                indicators_found.append(indicator)
            else:
                indicators_missing.append(indicator)

        return indicators_found, indicators_missing

    def _determine_result(
        self,
        execution_result: dict[str, Any],
        indicators_found: list[str],
        indicators_missing: list[str],
    ) -> ValidationResult:
        """
        Determine validation result based on execution and indicators

        Args:
            execution_result: Result from docker_manager.execute_code
            indicators_found: List of found indicators
            indicators_missing: List of missing indicators

        Returns:
            ValidationResult
        """
        # Check for timeout (exit code 124 is timeout command's timeout code)
        if execution_result["exit_code"] == 124:
            return ValidationResult.TIMEOUT

        # Check for errors
        if not execution_result["success"] and execution_result["exit_code"] != 0 and not indicators_found:
            # Some exploits may intentionally return non-zero
            # Only consider it an error if no indicators were found
            return ValidationResult.ERROR

        # Determine based on indicators
        total_indicators = len(indicators_found) + len(indicators_missing)

        if total_indicators == 0:
            # No indicators specified - use exit code
            return ValidationResult.EXPLOITABLE if execution_result["success"] else ValidationResult.NOT_EXPLOITABLE

        found_ratio = len(indicators_found) / total_indicators

        if found_ratio == 1.0:
            return ValidationResult.EXPLOITABLE
        elif found_ratio >= 0.5:
            return ValidationResult.PARTIAL
        else:
            return ValidationResult.NOT_EXPLOITABLE

    def _save_results(self, metrics: ValidationMetrics) -> None:
        """
        Save validation results to file

        Args:
            metrics: ValidationMetrics to save
        """
        try:
            result_file = self.results_dir / f"{metrics.validation_id}.json"
            with open(result_file, "w") as f:
                json.dump(asdict(metrics), f, indent=2)
            logger.debug(f"Saved results to {result_file}")
        except Exception as e:
            logger.warning(f"Failed to save results: {e}")

    def get_metrics_summary(self) -> dict[str, Any]:
        """
        Get summary of all validation metrics

        Returns:
            Dict with summary statistics
        """
        if not self._metrics:
            return {
                "total_validations": 0,
                "by_result": {},
                "by_exploit_type": {},
                "avg_execution_time_ms": 0,
            }

        total = len(self._metrics)
        by_result = {}
        by_exploit_type = {}
        total_time = 0

        for metric in self._metrics:
            # Count by result
            by_result[metric.result] = by_result.get(metric.result, 0) + 1

            # Count by exploit type
            by_exploit_type[metric.exploit_type] = by_exploit_type.get(metric.exploit_type, 0) + 1

            total_time += metric.execution_time_ms

        return {
            "total_validations": total,
            "by_result": by_result,
            "by_exploit_type": by_exploit_type,
            "avg_execution_time_ms": total_time // total if total > 0 else 0,
            "success_rate": (by_result.get(ValidationResult.EXPLOITABLE.value, 0) / total) * 100,
        }

    def export_metrics(self, output_file: str) -> None:
        """
        Export all metrics to a JSON file

        Args:
            output_file: Path to output file
        """
        try:
            with open(output_file, "w") as f:
                json.dump(
                    {
                        "summary": self.get_metrics_summary(),
                        "validations": [asdict(m) for m in self._metrics],
                    },
                    f,
                    indent=2,
                )
            logger.info(f"Exported metrics to {output_file}")
        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")


def create_example_exploits() -> list[ExploitConfig]:
    """Create example exploits for testing"""
    return [
        # SQL Injection example
        ExploitConfig(
            name="SQL Injection - Basic",
            exploit_type=ExploitType.SQL_INJECTION,
            language="python",
            code="""
import sqlite3

# Create test database
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
conn.commit()

# Vulnerable query (for demonstration)
username = "admin' OR '1'='1"
query = f"SELECT * FROM users WHERE username = '{username}'"
print(f"Query: {query}")

cursor.execute(query)
results = cursor.fetchall()
print(f"Results: {results}")

if len(results) > 0:
    print("SQL_INJECTION_SUCCESS")
""",
            expected_indicators=["SQL_INJECTION_SUCCESS"],
            timeout=10,
            metadata={"severity": "high", "cwe": "CWE-89"},
        ),
        # Command Injection example
        ExploitConfig(
            name="Command Injection - Basic",
            exploit_type=ExploitType.COMMAND_INJECTION,
            language="python",
            code="""
import subprocess
import shlex

# Vulnerable code (for demonstration)
user_input = "test; echo COMMAND_INJECTION_SUCCESS"

# FIXED: Use list-based command instead of shell=True
# This prevents command injection by not invoking a shell
command = ["echo", user_input]

result = subprocess.run(command, capture_output=True, text=True)
print(result.stdout)
print(result.stderr)
""",
            expected_indicators=["COMMAND_INJECTION_SUCCESS"],
            timeout=10,
            metadata={"severity": "critical", "cwe": "CWE-78"},
        ),
        # Path Traversal example
        ExploitConfig(
            name="Path Traversal - Basic",
            exploit_type=ExploitType.PATH_TRAVERSAL,
            language="python",
            code="""
import os

# Create test file
with open('/tmp/secret.txt', 'w') as f:
    f.write('SECRET_DATA')

# Vulnerable code (for demonstration)
filename = "../../../tmp/secret.txt"
try:
    with open(filename, 'r') as f:
        content = f.read()
        print(f"File content: {content}")
        if "SECRET_DATA" in content:
            print("PATH_TRAVERSAL_SUCCESS")
except Exception as e:
    print(f"Error: {e}")
""",
            expected_indicators=["PATH_TRAVERSAL_SUCCESS"],
            timeout=10,
            metadata={"severity": "high", "cwe": "CWE-22"},
        ),
    ]


if __name__ == "__main__":
    import sys

    print("Sandbox Validator - Example Usage")
    print("=" * 50)

    # Check if Docker is available
    try:
        manager = DockerManager()
        print("Docker is available")
    except Exception as e:
        print(f"Docker is not available: {e}")
        print("Please ensure Docker is installed and running")
        sys.exit(1)

    # Create validator
    validator = SandboxValidator(docker_manager=manager)

    # Create example exploits
    exploits = create_example_exploits()
    print(f"\nValidating {len(exploits)} example exploits...")

    # Validate exploits
    results = validator.validate_multiple(exploits, reuse_container=False)

    # Print results
    print("\n" + "=" * 50)
    print("VALIDATION RESULTS")
    print("=" * 50)

    for result in results:
        print(f"\nExploit: {result.exploit_name}")
        print(f"Type: {result.exploit_type}")
        print(f"Result: {result.result}")
        print(f"Execution Time: {result.execution_time_ms}ms")
        print(
            f"Indicators Found: {len(result.indicators_found)}/{len(result.indicators_found) + len(result.indicators_missing)}"
        )
        if result.indicators_found:
            print(f"  - {', '.join(result.indicators_found)}")
        if result.error_message:
            print(f"Error: {result.error_message}")

    # Print summary
    summary = validator.get_metrics_summary()
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"Total Validations: {summary['total_validations']}")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Average Execution Time: {summary['avg_execution_time_ms']}ms")
    print("\nResults by Type:")
    for result_type, count in summary["by_result"].items():
        print(f"  - {result_type}: {count}")

    # Export metrics
    export_file = ".argus/sandbox-results/metrics-summary.json"
    validator.export_metrics(export_file)
    print(f"\nMetrics exported to: {export_file}")
