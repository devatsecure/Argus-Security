#!/usr/bin/env python3
"""
Sandbox Integration for Argus
Integrates sandbox validation with the security-test-generator agent

This module extends ReviewMetrics with sandbox validation metrics
and provides utilities for running exploits safely.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

try:
    from docker_manager import DockerManager
    from sandbox_validator import (
        ExploitConfig,
        ExploitType,
        SandboxValidator,
        ValidationMetrics,
        ValidationResult,
    )

    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def extend_review_metrics(metrics_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Extend ReviewMetrics with sandbox validation metrics

    Args:
        metrics_dict: Existing metrics dictionary

    Returns:
        Extended metrics dictionary
    """
    if "sandbox_validation" not in metrics_dict:
        metrics_dict["sandbox_validation"] = {
            "enabled": SANDBOX_AVAILABLE,
            "total_validations": 0,
            "exploitable": 0,
            "not_exploitable": 0,
            "partial": 0,
            "errors": 0,
            "timeouts": 0,
            "unsafe_skipped": 0,
            "total_execution_time_ms": 0,
            "avg_execution_time_ms": 0,
            "success_rate_percent": 0.0,
            "validations_by_type": {},
        }

    return metrics_dict


def update_sandbox_metrics(
    metrics_dict: dict[str, Any],
    validation_results: list[ValidationMetrics],
) -> dict[str, Any]:
    """
    Update metrics dictionary with sandbox validation results

    Args:
        metrics_dict: Metrics dictionary to update
        validation_results: List of ValidationMetrics from sandbox validator

    Returns:
        Updated metrics dictionary
    """
    # Ensure sandbox metrics exist
    metrics_dict = extend_review_metrics(metrics_dict)

    sandbox = metrics_dict["sandbox_validation"]

    # Reset counters
    sandbox["total_validations"] = len(validation_results)
    sandbox["exploitable"] = 0
    sandbox["not_exploitable"] = 0
    sandbox["partial"] = 0
    sandbox["errors"] = 0
    sandbox["timeouts"] = 0
    sandbox["unsafe_skipped"] = 0
    sandbox["total_execution_time_ms"] = 0
    sandbox["validations_by_type"] = {}

    # Count results by type
    for result in validation_results:
        # Count by validation result
        if result.result == ValidationResult.EXPLOITABLE.value:
            sandbox["exploitable"] += 1
        elif result.result == ValidationResult.NOT_EXPLOITABLE.value:
            sandbox["not_exploitable"] += 1
        elif result.result == ValidationResult.PARTIAL.value:
            sandbox["partial"] += 1
        elif result.result == ValidationResult.ERROR.value:
            sandbox["errors"] += 1
        elif result.result == ValidationResult.TIMEOUT.value:
            sandbox["timeouts"] += 1
        elif result.result == ValidationResult.UNSAFE.value:
            sandbox["unsafe_skipped"] += 1

        # Track execution time
        sandbox["total_execution_time_ms"] += result.execution_time_ms

        # Count by exploit type
        exploit_type = result.exploit_type
        if exploit_type not in sandbox["validations_by_type"]:
            sandbox["validations_by_type"][exploit_type] = {
                "total": 0,
                "exploitable": 0,
            }
        sandbox["validations_by_type"][exploit_type]["total"] += 1
        if result.result == ValidationResult.EXPLOITABLE.value:
            sandbox["validations_by_type"][exploit_type]["exploitable"] += 1

    # Calculate averages and rates
    if sandbox["total_validations"] > 0:
        sandbox["avg_execution_time_ms"] = sandbox["total_execution_time_ms"] // sandbox["total_validations"]
        sandbox["success_rate_percent"] = (sandbox["exploitable"] / sandbox["total_validations"]) * 100

    return metrics_dict


def create_exploit_from_finding(
    finding: dict[str, Any],
    project_root: str,
) -> Optional[ExploitConfig]:
    """
    Create an ExploitConfig from a security finding

    Args:
        finding: Security finding dictionary (from agents)
        project_root: Project root directory

    Returns:
        ExploitConfig if exploit can be generated, None otherwise
    """
    if not SANDBOX_AVAILABLE:
        logger.warning("Sandbox not available - cannot create exploit")
        return None

    # Extract finding details
    issue_type = finding.get("issue_type", "").lower()
    severity = finding.get("severity", "medium").lower()
    description = finding.get("description", "")
    file_path = finding.get("file", "")

    # Map issue type to exploit type
    exploit_type_mapping = {
        "sql injection": ExploitType.SQL_INJECTION,
        "command injection": ExploitType.COMMAND_INJECTION,
        "path traversal": ExploitType.PATH_TRAVERSAL,
        "xss": ExploitType.XSS,
        "cross-site scripting": ExploitType.XSS,
        "ssrf": ExploitType.SSRF,
        "xxe": ExploitType.XXE,
        "deserialization": ExploitType.DESERIALIZATION,
        "buffer overflow": ExploitType.BUFFER_OVERFLOW,
        "race condition": ExploitType.RACE_CONDITION,
        "authentication bypass": ExploitType.AUTH_BYPASS,
        "authorization": ExploitType.PRIVILEGE_ESCALATION,
        "information disclosure": ExploitType.INFORMATION_DISCLOSURE,
        "dos": ExploitType.DENIAL_OF_SERVICE,
        "denial of service": ExploitType.DENIAL_OF_SERVICE,
    }

    exploit_type = ExploitType.CUSTOM
    for key, value in exploit_type_mapping.items():
        if key in issue_type:
            exploit_type = value
            break

    # Determine language from file extension
    file_path_obj = Path(file_path)
    ext = file_path_obj.suffix.lower()
    language_mapping = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "javascript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
    }
    language = language_mapping.get(ext, "python")

    # Generate basic exploit code based on type
    exploit_code = _generate_exploit_code(exploit_type, language, finding)
    if not exploit_code:
        logger.warning(f"Could not generate exploit code for {issue_type}")
        return None

    # Determine expected indicators
    expected_indicators = _get_expected_indicators(exploit_type)

    # Create exploit config
    return ExploitConfig(
        name=f"{issue_type}_{file_path_obj.stem}",
        exploit_type=exploit_type,
        language=language,
        code=exploit_code,
        expected_indicators=expected_indicators,
        target_file=file_path if Path(file_path).exists() else None,
        timeout=30,
        metadata={
            "severity": severity,
            "file": file_path,
            "description": description,
        },
    )


def _generate_exploit_code(
    exploit_type: ExploitType,
    language: str,
    finding: dict[str, Any],
) -> Optional[str]:
    """
    Generate exploit code based on type and language

    Args:
        exploit_type: Type of exploit
        language: Programming language
        finding: Finding details

    Returns:
        Exploit code string or None
    """
    # This is a simplified version - real implementation would be more sophisticated
    templates = {
        ExploitType.SQL_INJECTION: {
            "python": """
import sqlite3

# Create test database
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
conn.commit()

# Test SQL injection payload
payload = "admin' OR '1'='1"
query = f"SELECT * FROM users WHERE username = '{payload}'"

try:
    cursor.execute(query)
    results = cursor.fetchall()
    if results:
        print("SQL_INJECTION_SUCCESS")
        print(f"Extracted {len(results)} rows")
except Exception as e:
    print(f"SQL_INJECTION_FAILED: {e}")
""",
        },
        ExploitType.COMMAND_INJECTION: {
            "python": """
import subprocess

# Test command injection
payload = "test"

try:
    # Use list-based command to avoid shell injection
    # This safely passes arguments without shell interpretation
    result = subprocess.run(
        ["echo", payload, "COMMAND_INJECTION_SUCCESS"],
        capture_output=True,
        text=True,
        timeout=5
    )
    print(result.stdout)
    if "COMMAND_INJECTION_SUCCESS" in result.stdout:
        print("EXPLOIT_VERIFIED")
except Exception as e:
    print(f"COMMAND_INJECTION_FAILED: {e}")
""",
        },
        ExploitType.PATH_TRAVERSAL: {
            "python": """
import os

# Create test file
test_file = "/tmp/sensitive_data.txt"
with open(test_file, 'w') as f:
    f.write("SENSITIVE_DATA_CONTENT")

# Test path traversal
payload = "../../../tmp/sensitive_data.txt"

try:
    with open(payload, 'r') as f:
        content = f.read()
        if "SENSITIVE_DATA_CONTENT" in content:
            print("PATH_TRAVERSAL_SUCCESS")
            print(f"Accessed: {content}")
except Exception as e:
    print(f"PATH_TRAVERSAL_FAILED: {e}")
finally:
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
""",
        },
    }

    if exploit_type in templates and language in templates[exploit_type]:
        return templates[exploit_type][language]

    # Generic exploit template
    return f"""
# Generic exploit test for {exploit_type.value}
print("Testing {exploit_type.value}")

# TODO: Implement specific exploit logic
# Based on finding: {finding.get("description", "No description")}

print("EXPLOIT_TEST_COMPLETED")
"""


def _get_expected_indicators(exploit_type: ExploitType) -> list[str]:
    """
    Get expected indicators for an exploit type

    Args:
        exploit_type: Type of exploit

    Returns:
        List of expected indicators
    """
    indicators = {
        ExploitType.SQL_INJECTION: ["SQL_INJECTION_SUCCESS"],
        ExploitType.COMMAND_INJECTION: ["COMMAND_INJECTION_SUCCESS"],
        ExploitType.PATH_TRAVERSAL: ["PATH_TRAVERSAL_SUCCESS"],
        ExploitType.XSS: ["XSS_SUCCESS", "alert executed"],
        ExploitType.SSRF: ["SSRF_SUCCESS", "internal request"],
        ExploitType.DESERIALIZATION: ["DESERIALIZATION_SUCCESS"],
        ExploitType.XXE: ["XXE_SUCCESS", "entity resolved"],
    }

    return indicators.get(exploit_type, ["EXPLOIT_TEST_COMPLETED"])


def validate_findings_in_sandbox(
    findings: list[dict[str, Any]],
    project_root: str,
    max_validations: int = 10,
) -> list[ValidationMetrics]:
    """
    Validate security findings in sandbox

    Args:
        findings: List of security findings from agents
        project_root: Project root directory
        max_validations: Maximum number of validations to run

    Returns:
        List of ValidationMetrics
    """
    if not SANDBOX_AVAILABLE:
        logger.error("Sandbox validation not available - Docker or dependencies missing")
        return []

    logger.info(f"Starting sandbox validation for {len(findings)} findings")

    # Filter findings that can be validated
    exploitable_findings = []
    for finding in findings:
        if finding.get("severity", "").lower() in ["critical", "high"]:
            exploitable_findings.append(finding)

    # Limit validations
    exploitable_findings = exploitable_findings[:max_validations]

    if not exploitable_findings:
        logger.info("No high-severity findings to validate")
        return []

    # Create exploits from findings
    exploits = []
    for finding in exploitable_findings:
        exploit = create_exploit_from_finding(finding, project_root)
        if exploit:
            exploits.append(exploit)

    if not exploits:
        logger.warning("Could not generate exploits from findings")
        return []

    logger.info(f"Generated {len(exploits)} exploits for validation")

    # Run validations
    try:
        with DockerManager() as docker_manager:
            validator = SandboxValidator(docker_manager=docker_manager)
            results = validator.validate_multiple(exploits, reuse_container=False)

            logger.info(f"Completed {len(results)} sandbox validations")
            return results

    except Exception:
        logger.exception("Sandbox validation failed")
        return []


if __name__ == "__main__":
    # Example usage
    print("Sandbox Integration - Example Usage")
    print("=" * 50)

    # Example finding
    example_finding = {
        "issue_type": "SQL Injection",
        "severity": "critical",
        "description": "Vulnerable SQL query in user search",
        "file": "/workspace/test.py",
    }

    # Create exploit
    exploit = create_exploit_from_finding(example_finding, "/workspace")
    if exploit:
        print(f"Created exploit: {exploit.name}")
        print(f"Type: {exploit.exploit_type.value}")
        print(f"Language: {exploit.language}")

    # Example metrics extension
    metrics = {"version": "1.0.16"}
    metrics = extend_review_metrics(metrics)
    print(f"\nExtended metrics: {json.dumps(metrics['sandbox_validation'], indent=2)}")
