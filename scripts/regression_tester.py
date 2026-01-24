#!/usr/bin/env python3
"""
Security Regression Testing for Argus
Ensures fixed vulnerabilities don't reappear

This module generates regression tests from fixed security findings and runs them
to detect if vulnerabilities have been reintroduced.

Usage:
    # Generate tests from fixed findings
    python regression_tester.py --mode generate --fixed-findings fixed.json

    # Run all regression tests
    python regression_tester.py --mode run

    # Run specific vulnerability type
    python regression_tester.py --mode run --vuln-type sql-injection

    # Update existing tests
    python regression_tester.py --mode update --test-id abc123
"""

import hashlib
import json
import logging
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RegressionTest:
    """Security regression test with metadata"""

    test_id: str
    vulnerability_type: str
    cve_id: Optional[str]
    cwe_id: str
    file_path: str
    function_name: str
    date_fixed: str
    test_code: str
    language: str
    description: str
    severity: str = "medium"
    exploit_payload: Optional[str] = None
    expected_behavior: str = "should_sanitize"


class RegressionTester:
    """Generate and run security regression tests"""

    SUPPORTED_LANGUAGES = ["python", "javascript", "typescript", "go", "java"]

    def __init__(self, test_dir: Path = None):
        # Use /cache for Docker containers with read-only workspace, otherwise use tests/
        default_dir = Path("tests/security_regression")
        if test_dir:
            self.test_dir = test_dir
        else:
            # Try to use default, fallback to /cache if not writable
            try:
                default_dir.mkdir(parents=True, exist_ok=True)
                # Test if writable
                test_file = default_dir / ".write_test"
                test_file.touch()
                test_file.unlink()
                self.test_dir = default_dir
            except (PermissionError, OSError):
                # Fallback to /cache for Docker read-only mounts
                self.test_dir = Path("/cache/security_regression")
                self.test_dir.mkdir(parents=True, exist_ok=True)

        self.tests: List[RegressionTest] = []
        self._load_existing_tests()

    def generate_regression_test(self, fixed_finding: Dict[str, Any]) -> RegressionTest:
        """Generate regression test for a fixed vulnerability"""
        vuln_type = fixed_finding.get("type", "unknown")
        file_path = fixed_finding.get("path", "")
        cve_id = fixed_finding.get("cve")
        cwe_id = fixed_finding.get("cwe", "CWE-Unknown")
        description = fixed_finding.get("description", "")
        severity = fixed_finding.get("severity", "medium")

        logger.info(f"Generating regression test for {vuln_type} in {file_path}")

        # Generate test ID from finding fingerprint
        test_id = self._generate_test_id(vuln_type, file_path, cve_id or "")

        # Detect language
        language = self._detect_language(file_path)

        if language not in self.SUPPORTED_LANGUAGES:
            logger.warning(f"Unsupported language for {file_path}: {language}")
            language = "python"  # Default fallback

        # Extract function name from finding
        function_name = self._extract_function_name(fixed_finding)

        # Determine exploit payload and expected behavior
        exploit_payload = self._get_exploit_payload(vuln_type)
        expected_behavior = self._get_expected_behavior(vuln_type)

        # Generate test code
        test_code = self._generate_test_code(
            language, vuln_type, file_path, function_name, exploit_payload
        )

        test = RegressionTest(
            test_id=test_id,
            vulnerability_type=vuln_type,
            cve_id=cve_id,
            cwe_id=cwe_id,
            file_path=file_path,
            function_name=function_name,
            date_fixed=datetime.utcnow().isoformat(),
            test_code=test_code,
            language=language,
            description=description,
            severity=severity,
            exploit_payload=exploit_payload,
            expected_behavior=expected_behavior,
        )

        # Save test
        self._save_test(test)
        self.tests.append(test)

        logger.info(f"✅ Generated regression test {test_id}")
        return test

    def _generate_test_id(self, vuln_type: str, file_path: str, cve_id: str) -> str:
        """Generate unique test ID"""
        content = f"{vuln_type}{file_path}{cve_id}".encode()
        return hashlib.sha256(content).hexdigest()[:12]

    def _extract_function_name(self, finding: Dict[str, Any]) -> str:
        """Extract function name from finding"""
        # Try different fields where function name might be
        for field in ["function", "method", "symbol", "target"]:
            if field in finding and finding[field]:
                return finding[field]

        # Try to extract from code snippet if available
        snippet = finding.get("snippet", "")
        if snippet and "def " in snippet:
            # Python function
            start = snippet.find("def ") + 4
            end = snippet.find("(", start)
            if end > start:
                return snippet[start:end].strip()

        return "vulnerable_function"

    def _get_exploit_payload(self, vuln_type: str) -> str:
        """Get typical exploit payload for vulnerability type"""
        payloads = {
            "sql-injection": "' OR '1'='1",
            "sql_injection": "' OR '1'='1",
            "xss": "<script>alert('XSS')</script>",
            "cross-site-scripting": "<script>alert('XSS')</script>",
            "command-injection": "; cat /etc/passwd",
            "command_injection": "; cat /etc/passwd",
            "path-traversal": "../../etc/passwd",
            "path_traversal": "../../etc/passwd",
            "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "ssrf": "http://169.254.169.254/latest/meta-data/",
            "ldap-injection": "*)(uid=*))(|(uid=*",
            "csrf": "malicious_token_value",
            "open-redirect": "https://evil.com",
        }
        return payloads.get(vuln_type.lower(), "malicious_input")

    def _get_expected_behavior(self, vuln_type: str) -> str:
        """Get expected behavior after fix"""
        behaviors = {
            "sql-injection": "should_use_parameterized_query",
            "xss": "should_escape_output",
            "command-injection": "should_reject_or_sanitize",
            "path-traversal": "should_validate_path",
            "xxe": "should_disable_external_entities",
            "ssrf": "should_validate_url",
        }
        return behaviors.get(vuln_type.lower(), "should_sanitize")

    def _generate_test_code(
        self,
        language: str,
        vuln_type: str,
        file_path: str,
        function_name: str,
        exploit_payload: str,
    ) -> str:
        """Generate test code for vulnerability"""
        if language == "python":
            return self._generate_python_test(
                vuln_type, file_path, function_name, exploit_payload
            )
        elif language in ["javascript", "typescript"]:
            return self._generate_javascript_test(
                vuln_type, file_path, function_name, exploit_payload
            )
        elif language == "go":
            return self._generate_go_test(
                vuln_type, file_path, function_name, exploit_payload
            )
        else:
            return self._generate_generic_test(vuln_type, file_path, function_name)

    def _generate_python_test(
        self, vuln_type: str, file_path: str, function_name: str, exploit_payload: str
    ) -> str:
        """Generate Python pytest test"""
        module_path = file_path.replace("/", ".").replace(".py", "")
        vuln_snake = vuln_type.lower().replace("-", "_")

        # Vulnerability-specific test templates
        templates = {
            "sql_injection": '''
import pytest
from {module_path} import {function_name}

def test_sql_injection_regression():
    """Regression test: Ensure SQL injection is still fixed"""
    # Test with SQL injection payload
    malicious_input = "{exploit_payload}"

    # Should NOT execute SQL injection (should sanitize or use parameterized query)
    try:
        result = {function_name}(malicious_input)
        # If we get here, check that injection didn't work
        result_str = str(result)
        assert "1'='1" not in result_str, "SQL injection vulnerability returned!"
        assert len(result_str) < 1000, "Suspiciously large result - possible injection"
    except ValueError:
        # Expected: should raise error for malicious input
        pass
    except Exception as e:
        # Should not crash with other errors
        if "SQL" in str(e) and "syntax" in str(e).lower():
            pytest.fail("SQL injection still possible - syntax error indicates unescaped SQL")

def test_sql_injection_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "valid_user_123"
    result = {function_name}(normal_input)
    assert result is not None, "Function broken for normal input"
''',
            "xss": '''
import pytest
from {module_path} import {function_name}

def test_xss_regression():
    """Regression test: Ensure XSS is still fixed"""
    xss_payload = "{exploit_payload}"

    result = {function_name}(xss_payload)

    # Output should be escaped
    assert "<script>" not in result, "XSS vulnerability returned - script tag not escaped!"
    assert "alert(" not in result or "&lt;" in result, "JavaScript not properly escaped"

    # Check for common XSS evasion techniques
    evasion_payloads = [
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
    ]

    for payload in evasion_payloads:
        result = {function_name}(payload)
        assert "onerror=" not in result and "onload=" not in result, f"XSS evasion possible: {{payload}}"

def test_xss_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "Hello <b>World</b>"
    result = {function_name}(normal_input)
    assert "Hello" in result, "Normal text missing from output"
''',
            "command_injection": '''
import pytest
from {module_path} import {function_name}

def test_command_injection_regression():
    """Regression test: Ensure command injection is still fixed"""
    malicious_inputs = [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
    ]

    for malicious_input in malicious_inputs:
        # Should not execute command
        try:
            result = {function_name}(malicious_input)
            # If no exception, verify command wasn't executed
            result_str = str(result)
            assert "root:" not in result_str, f"Command injection possible with: {{malicious_input}}"
            assert "/bin/bash" not in result_str, "System files accessible"
        except (ValueError, SecurityError, PermissionError):
            # Expected: should raise error for malicious input
            pass

def test_command_injection_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "test.txt"
    result = {function_name}(normal_input)
    assert result is not None, "Function broken for normal input"
''',
            "path_traversal": '''
import pytest
from {module_path} import {function_name}

def test_path_traversal_regression():
    """Regression test: Ensure path traversal is still fixed"""
    traversal_payloads = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..\\\\..\\\\windows\\\\system32",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    for payload in traversal_payloads:
        try:
            result = {function_name}(payload)
            # Should not access sensitive files
            result_str = str(result)
            assert "root:" not in result_str, f"Path traversal possible: {{payload}}"
            assert "system32" not in result_str.lower(), "Windows system files accessible"
        except (ValueError, FileNotFoundError, PermissionError):
            # Expected: should reject or sanitize path
            pass

def test_path_traversal_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "safe/path/file.txt"
    result = {function_name}(normal_input)
    assert result is not None, "Function broken for normal path"
''',
        }

        # Get template or use generic
        template = templates.get(vuln_snake)

        if not template:
            # Generic template for other vulnerability types
            template = '''
import pytest
from {module_path} import {function_name}

def test_{vuln_snake}_regression():
    """Regression test for {vuln_type}"""
    malicious_input = "{exploit_payload}"

    # Test that vulnerability is fixed
    try:
        result = {function_name}(malicious_input)
        # Verify malicious input was sanitized
        assert isinstance(result, (str, dict, list)), "Unexpected return type"
    except ValueError:
        # Expected: should reject malicious input
        pass

def test_{vuln_snake}_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "safe_input_value"
    result = {function_name}(normal_input)
    assert result is not None, "Function broken for normal input"
'''

        return template.format(
            module_path=module_path,
            function_name=function_name,
            exploit_payload=exploit_payload,
            vuln_type=vuln_type,
            vuln_snake=vuln_snake,
        )

    def _generate_javascript_test(
        self, vuln_type: str, file_path: str, function_name: str, exploit_payload: str
    ) -> str:
        """Generate JavaScript/TypeScript Jest test"""
        import_path = file_path.replace(".js", "").replace(".ts", "")

        template = f'''
const {{ {function_name} }} = require('{import_path}');

describe('Security Regression: {vuln_type}', () => {{
    test('should prevent {vuln_type} vulnerability', () => {{
        const maliciousInput = '{exploit_payload}';

        // Should handle malicious input safely
        expect(() => {{
            const result = {function_name}(maliciousInput);

            // Verify output is sanitized
            if (typeof result === 'string') {{
                expect(result).not.toContain('<script>');
                expect(result).not.toContain('onerror=');
            }}
        }}).not.toThrow();
    }});

    test('should work with normal input', () => {{
        const normalInput = 'Hello World';
        const result = {function_name}(normalInput);

        expect(result).toBeDefined();
        expect(result).toContain('Hello World');
    }});

    test('should handle edge cases', () => {{
        const edgeCases = ['', null, undefined, 123];

        edgeCases.forEach(input => {{
            expect(() => {{
                {function_name}(input);
            }}).not.toThrow();
        }});
    }});
}});
'''
        return template

    def _generate_go_test(
        self, vuln_type: str, file_path: str, function_name: str, exploit_payload: str
    ) -> str:
        """Generate Go test"""
        package_name = Path(file_path).parent.name or "main"

        template = f'''
package {package_name}

import (
    "testing"
    "strings"
)

func TestRegressionSecurity{function_name.title()}(t *testing.T) {{
    maliciousInput := "{exploit_payload}"

    result, err := {function_name}(maliciousInput)
    if err != nil {{
        // Expected: should reject malicious input
        return
    }}

    // Verify output is sanitized
    if strings.Contains(result, "<script>") {{
        t.Error("XSS vulnerability still present")
    }}
}}

func TestNormalInput{function_name.title()}(t *testing.T) {{
    normalInput := "safe input"

    result, err := {function_name}(normalInput)
    if err != nil {{
        t.Errorf("Function broken for normal input: %v", err)
    }}

    if result == "" {{
        t.Error("Empty result for normal input")
    }}
}}
'''
        return template

    def _generate_generic_test(
        self, vuln_type: str, file_path: str, function_name: str
    ) -> str:
        """Generate generic test template"""
        return f'''
# Regression test for {vuln_type}
# File: {file_path}
# Function: {function_name}

# TODO: Implement test for {vuln_type}
# This test should verify that the vulnerability is still fixed
'''

    def _save_test(self, test: RegressionTest):
        """Save test to disk"""
        # Organize by vulnerability type
        vuln_dir = self.test_dir / test.vulnerability_type.lower().replace("-", "_")
        vuln_dir.mkdir(parents=True, exist_ok=True)

        # Determine file extension
        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts", "go": "_test.go"}
        ext = ext_map.get(test.language, ".py")
        test_file = vuln_dir / f"test_{test.test_id}{ext}"

        # Write test code
        with open(test_file, "w") as f:
            f.write(test.test_code)

        # Write metadata
        metadata_file = vuln_dir / f"test_{test.test_id}.json"
        with open(metadata_file, "w") as f:
            json.dump(asdict(test), f, indent=2)

        logger.info(f"Saved regression test to {test_file}")

    def _load_existing_tests(self):
        """Load existing regression tests"""
        if not self.test_dir.exists():
            return

        for metadata_file in self.test_dir.glob("**/*.json"):
            try:
                with open(metadata_file) as f:
                    metadata = json.load(f)

                # Find corresponding test file
                test_id = metadata["test_id"]
                language = metadata.get("language", "python")

                ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts", "go": "_test.go"}
                ext = ext_map.get(language, ".py")
                test_file = metadata_file.parent / f"test_{test_id}{ext}"

                if test_file.exists():
                    with open(test_file) as f:
                        test_code = f.read()

                    test = RegressionTest(
                        test_id=metadata["test_id"],
                        vulnerability_type=metadata["vulnerability_type"],
                        cve_id=metadata.get("cve_id"),
                        cwe_id=metadata["cwe_id"],
                        file_path=metadata["file_path"],
                        function_name=metadata["function_name"],
                        date_fixed=metadata["date_fixed"],
                        test_code=test_code,
                        language=language,
                        description=metadata.get("description", ""),
                        severity=metadata.get("severity", "medium"),
                        exploit_payload=metadata.get("exploit_payload"),
                        expected_behavior=metadata.get("expected_behavior", "should_sanitize"),
                    )

                    self.tests.append(test)
            except Exception as e:
                logger.warning(f"Failed to load test {metadata_file}: {e}")

        logger.info(f"Loaded {len(self.tests)} existing regression tests")

    def run_all_tests(self, vuln_type: Optional[str] = None) -> Dict[str, Any]:
        """Run all regression tests"""
        tests_to_run = self.tests
        if vuln_type:
            tests_to_run = [t for t in self.tests if t.vulnerability_type == vuln_type]

        logger.info(f"Running {len(tests_to_run)} regression tests")

        results = {
            "total": len(tests_to_run),
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "failures": [],
            "timestamp": datetime.utcnow().isoformat(),
        }

        for test in tests_to_run:
            try:
                if test.language == "python":
                    success, output = self._run_pytest(test)
                elif test.language in ["javascript", "typescript"]:
                    success, output = self._run_jest(test)
                elif test.language == "go":
                    success, output = self._run_go_test(test)
                else:
                    logger.warning(f"Unsupported language: {test.language}")
                    results["skipped"] += 1
                    continue

                if success:
                    results["passed"] += 1
                    logger.info(f"✅ Test passed: {test.test_id}")
                else:
                    results["failed"] += 1
                    results["failures"].append(
                        {
                            "test_id": test.test_id,
                            "vulnerability": test.vulnerability_type,
                            "file": test.file_path,
                            "severity": test.severity,
                            "output": output[:500] if output else "No output",
                        }
                    )
                    logger.error(f"❌ Test failed: {test.test_id} - {test.vulnerability_type}")
            except Exception as e:
                results["errors"] += 1
                logger.error(f"⚠️  Error running test {test.test_id}: {e}")

        self._print_results(results)

        # Try to save results, but don't fail if filesystem is read-only (Docker containers)
        try:
            self._save_results(results)
        except (PermissionError, OSError) as e:
            logger.warning(f"Could not save regression test results (read-only filesystem?): {e}")
            logger.info("Results displayed above but not persisted to disk")

        return results

    def _run_pytest(self, test: RegressionTest) -> tuple[bool, str]:
        """Run Python pytest"""
        test_file = (
            self.test_dir
            / test.vulnerability_type.lower().replace("-", "_")
            / f"test_{test.test_id}.py"
        )

        if not test_file.exists():
            logger.error(f"Test file not found: {test_file}")
            return False, "Test file not found"

        try:
            result = subprocess.run(
                ["pytest", str(test_file), "-v", "--tb=short"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Test timed out after 60 seconds"
        except FileNotFoundError:
            logger.warning("pytest not found - skipping Python tests")
            return False, "pytest not installed"
        except Exception as e:
            logger.error(f"pytest failed: {e}")
            return False, str(e)

    def _run_jest(self, test: RegressionTest) -> tuple[bool, str]:
        """Run JavaScript/TypeScript Jest"""
        ext = ".js" if test.language == "javascript" else ".ts"
        test_file = (
            self.test_dir
            / test.vulnerability_type.lower().replace("-", "_")
            / f"test_{test.test_id}{ext}"
        )

        if not test_file.exists():
            return False, "Test file not found"

        try:
            result = subprocess.run(
                ["jest", str(test_file), "--verbose"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Test timed out after 60 seconds"
        except FileNotFoundError:
            logger.warning("jest not found - skipping JavaScript tests")
            return False, "jest not installed"
        except Exception as e:
            return False, str(e)

    def _run_go_test(self, test: RegressionTest) -> tuple[bool, str]:
        """Run Go test"""
        test_file = (
            self.test_dir
            / test.vulnerability_type.lower().replace("-", "_")
            / f"test_{test.test_id}_test.go"
        )

        if not test_file.exists():
            return False, "Test file not found"

        try:
            result = subprocess.run(
                ["go", "test", "-v", str(test_file)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, "Test timed out after 60 seconds"
        except FileNotFoundError:
            logger.warning("go not found - skipping Go tests")
            return False, "go not installed"
        except Exception as e:
            return False, str(e)

    def _print_results(self, results: Dict[str, Any]):
        """Print test results"""
        print("\n" + "=" * 80)
        print("🧪 SECURITY REGRESSION TEST RESULTS")
        print("=" * 80)
        print(f"\nTotal Tests: {results['total']}")
        print(f"✅ Passed: {results['passed']}")
        print(f"❌ Failed: {results['failed']}")
        print(f"⚠️  Errors: {results['errors']}")
        print(f"⏭️  Skipped: {results['skipped']}")

        if results["failures"]:
            print(f"\n{'='*80}")
            print("❌ FAILED TESTS - VULNERABILITIES MAY HAVE RETURNED:")
            print(f"{'='*80}")
            for failure in results["failures"]:
                print(f"\n  🚨 {failure['vulnerability'].upper()} [{failure['severity']}]")
                print(f"     File: {failure['file']}")
                print(f"     Test ID: {failure['test_id']}")
                if failure.get("output"):
                    print(f"     Output: {failure['output'][:200]}")

        success_rate = (
            (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0
        )
        print(f"\n{'='*80}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"{'='*80}\n")

    def _save_results(self, results: Dict[str, Any]):
        """Save test results to JSON"""
        results_file = self.test_dir / "latest_results.json"
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {results_file}")

    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension"""
        ext = Path(file_path).suffix.lower()

        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
        }

        return mapping.get(ext, "unknown")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about regression tests"""
        stats = {
            "total_tests": len(self.tests),
            "by_language": {},
            "by_vulnerability": {},
            "by_severity": {},
        }

        for test in self.tests:
            # Count by language
            stats["by_language"][test.language] = (
                stats["by_language"].get(test.language, 0) + 1
            )

            # Count by vulnerability type
            stats["by_vulnerability"][test.vulnerability_type] = (
                stats["by_vulnerability"].get(test.vulnerability_type, 0) + 1
            )

            # Count by severity
            stats["by_severity"][test.severity] = stats["by_severity"].get(test.severity, 0) + 1

        return stats


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Security Regression Testing for Argus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate tests from fixed findings
  python regression_tester.py --mode generate --fixed-findings fixed.json

  # Run all regression tests
  python regression_tester.py --mode run

  # Run specific vulnerability type
  python regression_tester.py --mode run --vuln-type sql-injection

  # Show statistics
  python regression_tester.py --mode stats
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["generate", "run", "stats"],
        required=True,
        help="Operation mode",
    )
    parser.add_argument("--fixed-findings", help="JSON file with fixed findings")
    parser.add_argument("--test-dir", help="Test directory (default: tests/security_regression)")
    parser.add_argument("--vuln-type", help="Filter by vulnerability type")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Initialize tester
    tester = RegressionTester(Path(args.test_dir) if args.test_dir else None)

    if args.mode == "generate":
        if not args.fixed_findings:
            print("❌ Error: --fixed-findings required for generate mode")
            sys.exit(1)

        try:
            with open(args.fixed_findings) as f:
                findings = json.load(f)

            generated = 0
            for finding in findings:
                try:
                    tester.generate_regression_test(finding)
                    generated += 1
                except Exception as e:
                    logger.error(f"Failed to generate test for finding: {e}")

            print(f"\n✅ Generated {generated} regression tests")
        except FileNotFoundError:
            print(f"❌ Error: File not found: {args.fixed_findings}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON in {args.fixed_findings}: {e}")
            sys.exit(1)

    elif args.mode == "run":
        results = tester.run_all_tests(vuln_type=args.vuln_type)

        # Exit with error if tests failed
        if results["failed"] > 0:
            print("\n⚠️  CRITICAL: Regression tests failed - vulnerabilities may have returned!")
            sys.exit(1)
        elif results["errors"] > 0:
            print("\n⚠️  WARNING: Some tests had errors")
            sys.exit(2)
        else:
            print("\n✅ All regression tests passed - no vulnerabilities detected")
            sys.exit(0)

    elif args.mode == "stats":
        stats = tester.get_stats()

        print("\n" + "=" * 80)
        print("📊 REGRESSION TEST STATISTICS")
        print("=" * 80)
        print(f"\nTotal Tests: {stats['total_tests']}")

        if stats["by_language"]:
            print("\nBy Language:")
            for lang, count in sorted(stats["by_language"].items()):
                print(f"  {lang}: {count}")

        if stats["by_vulnerability"]:
            print("\nBy Vulnerability Type:")
            for vuln, count in sorted(
                stats["by_vulnerability"].items(), key=lambda x: x[1], reverse=True
            ):
                print(f"  {vuln}: {count}")

        if stats["by_severity"]:
            print("\nBy Severity:")
            for severity, count in sorted(stats["by_severity"].items()):
                print(f"  {severity}: {count}")

        print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    main()
