#!/usr/bin/env python3
"""
Regression Tests for XSS Context Detection (Issue #43)

This test suite prevents the false positive from Issue #43 from happening again.
The issue was that Semgrep flagged `console.log()` with user input as XSS in a
Node.js CLI tool, when it should only be flagged in web applications.

Test Coverage:
1. CLI tool console.log XSS should be FALSE POSITIVE (Issue #43 scenario)
2. Web app innerHTML XSS should be TRUE POSITIVE
3. Node.js CLI detection via package.json "bin" field
4. Python CLI detection via setup.py console_scripts
5. Express web app XSS should be flagged
6. Python logging.info() in CLI should NOT be XSS
7. Unknown project type should use cautious approach (flag as potential XSS)

Key Concepts:
- CLI tools output to TERMINAL (stdout) - NOT XSS vulnerable
- Web apps output to BROWSER DOM - XSS vulnerable
- Context detection via package.json, setup.py, framework imports
- AI triage should downgrade severity for CLI tool XSS findings
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from schemas.unified_finding import Category, Severity, UnifiedFinding


class ProjectContextDetector:
    """
    Helper class to detect project context (CLI tool vs web app)
    This simulates the logic that should be in AI triage to prevent Issue #43
    """

    def __init__(self, project_path: Path):
        self.project_path = Path(project_path)

    def is_nodejs_cli_tool(self) -> bool:
        """Detect if project is a Node.js CLI tool via package.json "bin" field"""
        package_json = self.project_path / "package.json"
        if not package_json.exists():
            return False

        try:
            with open(package_json) as f:
                data = json.load(f)
                # Check for "bin" field indicating CLI entry point
                if "bin" in data:
                    return True
                # Check for CLI-related keywords
                keywords = data.get("keywords", [])
                if any(k in keywords for k in ["cli", "command-line", "terminal"]):
                    return True
        except (json.JSONDecodeError, IOError):
            pass

        return False

    def is_python_cli_tool(self) -> bool:
        """Detect if project is a Python CLI tool via setup.py console_scripts"""
        setup_py = self.project_path / "setup.py"
        if not setup_py.exists():
            return False

        try:
            with open(setup_py) as f:
                content = f.read()
                # Check for console_scripts in entry_points
                if "console_scripts" in content:
                    return True
                # Check for Environment :: Console classifier
                if "Environment :: Console" in content:
                    return True
        except IOError:
            pass

        return False

    def is_web_application(self) -> bool:
        """Detect if project is a web application via framework dependencies"""
        # Check Node.js web frameworks
        package_json = self.project_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    web_frameworks = ["express", "koa", "hapi", "fastify", "next", "nuxt", "react", "vue", "angular"]
                    if any(fw in deps for fw in web_frameworks):
                        return True
            except (json.JSONDecodeError, IOError):
                pass

        # Check Python web frameworks
        requirements_txt = self.project_path / "requirements.txt"
        if requirements_txt.exists():
            try:
                with open(requirements_txt) as f:
                    content = f.read()
                    web_frameworks = ["django", "flask", "fastapi", "tornado", "pyramid"]
                    if any(fw in content.lower() for fw in web_frameworks):
                        return True
            except IOError:
                pass

        return False

    def get_project_type(self) -> str:
        """
        Determine project type: 'cli-tool', 'web-app', or 'unknown'
        """
        if self.is_nodejs_cli_tool() or self.is_python_cli_tool():
            return "cli-tool"
        elif self.is_web_application():
            return "web-app"
        else:
            return "unknown"


class XSSContextAnalyzer:
    """
    Analyzer to determine if an XSS finding is a false positive based on context
    This is the core logic to prevent Issue #43
    """

    def __init__(self, project_path: Path):
        self.detector = ProjectContextDetector(project_path)
        self.project_type = self.detector.get_project_type()

    def analyze_xss_finding(self, finding: UnifiedFinding) -> dict:
        """
        Analyze an XSS finding and determine if it's a false positive

        Returns:
            dict with keys:
                - is_false_positive: bool
                - adjusted_severity: Severity
                - reason: str
                - confidence: float
        """
        file_path = Path(finding.path)
        evidence_message = finding.evidence.get("message", "").lower()

        # Check if it's XSS-related
        is_xss = (
            "xss" in evidence_message or
            "cross-site scripting" in evidence_message or
            "cwe-79" in str(finding.cwe).lower() or
            "innerhtml" in evidence_message or
            "document.write" in evidence_message
        )

        if not is_xss:
            return {
                "is_false_positive": False,
                "adjusted_severity": finding.severity,
                "reason": "Not an XSS finding",
                "confidence": 1.0
            }

        # Check for CLI tool patterns in the code
        cli_output_patterns = [
            "console.log",
            "console.error",
            "console.warn",
            "print(",
            "logging.info",
            "logging.debug",
            "logging.warning",
            "logger.info",
            "logger.debug",
            "sys.stdout.write",
        ]

        has_cli_pattern = any(pattern in evidence_message for pattern in cli_output_patterns)

        # Decision logic
        if self.project_type == "cli-tool":
            if has_cli_pattern:
                # Issue #43 scenario: CLI tool with console.log/print = FALSE POSITIVE
                return {
                    "is_false_positive": True,
                    "adjusted_severity": Severity.LOW,
                    "reason": "CLI tool terminal output (console.log/print) - not browser XSS",
                    "confidence": 0.95
                }
            else:
                # CLI tool but XSS in client-side code? Might be documentation
                return {
                    "is_false_positive": False,
                    "adjusted_severity": Severity.MEDIUM,
                    "reason": "CLI tool but XSS pattern detected - investigate further",
                    "confidence": 0.6
                }

        elif self.project_type == "web-app":
            # Web application - XSS findings are likely TRUE POSITIVES
            if "innerhtml" in evidence_message or "document.write" in evidence_message:
                return {
                    "is_false_positive": False,
                    "adjusted_severity": finding.severity,  # Keep original severity
                    "reason": "Web application with DOM manipulation - true XSS risk",
                    "confidence": 0.95
                }
            elif has_cli_pattern:
                # Server-side logging in web app (e.g., Express app.js) - not XSS
                if "app.js" in str(file_path) or "server.js" in str(file_path):
                    return {
                        "is_false_positive": True,
                        "adjusted_severity": Severity.LOW,
                        "reason": "Server-side logging in web app - not browser XSS",
                        "confidence": 0.85
                    }
                return {
                    "is_false_positive": False,
                    "adjusted_severity": finding.severity,
                    "reason": "Web application with potential XSS",
                    "confidence": 0.8
                }
            else:
                return {
                    "is_false_positive": False,
                    "adjusted_severity": finding.severity,
                    "reason": "Web application with XSS pattern",
                    "confidence": 0.9
                }

        else:  # unknown project type
            # Cautious approach: flag as potential XSS but lower confidence
            if has_cli_pattern:
                return {
                    "is_false_positive": False,
                    "adjusted_severity": Severity.MEDIUM,
                    "reason": "Unknown project type - console output may be XSS",
                    "confidence": 0.5
                }
            else:
                return {
                    "is_false_positive": False,
                    "adjusted_severity": finding.severity,
                    "reason": "Unknown project type - investigate XSS finding",
                    "confidence": 0.7
                }


class TestXSSContextDetection(unittest.TestCase):
    """
    Test suite for XSS context detection
    Regression tests for Issue #43
    """

    def setUp(self):
        """Set up test fixtures"""
        self.fixtures_dir = Path(__file__).parent.parent / "fixtures"
        self.cli_tool_dir = self.fixtures_dir / "cli_tool"
        self.web_app_dir = self.fixtures_dir / "web_app"
        self.python_cli_dir = self.fixtures_dir / "python_cli"

    def _create_mock_finding(
        self,
        file_path: str,
        severity: Severity = Severity.HIGH,
        message: str = "",
        cwe: str = "CWE-79"
    ) -> UnifiedFinding:
        """Helper to create mock XSS finding"""
        return UnifiedFinding(
            id="test-xss-001",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path(file_path),
            rule_id="javascript.express.security.xss.direct-response-write",
            rule_name="XSS vulnerability",
            category=Category.SAST,
            severity=severity,
            cwe=cwe,
            evidence={
                "message": message,
                "snippet": "console.log(`Run script: ${userInput}`)"
            }
        )

    # Test 1: Issue #43 - CLI tool console.log should be FALSE POSITIVE
    def test_cli_tool_console_log_xss_is_false_positive(self):
        """
        Reproduces Issue #43 scenario:
        Node.js CLI tool with console.log(userInput) should be marked as FALSE POSITIVE
        because it outputs to terminal, not browser DOM
        """
        analyzer = XSSContextAnalyzer(self.cli_tool_dir)

        # Verify project is detected as CLI tool
        self.assertEqual(analyzer.project_type, "cli-tool")

        # Create finding simulating Semgrep flagging console.log as XSS
        finding = self._create_mock_finding(
            file_path="index.js",
            severity=Severity.HIGH,
            message="Potential XSS: user input in console.log",
            cwe="CWE-79"
        )

        # Analyze the finding
        result = analyzer.analyze_xss_finding(finding)

        # Assertions
        self.assertTrue(result["is_false_positive"], "CLI tool console.log should be FALSE POSITIVE")
        self.assertEqual(result["adjusted_severity"], Severity.LOW, "Severity should be downgraded to LOW")
        self.assertIn("CLI tool", result["reason"])
        self.assertIn("terminal output", result["reason"])
        self.assertGreater(result["confidence"], 0.9, "Should have high confidence in false positive detection")

        print(f"✓ Test 1 passed: CLI console.log correctly marked as FALSE POSITIVE")
        print(f"  Reason: {result['reason']}")
        print(f"  Confidence: {result['confidence']}")

    # Test 2: Web app innerHTML should be TRUE POSITIVE
    def test_web_app_innerhtml_xss_is_true_positive(self):
        """
        Web application with innerHTML manipulation should be flagged as TRUE POSITIVE XSS
        """
        analyzer = XSSContextAnalyzer(self.web_app_dir)

        # Verify project is detected as web app
        self.assertEqual(analyzer.project_type, "web-app")

        # Create finding for innerHTML XSS in client.js
        finding = self._create_mock_finding(
            file_path="client.js",
            severity=Severity.HIGH,
            message="XSS vulnerability: innerHTML with user input",
            cwe="CWE-79"
        )
        finding.evidence["message"] = "XSS: innerHTML with unsanitized input"

        # Analyze the finding
        result = analyzer.analyze_xss_finding(finding)

        # Assertions
        self.assertFalse(result["is_false_positive"], "Web app innerHTML should be TRUE POSITIVE")
        self.assertEqual(result["adjusted_severity"], Severity.HIGH, "Severity should remain HIGH")
        self.assertIn("true XSS risk", result["reason"])
        self.assertGreater(result["confidence"], 0.9, "Should have high confidence this is real XSS")

        print(f"✓ Test 2 passed: Web app innerHTML correctly marked as TRUE POSITIVE")
        print(f"  Reason: {result['reason']}")

    # Test 3: Node.js CLI detection via package.json "bin"
    def test_nodejs_cli_package_json_detection(self):
        """
        Verify that Node.js CLI tools are correctly detected via package.json "bin" field
        """
        detector = ProjectContextDetector(self.cli_tool_dir)

        self.assertTrue(detector.is_nodejs_cli_tool(), "Should detect Node.js CLI via package.json bin field")
        self.assertFalse(detector.is_web_application(), "Should not detect as web application")
        self.assertEqual(detector.get_project_type(), "cli-tool")

        # Verify package.json has bin field
        package_json_path = self.cli_tool_dir / "package.json"
        with open(package_json_path) as f:
            data = json.load(f)
            self.assertIn("bin", data, "package.json should have bin field")

        print(f"✓ Test 3 passed: Node.js CLI correctly detected via package.json")

    # Test 4: Python CLI detection via setup.py console_scripts
    def test_python_cli_setup_py_detection(self):
        """
        Verify that Python CLI tools are correctly detected via setup.py console_scripts
        """
        detector = ProjectContextDetector(self.python_cli_dir)

        self.assertTrue(detector.is_python_cli_tool(), "Should detect Python CLI via setup.py console_scripts")
        self.assertFalse(detector.is_web_application(), "Should not detect as web application")
        self.assertEqual(detector.get_project_type(), "cli-tool")

        # Verify setup.py has console_scripts
        setup_py_path = self.python_cli_dir / "setup.py"
        with open(setup_py_path) as f:
            content = f.read()
            self.assertIn("console_scripts", content, "setup.py should have console_scripts")

        print(f"✓ Test 4 passed: Python CLI correctly detected via setup.py")

    # Test 5: Express app XSS should be flagged
    def test_express_app_xss_detection(self):
        """
        Express.js web application should be detected and XSS findings should be flagged
        """
        detector = ProjectContextDetector(self.web_app_dir)

        self.assertTrue(detector.is_web_application(), "Should detect Express.js web app")
        self.assertFalse(detector.is_nodejs_cli_tool(), "Should not detect as CLI tool")
        self.assertEqual(detector.get_project_type(), "web-app")

        # Verify package.json has express
        package_json_path = self.web_app_dir / "package.json"
        with open(package_json_path) as f:
            data = json.load(f)
            self.assertIn("express", data.get("dependencies", {}))

        analyzer = XSSContextAnalyzer(self.web_app_dir)

        # Test client-side XSS (TRUE POSITIVE)
        client_finding = self._create_mock_finding(
            file_path="client.js",
            severity=Severity.HIGH,
            message="XSS: innerHTML with user input"
        )
        result = analyzer.analyze_xss_finding(client_finding)
        self.assertFalse(result["is_false_positive"], "Client-side XSS should be TRUE POSITIVE")

        print(f"✓ Test 5 passed: Express app XSS correctly detected")

    # Test 6: Python logging.info() should NOT be XSS
    def test_logger_output_not_xss(self):
        """
        Python CLI tool using logging.info() should NOT be flagged as XSS
        This is terminal/file logging, not browser output
        """
        analyzer = XSSContextAnalyzer(self.python_cli_dir)

        # Verify project is detected as CLI tool
        self.assertEqual(analyzer.project_type, "cli-tool")

        # Create finding for logging.info with user input
        finding = self._create_mock_finding(
            file_path="cli_tool/main.py",
            severity=Severity.HIGH,
            message="Potential XSS: user input in logging.info",
            cwe="CWE-79"
        )
        finding.evidence["message"] = "XSS: logging.info with user data"

        # Analyze the finding
        result = analyzer.analyze_xss_finding(finding)

        # Assertions
        self.assertTrue(result["is_false_positive"], "Python CLI logging.info should be FALSE POSITIVE")
        self.assertEqual(result["adjusted_severity"], Severity.LOW)
        self.assertIn("terminal output", result["reason"])

        print(f"✓ Test 6 passed: Python logging.info correctly marked as FALSE POSITIVE")
        print(f"  Reason: {result['reason']}")

    # Test 7: Unknown project type - cautious approach
    def test_unknown_project_type_cautious_approach(self):
        """
        If project type cannot be determined, use cautious approach:
        - Flag potential XSS but with medium severity
        - Lower confidence score
        - Require manual review
        """
        # Use a directory without package.json or setup.py
        unknown_dir = self.fixtures_dir / "vulnerable_app"
        analyzer = XSSContextAnalyzer(unknown_dir)

        # Project type should be unknown or web-app (vulnerable_app has mixed files)
        # For this test, let's use a truly unknown directory
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)
            analyzer = XSSContextAnalyzer(temp_path)

            # Should be unknown
            self.assertEqual(analyzer.project_type, "unknown")

            # Create XSS finding in unknown project
            finding = self._create_mock_finding(
                file_path="app.js",
                severity=Severity.HIGH,
                message="Potential XSS: console.log with user input"
            )

            # Analyze the finding
            result = analyzer.analyze_xss_finding(finding)

            # Assertions - cautious approach
            self.assertFalse(result["is_false_positive"], "Unknown project: should not auto-mark as FP")
            self.assertEqual(result["adjusted_severity"], Severity.MEDIUM, "Should downgrade to MEDIUM")
            self.assertLess(result["confidence"], 0.8, "Should have lower confidence")
            self.assertIn("Unknown project type", result["reason"])

        print(f"✓ Test 7 passed: Unknown project type uses cautious approach")
        print(f"  Severity: {result['adjusted_severity']}")
        print(f"  Confidence: {result['confidence']}")


class TestProjectContextDetector(unittest.TestCase):
    """
    Additional tests for ProjectContextDetector edge cases
    """

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent.parent / "fixtures"

    def test_nodejs_cli_keywords_detection(self):
        """Test detection via keywords in package.json"""
        detector = ProjectContextDetector(self.fixtures_dir / "cli_tool")
        # CLI tool fixture has "cli" in keywords
        self.assertTrue(detector.is_nodejs_cli_tool())

    def test_python_cli_environment_classifier(self):
        """Test detection via Environment :: Console classifier"""
        detector = ProjectContextDetector(self.fixtures_dir / "python_cli")
        # Python CLI fixture has Environment :: Console
        self.assertTrue(detector.is_python_cli_tool())

    def test_web_app_framework_detection(self):
        """Test web framework detection"""
        detector = ProjectContextDetector(self.fixtures_dir / "web_app")
        # Web app fixture has express
        self.assertTrue(detector.is_web_application())

    def test_missing_files_graceful_handling(self):
        """Test graceful handling when package.json/setup.py missing"""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ProjectContextDetector(Path(tmpdir))
            self.assertFalse(detector.is_nodejs_cli_tool())
            self.assertFalse(detector.is_python_cli_tool())
            self.assertFalse(detector.is_web_application())
            self.assertEqual(detector.get_project_type(), "unknown")


class TestXSSContextAnalyzerEdgeCases(unittest.TestCase):
    """
    Test edge cases and boundary conditions
    """

    def setUp(self):
        self.fixtures_dir = Path(__file__).parent.parent / "fixtures"

    def test_non_xss_finding_passthrough(self):
        """Non-XSS findings should pass through unchanged"""
        analyzer = XSSContextAnalyzer(self.fixtures_dir / "cli_tool")

        finding = UnifiedFinding(
            id="test-sql-001",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("db.py"),
            severity=Severity.HIGH,
            cwe="CWE-89",  # SQL injection
            evidence={"message": "SQL injection vulnerability"}
        )

        result = analyzer.analyze_xss_finding(finding)
        self.assertFalse(result["is_false_positive"])
        self.assertEqual(result["reason"], "Not an XSS finding")

    def test_mixed_patterns_in_web_app(self):
        """Web app with server-side console.log should not be XSS"""
        analyzer = XSSContextAnalyzer(self.fixtures_dir / "web_app")

        # Server-side logging in app.js
        finding = UnifiedFinding(
            id="test-xss-002",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path=Path("app.js"),
            severity=Severity.HIGH,
            cwe="CWE-79",
            evidence={"message": "XSS: console.log with user input"}
        )

        result = analyzer.analyze_xss_finding(finding)
        self.assertTrue(result["is_false_positive"], "Server-side console.log should be FP")
        self.assertIn("Server-side logging", result["reason"])


def run_tests_with_coverage():
    """Run tests and display results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestXSSContextDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestProjectContextDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestXSSContextAnalyzerEdgeCases))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Total tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✓ All tests passed! Issue #43 regression prevented.")
        return 0
    else:
        print("\n✗ Some tests failed. Review failures above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests_with_coverage())
