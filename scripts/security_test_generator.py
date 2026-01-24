#!/usr/bin/env python3
"""
Security Test Suite Generator for Argus
Generates pytest/Jest tests for discovered vulnerabilities

This module uses AI to automatically generate security regression tests
from discovered vulnerabilities, supporting both Python (pytest) and
JavaScript (Jest) test frameworks.
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class GeneratedTestSuite:
    """Generated security test suite"""

    language: str  # python, javascript
    framework: str  # pytest, jest
    tests: list[str] = field(default_factory=list)  # List of test code strings
    setup_code: str = ""
    imports: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def test_count(self) -> int:
        """Return number of generated tests"""
        return len(self.tests)


class SecurityTestGenerator:
    """Generate security tests using AI"""

    # Vulnerability type to test pattern mapping
    VULN_PATTERNS = {
        "sql-injection": {
            "test_type": "injection",
            "payloads": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
        },
        "xss": {
            "test_type": "injection",
            "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
        },
        "command-injection": {
            "test_type": "injection",
            "payloads": ["; ls -la", "| whoami", "&& cat /etc/passwd"],
        },
        "path-traversal": {
            "test_type": "traversal",
            "payloads": ["../../etc/passwd", "..\\..\\windows\\system32\\config\\sam"],
        },
        "xxe": {
            "test_type": "xml",
            "payloads": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'],
        },
    }

    def __init__(self, llm_manager=None, debug: bool = False):
        """
        Initialize test generator

        Args:
            llm_manager: LLM manager instance (created if None)
            debug: Enable debug logging
        """
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        if llm_manager is None:
            try:
                from orchestrator.llm_manager import LLMManager

                self.llm = LLMManager()
            except ImportError:
                logger.warning("LLM manager not available, using fallback templates")
                self.llm = None
        else:
            self.llm = llm_manager

        self.stats = {
            "total_findings": 0,
            "tests_generated": 0,
            "tests_failed": 0,
            "languages": {},
        }

    def generate_test_suite(
        self, findings: list[dict], output_path: str = "tests/security/", filename: Optional[str] = None
    ) -> GeneratedTestSuite:
        """
        Generate complete test suite for findings

        Args:
            findings: List of UnifiedFinding dictionaries
            output_path: Directory to write test files
            filename: Optional custom filename (auto-detected if None)

        Returns:
            GeneratedTestSuite object with generated tests
        """
        self.stats["total_findings"] = len(findings)

        if not findings:
            logger.warning("No findings provided, generating empty test suite")
            return GeneratedTestSuite(language="python", framework="pytest")

        # Detect language from findings
        language = self._detect_language(findings)
        framework = "pytest" if language == "python" else "jest"

        logger.info(f"Generating {framework} tests for {len(findings)} findings in {language}")

        # Track language stats
        self.stats["languages"][language] = self.stats["languages"].get(language, 0) + len(findings)

        # Generate tests for each finding
        tests = []
        for idx, finding in enumerate(findings, 1):
            logger.debug(f"Processing finding {idx}/{len(findings)}: {finding.get('id', 'unknown')}")
            test_code = self._generate_test(finding, language, framework)
            if test_code:
                tests.append(test_code)
                self.stats["tests_generated"] += 1
            else:
                self.stats["tests_failed"] += 1

        # Generate setup code
        setup_code = self._generate_setup(language, framework)
        imports = self._generate_imports(language, framework)

        suite = GeneratedTestSuite(
            language=language,
            framework=framework,
            tests=tests,
            setup_code=setup_code,
            imports=imports,
            metadata={"findings_count": len(findings), "generated_count": len(tests)},
        )

        # Write to file
        if filename is None:
            filename = f"test_security_generated.py" if language == "python" else "security.test.js"

        self._write_test_file(suite, output_path, filename)

        return suite

    def _generate_test(self, finding: dict, language: str, framework: str) -> Optional[str]:
        """
        Generate a single test using AI or templates

        Args:
            finding: UnifiedFinding dictionary
            language: Target language (python/javascript)
            framework: Test framework (pytest/jest)

        Returns:
            Generated test code or None if generation fails
        """
        vuln_type = finding.get("type", "unknown")
        finding_id = finding.get("id", "unknown")
        file_path = finding.get("path", "")
        description = finding.get("description", "")
        code_snippet = finding.get("code_snippet", "")
        severity = finding.get("severity", "medium")

        # Normalize vulnerability type
        normalized_vuln = self._normalize_vuln_type(vuln_type)

        logger.debug(f"Generating {framework} test for {normalized_vuln} vulnerability")

        # Try AI generation first
        if self.llm:
            test_code = self._generate_with_ai(
                finding_id=finding_id,
                vuln_type=normalized_vuln,
                file_path=file_path,
                description=description,
                code_snippet=code_snippet,
                severity=severity,
                language=language,
                framework=framework,
            )
            if test_code:
                return test_code

        # Fallback to template generation
        logger.debug(f"Using template generation for {normalized_vuln}")
        return self._generate_with_template(
            finding_id=finding_id,
            vuln_type=normalized_vuln,
            file_path=file_path,
            description=description,
            language=language,
            framework=framework,
        )

    def _generate_with_ai(
        self,
        finding_id: str,
        vuln_type: str,
        file_path: str,
        description: str,
        code_snippet: str,
        severity: str,
        language: str,
        framework: str,
    ) -> Optional[str]:
        """Generate test using AI/LLM"""
        prompt = f"""You are a security test engineer. Generate a {framework} security test for this vulnerability.

**Vulnerability Details:**
- ID: {finding_id}
- Type: {vuln_type}
- Severity: {severity}
- File: {file_path}
- Description: {description}
- Vulnerable Code:
```
{code_snippet}
```

**Requirements:**
1. Write a {framework} test that:
   - Tests if the vulnerability is exploitable (positive test case)
   - Verifies that proper input validation prevents exploitation (negative test case)
   - Uses realistic test data and payloads
   - Has clear test names following {framework} conventions
   - Includes detailed assertions
2. For API vulnerabilities, use requests/axios to send HTTP requests
3. For code vulnerabilities, import and test the vulnerable function directly
4. Include docstrings/comments explaining the test

**Generate ONLY the test code, no markdown code blocks or explanations. Start directly with the test function/describe block:**
"""

        try:
            test_code, _ = self.llm.call_llm_api(prompt, max_tokens=1500)
            cleaned_code = self._clean_test_code(test_code)

            # Validate generated code
            if self._validate_test_code(cleaned_code, framework):
                return cleaned_code
            else:
                logger.warning(f"Generated test code failed validation for {finding_id}")
                return None

        except Exception as e:
            logger.error(f"Failed to generate test for {finding_id}: {e}")
            return None

    def _generate_with_template(
        self, finding_id: str, vuln_type: str, file_path: str, description: str, language: str, framework: str
    ) -> str:
        """Generate test using templates (fallback when AI unavailable)"""
        test_name = self._sanitize_test_name(finding_id)
        file_basename = Path(file_path).name if file_path else "unknown"

        if language == "python":
            return self._generate_python_template(test_name, vuln_type, file_basename, description)
        else:
            return self._generate_javascript_template(test_name, vuln_type, file_basename, description)

    def _generate_python_template(self, test_name: str, vuln_type: str, filename: str, description: str) -> str:
        """Generate Python pytest template"""
        payloads = self._get_test_payloads(vuln_type)

        return f'''
def test_{test_name}_exploit():
    """
    Test exploitation of {vuln_type} vulnerability

    Finding: {test_name}
    File: {filename}
    Description: {description}
    """
    # Test with malicious payloads
    test_payloads = {payloads}

    for payload in test_payloads:
        # TODO: Adjust this test based on your application's API/interface
        # This is a template that needs customization
        response = requests.get(
            "http://localhost:8000/vulnerable-endpoint",
            params={{"input": payload}}
        )

        # Verify vulnerability is exploitable
        # Adjust assertion based on expected behavior
        assert response.status_code in [200, 400, 500], f"Unexpected status for payload: {{payload}}"


def test_{test_name}_fix_verification():
    """
    Verify that {vuln_type} vulnerability is properly fixed

    This test should PASS after the vulnerability is fixed.
    """
    # Test with safe inputs
    safe_inputs = ["normal_input", "test123", "valid-data"]

    for safe_input in safe_inputs:
        response = requests.get(
            "http://localhost:8000/vulnerable-endpoint",
            params={{"input": safe_input}}
        )

        # Verify safe inputs are handled correctly
        assert response.status_code == 200, f"Safe input rejected: {{safe_input}}"
'''

    def _generate_javascript_template(self, test_name: str, vuln_type: str, filename: str, description: str) -> str:
        """Generate JavaScript Jest template"""
        payloads = self._get_test_payloads(vuln_type)

        return f'''
describe('{test_name} - {vuln_type}', () => {{
    /**
     * Test exploitation of {vuln_type} vulnerability
     *
     * Finding: {test_name}
     * File: {filename}
     * Description: {description}
     */
    test('should be exploitable with malicious payloads', async () => {{
        const testPayloads = {json.dumps(payloads)};

        for (const payload of testPayloads) {{
            // TODO: Adjust this test based on your application's API
            const response = await request(app)
                .get('/vulnerable-endpoint')
                .query({{ input: payload }});

            // Verify vulnerability behavior
            expect([200, 400, 500]).toContain(response.status);
        }}
    }});

    /**
     * Verify that {vuln_type} vulnerability is properly fixed
     * This test should PASS after the vulnerability is fixed.
     */
    test('should properly validate safe inputs', async () => {{
        const safeInputs = ['normal_input', 'test123', 'valid-data'];

        for (const safeInput of safeInputs) {{
            const response = await request(app)
                .get('/vulnerable-endpoint')
                .query({{ input: safeInput }});

            expect(response.status).toBe(200);
        }}
    }});
}});
'''

    def _clean_test_code(self, code: str) -> str:
        """
        Remove markdown formatting and clean LLM response

        Args:
            code: Raw LLM output

        Returns:
            Cleaned test code
        """
        # Remove markdown code blocks
        code = re.sub(r"^```(?:python|javascript|typescript|js)?\s*\n", "", code, flags=re.MULTILINE)
        code = re.sub(r"\n```\s*$", "", code, flags=re.MULTILINE)

        # Remove leading/trailing whitespace
        code = code.strip()

        # Remove common LLM preambles
        code = re.sub(r"^Here(?:'s| is) the .*?:\s*\n", "", code, flags=re.IGNORECASE)

        return code

    def _validate_test_code(self, code: str, framework: str) -> bool:
        """
        Validate generated test code syntax

        Args:
            code: Generated test code
            framework: Test framework (pytest/jest)

        Returns:
            True if code appears valid
        """
        if not code or len(code) < 50:
            return False

        if framework == "pytest":
            # Check for pytest patterns
            return "def test_" in code and ("assert" in code or "pytest" in code)
        else:
            # Check for Jest patterns
            return ("describe(" in code or "test(" in code or "it(" in code) and "expect(" in code

    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type to standard format"""
        vuln_lower = vuln_type.lower().replace("_", "-")

        # Map common variations
        mappings = {
            "sqli": "sql-injection",
            "sql": "sql-injection",
            "cross-site-scripting": "xss",
            "rce": "command-injection",
            "cmd-injection": "command-injection",
            "lfi": "path-traversal",
            "directory-traversal": "path-traversal",
        }

        return mappings.get(vuln_lower, vuln_lower)

    def _get_test_payloads(self, vuln_type: str) -> list[str]:
        """Get test payloads for vulnerability type"""
        pattern = self.VULN_PATTERNS.get(vuln_type, {})
        return pattern.get("payloads", ["malicious_input", "test<>payload", "../../../etc/passwd"])

    def _sanitize_test_name(self, finding_id: str) -> str:
        """Convert finding ID to valid test function name"""
        # Remove special characters, replace with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", finding_id)
        # Remove consecutive underscores
        sanitized = re.sub(r"_+", "_", sanitized)
        # Remove leading/trailing underscores
        return sanitized.strip("_").lower()

    def _detect_language(self, findings: list[dict]) -> str:
        """
        Detect primary language from findings

        Args:
            findings: List of findings

        Returns:
            Detected language (python/javascript)
        """
        language_hints = {"python": 0, "javascript": 0}

        for finding in findings:
            file_path = finding.get("path", "").lower()

            # File extension based detection
            if file_path.endswith((".py", ".pyw")):
                language_hints["python"] += 1
            elif file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
                language_hints["javascript"] += 1

            # Content based detection
            code_snippet = finding.get("code_snippet", "")
            if "import " in code_snippet and "from " in code_snippet:
                language_hints["python"] += 0.5
            if ("require(" in code_snippet or "import {" in code_snippet or "import *" in code_snippet):
                language_hints["javascript"] += 0.5

        # Return language with highest score, default to python
        return "javascript" if language_hints["javascript"] > language_hints["python"] else "python"

    def _generate_setup(self, language: str, framework: str) -> str:
        """Generate setup/teardown code"""
        if language == "python":
            return '''
import pytest
import requests
from typing import Optional


@pytest.fixture
def api_client():
    """Fixture for API testing"""
    session = requests.Session()
    session.headers.update({"User-Agent": "SecurityTest/1.0"})
    yield session
    session.close()


@pytest.fixture
def base_url():
    """Base URL for testing"""
    return "http://localhost:8000"  # Configure as needed
'''
        else:  # javascript
            return '''
const request = require('supertest');
const app = require('../app');  // Adjust path to your app


describe('Security Tests - Generated', () => {
    // Setup runs before all tests
    beforeAll(() => {
        // Initialize test environment
    });

    afterAll(() => {
        // Cleanup
    });

    // Individual tests follow...
'''

    def _generate_imports(self, language: str, framework: str) -> list[str]:
        """Generate import statements"""
        if language == "python":
            return [
                "import pytest",
                "import requests",
                "import json",
                "from typing import Optional, Any",
                "from pathlib import Path",
            ]
        else:
            return [
                "const request = require('supertest');",
                "const axios = require('axios');",
                "const { describe, test, expect, beforeAll, afterAll } = require('@jest/globals');",
            ]

    def _write_test_file(self, suite: GeneratedTestSuite, output_path: str, filename: str):
        """Write test suite to file"""
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)

        file_path = output_dir / filename

        # Combine imports, setup, and tests
        content = "\n".join(suite.imports) + "\n\n"
        content += suite.setup_code + "\n\n"
        content += "\n\n".join(suite.tests)

        # Add closing for JavaScript describe block
        if suite.language == "javascript":
            content += "\n});\n"

        with open(file_path, "w") as f:
            f.write(content)

        logger.info(f"✅ Generated {len(suite.tests)} security tests in {file_path}")

    def generate_regression_test(self, fixed_finding: dict, language: str = "python") -> str:
        """
        Generate regression test for a fixed vulnerability

        Args:
            fixed_finding: Finding that has been fixed
            language: Target language (python/javascript)

        Returns:
            Test code that verifies the fix
        """
        finding_id = fixed_finding.get("id", "unknown")
        vuln_type = fixed_finding.get("type", "unknown")
        description = fixed_finding.get("description", "")

        test_name = self._sanitize_test_name(f"regression_{finding_id}")

        if language == "python":
            return f'''
def test_{test_name}():
    """
    Regression test: Ensure {vuln_type} vulnerability remains fixed

    Finding ID: {finding_id}
    Description: {description}

    This test should PASS if the vulnerability is properly fixed.
    If this test fails, the vulnerability has been reintroduced.
    """
    # Test that previously vulnerable code now handles input safely
    safe_inputs = ["normal_input", "test123", "valid-data"]

    for safe_input in safe_inputs:
        # TODO: Call the previously vulnerable function/endpoint
        result = vulnerable_function(safe_input)  # Replace with actual function

        # Verify safe behavior
        assert result is not None, "Function should handle safe input"

    # Verify malicious inputs are rejected
    malicious_inputs = {self._get_test_payloads(vuln_type)}

    for malicious_input in malicious_inputs:
        # Should raise exception or return error
        with pytest.raises((ValueError, SecurityError)):  # Adjust exception types
            vulnerable_function(malicious_input)
'''
        else:
            return f'''
test('regression: {vuln_type} vulnerability remains fixed - {finding_id}', async () => {{
    /**
     * Regression test: Ensure {vuln_type} vulnerability remains fixed
     * Description: {description}
     *
     * This test should PASS if the vulnerability is properly fixed.
     */
    const safeInputs = ['normal_input', 'test123', 'valid-data'];

    for (const safeInput of safeInputs) {{
        const result = await vulnerableFunction(safeInput);
        expect(result).toBeDefined();
    }}

    // Verify malicious inputs are rejected
    const maliciousInputs = {json.dumps(self._get_test_payloads(vuln_type))};

    for (const maliciousInput of maliciousInputs) {{
        await expect(vulnerableFunction(maliciousInput)).rejects.toThrow();
    }}
}});
'''

    def print_stats(self):
        """Print generation statistics"""
        print("\n" + "=" * 50)
        print("Security Test Generation Statistics")
        print("=" * 50)
        print(f"Total findings processed: {self.stats['total_findings']}")
        print(f"Tests successfully generated: {self.stats['tests_generated']}")
        print(f"Tests failed to generate: {self.stats['tests_failed']}")
        print(f"\nLanguages detected:")
        for lang, count in self.stats["languages"].items():
            print(f"  - {lang}: {count} findings")
        print("=" * 50 + "\n")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Generate security tests from vulnerability findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Input JSON file with findings (UnifiedFinding format)",
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="tests/security/",
        help="Output directory for generated tests (default: tests/security/)",
    )

    parser.add_argument(
        "--filename",
        "-f",
        help="Custom output filename (auto-detected if not provided)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Load findings
    try:
        with open(args.input) as f:
            data = json.load(f)

        # Handle both direct list and wrapped format
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
        else:
            print(f"❌ Error: Invalid input format. Expected list or dict with 'findings' key", file=sys.stderr)
            return 1

    except FileNotFoundError:
        print(f"❌ Error: Input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in input file: {e}", file=sys.stderr)
        return 1

    # Generate tests
    generator = SecurityTestGenerator(debug=args.debug)
    suite = generator.generate_test_suite(findings, args.output_dir, args.filename)

    # Print statistics
    generator.print_stats()

    if suite.test_count() > 0:
        print(f"✅ Successfully generated {suite.test_count()} security tests")
        return 0
    else:
        print("⚠️  No tests were generated", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
