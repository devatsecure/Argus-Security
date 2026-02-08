#!/usr/bin/env python3
"""
Unit tests for Security Test Generator
Tests core functionality without requiring LLM integration
"""

import json
import tempfile
from pathlib import Path

import pytest

from scripts.security_test_generator import SecurityTestGenerator, GeneratedTestSuite


class TestSecurityTestGenerator:
    """Test suite for SecurityTestGenerator"""

    @pytest.fixture
    def generator(self):
        """Create generator instance without LLM"""
        return SecurityTestGenerator(llm_manager=None)

    @pytest.fixture
    def sample_findings(self):
        """Sample vulnerability findings"""
        return [
            {
                "id": "sql-injection-001",
                "type": "sql-injection",
                "severity": "high",
                "path": "app/users/views.py",
                "description": "SQL injection vulnerability in user search endpoint",
                "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
            },
            {
                "id": "xss-002",
                "type": "xss",
                "severity": "medium",
                "path": "frontend/src/components/UserProfile.jsx",
                "description": "XSS vulnerability due to unescaped user input",
                "code_snippet": "return <div dangerouslySetInnerHTML={{ __html: name }} />;",
            },
        ]

    def test_initialization(self, generator):
        """Test generator initialization"""
        assert generator is not None
        # LLM may be initialized if API key is available, or None if not
        # The important thing is the generator is properly initialized
        assert generator.stats["total_findings"] == 0

    def test_language_detection_python(self, generator):
        """Test language detection for Python files"""
        findings = [
            {"path": "app/views.py", "code_snippet": "import requests\nfrom typing import Optional"},
            {"path": "utils/helpers.py", "code_snippet": "def process():"},
        ]
        language = generator._detect_language(findings)
        assert language == "python"

    def test_language_detection_javascript(self, generator):
        """Test language detection for JavaScript files"""
        findings = [
            {"path": "src/components/App.jsx", "code_snippet": "import React from 'react'"},
            {"path": "utils/helpers.js", "code_snippet": "const foo = require('bar')"},
        ]
        language = generator._detect_language(findings)
        assert language == "javascript"

    def test_vuln_type_normalization(self, generator):
        """Test vulnerability type normalization"""
        assert generator._normalize_vuln_type("sqli") == "sql-injection"
        assert generator._normalize_vuln_type("SQL-INJECTION") == "sql-injection"
        assert generator._normalize_vuln_type("cross-site-scripting") == "xss"
        assert generator._normalize_vuln_type("rce") == "command-injection"
        assert generator._normalize_vuln_type("lfi") == "path-traversal"

    def test_sanitize_test_name(self, generator):
        """Test test name sanitization"""
        assert generator._sanitize_test_name("sql-injection-001") == "sql_injection_001"
        assert generator._sanitize_test_name("XSS/test/123") == "xss_test_123"
        assert generator._sanitize_test_name("__weird___name__") == "weird_name"

    def test_get_test_payloads(self, generator):
        """Test payload retrieval for different vulnerability types"""
        sql_payloads = generator._get_test_payloads("sql-injection")
        assert "' OR '1'='1" in sql_payloads
        assert len(sql_payloads) >= 3

        xss_payloads = generator._get_test_payloads("xss")
        assert "<script>alert('XSS')</script>" in xss_payloads

        # Unknown type should return default payloads
        unknown_payloads = generator._get_test_payloads("unknown-vuln")
        assert len(unknown_payloads) >= 3

    def test_clean_test_code(self, generator):
        """Test LLM output cleaning"""
        # Test markdown code block removal
        code_with_markdown = "```python\ndef test_foo():\n    assert True\n```"
        cleaned = generator._clean_test_code(code_with_markdown)
        assert "```" not in cleaned
        assert "def test_foo():" in cleaned

        # Test preamble removal
        code_with_preamble = "Here's the test:\ndef test_foo():\n    assert True"
        cleaned = generator._clean_test_code(code_with_preamble)
        assert "Here's the test:" not in cleaned

    def test_validate_test_code_pytest(self, generator):
        """Test pytest code validation"""
        # Code must be >= 50 chars and contain 'def test_' and 'assert' or 'pytest'
        valid_code = "def test_foo_vulnerability():\n    # Test security vulnerability\n    assert True"
        assert generator._validate_test_code(valid_code, "pytest")

        invalid_code = "def foo():\n    print('not a test')  # no test_ prefix, no assert keyword present"
        assert not generator._validate_test_code(invalid_code, "pytest")

        # Too short (< 50 chars)
        assert not generator._validate_test_code("def test_x(): pass", "pytest")

    def test_validate_test_code_jest(self, generator):
        """Test Jest code validation"""
        valid_code = "test('should work', () => {\n    expect(true).toBe(true);\n});"
        assert generator._validate_test_code(valid_code, "jest")

        valid_describe = "describe('test suite', () => {\n    it('works', () => expect(1).toBe(1));\n});"
        assert generator._validate_test_code(valid_describe, "jest")

        invalid_code = "function foo() { console.log('test'); }"
        assert not generator._validate_test_code(invalid_code, "jest")

    def test_generate_python_template(self, generator):
        """Test Python template generation"""
        test_code = generator._generate_python_template(
            test_name="sql_injection_001",
            vuln_type="sql-injection",
            filename="views.py",
            description="SQL injection in search",
        )

        assert "def test_sql_injection_001_exploit():" in test_code
        assert "def test_sql_injection_001_fix_verification():" in test_code
        assert "' OR '1'='1" in test_code  # SQL injection payload
        assert "requests.get" in test_code
        assert "assert" in test_code

    def test_generate_javascript_template(self, generator):
        """Test JavaScript template generation"""
        test_code = generator._generate_javascript_template(
            test_name="xss_002", vuln_type="xss", filename="App.jsx", description="XSS in component"
        )

        assert "describe('xss_002 - xss'" in test_code
        assert "test('should be exploitable" in test_code
        assert "test('should properly validate" in test_code
        assert "<script>alert('XSS')</script>" in test_code  # XSS payload
        assert "expect(" in test_code

    def test_generate_setup_python(self, generator):
        """Test Python setup code generation"""
        setup = generator._generate_setup("python", "pytest")

        assert "import pytest" in setup
        assert "@pytest.fixture" in setup
        assert "def api_client():" in setup
        assert "def base_url():" in setup

    def test_generate_setup_javascript(self, generator):
        """Test JavaScript setup code generation"""
        setup = generator._generate_setup("javascript", "jest")

        assert "const request = require('supertest');" in setup
        assert "describe('Security Tests - Generated'" in setup
        assert "beforeAll" in setup
        assert "afterAll" in setup

    def test_generate_imports_python(self, generator):
        """Test Python import generation"""
        imports = generator._generate_imports("python", "pytest")

        assert "import pytest" in imports
        assert "import requests" in imports
        assert "import json" in imports

    def test_generate_imports_javascript(self, generator):
        """Test JavaScript import generation"""
        imports = generator._generate_imports("javascript", "jest")

        assert "const request = require('supertest');" in imports
        assert "const axios = require('axios');" in imports

    def test_generate_regression_test_python(self, generator):
        """Test regression test generation for Python"""
        finding = {
            "id": "sql-injection-fixed-123",
            "type": "sql-injection",
            "description": "Fixed SQL injection",
        }

        test_code = generator.generate_regression_test(finding, language="python")

        assert "def test_regression_sql_injection_fixed_123():" in test_code
        assert "Regression test:" in test_code
        assert "should PASS if the vulnerability is properly fixed" in test_code
        assert "safe_inputs" in test_code
        assert "malicious_inputs" in test_code
        assert "pytest.raises" in test_code

    def test_generate_regression_test_javascript(self, generator):
        """Test regression test generation for JavaScript"""
        finding = {
            "id": "xss-fixed-456",
            "type": "xss",
            "description": "Fixed XSS vulnerability",
        }

        test_code = generator.generate_regression_test(finding, language="javascript")

        assert "test('regression: xss vulnerability remains fixed" in test_code
        assert "safeInputs" in test_code
        assert "maliciousInputs" in test_code
        assert "expect(" in test_code
        assert ".rejects.toThrow()" in test_code

    def test_generate_test_suite_empty(self, generator):
        """Test test suite generation with no findings"""
        suite = generator.generate_test_suite(findings=[], output_path="/tmp/test_output/")

        assert suite.language == "python"
        assert suite.framework == "pytest"
        assert len(suite.tests) == 0

    def test_generate_test_suite_with_findings(self, generator, sample_findings):
        """Test test suite generation with findings"""
        with tempfile.TemporaryDirectory() as tmpdir:
            suite = generator.generate_test_suite(findings=sample_findings, output_path=tmpdir)

            assert suite.language == "python"  # Both samples are Python files
            assert suite.framework == "pytest"
            assert len(suite.tests) == 2
            assert suite.metadata["findings_count"] == 2
            assert suite.metadata["generated_count"] == 2

            # Check file was created
            output_file = Path(tmpdir) / "test_security_generated.py"
            assert output_file.exists()

            # Check file contents
            content = output_file.read_text()
            assert "import pytest" in content
            assert "test_sql_injection_001_exploit" in content
            assert "test_xss_002_exploit" in content

    def test_stats_tracking(self, generator, sample_findings):
        """Test statistics tracking"""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator.generate_test_suite(findings=sample_findings, output_path=tmpdir)

            assert generator.stats["total_findings"] == 2
            assert generator.stats["tests_generated"] == 2
            assert generator.stats["tests_failed"] == 0
            assert generator.stats["languages"]["python"] == 2

    def test_write_test_file_python(self, generator):
        """Test writing Python test file"""
        suite = GeneratedTestSuite(
            language="python",
            framework="pytest",
            tests=["def test_foo():\n    assert True"],
            setup_code="import pytest",
            imports=["import pytest", "import requests"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            generator._write_test_file(suite, tmpdir, "test_custom.py")

            output_file = Path(tmpdir) / "test_custom.py"
            assert output_file.exists()

            content = output_file.read_text()
            assert "import pytest" in content
            assert "import requests" in content
            assert "def test_foo():" in content

    def test_write_test_file_javascript(self, generator):
        """Test writing JavaScript test file"""
        suite = GeneratedTestSuite(
            language="javascript",
            framework="jest",
            tests=["test('works', () => expect(true).toBe(true));"],
            setup_code="describe('tests', () => {",
            imports=["const request = require('supertest');"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            generator._write_test_file(suite, tmpdir, "security.test.js")

            output_file = Path(tmpdir) / "security.test.js"
            assert output_file.exists()

            content = output_file.read_text()
            assert "const request = require('supertest');" in content
            assert "describe('tests', () => {" in content
            assert "test('works'" in content
            assert "});" in content  # Closing brace for describe

    def test_test_suite_test_count(self):
        """Test TestSuite test_count method"""
        suite = GeneratedTestSuite(language="python", framework="pytest", tests=["test1", "test2", "test3"])

        assert suite.test_count() == 3

        empty_suite = GeneratedTestSuite(language="python", framework="pytest")
        assert empty_suite.test_count() == 0


class TestSecurityTestGeneratorCLI:
    """Test CLI functionality"""

    def test_cli_with_invalid_input_file(self, tmp_path):
        """Test CLI with non-existent input file"""
        import subprocess

        result = subprocess.run(
            ["python3", "scripts/security_test_generator.py", "--input", "nonexistent.json"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "Error: Input file not found" in result.stderr

    def test_cli_with_valid_input(self, tmp_path):
        """Test CLI with valid input file"""
        import subprocess

        # Create sample input file
        input_file = tmp_path / "findings.json"
        input_file.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "test-001",
                            "type": "sql-injection",
                            "path": "app.py",
                            "description": "Test finding",
                            "code_snippet": "SELECT * FROM users",
                        }
                    ]
                }
            )
        )

        output_dir = tmp_path / "tests"

        result = subprocess.run(
            ["python3", "scripts/security_test_generator.py", "--input", str(input_file), "--output-dir", str(output_dir)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Successfully generated" in result.stdout
        assert (output_dir / "test_security_generated.py").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
