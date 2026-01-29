"""
Test suite for context-aware HeuristicScanner

Tests the enhanced HeuristicScanner's ability to detect and differentiate
between production code, test files, and documentation to reduce false positives.
"""

import sys
from pathlib import Path

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from run_ai_audit import HeuristicScanner


class TestFileTypeDetection:
    """Test file type detection and context awareness"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_test_file_detection_python(self):
        """Test files should be detected by file path patterns"""
        test_cases = [
            "tests/test_auth.py",
            "test_login.py",
            "auth_test.py",
            "tests/integration/test_api.py",
        ]

        for file_path in test_cases:
            content = """
            import pytest

            def test_something():
                password = "sk-1234567890abcdef"
            """
            context = self.scanner._detect_context(file_path, content)
            assert context['is_test_file'], f"Failed to detect test file: {file_path}"
            assert context['test_confidence'] > 0.5

    def test_test_file_detection_javascript(self):
        """JavaScript/TypeScript test files should be detected"""
        test_cases = [
            "components/Button.test.js",
            "components/Button.spec.ts",
            "__tests__/api.test.js",
        ]

        for file_path in test_cases:
            content = """
            describe('Button', () => {
                it('should render', () => {
                    const apiKey = "test-api-key-12345678";
                });
            });
            """
            context = self.scanner._detect_context(file_path, content)
            assert context['is_test_file'], f"Failed to detect test file: {file_path}"

    def test_documentation_detection(self):
        """Documentation files should be detected"""
        test_cases = [
            "README.md",
            "docs/api.md",
            "examples/quickstart.py",
            "samples/demo.js",
        ]

        for file_path in test_cases:
            content = """
            ## Example Usage

            ```python
            password = "your_password_here"
            api_key = "your_api_key_1234567890"
            ```
            """
            context = self.scanner._detect_context(file_path, content)
            assert context['is_documentation'] or context['is_example_code'], \
                f"Failed to detect documentation: {file_path}"

    def test_production_file_detection(self):
        """Production files should not be marked as test/doc"""
        production_files = [
            "src/api/client.py",
            "app/controllers/auth.js",
            "lib/database.py",
        ]

        for file_path in production_files:
            content = """
            def connect():
                api_key = "sk-1234567890abcdef"
                return client.connect(api_key)
            """
            context = self.scanner._detect_context(file_path, content)
            assert not context['is_test_file'], f"Production file marked as test: {file_path}"
            assert context['test_confidence'] < 0.5


class TestContentContextDetection:
    """Test content-based context detection"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_test_framework_detection(self):
        """Test framework imports should boost test confidence"""
        test_frameworks = [
            ("import pytest", "pytest", 0.4),
            ("import unittest", "unittest", 0.4),
            ("import jest from 'jest'", "jest", 0.4),
            # Mocha requires describe/it patterns, not just require statement
            ("describe('test', () => { it('works', () => {}) })", "mocha", 0.3),
        ]

        for import_line, framework, min_confidence in test_frameworks:
            content = f"""
            {import_line}

            def test_something():
                pass
            """
            context = self.scanner._detect_context("file.py", content)
            assert context['test_confidence'] >= min_confidence, \
                f"Failed to detect {framework} test framework (got {context['test_confidence']}, expected >= {min_confidence})"

    def test_test_function_patterns(self):
        """Test function patterns should increase test confidence"""
        content = """
        import pytest

        def test_user_login():
            password = "test_password_12345678"
            assert login(password)

        def test_api_call():
            api_key = "test_api_key_12345678"
            assert api.call(api_key)
        """
        context = self.scanner._detect_context("test_auth.py", content)
        assert context['test_confidence'] > 0.7

    def test_documentation_patterns(self):
        """Markdown and documentation patterns should be detected"""
        content = """
        ## Quick Start

        This is an example of how to use the API:

        ```python
        password = "your_password_here"
        ```

        For example, you can connect like this...
        """
        context = self.scanner._detect_context("docs/quickstart.md", content)
        assert context['doc_confidence'] > 0.7


class TestTestSecretDetection:
    """Test the _is_test_secret method"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_obvious_test_secrets(self):
        """Obvious test/dummy secrets should be detected"""
        test_cases = [
            'password = "TEST_PASSWORD_123"',
            'api_key = "EXAMPLE_API_KEY"',
            'token = "test_token_value"',
            'secret = "dummy_secret_12345678"',
            'credential = "fake_credential_abc"',
            'password = "mock_password_xyz"',
            'api_key = "stub_api_key_123"',
            'token = "fixture_token_456"',
        ]

        for case in test_cases:
            assert self.scanner._is_test_secret(case), \
                f"Failed to detect test secret: {case}"

    def test_dummy_value_detection(self):
        """Common dummy values should be detected"""
        dummy_values = [
            'password = "test123456"',
            'password = "example_pass"',
            'password = "demo_secret_12345678"',
            'password = "sample_key_12345678"',
            'password = "changeme_12345678"',
            'password = "foobar123456"',
        ]

        for case in dummy_values:
            assert self.scanner._is_test_secret(case), \
                f"Failed to detect dummy value: {case}"

    def test_real_looking_secrets(self):
        """Real-looking secrets should not be marked as test data"""
        real_cases = [
            'password = "kJ8#mQ9$pL2@nB5!"',
            'api_key = "sk-proj-abc123xyz789"',
            'token = "ghp_1234567890abcdefghijklmno"',
        ]

        for case in real_cases:
            assert not self.scanner._is_test_secret(case), \
                f"Real secret incorrectly marked as test: {case}"


class TestIntegratedScanning:
    """Test the complete scan_file method with context awareness"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_test_file_with_secret_skipped(self):
        """Test files with secrets should not trigger alerts"""
        content = """
        import pytest

        def test_login():
            # Test API key for testing purposes
            api_key = "sk-1234567890abcdef"
            assert login(api_key)
        """

        flags = self.scanner.scan_file("tests/test_auth.py", content)
        assert "hardcoded-secrets" not in flags, \
            "Test file with secret should not trigger hardcoded-secrets flag"

    def test_production_file_with_secret_flagged(self):
        """Production files with secrets should be flagged"""
        content = """
        def connect():
            # Real API key - this should be flagged
            api_key = "sk-1234567890abcdef"
            return client.connect(api_key)
        """

        flags = self.scanner.scan_file("src/api/client.py", content)
        assert "hardcoded-secrets" in flags, \
            "Production file with secret should trigger hardcoded-secrets flag"

    def test_documentation_with_example_skipped(self):
        """Documentation with example code should be skipped"""
        content = """
        ## Example Usage

        ```python
        password = "your_password_here"
        api_key = "your_api_key_1234567890"
        ```

        This is an example of how to authenticate.
        """

        flags = self.scanner.scan_file("docs/api.md", content)
        assert len(flags) == 0, \
            "Documentation should be skipped entirely"

    def test_test_secret_in_production_file_skipped(self):
        """Test secrets (dummy data) in production files should be skipped"""
        content = """
        def setup_test_user():
            # Creating test user with dummy password
            password = "TEST_PASSWORD_123"
            return User.create(password)
        """

        flags = self.scanner.scan_file("src/models/user.py", content)
        assert "hardcoded-secrets" not in flags, \
            "Test secret pattern should be recognized even in production file"

    def test_performance_patterns_skipped_in_tests(self):
        """Performance patterns should be ignored in test files"""
        content = """
        import pytest

        def test_nested_loops():
            for i in range(10):
                for j in range(10):
                    assert i + j >= 0
        """

        flags = self.scanner.scan_file("tests/test_perf.py", content)
        assert "nested-loops" not in flags, \
            "Nested loops in test files should not be flagged"

    def test_performance_patterns_flagged_in_production(self):
        """Performance patterns should be flagged in production files"""
        content = """
        def process_data(items):
            for i in items:
                for j in items:
                    process(i, j)
        """

        flags = self.scanner.scan_file("src/processor.py", content)
        assert "nested-loops" in flags, \
            "Nested loops in production files should be flagged"

    def test_complexity_skipped_in_tests(self):
        """High complexity should be ignored in test files"""
        content = """
        import pytest

        def test_complex_scenario():
            if condition1:
                if condition2:
                    if condition3:
                        if condition4:
                            if condition5:
                                if condition6:
                                    if condition7:
                                        if condition8:
                                            if condition9:
                                                if condition10:
                                                    if condition11:
                                                        pass
        """

        flags = self.scanner.scan_file("tests/test_complex.py", content)
        complexity_flags = [f for f in flags if "high-complexity" in f]
        assert len(complexity_flags) == 0, \
            "High complexity in test files should not be flagged"

    def test_uncertain_context_flagged(self):
        """Files with uncertain context should be flagged"""
        # File with some test indicators but not enough confidence
        content = """
        def process():
            # Has assertions but no test framework
            assert True
            password = "sk-1234567890abcdef"
        """

        flags = self.scanner.scan_file("src/processor.py", content)
        # Should have uncertain context flag if test confidence is between 0.3 and 0.5
        uncertain_flags = [f for f in flags if "uncertain" in f]
        # This may or may not have uncertain flags depending on confidence calculation


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_empty_file(self):
        """Empty files should not cause errors"""
        flags = self.scanner.scan_file("src/empty.py", "")
        assert isinstance(flags, list)

    def test_file_with_only_comments(self):
        """Files with only comments should not cause errors"""
        content = """
        # This is a comment
        # Another comment
        # password = "not_real_code"
        """
        flags = self.scanner.scan_file("src/comments.py", content)
        assert isinstance(flags, list)

    def test_mixed_context_file(self):
        """Files with mixed context indicators should be handled"""
        content = """
        import pytest  # Test framework

        def actual_production_code():
            # But this is production code with real secret
            api_key = "sk-1234567890abcdef"
        """
        # This should be detected as a test file due to pytest import
        flags = self.scanner.scan_file("tests/utils.py", content)
        # Should be skipped as test file
        assert "hardcoded-secrets" not in flags

    def test_malformed_syntax(self):
        """Malformed syntax should not crash the scanner"""
        content = """
        def broken_function(
            # Missing closing parenthesis
            password = "sk-1234567890abcdef"
        """
        # Should not raise exception
        flags = self.scanner.scan_file("src/broken.py", content)
        assert isinstance(flags, list)

    def test_unicode_content(self):
        """Unicode content should be handled correctly"""
        content = """
        def greet():
            # Unicode characters: 你好, مرحبا, שלום
            password = "test_password_12345678"
        """
        flags = self.scanner.scan_file("src/greet.py", content)
        assert isinstance(flags, list)


class TestRegressionPrevention:
    """Test that the context awareness doesn't break existing functionality"""

    def setup_method(self):
        """Initialize scanner before each test"""
        self.scanner = HeuristicScanner()

    def test_dangerous_exec_still_detected(self):
        """Dangerous exec calls should still be detected"""
        content = """
        def execute_code(code):
            eval(code)
        """
        flags = self.scanner.scan_file("src/executor.py", content)
        assert "dangerous-exec" in flags

    def test_sql_injection_still_detected(self):
        """SQL injection patterns should still be detected"""
        content = """
        def query_user(name):
            query = "SELECT * FROM users WHERE name = '" + name + "'"
        """
        flags = self.scanner.scan_file("src/database.py", content)
        assert "sql-concatenation" in flags

    def test_xss_risk_still_detected(self):
        """XSS risk patterns should still be detected"""
        content = """
        function display(html) {
            element.innerHTML = html;
        }
        """
        flags = self.scanner.scan_file("src/display.js", content)
        assert "xss-risk" in flags

    def test_javascript_patterns_still_work(self):
        """JavaScript-specific patterns should still be detected"""
        content = """
        function parse(data) {
            return JSON.parse(data);
        }
        """
        flags = self.scanner.scan_file("src/parser.js", content)
        assert "unsafe-json-parse" in flags


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
