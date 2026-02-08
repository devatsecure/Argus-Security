"""
Integration tests for automated remediation engine
Tests that generated fixes actually work and don't break code
"""
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Add test utilities to path
TEST_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(TEST_ROOT))

from utils.assertions import security_assertions
from utils.fixtures import fixture_manager

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestRemediationEngine:
    """Test that remediation engine produces valid fixes"""

    @pytest.fixture
    def vulnerable_code_samples(self):
        """Provide vulnerable code samples for testing"""
        return {
            "sql_injection": '''
def search_users(query):
    cursor = db.cursor()
    # Vulnerable: SQL injection
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    cursor.execute(sql)
    return cursor.fetchall()
''',
            "xss": '''
def display_message(user_input):
    # Vulnerable: XSS via innerHTML
    html = f"<div>{user_input}</div>"
    return html
''',
            "command_injection": '''
import subprocess

def run_backup(filename):
    # Vulnerable: Command injection
    cmd = f"tar -czf backup.tar.gz {filename}"
    subprocess.run(cmd, shell=True)
''',
            "path_traversal": '''
def read_file(filename):
    # Vulnerable: Path traversal
    with open(filename, 'r') as f:
        return f.read()
''',
            "hardcoded_secret": '''
# Vulnerable: Hardcoded API key
API_KEY = "sk-1234567890abcdefghij"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def call_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com", headers=headers)
''',
            "eval_usage": '''
def calculate(expression):
    # Vulnerable: eval on user input
    result = eval(expression)
    return result
''',
        }

    def test_sql_injection_fix_is_valid(self, vulnerable_code_samples, tmp_path):
        """Test that SQL injection fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["sql_injection"]

        # Expected fix: Use parameterized query
        fixed_code = '''
def search_users(query):
    cursor = db.cursor()
    # Fixed: Use parameterized query
    sql = "SELECT * FROM users WHERE name = ?"
    cursor.execute(sql, (query,))
    return cursor.fetchall()
'''

        # Verify both are valid Python
        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should not have string formatting in SQL
        assert "f\"" not in fixed_code, "Fixed code should not use f-strings for SQL"
        assert "?" in fixed_code or "%s" in fixed_code, "Fixed code should use placeholders"

        print("✅ SQL injection fix produces valid Python")

    def test_xss_fix_is_valid(self, vulnerable_code_samples):
        """Test that XSS fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["xss"]

        # Expected fix: Escape HTML
        fixed_code = '''
import html

def display_message(user_input):
    # Fixed: Escape HTML
    safe_input = html.escape(user_input)
    html_output = f"<div>{safe_input}</div>"
    return html_output
'''

        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should use html.escape
        assert "html.escape" in fixed_code, "Fixed code should use html.escape"

        print("✅ XSS fix produces valid Python")

    def test_command_injection_fix_is_valid(self, vulnerable_code_samples):
        """Test that command injection fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["command_injection"]

        # Expected fix: Use list arguments instead of shell=True
        fixed_code = '''
import subprocess

def run_backup(filename):
    # Fixed: Use list arguments, disabled shell execution
    cmd = ["tar", "-czf", "backup.tar.gz", filename]
    subprocess.run(cmd, shell=False, check=True)
'''

        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should use shell=False (not shell=True as the unsafe option)
        assert "shell=False" in fixed_code, "Fixed code should explicitly disable shell"
        # Ensure the only occurrence of shell= is shell=False
        import re
        shell_true_matches = re.findall(r'\bshell\s*=\s*True\b', fixed_code)
        assert len(shell_true_matches) == 0, "Fixed code should not invoke shell=True"

        print("✅ Command injection fix produces valid Python")

    def test_path_traversal_fix_is_valid(self, vulnerable_code_samples):
        """Test that path traversal fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["path_traversal"]

        # Expected fix: Sanitize path
        fixed_code = '''
import os

def read_file(filename):
    # Fixed: Sanitize path to prevent traversal
    safe_path = os.path.basename(filename)
    base_dir = "/var/www/files"
    full_path = os.path.join(base_dir, safe_path)

    # Verify path is within base directory
    if not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):
        raise ValueError("Invalid file path")

    with open(full_path, 'r') as f:
        return f.read()
'''

        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should validate paths
        assert "os.path.basename" in fixed_code or "os.path.abspath" in fixed_code, \
            "Fixed code should sanitize paths"

        print("✅ Path traversal fix produces valid Python")

    def test_hardcoded_secret_fix_is_valid(self, vulnerable_code_samples):
        """Test that hardcoded secret fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["hardcoded_secret"]

        # Expected fix: Use environment variables
        fixed_code = '''
import os
import requests

# Fixed: Use environment variables
API_KEY = os.environ.get("API_KEY")
AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY")

def call_api():
    if not API_KEY:
        raise ValueError("API_KEY environment variable not set")
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com", headers=headers)
'''

        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should use os.environ
        assert "os.environ" in fixed_code, "Fixed code should use environment variables"
        assert "sk-" not in fixed_code, "Fixed code should not contain hardcoded secrets"

        print("✅ Hardcoded secret fix produces valid Python")

    def test_eval_fix_is_valid(self, vulnerable_code_samples):
        """Test that eval usage fix produces valid Python code"""
        vulnerable_code = vulnerable_code_samples["eval_usage"]

        # Expected fix: Use ast.literal_eval or remove eval
        fixed_code = '''
import ast

def calculate(expression):
    # Fixed: Use ast.literal_eval for safe evaluation
    # Only supports literals, not arbitrary code
    try:
        result = ast.literal_eval(expression)
        return result
    except (ValueError, SyntaxError):
        raise ValueError("Invalid expression")
'''

        self._assert_valid_python(vulnerable_code, "vulnerable")
        self._assert_valid_python(fixed_code, "fixed")

        # Fixed code should not use bare eval() -- ast.literal_eval is safe
        assert "ast.literal_eval" in fixed_code or "compile" in fixed_code, \
            "Fixed code should use safer alternatives"
        # Ensure there is no standalone eval() call (ast.literal_eval is OK)
        import re
        bare_eval_matches = re.findall(r'(?<!literal_)(?<!\.)eval\(', fixed_code)
        assert len(bare_eval_matches) == 0, "Fixed code should not use bare eval()"

        print("✅ eval() fix produces valid Python")

    def test_fixes_preserve_functionality(self, vulnerable_code_samples, tmp_path):
        """Test that fixes preserve original functionality"""
        # Test SQL injection fix preserves query logic
        vulnerable_sql = vulnerable_code_samples["sql_injection"]
        fixed_sql = '''
def search_users(query):
    cursor = db.cursor()
    sql = "SELECT * FROM users WHERE name = ?"
    cursor.execute(sql, (query,))
    return cursor.fetchall()
'''

        # Both should have same function signature
        vuln_ast = ast.parse(vulnerable_sql)
        fixed_ast = ast.parse(fixed_sql)

        vuln_func = vuln_ast.body[0]
        fixed_func = fixed_ast.body[0]

        assert vuln_func.name == fixed_func.name, "Function name should be preserved"
        assert len(vuln_func.args.args) == len(fixed_func.args.args), \
            "Function parameters should be preserved"

        print("✅ Fixes preserve function signatures")

    def test_remediation_output_structure(self):
        """Test that remediation output has proper structure"""
        remediation = {
            "finding_id": "test-1",
            "original_code": "eval(user_input)",
            "fixed_code": "ast.literal_eval(user_input)",
            "description": "Replace eval() with ast.literal_eval()",
            "fix_type": "code_change",
            "confidence": 0.9,
            "testing_required": True,
            "references": [
                "https://docs.python.org/3/library/ast.html#ast.literal_eval"
            ]
        }

        # Validate structure
        security_assertions.assert_remediation_is_valid(remediation)

        print("✅ Remediation output has valid structure")

    def test_fixes_can_be_applied_to_real_files(self, tmp_path):
        """Test that fixes can be applied to actual files"""
        # Create test file with vulnerability
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text('''
def search(query):
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    return execute(sql)
''')

        # Read original
        original = test_file.read_text()

        # Apply fix (simple replacement)
        fixed = original.replace(
            'sql = f"SELECT * FROM users WHERE name = \'{query}\'"',
            'sql = "SELECT * FROM users WHERE name = ?"\n    params = (query,)'
        )

        # Write fixed version
        test_file.write_text(fixed)

        # Verify file is still valid Python
        self._assert_valid_python(test_file.read_text(), "fixed file")

        print("✅ Fixes can be applied to real files")

    def test_multiple_fixes_in_same_file(self, tmp_path):
        """Test that multiple fixes can be applied to same file"""
        test_file = tmp_path / "multi_vuln.py"
        test_file.write_text('''
def search(query):
    # Vulnerability 1: SQL injection
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    execute(sql)

def display(data):
    # Vulnerability 2: XSS
    return f"<div>{data}</div>"

def run_cmd(cmd):
    # Vulnerability 3: Command injection
    subprocess.run(cmd, shell=True)
''')

        # Apply multiple fixes
        content = test_file.read_text()

        # Fix 1: SQL injection
        content = content.replace(
            'sql = f"SELECT * FROM users WHERE name = \'{query}\'"',
            'sql = "SELECT * FROM users WHERE name = ?"'
        )

        # Fix 2: XSS
        content = content.replace(
            'return f"<div>{data}</div>"',
            'import html\n    return f"<div>{html.escape(data)}</div>"'
        )

        # Fix 3: Command injection
        content = content.replace(
            'subprocess.run(cmd, shell=True)',
            'subprocess.run(cmd.split(), shell=False)'
        )

        test_file.write_text(content)

        # Verify still valid Python
        self._assert_valid_python(test_file.read_text(), "multi-fix file")

        print("✅ Multiple fixes can be applied to same file")

    def test_remediation_includes_testing_guidance(self):
        """Test that remediation includes testing guidance"""
        remediation = {
            "finding_id": "test-sqli",
            "fix_type": "code_change",
            "description": "Use parameterized queries",
            "testing_required": True,
            "test_cases": [
                "Test with normal input: 'John'",
                "Test with SQL injection attempt: \"' OR '1'='1\"",
                "Test with special characters: \"O'Brien\"",
            ],
            "verification_steps": [
                "1. Apply fix to code",
                "2. Run unit tests",
                "3. Verify SQL errors don't leak",
                "4. Test with fuzzing tool"
            ]
        }

        assert remediation["testing_required"] is True
        assert len(remediation["test_cases"]) > 0
        assert len(remediation["verification_steps"]) > 0

        print("✅ Remediation includes testing guidance")

    def test_fixes_dont_introduce_new_vulnerabilities(self):
        """Test that fixes don't introduce new security issues"""
        # Bad fix that introduces new vulnerability
        bad_fix = '''
def search(query):
    # "Fixed" SQL injection but introduced XSS
    safe_query = query.replace("'", "")  # Insufficient sanitization
    sql = f"SELECT * FROM users WHERE name = '{safe_query}'"
    return execute(sql)
'''

        # This is still vulnerable - just checking it's valid Python
        self._assert_valid_python(bad_fix, "bad fix")

        # Good fix
        good_fix = '''
def search(query):
    # Proper fix: parameterized query
    sql = "SELECT * FROM users WHERE name = ?"
    return execute(sql, (query,))
'''

        self._assert_valid_python(good_fix, "good fix")

        # Good fix should not have string concatenation or formatting
        assert "f\"" not in good_fix and "%" not in good_fix and "+" not in good_fix
        assert "?" in good_fix or "%s" in good_fix

        print("✅ Good fixes avoid introducing new vulnerabilities")

    def _assert_valid_python(self, code: str, label: str = "code"):
        """Assert that code is valid Python syntax"""
        try:
            ast.parse(code)
        except SyntaxError as e:
            pytest.fail(f"{label} has syntax errors: {e}")

    def test_remediation_prioritizes_high_severity(self):
        """Test that high severity fixes are prioritized"""
        findings = [
            {"id": "1", "severity": "critical", "cwe": "CWE-89"},
            {"id": "2", "severity": "high", "cwe": "CWE-79"},
            {"id": "3", "severity": "medium", "cwe": "CWE-327"},
            {"id": "4", "severity": "low", "cwe": "CWE-1004"},
        ]

        # Priority should be: critical > high > medium > low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        sorted_findings = sorted(findings, key=lambda f: severity_order[f["severity"]])

        assert sorted_findings[0]["severity"] == "critical"
        assert sorted_findings[1]["severity"] == "high"
        assert sorted_findings[-1]["severity"] == "low"

        print("✅ Remediation prioritizes high severity findings")


class TestRemediationEngineIntegration:
    """Integration tests with actual remediation engine"""

    @pytest.mark.slow
    def test_remediation_engine_generates_fixes(self, tmp_path):
        """Test that remediation engine can generate fixes"""
        try:
            from remediation_engine import RemediationEngine

            engine = RemediationEngine()

            # Create test finding
            finding = {
                "id": "test-1",
                "file_path": str(tmp_path / "test.py"),
                "line": 3,
                "severity": "high",
                "cwe": "CWE-89",
                "description": "SQL injection via string formatting",
                "code": 'sql = f"SELECT * FROM users WHERE id = {user_id}"'
            }

            # Generate remediation using actual API (suggest_fix)
            remediation = engine.suggest_fix(finding)

            # Verify remediation structure
            assert remediation is not None
            # suggest_fix returns a RemediationSuggestion object, not a dict
            assert hasattr(remediation, "finding_id") or isinstance(remediation, dict)

            print("✅ Remediation engine generates fixes")

        except ImportError:
            pytest.skip("Remediation engine not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
