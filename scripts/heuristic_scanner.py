#!/usr/bin/env python3
"""
Heuristic Scanner Module

Pre-scan code for obvious issues before LLM analysis with context awareness
to reduce false positives. Distinguishes between production code, test code,
and documentation.

Extracted from run_ai_audit.py for better maintainability.
"""

import ast
import logging
import re

__all__ = ["HeuristicScanner"]

logger = logging.getLogger(__name__)


class HeuristicScanner:
    """Pre-scan code for obvious issues before LLM analysis
    NOW WITH CONTEXT AWARENESS to reduce false positives

    Feature: Heuristic Guardrails with Context Detection
    This class performs lightweight pattern-matching to identify potential issues
    before sending code to expensive LLM APIs. Distinguishes between production code,
    test code, and documentation to reduce false positives.
    """

    def __init__(self):
        """Initialize the context-aware heuristic scanner"""
        self.findings = []

        # Test file patterns
        self.test_patterns = [
            r"test_.*\.py$",
            r".*_test\.py$",
            r".*\.test\.(js|ts)$",
            r".*\.spec\.(js|ts)$",
            r"test/.*",
            r"tests/.*",
            r"__tests__/.*",
            r".*_spec\.rb$",
        ]

        # Documentation patterns
        self.doc_patterns = [
            r"docs?/.*",
            r"README.*",
            r".*\.md$",
            r"examples?/.*",
            r"samples?/.*",
            r"demo/.*",
            r"tutorial/.*",
        ]

        # Test-specific dummy data patterns
        self.test_data_patterns = [
            r"(TEST|EXAMPLE|DEMO|SAMPLE)_[A-Z_]+",
            r"dummy_\w+",
            r"fake_\w+",
            r"mock_\w+",
            r"stub_\w+",
            r"fixture_\w+",
            r'(password|secret|key|token)\s*=\s*["\']test',
            r'(password|secret|key|token)\s*=\s*["\']example',
            r'(password|secret|key|token)\s*=\s*["\']123',
            r'(password|secret|key|token)\s*=\s*["\']xxx',
            r'(password|secret|key|token)\s*=\s*["\']foo',
        ]

        # Parameterized query indicators (safe SQL patterns)
        self.parameterized_query_patterns = [
            r"\?\s*[,\)]",  # ? placeholders (SQLite, MySQL)
            r"\$\d+",  # $1, $2 placeholders (PostgreSQL)
            r":\w+",  # :name named parameters
            r"@\w+",  # @param (SQL Server, MySQL)
            r"params\s*[\[.]",  # params[] or params. array usage
            r"\.prepare\s*\(",  # prepared statements
            r"parameterized",  # explicit parameterized mention
            r"placeholder",  # placeholder mention
            r"bind_param|bindParam|bindValue",  # PHP/PDO binding
            r"\.execute\s*\([^)]*,\s*[\[\(]",  # execute(query, [params])
            r"\.query\s*\([^)]*,\s*[\[\(]",  # query(sql, [params])
        ]

        # Safe command execution patterns
        self.safe_exec_patterns = [
            r"shell\s*:\s*false",  # JS/TS spawn with shell: false
            r"shell\s*=\s*False",  # Python subprocess with shell=False
            r"spawn\s*\(\s*process\.execPath",  # Node spawn with own binary
            r'spawn\s*\(\s*["\'][^"\']*["\']'  # spawn with hardcoded command
            r"\s*,\s*\[",  # followed by array of args
            r"execFile\s*\(",  # Node execFile (no shell)
            r"exec\.Command\s*\(",  # Go exec.Command (no shell)
            r"ProcessBuilder\s*\(",  # Java ProcessBuilder (no shell)
        ]

        # Input validation patterns (mitigations before dangerous operations)
        self.input_validation_patterns = [
            r"MAX_\w+\s*=\s*\d+",  # MAX_LENGTH, MAX_COUNT constants
            r"\.length\s*[<>]=?\s*\d+",  # .length < N checks
            r"len\s*\(\s*\w+\s*\)\s*[<>]=?",  # len(x) < N checks
            r"\.limit\s*\(",  # .limit() calls
            r"\.slice\s*\(",  # .slice() to bound input
            r"\.substring\s*\(",  # .substring() to bound input
            r"validate\w*\s*\(",  # validate() calls before ops
            r"sanitize\w*\s*\(",  # sanitize() calls
            r"if\s*\(\s*\w+\.length\s*>",  # if (input.length > MAX)
        ]

        # Localhost/dev-tool indicators
        self.localhost_indicators = [
            r"localhost",
            r"127\.0\.0\.1",
            r"0\.0\.0\.0",
            r"::1",
        ]

        self.dev_tool_indicators = [
            r"cli\b",
            r"daemon",
            r"desktop.app",
            r"electron",
            r"local.server",
            r"dev.tool",
            r"development.only",
        ]

        # Backup/config file extensions that could expose credentials
        self.backup_file_patterns = [
            r"\.bak$",
            r"\.backup$",
            r"\.old$",
            r"\.orig$",
            r"\.save$",
            r"\.swp$",
            r"\.swo$",
            r"~$",
            r"\.conf\.bak$",
            r"\.config\.old$",
            r"\.inc\.php\.bak$",
            r"\.dist$",
        ]

        # Content patterns that programmatically create backup files
        self.backup_content_patterns = [
            r"@copy\s*\(\s*\$\w+\s*,\s*\$\w*bak\w*\)",  # @copy($conf, $bakconf)
            r"file_put_contents\s*\([^)]*\.bak",  # file_put_contents(...\.bak)
            r"copy\s*\([^)]*\.(bak|backup|old)\b",  # copy(..., file.bak)
            r"rename\s*\([^)]*\.(bak|backup|old)\b",  # rename(..., file.bak)
            r"shutil\.copy\w*\s*\([^)]*\.(bak|backup|old)\b",  # shutil.copy(..., file.bak)
            r"\.write\s*\([^)]*\.(bak|backup|old)\b",  # .write(...bak)
        ]

        # CSRF token patterns (safe indicators)
        self.csrf_token_patterns = [
            r"csrf_token",
            r"_token",
            r"csrfmiddlewaretoken",
            r"authenticity_token",
            r"__RequestVerificationToken",
            r"anti-forgery",
            r"X-CSRF-Token",
        ]

        # Form/state-changing endpoint patterns
        self.form_action_patterns = [
            r"<form\b",
            r'method\s*=\s*["\']?POST',
            r'method\s*=\s*["\']?PUT',
            r'method\s*=\s*["\']?DELETE',
            r"password_new",
            r"password_conf",
        ]

        # Weak/predictable session ID generation patterns
        self.weak_session_patterns = [
            r"last_session_id\s*\+\+",  # Sequential: last_session_id++
            r"session_id\s*\+=\s*1",  # Sequential: session_id += 1
            r"session_counter\s*\+\+",  # Sequential: session_counter++
            r"session_id\s*=\s*session_id\s*\+\s*1",  # Sequential: session_id = session_id + 1
            r"md5\s*\(\s*time\s*\(\s*\)\s*\)",  # Predictable: md5(time())
            r"md5\s*\(\s*microtime\s*\(\s*\)\s*\)",  # Predictable: md5(microtime())
            r"(?:session|token|sess_id)\s*=.*\brand\s*\(",  # Predictable: rand() for session/token
            r"(?:session|token|sess_id)\s*=.*\bmt_rand\s*\(",  # Predictable: mt_rand() for session/token
        ]

        # Insecure cookie flag patterns
        self.insecure_cookie_patterns = [
            r"setcookie\s*\([^)]*\)",  # setcookie() call (checked for missing flags)
            r"session\.cookie_httponly\s*=\s*(false|0|off)",  # session.cookie_httponly disabled
            r"session\.cookie_secure\s*=\s*(false|0|off)",  # session.cookie_secure disabled
        ]

    def _detect_context(self, file_path: str, content: str) -> dict:
        """Detect file context to determine if it's test/doc/production

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Context dictionary with flags and confidence
        """
        context = {
            "is_test_file": False,
            "is_documentation": False,
            "is_example_code": False,
            "test_confidence": 0.0,
            "doc_confidence": 0.0,
            "reasons": [],
        }

        # Check file path patterns
        for pattern in self.test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                context["is_test_file"] = True
                context["test_confidence"] += 0.3
                context["reasons"].append(f"Test file pattern: {pattern}")
                break

        for pattern in self.doc_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                context["is_documentation"] = True
                context["doc_confidence"] += 0.4
                context["reasons"].append(f"Doc file pattern: {pattern}")
                break

        # Check content for test indicators
        test_content_indicators = [
            (r"import\s+(unittest|pytest|jest|mocha|jasmine|rspec)", 0.4, "Test framework import"),
            (r"@test|@Test|it\(|describe\(|context\(", 0.3, "Test decoration/function"),
            (r"class.*Test|Test.*class|.*TestCase", 0.3, "Test class definition"),
            (r"def\s+test_|function\s+test", 0.3, "Test function definition"),
            (r"expect\(|assert|should|toBe|toEqual", 0.2, "Test assertion"),
            (r"mock|stub|spy|fake|fixture", 0.2, "Test double pattern"),
        ]

        for pattern, weight, reason in test_content_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                context["test_confidence"] += weight
                context["reasons"].append(reason)

        # Check content for documentation indicators
        doc_content_indicators = [
            (r"^#{1,6}\s+", 0.4, "Markdown heading"),
            (r"```|~~~", 0.3, "Code block in documentation"),
            (r"## Example|### Usage|## Quick Start", 0.4, "Documentation section"),
            (r"This is an example|For example|Sample code", 0.3, "Example reference"),
        ]

        for pattern, weight, reason in doc_content_indicators:
            if re.search(pattern, content, re.MULTILINE):
                context["doc_confidence"] += weight
                context["reasons"].append(reason)

        # Check for example code indicators
        if context["doc_confidence"] > 0.3 or "example" in file_path.lower():
            context["is_example_code"] = True

        # Normalize confidences
        context["test_confidence"] = min(context["test_confidence"], 1.0)
        context["doc_confidence"] = min(context["doc_confidence"], 1.0)

        return context

    def _is_test_secret(self, content: str) -> bool:
        """Check if secret pattern is actually test/dummy data

        Args:
            content: Code snippet containing the secret pattern

        Returns:
            True if this is test data, False if potentially real
        """
        # Check for test data patterns
        for pattern in self.test_data_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        # Extract the actual value (between quotes)
        value_match = re.search(r'["\']([^"\']+)["\']', content)
        if not value_match:
            return False

        value = value_match.group(1).lower()

        # Check for obvious dummy values in the actual secret value
        # These should appear as standalone words or be the entire/majority of the value
        dummy_indicators = [
            "test",
            "example",
            "demo",
            "sample",
            "dummy",
            "fake",
            "mock",
            "123456",
            "changeme",
            "xxx",
            "foo",
            "bar",
            "your_",
            "placeholder",
        ]

        for dummy in dummy_indicators:
            if dummy in value:
                # Check if it's a significant part of the value
                # Require either:
                # 1. The dummy is at least 50% of the value (e.g., "test123" where "test" is 57%)
                # 2. The value starts with the dummy indicator (e.g., "test_password")
                # 3. The dummy is 6+ chars and makes up 40%+ (e.g., "123456" in "test123456")
                dummy_percentage = len(dummy) / len(value)
                if value.startswith(dummy) or value.endswith(dummy):
                    return True
                elif dummy_percentage >= 0.5:
                    return True
                elif len(dummy) >= 6 and dummy_percentage >= 0.4:
                    return True

        # Check if value is just the word "password" or "secret" with simple additions
        simple_test_patterns = [
            r"^(password|secret|token|key|api[_-]?key)$",
            r"^(password|secret|token|key)\d+$",
            r"^\d{4,8}$",  # Simple numeric passwords like 123456
        ]

        for pattern in simple_test_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True

        return False

    def _has_parameterized_queries(self, content: str) -> bool:
        """Check if the code uses parameterized queries (safe SQL patterns)

        Args:
            content: File content as string

        Returns:
            True if parameterized query patterns are found
        """
        for pattern in self.parameterized_query_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_safe_exec_pattern(self, content: str) -> bool:
        """Check if command execution uses safe patterns (no shell, hardcoded args)

        Args:
            content: File content as string

        Returns:
            True if safe execution patterns are found
        """
        for pattern in self.safe_exec_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_input_validation_before_regex(self, content: str) -> bool:
        """Check if input is validated/bounded before regex operations

        This catches cases like MAX_TAG_COUNT limits checked before regex
        processing, which mitigates ReDoS risks.

        Args:
            content: File content as string

        Returns:
            True if input validation patterns are found near regex usage
        """
        has_regex = bool(re.search(r"re\.(search|match|findall|sub|compile)|RegExp|\.match\(|\.replace\(", content))
        if not has_regex:
            return False

        for pattern in self.input_validation_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _detect_deployment_context(self, file_path: str, content: str) -> dict:
        """Detect if the project is a localhost-only or dev tool

        This helps avoid false positives for findings like 'missing auth'
        or 'resource exhaustion' that are low-risk for local dev tools.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Dictionary with deployment context flags
        """
        deploy_context = {"is_localhost_only": False, "is_dev_tool": False, "localhost_confidence": 0.0, "reasons": []}

        # Check for localhost binding patterns in the content
        for pattern in self.localhost_indicators:
            if re.search(pattern, content, re.I):
                deploy_context["localhost_confidence"] += 0.2
                deploy_context["reasons"].append(f"Localhost pattern: {pattern}")

        # Check for dev tool indicators in file path and content
        for pattern in self.dev_tool_indicators:
            if re.search(pattern, file_path, re.I) or re.search(pattern, content, re.I):
                deploy_context["localhost_confidence"] += 0.15
                deploy_context["reasons"].append(f"Dev tool pattern: {pattern}")

        # Check for explicit localhost-only server binding
        if re.search(r"listen\s*\(\s*\d+\s*,\s*['\"](?:localhost|127\.0\.0\.1)['\"]", content, re.I):
            deploy_context["localhost_confidence"] += 0.3
            deploy_context["reasons"].append("Server explicitly binds to localhost")

        # Check for absence of production deployment indicators
        has_production = bool(
            re.search(r"docker|kubernetes|k8s|aws|gcp|azure|heroku|deploy|production|nginx|apache", content, re.I)
        )
        if not has_production:
            deploy_context["localhost_confidence"] += 0.1

        deploy_context["localhost_confidence"] = min(deploy_context["localhost_confidence"], 1.0)
        deploy_context["is_localhost_only"] = deploy_context["localhost_confidence"] >= 0.4
        deploy_context["is_dev_tool"] = deploy_context["localhost_confidence"] >= 0.3

        return deploy_context

    def _is_backup_file(self, file_path: str) -> bool:
        """Check if the file path matches a dangerous backup/config file extension

        Args:
            file_path: Path to the file

        Returns:
            True if the file matches a backup file pattern
        """
        for pattern in self.backup_file_patterns:
            if re.search(pattern, file_path, re.I):
                return True
        return False

    def _creates_backup_files(self, content: str) -> bool:
        """Check if the code programmatically creates backup files

        Args:
            content: File content as string

        Returns:
            True if backup file creation patterns are found
        """
        for pattern in self.backup_content_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_csrf_protection(self, content: str) -> bool:
        """Check if the code contains CSRF token/protection patterns

        Args:
            content: File content as string

        Returns:
            True if CSRF protection patterns are found
        """
        for pattern in self.csrf_token_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_form_actions(self, content: str) -> bool:
        """Check if the code contains form submissions or state-changing endpoints

        Args:
            content: File content as string

        Returns:
            True if form/state-changing patterns are found
        """
        for pattern in self.form_action_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_state_change_via_get(self, content: str) -> bool:
        """Check if state-changing operations use GET parameters (worse than missing CSRF)

        Args:
            content: File content as string

        Returns:
            True if state-changing operations accessed via GET are found
        """
        # Detect password change or sensitive operations via $_GET
        get_state_patterns = [
            r'\$_GET\s*\[\s*["\']password',  # $_GET['password_new'] etc.
            r'\$_GET\s*\[\s*["\']pass',  # $_GET['pass']
            r'\$_GET\s*\[\s*["\']token',  # $_GET['token']
            r'\$_GET\s*\[\s*["\']secret',  # $_GET['secret']
            r'request\.GET\s*\.get\s*\(\s*["\']password',  # Django request.GET.get('password')
            r'request\.GET\s*\[\s*["\']password',  # Django request.GET['password']
            r'params\[\s*["\']password.*\]\s*.*GET',  # Generic GET password params
        ]
        for pattern in get_state_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_weak_session_ids(self, content: str) -> bool:
        """Check if the code uses weak/predictable session ID generation

        Args:
            content: File content as string

        Returns:
            True if weak session ID patterns are found
        """
        for pattern in self.weak_session_patterns:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _has_insecure_cookie_flags(self, content: str) -> bool:
        """Check if cookies are set without httponly/secure flags

        Args:
            content: File content as string

        Returns:
            True if insecure cookie patterns are found
        """
        # Check for explicit disabling of security flags
        for pattern in self.insecure_cookie_patterns[1:]:  # Skip the setcookie catch-all
            if re.search(pattern, content, re.I):
                return True

        # Check for setcookie() calls without httponly flag
        # PHP setcookie signature: setcookie(name, value, expires, path, domain, secure, httponly)
        # If httponly is not set (fewer than 7 args) or explicitly false
        setcookie_matches = re.findall(r"setcookie\s*\(([^)]*)\)", content, re.I)
        for match in setcookie_matches:
            args = [a.strip() for a in match.split(",")]
            # setcookie with fewer than 7 args means httponly not set
            if len(args) < 7:
                return True
            # Check if httponly is explicitly false
            if len(args) >= 7 and re.match(r"(false|0)", args[6].strip(), re.I):
                return True

        return False

    def scan_file(self, file_path: str, content: str) -> list:
        """Run context-aware heuristic checks on a file

        Args:
            file_path: Path to the file being scanned
            content: File content as string

        Returns:
            List of flag strings indicating potential issues
        """
        flags = []

        # Detect file context first
        context = self._detect_context(file_path, content)

        # Skip or downweight findings in test/doc context
        if context["is_test_file"] and context["test_confidence"] > 0.5:
            logger.debug(f"Skipping test file: {file_path} (confidence: {context['test_confidence']:.2f})")
            return []  # Skip test files entirely

        if context["is_documentation"] and context["doc_confidence"] > 0.5:
            logger.debug(f"Skipping documentation: {file_path} (confidence: {context['doc_confidence']:.2f})")
            return []  # Skip documentation entirely

        # Detect deployment context for severity adjustment
        deploy_context = self._detect_deployment_context(file_path, content)

        # Security patterns (with test data filtering)
        secret_pattern = r'(password|secret|api[_-]?key|token|credential)\s*=\s*["\'][^"\']{8,}["\']'
        if re.search(secret_pattern, content, re.I):
            # Extract the match for detailed check
            match = re.search(secret_pattern, content, re.I)
            if match and not self._is_test_secret(match.group(0)):
                flags.append("hardcoded-secrets")
            else:
                logger.debug(f"Skipped test secret in {file_path}")

        if re.search(r"eval\(|exec\(|__import__\(|compile\(", content):
            flags.append("dangerous-exec")

        # SQL injection detection: check for concatenation BUT also check for
        # parameterized queries which indicate safe usage
        if re.search(r"(SELECT|INSERT|UPDATE|DELETE).*[\+\%].*", content, re.I):
            if self._has_parameterized_queries(content):
                flags.append("sql-parameterized-safe")
                logger.debug(f"SQL concatenation found but parameterized queries detected in {file_path}")
            else:
                flags.append("sql-concatenation")

        # Command execution detection: check for dangerous patterns BUT also
        # check for safe patterns (shell:false, hardcoded args)
        if re.search(r"spawn\(|exec\(|subprocess|child_process|os\.system|os\.popen", content, re.I):
            if self._has_safe_exec_pattern(content):
                flags.append("cmd-exec-safe-pattern")
                logger.debug(f"Command execution found with safe patterns in {file_path}")
            elif re.search(r"shell\s*[=:]\s*(true|True)|os\.system\(|os\.popen\(", content, re.I):
                flags.append("cmd-injection-risk")

        # Regex/ReDoS detection: check if input validation exists before regex
        if re.search(r"re\.(search|match|findall|sub)|RegExp|new\s+RegExp", content, re.I):
            if self._has_input_validation_before_regex(content):
                flags.append("regex-input-validated")
                logger.debug(f"Regex found with input validation in {file_path}")

        if re.search(r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", content):
            flags.append("xss-risk")

        # Performance patterns (only for non-test files)
        if not context["is_test_file"]:
            if re.search(r"for\s+\w+\s+in.*:\s*for\s+\w+\s+in", content, re.DOTALL):
                flags.append("nested-loops")

            if content.count("SELECT ") > 5:
                flags.append("n-plus-one-query-risk")

        # Python-specific complexity (skip for test files)
        if file_path.endswith(".py") and not context["is_test_file"]:
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        complexity = self._calculate_complexity(node)
                        if complexity > 15:
                            flags.append(f"high-complexity-{node.name}")
            except Exception:
                pass  # Skip if AST parsing fails

        # JavaScript/TypeScript patterns
        if file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            if re.search(r"JSON\.parse\([^)]*\)", content) and "try" not in content:
                flags.append("unsafe-json-parse")

            if re.search(r"localStorage\.|sessionStorage\.", content):
                flags.append("client-storage-usage")

        # Backup file exposure detection (DVWA-013)
        if self._is_backup_file(file_path):
            flags.append("backup-file-exposure")
            logger.debug(f"Backup file detected: {file_path}")

        if self._creates_backup_files(content):
            flags.append("creates-backup-files")
            logger.debug(f"Code creates backup files in {file_path}")

        # CSRF token missing detection (DVWA-009)
        if self._has_form_actions(content):
            if not self._has_csrf_protection(content):
                flags.append("csrf-token-missing")
                logger.debug(f"Form/state-change without CSRF protection in {file_path}")

        if self._has_state_change_via_get(content):
            flags.append("state-change-via-get")
            logger.debug(f"State-changing operation via GET in {file_path}")

        # Weak/predictable session ID detection (DVWA-011)
        if self._has_weak_session_ids(content):
            flags.append("weak-session-id")
            logger.debug(f"Weak/predictable session ID generation in {file_path}")

        if self._has_insecure_cookie_flags(content):
            flags.append("insecure-cookie-flags")
            logger.debug(f"Insecure cookie flags detected in {file_path}")

        # Add deployment context info for downstream AI analysis
        if deploy_context["is_localhost_only"]:
            flags.append(f"localhost-only-{deploy_context['localhost_confidence']:.2f}")
            logger.debug(f"Localhost-only context detected for {file_path}: {deploy_context['reasons']}")

        if deploy_context["is_dev_tool"]:
            flags.append("dev-tool-context")

        # Add context info to flags if in grey area (medium confidence test/doc)
        if 0.3 <= context["test_confidence"] < 0.5:
            flags.append(f"test-context-uncertain-{context['test_confidence']:.2f}")

        if 0.3 <= context["doc_confidence"] < 0.5:
            flags.append(f"doc-context-uncertain-{context['doc_confidence']:.2f}")

        return flags

    def _calculate_complexity(self, node) -> int:
        """Calculate cyclomatic complexity of a function

        Args:
            node: AST FunctionDef node

        Returns:
            Cyclomatic complexity score
        """
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def should_skip_file(self, flags: list) -> bool:
        """Determine if a file should be skipped based on heuristic results

        Args:
            flags: List of heuristic flags

        Returns:
            True if file appears clean and can be skipped
        """
        # For now, don't skip any files - just use flags to inform LLM
        # This can be made configurable later
        return False

    def scan_codebase(self, files: list) -> dict:
        """Scan entire codebase and return summary

        Args:
            files: List of file dictionaries with 'path' and 'content'

        Returns:
            Dictionary mapping file paths to their heuristic flags
        """
        results = {}
        for file_info in files:
            path = file_info["path"]
            content = file_info["content"]
            flags = self.scan_file(path, content)
            if flags:
                results[path] = flags
        return results
