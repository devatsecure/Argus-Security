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
            r'test_.*\.py$',
            r'.*_test\.py$',
            r'.*\.test\.(js|ts)$',
            r'.*\.spec\.(js|ts)$',
            r'test/.*',
            r'tests/.*',
            r'__tests__/.*',
            r'.*_spec\.rb$'
        ]

        # Documentation patterns
        self.doc_patterns = [
            r'docs?/.*',
            r'README.*',
            r'.*\.md$',
            r'examples?/.*',
            r'samples?/.*',
            r'demo/.*',
            r'tutorial/.*'
        ]

        # Test-specific dummy data patterns
        self.test_data_patterns = [
            r'(TEST|EXAMPLE|DEMO|SAMPLE)_[A-Z_]+',
            r'dummy_\w+',
            r'fake_\w+',
            r'mock_\w+',
            r'stub_\w+',
            r'fixture_\w+',
            r'(password|secret|key|token)\s*=\s*["\']test',
            r'(password|secret|key|token)\s*=\s*["\']example',
            r'(password|secret|key|token)\s*=\s*["\']123',
            r'(password|secret|key|token)\s*=\s*["\']xxx',
            r'(password|secret|key|token)\s*=\s*["\']foo'
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
            'is_test_file': False,
            'is_documentation': False,
            'is_example_code': False,
            'test_confidence': 0.0,
            'doc_confidence': 0.0,
            'reasons': []
        }

        # Check file path patterns
        for pattern in self.test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                context['is_test_file'] = True
                context['test_confidence'] += 0.3
                context['reasons'].append(f"Test file pattern: {pattern}")
                break

        for pattern in self.doc_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                context['is_documentation'] = True
                context['doc_confidence'] += 0.4
                context['reasons'].append(f"Doc file pattern: {pattern}")
                break

        # Check content for test indicators
        test_content_indicators = [
            (r'import\s+(unittest|pytest|jest|mocha|jasmine|rspec)', 0.4, "Test framework import"),
            (r'@test|@Test|it\(|describe\(|context\(', 0.3, "Test decoration/function"),
            (r'class.*Test|Test.*class|.*TestCase', 0.3, "Test class definition"),
            (r'def\s+test_|function\s+test', 0.3, "Test function definition"),
            (r'expect\(|assert|should|toBe|toEqual', 0.2, "Test assertion"),
            (r'mock|stub|spy|fake|fixture', 0.2, "Test double pattern")
        ]

        for pattern, weight, reason in test_content_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                context['test_confidence'] += weight
                context['reasons'].append(reason)

        # Check content for documentation indicators
        doc_content_indicators = [
            (r'^#{1,6}\s+', 0.4, "Markdown heading"),
            (r'```|~~~', 0.3, "Code block in documentation"),
            (r'## Example|### Usage|## Quick Start', 0.4, "Documentation section"),
            (r'This is an example|For example|Sample code', 0.3, "Example reference")
        ]

        for pattern, weight, reason in doc_content_indicators:
            if re.search(pattern, content, re.MULTILINE):
                context['doc_confidence'] += weight
                context['reasons'].append(reason)

        # Check for example code indicators
        if context['doc_confidence'] > 0.3 or 'example' in file_path.lower():
            context['is_example_code'] = True

        # Normalize confidences
        context['test_confidence'] = min(context['test_confidence'], 1.0)
        context['doc_confidence'] = min(context['doc_confidence'], 1.0)

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
            'test', 'example', 'demo', 'sample', 'dummy', 'fake', 'mock',
            '123456', 'changeme', 'xxx', 'foo', 'bar', 'your_', 'placeholder'
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
            r'^(password|secret|token|key|api[_-]?key)$',
            r'^(password|secret|token|key)\d+$',
            r'^\d{4,8}$',  # Simple numeric passwords like 123456
        ]

        for pattern in simple_test_patterns:
            if re.match(pattern, value, re.IGNORECASE):
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
        if context['is_test_file'] and context['test_confidence'] > 0.5:
            logger.debug(f"Skipping test file: {file_path} (confidence: {context['test_confidence']:.2f})")
            return []  # Skip test files entirely

        if context['is_documentation'] and context['doc_confidence'] > 0.5:
            logger.debug(f"Skipping documentation: {file_path} (confidence: {context['doc_confidence']:.2f})")
            return []  # Skip documentation entirely

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

        if re.search(r"(SELECT|INSERT|UPDATE|DELETE).*[\+\%].*", content, re.I):
            flags.append("sql-concatenation")

        if re.search(r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", content):
            flags.append("xss-risk")

        # Performance patterns (only for non-test files)
        if not context['is_test_file']:
            if re.search(r"for\s+\w+\s+in.*:\s*for\s+\w+\s+in", content, re.DOTALL):
                flags.append("nested-loops")

            if content.count("SELECT ") > 5:
                flags.append("n-plus-one-query-risk")

        # Python-specific complexity (skip for test files)
        if file_path.endswith(".py") and not context['is_test_file']:
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

        # Add context info to flags if in grey area (medium confidence test/doc)
        if 0.3 <= context['test_confidence'] < 0.5:
            flags.append(f"test-context-uncertain-{context['test_confidence']:.2f}")

        if 0.3 <= context['doc_confidence'] < 0.5:
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
