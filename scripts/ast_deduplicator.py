#!/usr/bin/env python3
"""
AST-based De-duplication for Argus Security
Uses function/class boundaries instead of line buckets for accurate grouping

This module provides intelligent deduplication of security findings by:
1. Parsing source files to AST (Abstract Syntax Tree)
2. Finding enclosing function/class for each line
3. Grouping findings by function/class instead of arbitrary line buckets
4. Falling back to line buckets for non-structural files

Benefits:
- Eliminates false duplicates from long functions (e.g., line 15 and 45 in same function)
- Groups related findings within logical code boundaries
- Maintains backward compatibility with non-parseable files
- Supports multiple programming languages
"""

import ast
import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CodeLocation:
    """Structured code location with context

    Attributes:
        file_path: Path to the file
        line_number: Specific line number of the finding
        function_name: Name of enclosing function (None if not in function)
        class_name: Name of enclosing class (None if not in class)
        start_line: Start line of the enclosing scope
        end_line: End line of the enclosing scope
    """
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    start_line: int = 0
    end_line: int = 0


class ASTDeduplicator:
    """
    AST-based de-duplication using function/class boundaries

    Strategy:
    1. Parse file to AST (Python) or regex patterns (JavaScript/TypeScript)
    2. Find enclosing function/class for each line
    3. Group findings by function/class instead of line bucket
    4. Fallback to line bucket (10-line groups) for non-structural files

    Example:
        >>> dedup = ASTDeduplicator()
        >>> location = dedup.get_code_location("script.py", 25)
        >>> print(location.function_name)  # "process_data"
        >>> key = dedup.create_dedup_key(finding)
        >>> print(key)  # "script.py:SQL-injection:fn:process_data"
    """

    def __init__(self):
        """Initialize AST deduplicator with caching"""
        self.logger = logging.getLogger(__name__)
        self._ast_cache = {}  # Cache parsed ASTs for performance
        self._file_lines_cache = {}  # Cache file contents for JS/TS parsing

    def get_code_location(self, file_path: str, line_number: int) -> CodeLocation:
        """
        Get structured code location with AST context

        This is the main entry point for getting location context. It will:
        1. Check if file is parseable (Python, JS, TS)
        2. Parse with appropriate method (AST for Python, regex for JS/TS)
        3. Fall back to line bucket if parsing fails

        Args:
            file_path: Path to file (absolute or relative)
            line_number: Line number in file (1-indexed)

        Returns:
            CodeLocation with function/class context
        """
        # Normalize path
        try:
            file_path = str(Path(file_path).resolve())
        except Exception:
            pass  # Keep original path if resolution fails

        # Try AST parsing for structural languages
        if self._is_parseable(file_path):
            ast_location = self._parse_location(file_path, line_number)
            if ast_location:
                return ast_location

        # Fallback: line bucket (for non-parseable files or parse failures)
        line_bucket = (line_number // 10) * 10
        return CodeLocation(
            file_path=file_path,
            line_number=line_number,
            function_name=None,
            class_name=None,
            start_line=line_bucket,
            end_line=line_bucket + 9
        )

    def _is_parseable(self, file_path: str) -> bool:
        """Check if file can be parsed with AST or regex patterns

        Args:
            file_path: Path to file

        Returns:
            True if file is parseable, False otherwise
        """
        return (
            file_path.endswith(".py") or
            file_path.endswith(".js") or
            file_path.endswith(".jsx") or
            file_path.endswith(".ts") or
            file_path.endswith(".tsx")
        )

    def _parse_location(self, file_path: str, line_number: int) -> Optional[CodeLocation]:
        """Parse file and find enclosing function/class

        Routes to appropriate parser based on file extension.

        Args:
            file_path: Path to file
            line_number: Line number to find context for

        Returns:
            CodeLocation if successful, None if parsing failed
        """
        if file_path.endswith(".py"):
            return self._parse_python_location(file_path, line_number)
        elif file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
            return self._parse_js_location(file_path, line_number)

        return None

    def _parse_python_location(self, file_path: str, line_number: int) -> Optional[CodeLocation]:
        """Parse Python file with AST and find enclosing function/class

        Args:
            file_path: Path to Python file
            line_number: Line number to find context for

        Returns:
            CodeLocation with function/class context, or None on failure
        """
        try:
            # Get or cache AST
            if file_path not in self._ast_cache:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Parse with type_comments=False to avoid syntax errors in older Python versions
                try:
                    tree = ast.parse(content, filename=file_path)
                except SyntaxError as e:
                    self.logger.debug(f"Syntax error parsing {file_path}: {e}")
                    return None

                self._ast_cache[file_path] = tree

            tree = self._ast_cache[file_path]

            # Find enclosing function/class
            result = self._find_enclosing_node(tree, line_number)

            if result:
                func_name, class_name, start_line, end_line = result
                return CodeLocation(
                    file_path=file_path,
                    line_number=line_number,
                    function_name=func_name,
                    class_name=class_name,
                    start_line=start_line,
                    end_line=end_line
                )

        except FileNotFoundError:
            self.logger.debug(f"File not found: {file_path}")
        except Exception as e:
            self.logger.debug(f"Failed to parse Python file {file_path}: {e}")

        return None

    def _find_enclosing_node(
        self,
        tree: ast.AST,
        line_number: int,
        parent_class: Optional[str] = None
    ) -> Optional[Tuple[Optional[str], Optional[str], int, int]]:
        """
        Find enclosing function/class for a line using AST traversal

        This method handles nested structures correctly:
        - Functions at module level
        - Methods within classes
        - Nested functions (returns innermost function)

        Args:
            tree: AST tree or node to search
            line_number: Line number to find context for
            parent_class: Name of parent class (for recursive calls)

        Returns:
            Tuple of (function_name, class_name, start_line, end_line) or None
        """
        best_match = None
        best_range = float('inf')  # Track smallest enclosing range

        for node in ast.walk(tree):
            # Check class definitions
            if isinstance(node, ast.ClassDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        node_range = (node.end_lineno or node.lineno) - node.lineno

                        # Recurse to find function within class (innermost match)
                        inner_result = self._find_function_in_class(
                            node, line_number, node.name
                        )
                        if inner_result:
                            inner_range = inner_result[3] - inner_result[2]
                            if inner_range < best_range:
                                best_match = inner_result
                                best_range = inner_range
                        elif node_range < best_range:
                            # No function found, use class itself
                            best_match = (None, node.name, node.lineno, node.end_lineno or node.lineno)
                            best_range = node_range

            # Check function definitions at module level
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        node_range = (node.end_lineno or node.lineno) - node.lineno
                        if node_range < best_range:
                            best_match = (node.name, parent_class, node.lineno, node.end_lineno or node.lineno)
                            best_range = node_range

        return best_match

    def _find_function_in_class(
        self,
        class_node: ast.ClassDef,
        line_number: int,
        class_name: str
    ) -> Optional[Tuple[str, str, int, int]]:
        """Find function within a class (handles methods)

        Args:
            class_node: AST ClassDef node
            line_number: Line number to find
            class_name: Name of the class

        Returns:
            Tuple of (function_name, class_name, start_line, end_line) or None
        """
        best_match = None
        best_range = float('inf')

        for node in class_node.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                        node_range = (node.end_lineno or node.lineno) - node.lineno
                        if node_range < best_range:
                            best_match = (node.name, class_name, node.lineno, node.end_lineno or node.lineno)
                            best_range = node_range

        return best_match

    def _parse_js_location(self, file_path: str, line_number: int) -> Optional[CodeLocation]:
        """Parse JavaScript/TypeScript using regex patterns

        Note: This is a simplified parser using regex. For production use,
        consider using a proper JS/TS parser like esprima or @babel/parser
        via a Node.js bridge or pyodide.

        Detects:
        - function declarations: function foo() {}
        - arrow functions: const foo = () => {}
        - class methods: class Foo { bar() {} }
        - ES6 classes: class Foo {}

        Args:
            file_path: Path to JS/TS file
            line_number: Line number to find context for

        Returns:
            CodeLocation with function/class context, or None on failure
        """
        try:
            # Get or cache file contents
            if file_path not in self._file_lines_cache:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                self._file_lines_cache[file_path] = lines

            lines = self._file_lines_cache[file_path]

            # Track current context
            current_class = None
            current_function = None
            function_start = 0
            class_start = 0
            brace_depth = 0
            function_brace_start = None
            class_brace_start = None

            for i, line in enumerate(lines, start=1):
                # Count braces to track scope
                brace_depth += line.count('{') - line.count('}')

                # Detect class declaration
                class_match = re.search(r'class\s+(\w+)', line)
                if class_match:
                    current_class = class_match.group(1)
                    class_start = i
                    class_brace_start = brace_depth

                # Detect function/method declaration
                # Patterns: function foo(), const foo = () =>, async function foo(), foo() {
                func_patterns = [
                    r'(?:async\s+)?function\s+(\w+)',  # function foo()
                    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(',  # const foo = (
                    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[^\s]+)\s*=>',  # const foo = () =>
                    r'^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{',  # method shorthand: foo() {
                ]

                for pattern in func_patterns:
                    func_match = re.search(pattern, line)
                    if func_match:
                        current_function = func_match.group(1)
                        function_start = i
                        function_brace_start = brace_depth
                        break

                # Check if we're at the target line
                if i == line_number:
                    if current_function:
                        # Estimate function end (find closing brace at same depth)
                        function_end = self._find_scope_end(lines, function_start, function_brace_start or 0)
                        return CodeLocation(
                            file_path=file_path,
                            line_number=line_number,
                            function_name=current_function,
                            class_name=current_class,
                            start_line=function_start,
                            end_line=function_end
                        )
                    elif current_class:
                        # In class but not in function
                        class_end = self._find_scope_end(lines, class_start, class_brace_start or 0)
                        return CodeLocation(
                            file_path=file_path,
                            line_number=line_number,
                            function_name=None,
                            class_name=current_class,
                            start_line=class_start,
                            end_line=class_end
                        )

                # Reset function context if we've exited the scope
                if function_brace_start is not None and brace_depth <= function_brace_start:
                    if i > function_start:
                        current_function = None
                        function_brace_start = None

                # Reset class context if we've exited the scope
                if class_brace_start is not None and brace_depth <= class_brace_start:
                    if i > class_start:
                        current_class = None
                        class_brace_start = None

        except FileNotFoundError:
            self.logger.debug(f"File not found: {file_path}")
        except Exception as e:
            self.logger.debug(f"Failed to parse JS/TS file {file_path}: {e}")

        return None

    def _find_scope_end(self, lines: list, start_line: int, start_depth: int) -> int:
        """Find the end of a scope by tracking brace depth

        Args:
            lines: List of file lines
            start_line: Line where scope starts (1-indexed)
            start_depth: Brace depth at scope start

        Returns:
            Line number where scope ends
        """
        brace_depth = start_depth

        for i in range(start_line, len(lines) + 1):
            if i > len(lines):
                return len(lines)

            line = lines[i - 1]  # Convert to 0-indexed
            brace_depth += line.count('{') - line.count('}')

            # Found closing brace at same depth
            if brace_depth <= start_depth and '}' in line and i > start_line:
                return i

        # If we didn't find end, estimate conservatively
        return min(start_line + 50, len(lines))

    def create_dedup_key(
        self,
        finding: dict,
        use_code_hash: bool = False
    ) -> str:
        """
        Create de-duplication key for finding using AST context

        Key format:
        - With function: "file.py:rule-id:fn:function_name"
        - With class and function: "file.py:rule-id:class:ClassName:fn:method_name"
        - With class only: "file.py:rule-id:class:ClassName"
        - Fallback: "file.py:rule-id:L10" (line bucket)
        - With hash: "file.py:rule-id:fn:function_name:hash:abc123de"

        Args:
            finding: Finding dictionary with file_path, line_number, rule_id
            use_code_hash: If True, include code snippet hash for cross-file dedup

        Returns:
            De-duplication key string
        """
        file_path = finding.get("file_path", "unknown")
        line_number = finding.get("line_number", 0)
        rule_id = finding.get("rule_id", finding.get("issue_type", "unknown"))

        # Get code location with AST context
        location = self.get_code_location(file_path, line_number)

        # Build key based on available context
        if location.function_name:
            # Function-level deduplication (most precise)
            key = f"{file_path}:{rule_id}:fn:{location.function_name}"
            if location.class_name:
                # Method-level deduplication (class + function)
                key = f"{file_path}:{rule_id}:class:{location.class_name}:fn:{location.function_name}"
        elif location.class_name:
            # Class-level deduplication
            key = f"{file_path}:{rule_id}:class:{location.class_name}"
        else:
            # Fallback: line bucket (10-line groups)
            line_bucket = (line_number // 10) * 10
            key = f"{file_path}:{rule_id}:L{line_bucket}"

        # Optionally add code hash for cross-file deduplication
        # (useful for copy-pasted code or similar patterns across files)
        if use_code_hash:
            code_snippet = finding.get("code_snippet", finding.get("evidence", {}).get("snippet", ""))
            if code_snippet:
                # Use MD5 for speed (not cryptographic use)
                code_hash = hashlib.md5(code_snippet.encode()).hexdigest()[:8]
                key = f"{key}:hash:{code_hash}"

        return key

    def clear_cache(self):
        """Clear cached AST trees and file contents

        Call this periodically if processing many files to avoid memory bloat.
        """
        self._ast_cache.clear()
        self._file_lines_cache.clear()
        self.logger.debug("Cleared AST deduplicator cache")


def create_enhanced_dedup_key(finding: dict, deduplicator: ASTDeduplicator = None) -> str:
    """
    Convenience function for creating enhanced dedup key

    This is a standalone helper function that can be used without
    creating an ASTDeduplicator instance manually.

    Args:
        finding: Finding dictionary with file_path, line_number, rule_id
        deduplicator: Optional ASTDeduplicator instance (creates new if None)

    Returns:
        De-duplication key string

    Example:
        >>> finding = {"file_path": "app.py", "line_number": 42, "rule_id": "SQL-injection"}
        >>> key = create_enhanced_dedup_key(finding)
        >>> print(key)  # "app.py:SQL-injection:fn:process_user_input"
    """
    if deduplicator is None:
        deduplicator = ASTDeduplicator()

    return deduplicator.create_dedup_key(finding)


if __name__ == "__main__":
    # Example usage and testing
    import json

    logging.basicConfig(level=logging.INFO)

    print("AST Deduplicator - Example Usage\n")

    # Example findings
    example_findings = [
        {"file_path": "test.py", "line_number": 15, "rule_id": "SQL-injection"},
        {"file_path": "test.py", "line_number": 25, "rule_id": "SQL-injection"},  # Same function
        {"file_path": "test.py", "line_number": 45, "rule_id": "SQL-injection"},  # Different function
    ]

    dedup = ASTDeduplicator()

    for finding in example_findings:
        location = dedup.get_code_location(finding["file_path"], finding["line_number"])
        key = dedup.create_dedup_key(finding)

        print(f"Line {finding['line_number']}:")
        print(f"  Location: {location}")
        print(f"  Dedup Key: {key}")
        print()
