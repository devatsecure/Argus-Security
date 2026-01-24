#!/usr/bin/env python3
"""
Complexity and Performance Smell Detection
Flags functions with high complexity or large size as "Perf-Smell" in SARIF
"""

import ast
import json
import os
import re
import sys
from pathlib import Path

# Thresholds for complexity detection
MAX_FUNCTION_LINES = 50
MAX_CYCLOMATIC_COMPLEXITY = 10
MAX_COGNITIVE_COMPLEXITY = 15
MAX_NESTING_DEPTH = 4


class ComplexityAnalyzer(ast.NodeVisitor):
    """Analyze Python code for complexity metrics"""

    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []
        self.current_function = None
        self.nesting_depth = 0

    def visit_FunctionDef(self, node):
        """Analyze function complexity"""
        self.current_function = node.name
        start_line = node.lineno
        end_line = node.end_lineno or start_line
        function_lines = end_line - start_line + 1

        # Calculate cyclomatic complexity
        cyclomatic = self._calculate_cyclomatic_complexity(node)

        # Calculate cognitive complexity
        cognitive = self._calculate_cognitive_complexity(node)

        # Calculate nesting depth
        max_nesting = self._calculate_max_nesting(node)

        # Flag complexity issues
        if function_lines > MAX_FUNCTION_LINES:
            self.findings.append(
                {
                    "type": "perf-smell",
                    "severity": "medium",
                    "category": "performance",
                    "message": f"Function '{node.name}' is too long ({function_lines} lines, max {MAX_FUNCTION_LINES})",
                    "file": self.filepath,
                    "line": start_line,
                    "suggestion": f"Consider breaking down '{node.name}' into smaller functions",
                }
            )

        if cyclomatic > MAX_CYCLOMATIC_COMPLEXITY:
            self.findings.append(
                {
                    "type": "perf-smell",
                    "severity": "high" if cyclomatic > 20 else "medium",
                    "category": "performance",
                    "message": f"Function '{node.name}' has high cyclomatic complexity ({cyclomatic}, max {MAX_CYCLOMATIC_COMPLEXITY})",
                    "file": self.filepath,
                    "line": start_line,
                    "suggestion": f"Simplify '{node.name}' by reducing branches and conditions",
                }
            )

        if cognitive > MAX_COGNITIVE_COMPLEXITY:
            self.findings.append(
                {
                    "type": "perf-smell",
                    "severity": "high" if cognitive > 25 else "medium",
                    "category": "performance",
                    "message": f"Function '{node.name}' has high cognitive complexity ({cognitive}, max {MAX_COGNITIVE_COMPLEXITY})",
                    "file": self.filepath,
                    "line": start_line,
                    "suggestion": f"Reduce cognitive load in '{node.name}' by extracting complex logic",
                }
            )

        if max_nesting > MAX_NESTING_DEPTH:
            self.findings.append(
                {
                    "type": "perf-smell",
                    "severity": "medium",
                    "category": "quality",
                    "message": f"Function '{node.name}' has deep nesting ({max_nesting} levels, max {MAX_NESTING_DEPTH})",
                    "file": self.filepath,
                    "line": start_line,
                    "suggestion": f"Flatten nested logic in '{node.name}' using early returns or helper functions",
                }
            )

        self.generic_visit(node)
        self.current_function = None

    def _calculate_cyclomatic_complexity(self, node):
        """Calculate cyclomatic complexity (McCabe)"""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            # Add 1 for each decision point
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                # Add 1 for each boolean operator
                complexity += len(child.values) - 1

        return complexity

    def _calculate_cognitive_complexity(self, node):
        """Calculate cognitive complexity (SonarSource)"""
        complexity = 0
        nesting = 0

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1 + nesting
                nesting += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1 + nesting
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        return complexity

    def _calculate_max_nesting(self, node):
        """Calculate maximum nesting depth"""
        max_depth = 0

        def walk_depth(n, depth=0):
            nonlocal max_depth
            max_depth = max(max_depth, depth)

            for child in ast.iter_child_nodes(n):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                    walk_depth(child, depth + 1)
                else:
                    walk_depth(child, depth)

        walk_depth(node)
        return max_depth


def analyze_python_file(filepath: str) -> list[dict]:
    """Analyze a Python file for complexity issues"""
    try:
        with open(filepath, encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source, filename=filepath)
        analyzer = ComplexityAnalyzer(filepath)
        analyzer.visit(tree)

        return analyzer.findings
    except Exception as e:
        print(f"Warning: Could not analyze {filepath}: {e}", file=sys.stderr)
        return []


def analyze_javascript_file(filepath: str) -> list[dict]:
    """Analyze a JavaScript/TypeScript file for complexity issues"""
    findings = []

    try:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()

        # Simple heuristic: count function lines
        # For production, use a proper JS parser like esprima
        function_pattern = r"(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))"

        lines = content.split("\n")
        in_function = False
        function_start = 0
        function_name = ""
        brace_count = 0

        for i, line in enumerate(lines, 1):
            if re.search(function_pattern, line):
                in_function = True
                function_start = i
                match = re.search(r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+))", line)
                function_name = match.group(1) or match.group(2) if match else "anonymous"
                brace_count = line.count("{") - line.count("}")
            elif in_function:
                brace_count += line.count("{") - line.count("}")
                if brace_count == 0:
                    function_lines = i - function_start + 1
                    if function_lines > MAX_FUNCTION_LINES:
                        findings.append(
                            {
                                "type": "perf-smell",
                                "severity": "medium",
                                "category": "performance",
                                "message": f"Function '{function_name}' is too long ({function_lines} lines, max {MAX_FUNCTION_LINES})",
                                "file": filepath,
                                "line": function_start,
                                "suggestion": f"Consider breaking down '{function_name}' into smaller functions",
                            }
                        )
                    in_function = False

        return findings
    except Exception as e:
        print(f"Warning: Could not analyze {filepath}: {e}", file=sys.stderr)
        return []


def analyze_repository(repo_path: str) -> list[dict]:
    """Analyze all files in repository for complexity issues"""
    all_findings = []

    # Analyze Python files
    for py_file in Path(repo_path).rglob("*.py"):
        if ".git" in str(py_file) or "node_modules" in str(py_file):
            continue
        findings = analyze_python_file(str(py_file))
        all_findings.extend(findings)

    # Analyze JavaScript/TypeScript files
    for js_file in Path(repo_path).rglob("*.js"):
        if ".git" in str(js_file) or "node_modules" in str(js_file):
            continue
        findings = analyze_javascript_file(str(js_file))
        all_findings.extend(findings)

    for ts_file in Path(repo_path).rglob("*.ts"):
        if ".git" in str(ts_file) or "node_modules" in str(ts_file):
            continue
        findings = analyze_javascript_file(str(ts_file))
        all_findings.extend(findings)

    return all_findings


def generate_sarif(findings: list[dict], repo_path: str) -> str:
    """Generate SARIF 2.1.0 report from complexity findings"""
    results = []

    for finding in findings:
        severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

        results.append(
            {
                "ruleId": f"complexity/{finding['type']}",
                "level": severity_map.get(finding["severity"], "warning"),
                "message": {"text": finding["message"] + f"\n\nSuggestion: {finding['suggestion']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": os.path.relpath(finding["file"], repo_path)},
                            "region": {"startLine": finding["line"]},
                        }
                    }
                ],
            }
        )

    sarif_report = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent OS Complexity Analyzer",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/devatsecure/Argus-Security",
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_report, indent=2)


def main():
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."

    print("🔍 Analyzing code complexity...")
    findings = analyze_repository(repo_path)

    print(f"✅ Found {len(findings)} complexity issues")

    # Save SARIF report
    report_dir = Path(repo_path) / ".argus/reviews"
    report_dir.mkdir(parents=True, exist_ok=True)

    sarif_file = report_dir / "complexity-report.sarif"
    with open(sarif_file, "w") as f:
        f.write(generate_sarif(findings, repo_path))

    print(f"📄 SARIF report saved to: {sarif_file}")

    # Print summary
    severity_counts = {}
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print("\n📊 Summary:")
    for severity, count in sorted(severity_counts.items()):
        print(f"   {severity}: {count}")

    # Output for GitHub Actions
    print(f"::set-output name=complexity-issues::{len(findings)}")
    print(f"::set-output name=complexity-sarif::{sarif_file}")


if __name__ == "__main__":
    main()
