#!/usr/bin/env python3
"""
Unit Tests for Reachability Analyzer

Tests cover:
- Language detection from repo files
- Import checking across languages
- Vulnerable function extraction
- Function call finding
- Source file discovery
- Finding analysis and enrichment
- ReachabilityResult dataclass
- Edge cases (empty findings, unknown language, missing files)
"""

import sys
from pathlib import Path

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from reachability_analyzer import ReachabilityAnalyzer, ReachabilityResult

# ---------------------------------------------------------------------------
# ReachabilityResult Dataclass
# ---------------------------------------------------------------------------


class TestReachabilityResult:
    """Test ReachabilityResult dataclass"""

    def test_creation_reachable(self):
        result = ReachabilityResult(
            finding_id="f1",
            package="requests",
            cve="CVE-2024-0001",
            is_reachable=True,
            confidence="high",
            evidence=["Package imported", "Function called"],
            call_chain=["api.py:42"],
        )
        assert result.is_reachable is True
        assert result.confidence == "high"
        assert len(result.evidence) == 2
        assert result.call_chain is not None

    def test_creation_not_reachable(self):
        result = ReachabilityResult(
            finding_id="f2",
            package="lodash",
            cve="CVE-2024-0002",
            is_reachable=False,
            confidence="high",
            evidence=["Package not imported"],
        )
        assert result.is_reachable is False
        assert result.call_chain is None

    def test_default_call_chain(self):
        result = ReachabilityResult(
            finding_id="f3",
            package="pkg",
            cve="CVE",
            is_reachable=False,
            confidence="low",
            evidence=[],
        )
        assert result.call_chain is None


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------


class TestLanguageDetection:
    """Test _detect_language"""

    def test_detect_python_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "python"

    def test_detect_python_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "python"

    def test_detect_javascript(self, tmp_path):
        (tmp_path / "package.json").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "javascript"

    def test_detect_go(self, tmp_path):
        (tmp_path / "go.mod").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "go"

    def test_detect_java_pom(self, tmp_path):
        (tmp_path / "pom.xml").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "java"

    def test_detect_java_gradle(self, tmp_path):
        (tmp_path / "build.gradle").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "java"

    def test_detect_rust(self, tmp_path):
        (tmp_path / "Cargo.toml").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "rust"

    def test_detect_unknown(self, tmp_path):
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "unknown"

    def test_priority_javascript_over_python(self, tmp_path):
        """package.json is checked before requirements.txt"""
        (tmp_path / "package.json").touch()
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer.language == "javascript"


# ---------------------------------------------------------------------------
# Source File Discovery
# ---------------------------------------------------------------------------


class TestSourceFileDiscovery:
    """Test _get_source_files"""

    def test_python_files(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def foo(): pass")
        (tmp_path / "readme.md").write_text("# readme")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        files = analyzer._get_source_files()
        extensions = [f.suffix for f in files]
        assert all(ext == ".py" for ext in extensions)

    def test_javascript_files(self, tmp_path):
        (tmp_path / "package.json").touch()
        (tmp_path / "app.js").write_text("console.log('hi')")
        (tmp_path / "index.ts").write_text("export default {}")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        files = analyzer._get_source_files()
        extensions = {f.suffix for f in files}
        assert extensions <= {".js", ".jsx", ".ts", ".tsx"}

    def test_empty_repo(self, tmp_path):
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        files = analyzer._get_source_files()
        assert files == []

    def test_limit_500_files(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        for i in range(600):
            (tmp_path / f"file_{i}.py").write_text(f"x = {i}")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        files = analyzer._get_source_files()
        assert len(files) <= 500


# ---------------------------------------------------------------------------
# Import Checking
# ---------------------------------------------------------------------------


class TestImportChecking:
    """Test _check_imports"""

    def test_python_import_found(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import requests\nrequests.get('http://example.com')")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("requests") is True

    def test_python_from_import_found(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("flask") is True

    def test_python_import_not_found(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import os\nos.path.exists('/')")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("requests") is False

    def test_javascript_require_found(self, tmp_path):
        (tmp_path / "package.json").touch()
        (tmp_path / "app.js").write_text("const express = require('express')")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("express") is True

    def test_javascript_import_from_found(self, tmp_path):
        (tmp_path / "package.json").touch()
        (tmp_path / "app.js").write_text("import React from 'react'")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("react") is True

    def test_unknown_language_no_imports(self, tmp_path):
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("anything") is False

    def test_empty_repo_no_imports(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        assert analyzer._check_imports("requests") is False


# ---------------------------------------------------------------------------
# Vulnerable Function Extraction
# ---------------------------------------------------------------------------


class TestVulnerableFunctions:
    """Test _get_vulnerable_functions"""

    def test_python_eval_detected(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {"description": "Use of eval() function is dangerous"}
        funcs = analyzer._get_vulnerable_functions(finding)
        assert "eval" in funcs

    def test_python_pickle_detected(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {"description": "Unsafe use of pickle.loads for deserialization"}
        funcs = analyzer._get_vulnerable_functions(finding)
        assert "pickle.loads" in funcs

    def test_no_description(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {}
        funcs = analyzer._get_vulnerable_functions(finding)
        assert funcs == []

    def test_javascript_inner_html(self, tmp_path):
        (tmp_path / "package.json").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {"description": "Setting innerHTML directly can lead to XSS"}
        funcs = analyzer._get_vulnerable_functions(finding)
        assert "innerHTML" in funcs


# ---------------------------------------------------------------------------
# Function Call Finding
# ---------------------------------------------------------------------------


class TestFunctionCallFinding:
    """Test _find_function_calls"""

    def test_find_eval_call(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("result = eval(user_input)\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        calls = analyzer._find_function_calls(["eval"])
        assert len(calls) >= 1
        assert "app.py:1" in calls[0]

    def test_no_calls_found(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("x = 1 + 2\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        calls = analyzer._find_function_calls(["eval"])
        assert calls == []

    def test_empty_function_list(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        calls = analyzer._find_function_calls([])
        assert calls == []


# ---------------------------------------------------------------------------
# Finding Analysis
# ---------------------------------------------------------------------------


class TestFindingAnalysis:
    """Test _analyze_finding"""

    def test_reachable_with_function_calls(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import pickle\ndata = pickle.loads(user_input)\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {
            "id": "f1",
            "title": "pickle vulnerability",
            "rule_id": "CVE-2024-0001",
            "category": "VULN",
            "description": "Unsafe pickle.loads usage",
        }
        result = analyzer._analyze_finding(finding)
        assert result.is_reachable is True
        assert result.confidence == "high"
        assert result.call_chain is not None

    def test_reachable_imported_no_calls(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import requests\nresponse = requests.get('http://example.com')\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {
            "id": "f2",
            "title": "requests vulnerability in HTTP handling",
            "rule_id": "CVE-2024-0002",
            "category": "VULN",
            "description": "HTTP request vulnerability",
        }
        result = analyzer._analyze_finding(finding)
        assert result.is_reachable is True
        assert result.confidence == "medium"

    def test_not_reachable_not_imported(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import os\nx = 1\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        finding = {
            "id": "f3",
            "title": "lodash prototype pollution",
            "rule_id": "CVE-2024-0003",
            "category": "VULN",
            "description": "Prototype pollution in lodash",
        }
        result = analyzer._analyze_finding(finding)
        assert result.is_reachable is False
        assert result.confidence == "high"


# ---------------------------------------------------------------------------
# analyze_findings (batch)
# ---------------------------------------------------------------------------


class TestAnalyzeFindings:
    """Test analyze_findings"""

    def test_filters_vuln_only(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import os\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        findings = [
            {"id": "f1", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-1"},
            {"id": "f2", "category": "SAST", "title": "code issue", "rule_id": "R1"},
            {"id": "f3", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-2"},
        ]
        results = analyzer.analyze_findings(findings)
        assert len(results) == 2  # Only VULN category

    def test_empty_findings(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        results = analyzer.analyze_findings([])
        assert results == []


# ---------------------------------------------------------------------------
# enrich_findings
# ---------------------------------------------------------------------------


class TestEnrichFindings:
    """Test enrich_findings"""

    def test_enriches_vuln_findings(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import os\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        findings = [
            {"id": "f1", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-1", "description": ""},
            {"id": "f2", "category": "SAST", "title": "code issue", "rule_id": "R1"},
        ]
        enriched = analyzer.enrich_findings(findings)
        assert len(enriched) == 2

        # VULN finding should have reachability fields
        vuln_finding = [f for f in enriched if f["id"] == "f1"][0]
        assert "reachable" in vuln_finding
        assert "reachability_confidence" in vuln_finding
        assert "reachability_evidence" in vuln_finding

        # Non-VULN finding should be unmodified
        sast_finding = [f for f in enriched if f["id"] == "f2"][0]
        assert "reachable" not in sast_finding

    def test_enriches_with_call_chain(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "app.py").write_text("import pickle\ndata = pickle.loads(x)\n")

        analyzer = ReachabilityAnalyzer(str(tmp_path))
        findings = [
            {
                "id": "f1",
                "category": "VULN",
                "title": "pickle vulnerability",
                "rule_id": "CVE-1",
                "description": "Unsafe pickle.loads",
            },
        ]
        enriched = analyzer.enrich_findings(findings)
        assert enriched[0].get("call_chain") is not None

    def test_empty_findings_enrichment(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        analyzer = ReachabilityAnalyzer(str(tmp_path))
        enriched = analyzer.enrich_findings([])
        assert enriched == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
