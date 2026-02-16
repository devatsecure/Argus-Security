#!/usr/bin/env python3
"""
Test Suite for ReachabilityAnalyzer

Comprehensive tests covering:
- Initialization and language detection
- Finding analysis (happy path, edge cases)
- Import checking across languages
- Vulnerable function extraction and call finding
- Source file enumeration
- Finding enrichment
- Error handling and edge cases
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reachability_analyzer import ReachabilityAnalyzer, ReachabilityResult


class TestReachabilityResult(unittest.TestCase):
    """Tests for the ReachabilityResult dataclass"""

    def test_create_result_all_fields(self):
        result = ReachabilityResult(
            finding_id="abc123",
            package="requests",
            cve="CVE-2023-1234",
            is_reachable=True,
            confidence="high",
            evidence=["Package imported", "Function called"],
            call_chain=["app.py:10", "utils.py:25"],
        )
        self.assertEqual(result.finding_id, "abc123")
        self.assertEqual(result.package, "requests")
        self.assertEqual(result.cve, "CVE-2023-1234")
        self.assertTrue(result.is_reachable)
        self.assertEqual(result.confidence, "high")
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(len(result.call_chain), 2)

    def test_create_result_optional_call_chain_default_none(self):
        result = ReachabilityResult(
            finding_id="abc123",
            package="flask",
            cve="CVE-2023-5678",
            is_reachable=False,
            confidence="high",
            evidence=["Package not imported"],
        )
        self.assertIsNone(result.call_chain)

    def test_create_result_empty_evidence(self):
        result = ReachabilityResult(
            finding_id="id1",
            package="pkg",
            cve="CVE-2023-0001",
            is_reachable=False,
            confidence="low",
            evidence=[],
        )
        self.assertEqual(result.evidence, [])


class TestReachabilityAnalyzerInit(unittest.TestCase):
    """Tests for ReachabilityAnalyzer initialization"""

    def test_init_sets_repo_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.repo_path, Path(tmpdir))

    def test_init_detects_python_requirements(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "python")

    def test_init_detects_python_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "pyproject.toml").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "python")

    def test_init_detects_javascript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "javascript")

    def test_init_detects_go(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "go.mod").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "go")

    def test_init_detects_java_pom(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "pom.xml").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "java")

    def test_init_detects_java_gradle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "build.gradle").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "java")

    def test_init_detects_rust(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "Cargo.toml").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "rust")

    def test_init_detects_unknown_when_no_markers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "unknown")

    def test_init_priority_javascript_over_python(self):
        """package.json checked first so JS wins if both exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertEqual(analyzer.language, "javascript")


class TestGetSourceFiles(unittest.TestCase):
    """Tests for _get_source_files"""

    def test_python_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("print('hi')")
            (Path(tmpdir) / "utils.py").write_text("pass")
            (Path(tmpdir) / "readme.md").write_text("# readme")
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            py_files = [f for f in files if f.suffix == ".py"]
            self.assertEqual(len(py_files), 2)

    def test_javascript_source_files_multiple_extensions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            (Path(tmpdir) / "index.js").write_text("console.log('hi')")
            (Path(tmpdir) / "app.tsx").write_text("export default App")
            (Path(tmpdir) / "types.ts").write_text("export type Foo = string")
            (Path(tmpdir) / "component.jsx").write_text("<div/>")
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            self.assertEqual(len(files), 4)

    def test_unknown_language_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            self.assertEqual(files, [])

    def test_source_files_limited_to_500(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            for i in range(510):
                (Path(tmpdir) / f"mod_{i}.py").write_text(f"x = {i}")
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            self.assertLessEqual(len(files), 500)

    def test_go_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "go.mod").touch()
            (Path(tmpdir) / "main.go").write_text("package main")
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            self.assertEqual(len(files), 1)

    def test_rust_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "Cargo.toml").touch()
            (Path(tmpdir) / "main.rs").write_text("fn main() {}")
            analyzer = ReachabilityAnalyzer(tmpdir)
            files = analyzer._get_source_files()
            self.assertEqual(len(files), 1)


class TestCheckImports(unittest.TestCase):
    """Tests for _check_imports"""

    def test_python_import_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("requests"))

    def test_python_from_import_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("from flask import Flask\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("flask"))

    def test_python_import_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import os\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertFalse(analyzer._check_imports("requests"))

    def test_javascript_require_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            (Path(tmpdir) / "app.js").write_text("const express = require('express')\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("express"))

    def test_javascript_import_from_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            (Path(tmpdir) / "app.js").write_text("import React from 'react'\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("react"))

    def test_unknown_language_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.txt").write_text("import something\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertFalse(analyzer._check_imports("something"))

    def test_file_read_error_is_handled(self):
        """If a source file can't be read, it should not raise"""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests")
            analyzer = ReachabilityAnalyzer(tmpdir)
            with patch("builtins.open", side_effect=PermissionError("denied")):
                result = analyzer._check_imports("requests")
            self.assertFalse(result)

    def test_java_import_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "pom.xml").touch()
            (Path(tmpdir) / "App.java").write_text("import org.apache.commons.lang3\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("org.apache.commons.lang3"))

    def test_go_import_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "go.mod").touch()
            (Path(tmpdir) / "main.go").write_text("import 'github.com/gin-gonic/gin'\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertTrue(analyzer._check_imports("github.com/gin-gonic/gin"))

    def test_no_source_files_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            # No .py files in the directory
            analyzer = ReachabilityAnalyzer(tmpdir)
            self.assertFalse(analyzer._check_imports("requests"))


class TestGetVulnerableFunctions(unittest.TestCase):
    """Tests for _get_vulnerable_functions"""

    def test_python_eval_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "Use of eval() is dangerous"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("eval", funcs)

    def test_python_pickle_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "Use of pickle.loads for deserialization"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("pickle.loads", funcs)

    def test_python_yaml_load_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "Insecure use of yaml.load without Loader"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("yaml.load", funcs)

    def test_python_multiple_funcs_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "eval and exec used in this code"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("eval", funcs)
            self.assertIn("exec", funcs)

    def test_no_vulnerable_funcs_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "SQL injection via parameterized query"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertEqual(funcs, [])

    def test_javascript_eval_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "Use of eval() in JavaScript"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("eval", funcs)

    def test_javascript_innerhtml_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "XSS via innerHTML injection"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("innerHTML", funcs)

    def test_javascript_dangerously_set_inner_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "React XSS via dangerouslySetInnerHTML"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("dangerouslySetInnerHTML", funcs)

    def test_java_runtime_exec_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "pom.xml").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "Command injection via runtime.exec call"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertIn("Runtime.exec", funcs)

    def test_empty_description(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": ""}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertEqual(funcs, [])

    def test_missing_description(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertEqual(funcs, [])

    def test_unknown_language_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {"description": "eval exec pickle.loads"}
            funcs = analyzer._get_vulnerable_functions(finding)
            self.assertEqual(funcs, [])


class TestFindFunctionCalls(unittest.TestCase):
    """Tests for _find_function_calls"""

    def test_finds_eval_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("result = eval(user_input)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            calls = analyzer._find_function_calls(["eval"])
            self.assertTrue(len(calls) > 0)
            self.assertIn("app.py:1", calls[0])

    def test_finds_multiple_calls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("eval(x)\neval(y)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            calls = analyzer._find_function_calls(["eval"])
            self.assertEqual(len(calls), 2)

    def test_no_calls_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("x = 1 + 2\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            calls = analyzer._find_function_calls(["eval"])
            self.assertEqual(calls, [])

    def test_empty_functions_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("eval(x)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            calls = analyzer._find_function_calls([])
            self.assertEqual(calls, [])

    def test_file_read_error_handled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("eval(x)")
            analyzer = ReachabilityAnalyzer(tmpdir)
            with patch("builtins.open", side_effect=OSError("read error")):
                calls = analyzer._find_function_calls(["eval"])
            self.assertEqual(calls, [])

    def test_multiple_functions_searched(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("eval(x)\nexec(y)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            calls = analyzer._find_function_calls(["eval", "exec"])
            self.assertEqual(len(calls), 2)


class TestAnalyzeFinding(unittest.TestCase):
    """Tests for _analyze_finding"""

    def test_reachable_with_function_calls_high_confidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests\nresult = eval(user_input)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f1",
                "title": "requests vulnerability",
                "rule_id": "CVE-2023-1234",
                "description": "use of eval in requests handler",
            }
            result = analyzer._analyze_finding(finding)
            self.assertTrue(result.is_reachable)
            self.assertEqual(result.confidence, "high")
            self.assertIsNotNone(result.call_chain)
            self.assertTrue(len(result.evidence) >= 2)

    def test_reachable_imported_but_no_direct_calls_medium_confidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests\nx = 1\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f2",
                "title": "requests vulnerability",
                "rule_id": "CVE-2023-5678",
                "description": "buffer overflow in parser",
            }
            result = analyzer._analyze_finding(finding)
            self.assertTrue(result.is_reachable)
            self.assertEqual(result.confidence, "medium")
            self.assertIsNone(result.call_chain)

    def test_not_reachable_package_not_imported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import os\nprint('hello')\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f3",
                "title": "requests vulnerability",
                "rule_id": "CVE-2023-9999",
                "description": "some vulnerability",
            }
            result = analyzer._analyze_finding(finding)
            self.assertFalse(result.is_reachable)
            self.assertEqual(result.confidence, "high")
            self.assertIsNone(result.call_chain)
            self.assertTrue(any("not imported" in e for e in result.evidence))

    def test_finding_id_propagated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "unique-id-123",
                "title": "pkg vuln",
                "rule_id": "CVE-2023-0001",
                "description": "",
            }
            result = analyzer._analyze_finding(finding)
            self.assertEqual(result.finding_id, "unique-id-123")

    def test_cve_extracted_from_rule_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f4",
                "title": "pkg vuln",
                "rule_id": "CVE-2023-4444",
                "description": "",
            }
            result = analyzer._analyze_finding(finding)
            self.assertEqual(result.cve, "CVE-2023-4444")

    def test_package_extracted_from_title_first_word(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f5",
                "title": "flask vulnerability in version 2.0",
                "rule_id": "CVE-2023-1111",
                "description": "",
            }
            result = analyzer._analyze_finding(finding)
            self.assertEqual(result.package, "flask")

    def test_empty_title_produces_empty_package(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f6",
                "title": "",
                "rule_id": "CVE-2023-0000",
                "description": "",
            }
            # title.split()[0] will raise IndexError on empty string
            with self.assertRaises(IndexError):
                analyzer._analyze_finding(finding)

    def test_call_chain_limited_to_3_in_evidence(self):
        """Evidence shows at most 3 function calls"""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            lines = "\n".join([f"import requests"] + [f"eval(x{i})" for i in range(5)])
            (Path(tmpdir) / "app.py").write_text(lines)
            analyzer = ReachabilityAnalyzer(tmpdir)
            finding = {
                "id": "f7",
                "title": "requests vuln",
                "rule_id": "CVE-1",
                "description": "eval is dangerous",
            }
            result = analyzer._analyze_finding(finding)
            # The evidence string mentions at most 3 calls
            calls_in_evidence = [e for e in result.evidence if "Vulnerable function calls found" in e]
            if calls_in_evidence:
                # Count commas + 1 in the calls line
                self.assertTrue(calls_in_evidence[0].count(",") <= 2)


class TestAnalyzeFindings(unittest.TestCase):
    """Tests for analyze_findings"""

    def test_filters_vuln_category_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-1", "description": ""},
                {"id": "2", "category": "SAST", "title": "sast issue", "rule_id": "R1", "description": ""},
                {"id": "3", "category": "VULN", "title": "pkg2 vuln", "rule_id": "CVE-2", "description": ""},
            ]
            results = analyzer.analyze_findings(findings)
            self.assertEqual(len(results), 2)

    def test_no_vuln_findings_causes_zero_division(self):
        """Documents the ZeroDivisionError bug when no VULN findings exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "no_cat", "category": "SAST", "title": "something", "rule_id": "R1", "description": ""},
            ]
            with self.assertRaises(ZeroDivisionError):
                analyzer.analyze_findings(findings)

    def test_all_vuln_findings_analyzed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-1", "description": ""},
            ]
            results = analyzer.analyze_findings(findings)
            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], ReachabilityResult)

    def test_returns_list_of_reachability_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "requests vuln", "rule_id": "CVE-1", "description": ""},
                {"id": "2", "category": "VULN", "title": "flask vuln", "rule_id": "CVE-2", "description": ""},
            ]
            results = analyzer.analyze_findings(findings)
            self.assertTrue(all(isinstance(r, ReachabilityResult) for r in results))
            self.assertEqual(len(results), 2)


class TestEnrichFindings(unittest.TestCase):
    """Tests for enrich_findings"""

    def test_enriches_vuln_findings_with_reachability_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "requests vuln", "rule_id": "CVE-1", "description": ""},
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertEqual(len(enriched), 1)
            self.assertIn("reachable", enriched[0])
            self.assertIn("reachability_confidence", enriched[0])
            self.assertIn("reachability_evidence", enriched[0])

    def test_non_vuln_findings_passthrough_without_reachability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "pkg vuln", "rule_id": "CVE-1", "description": ""},
                {"id": "2", "category": "SAST", "title": "sast issue", "rule_id": "R1", "description": ""},
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertEqual(len(enriched), 2)
            sast_finding = [f for f in enriched if f["category"] == "SAST"][0]
            self.assertNotIn("reachable", sast_finding)

    def test_call_chain_added_when_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import requests\nresult = eval(user_input)\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {
                    "id": "1",
                    "category": "VULN",
                    "title": "requests vuln",
                    "rule_id": "CVE-1",
                    "description": "eval used in request handling",
                },
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertIn("call_chain", enriched[0])

    def test_enriched_preserves_original_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {
                    "id": "1",
                    "category": "VULN",
                    "title": "pkg vuln",
                    "rule_id": "CVE-1",
                    "description": "",
                    "custom_field": "custom_value",
                },
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertEqual(enriched[0]["custom_field"], "custom_value")

    def test_enriched_reachable_true_when_imported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import flask\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "flask vuln", "rule_id": "CVE-1", "description": ""},
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertTrue(enriched[0]["reachable"])

    def test_enriched_reachable_false_when_not_imported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").touch()
            (Path(tmpdir) / "app.py").write_text("import os\n")
            analyzer = ReachabilityAnalyzer(tmpdir)
            findings = [
                {"id": "1", "category": "VULN", "title": "flask vuln", "rule_id": "CVE-1", "description": ""},
            ]
            enriched = analyzer.enrich_findings(findings)
            self.assertFalse(enriched[0]["reachable"])


if __name__ == "__main__":
    unittest.main()
