"""
Tests for scripts/remediation_engine.py — Automated fix generation.

Covers:
- RemediationSuggestion dataclass (construction, serialization)
- RemediationEngine._detect_language
- RemediationEngine._get_cwe_references
- RemediationEngine._detect_output_destination (XSS context detection)
- RemediationEngine._template_generate_fix (template-based fixes)
- RemediationEngine.suggest_fix (with and without LLM)
- RemediationEngine.generate_batch_fixes
- RemediationEngine.export_as_json
- Edge cases: unknown vuln types, dataclass vs dict findings
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

# Patch LLMManager import before importing remediation_engine
with patch.dict("sys.modules", {"orchestrator": MagicMock(), "orchestrator.llm_manager": MagicMock()}):
    from remediation_engine import RemediationEngine, RemediationSuggestion


# ============================================================================
# RemediationSuggestion dataclass
# ============================================================================


class TestRemediationSuggestion:
    """Test the RemediationSuggestion dataclass."""

    def test_basic_construction(self):
        """Should construct with all required fields."""
        suggestion = RemediationSuggestion(
            finding_id="F-001",
            vulnerability_type="sql_injection",
            file_path="app.py",
            line_number=42,
            original_code='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            fixed_code='cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
            diff="--- a/app.py\n+++ b/app.py",
            explanation="Use parameterized queries.",
            testing_recommendations=["Test with SQL payloads"],
            confidence="high",
            cwe_references=["CWE-89"],
        )
        assert suggestion.finding_id == "F-001"
        assert suggestion.confidence == "high"
        assert suggestion.metadata == {}  # Default via __post_init__

    def test_to_dict_round_trip(self):
        """to_dict() should produce a dict that can recreate the object."""
        suggestion = RemediationSuggestion(
            finding_id="F-002",
            vulnerability_type="xss",
            file_path="template.html",
            line_number=10,
            original_code="<div>{user_data}</div>",
            fixed_code="<div>{{user_data|escape}}</div>",
            diff="",
            explanation="Escape output",
            testing_recommendations=[],
            confidence="medium",
            cwe_references=["CWE-79"],
            metadata={"generator": "template"},
        )
        d = suggestion.to_dict()
        assert isinstance(d, dict)
        assert d["finding_id"] == "F-002"
        assert d["metadata"]["generator"] == "template"

        restored = RemediationSuggestion.from_dict(d)
        assert restored.finding_id == suggestion.finding_id
        assert restored.vulnerability_type == suggestion.vulnerability_type

    def test_metadata_default_none_becomes_empty_dict(self):
        """metadata=None should become {} via __post_init__."""
        suggestion = RemediationSuggestion(
            finding_id="F-003",
            vulnerability_type="test",
            file_path="f.py",
            line_number=1,
            original_code="",
            fixed_code="",
            diff="",
            explanation="",
            testing_recommendations=[],
            confidence="low",
            cwe_references=[],
            metadata=None,
        )
        assert suggestion.metadata == {}


# ============================================================================
# RemediationEngine._detect_language
# ============================================================================


class TestDetectLanguage:
    """Test language detection from file extensions."""

    def _engine(self):
        return RemediationEngine(llm_manager=None)

    def test_python_file(self):
        assert self._engine()._detect_language("app.py") == "python"

    def test_javascript_file(self):
        assert self._engine()._detect_language("index.js") == "javascript"

    def test_typescript_file(self):
        assert self._engine()._detect_language("service.ts") == "typescript"

    def test_go_file(self):
        assert self._engine()._detect_language("main.go") == "go"

    def test_java_file(self):
        assert self._engine()._detect_language("App.java") == "java"

    def test_unknown_extension(self):
        assert self._engine()._detect_language("data.xyz") == "text"

    def test_no_extension(self):
        assert self._engine()._detect_language("Makefile") == "text"

    def test_path_with_directory(self):
        assert self._engine()._detect_language("src/controllers/auth.py") == "python"


# ============================================================================
# RemediationEngine._get_cwe_references
# ============================================================================


class TestGetCWEReferences:
    """Test CWE reference lookup."""

    def _engine(self):
        return RemediationEngine(llm_manager=None)

    def test_known_vuln_type(self):
        refs = self._engine()._get_cwe_references("sql_injection")
        assert "CWE-89" in refs

    def test_hyphenated_vuln_type(self):
        """Hyphens should be normalized to underscores."""
        refs = self._engine()._get_cwe_references("sql-injection")
        assert "CWE-89" in refs

    def test_unknown_vuln_type(self):
        refs = self._engine()._get_cwe_references("unknown_vuln_xyz")
        assert refs == ["CWE-Unknown"]

    def test_xss_references(self):
        refs = self._engine()._get_cwe_references("xss")
        assert "CWE-79" in refs

    def test_case_insensitive(self):
        refs = self._engine()._get_cwe_references("SQL_INJECTION")
        assert "CWE-89" in refs


# ============================================================================
# RemediationEngine._detect_output_destination
# ============================================================================


class TestDetectOutputDestination:
    """Test XSS context detection (CLI vs browser vs HTTP)."""

    def _engine(self):
        return RemediationEngine(llm_manager=None)

    def test_terminal_print(self):
        result = self._engine()._detect_output_destination("print(user_data)")
        assert result == "terminal"

    def test_terminal_logger(self):
        result = self._engine()._detect_output_destination("logger.info(data)")
        assert result == "terminal"

    def test_terminal_console_log(self):
        result = self._engine()._detect_output_destination("console.log(data)")
        assert result == "terminal"

    def test_browser_innerhtml(self):
        result = self._engine()._detect_output_destination("element.innerHTML = data")
        assert result == "browser"

    def test_browser_document_write(self):
        result = self._engine()._detect_output_destination("document.write(data)")
        assert result == "browser"

    def test_http_response(self):
        result = self._engine()._detect_output_destination("res.send(data)")
        assert result == "http-response"

    def test_http_render_template(self):
        result = self._engine()._detect_output_destination("render_template('page.html', data=data)")
        assert result == "http-response"

    def test_empty_code_unknown(self):
        result = self._engine()._detect_output_destination("")
        assert result == "unknown"

    def test_file_path_hint_cli(self):
        result = self._engine()._detect_output_destination("output(data)", file_path="bin/cli_tool.py")
        assert result == "terminal"

    def test_file_path_hint_web(self):
        result = self._engine()._detect_output_destination("output(data)", file_path="src/controllers/user.py")
        assert result == "http-response"


# ============================================================================
# RemediationEngine._template_generate_fix
# ============================================================================


class TestTemplateGenerateFix:
    """Test template-based fix generation."""

    def _engine(self):
        return RemediationEngine(llm_manager=None)

    def test_sql_injection_fix(self):
        """SQL injection findings should get parameterized query suggestion."""
        finding = {
            "id": "F-001",
            "type": "sql_injection",
            "path": "app.py",
            "line": 42,
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
        }
        result = self._engine()._template_generate_fix(finding)

        assert isinstance(result, RemediationSuggestion)
        assert result.vulnerability_type == "sql_injection"
        assert result.confidence == "medium"
        assert "CWE-89" in result.cwe_references
        assert result.file_path == "app.py"
        assert len(result.testing_recommendations) > 0

    def test_xss_in_cli_context(self):
        """XSS in CLI context should be flagged as false positive."""
        finding = {
            "id": "F-002",
            "type": "xss",
            "path": "cli_tool.py",
            "line": 10,
            "code_snippet": "print(f'Result: {user_input}')",
        }
        result = self._engine()._template_generate_fix(finding)
        assert result.vulnerability_type == "xss"
        # CLI context should produce high confidence (false positive)
        assert "terminal" in result.metadata.get("output_destination", "")

    def test_unknown_vuln_type_gets_generic_fix(self):
        """Unknown vulnerability types should get a generic fix suggestion."""
        finding = {
            "id": "F-003",
            "type": "custom_vuln_type_xyz",
            "path": "module.py",
            "line": 1,
            "code_snippet": "some_code()",
        }
        result = self._engine()._template_generate_fix(finding)
        assert result.confidence == "low"
        assert "manual review" in result.explanation.lower()

    def test_command_injection_fix(self):
        """Command injection should suggest avoiding shell=True."""
        finding = {
            "id": "F-004",
            "type": "command-injection",  # Note: hyphens should be normalized
            "path": "deploy.py",
            "line": 55,
            "code_snippet": "subprocess.run(f'ls {user_dir}', shell=True)",
        }
        result = self._engine()._template_generate_fix(finding)
        assert "CWE-78" in result.cwe_references
        assert "shell" in result.fixed_code.lower() or "subprocess" in result.fixed_code.lower()

    def test_finding_with_evidence_dict(self):
        """Findings with nested evidence.snippet should be handled."""
        finding = {
            "id": "F-005",
            "type": "hard_coded_secrets",
            "path": "config.py",
            "line": 3,
            "evidence": {"snippet": 'API_KEY = "sk_live_abc123def456"'},
        }
        result = self._engine()._template_generate_fix(finding)
        assert result.vulnerability_type == "hard_coded_secrets"
        assert "CWE-798" in result.cwe_references


# ============================================================================
# RemediationEngine.suggest_fix — LLM vs template fallback
# ============================================================================


class TestSuggestFix:
    """Test the top-level suggest_fix routing."""

    def test_falls_back_to_template_when_no_llm(self):
        """Without LLM, should use template-based fix."""
        engine = RemediationEngine(llm_manager=None)
        finding = {
            "id": "F-010",
            "type": "sql_injection",
            "path": "app.py",
            "line": 1,
            "code_snippet": "bad_query()",
        }
        result = engine.suggest_fix(finding)
        assert isinstance(result, RemediationSuggestion)
        assert result.metadata.get("generator") == "template"

    def test_falls_back_to_template_on_llm_failure(self):
        """If LLM call raises, should fall back to template."""
        mock_llm = MagicMock()
        mock_llm.call_llm_api.side_effect = RuntimeError("API error")
        engine = RemediationEngine(llm_manager=mock_llm)
        finding = {
            "id": "F-011",
            "type": "xss",
            "path": "view.js",
            "line": 5,
            "code_snippet": "element.innerHTML = data",
        }
        result = engine.suggest_fix(finding)
        assert isinstance(result, RemediationSuggestion)
        assert result.metadata.get("generator") == "template"

    def test_uses_llm_when_available(self):
        """With working LLM, should use AI-generated fix."""
        mock_llm = MagicMock()
        mock_llm.provider = "anthropic"
        mock_llm.model = "claude-test"
        ai_response = json.dumps({
            "fixed_code": "safe_query()",
            "explanation": "Used parameterized query",
            "testing_recommendations": ["Test with payloads"],
            "confidence": "high",
        })
        mock_llm.call_llm_api.return_value = (ai_response, 100, 50)

        engine = RemediationEngine(llm_manager=mock_llm)
        finding = {
            "id": "F-012",
            "type": "sql_injection",
            "path": "app.py",
            "line": 42,
            "code_snippet": "bad_query(uid)",
        }
        result = engine.suggest_fix(finding)
        assert result.metadata.get("generator") == "ai"
        assert result.fixed_code == "safe_query()"
        assert result.confidence == "high"


# ============================================================================
# RemediationEngine.generate_batch_fixes
# ============================================================================


class TestGenerateBatchFixes:
    """Test batch processing of findings."""

    def test_batch_processes_all_findings(self):
        """Should generate a suggestion for each finding."""
        engine = RemediationEngine(llm_manager=None)
        findings = [
            {"id": f"F-{i}", "type": "sql_injection", "path": "app.py", "line": i, "code_snippet": "q()"}
            for i in range(3)
        ]
        results = engine.generate_batch_fixes(findings)
        assert len(results) == 3

    def test_batch_respects_max_findings(self):
        """max_findings should limit the number processed."""
        engine = RemediationEngine(llm_manager=None)
        findings = [
            {"id": f"F-{i}", "type": "xss", "path": "v.js", "line": i, "code_snippet": "c()"}
            for i in range(10)
        ]
        results = engine.generate_batch_fixes(findings, max_findings=3)
        assert len(results) == 3

    def test_batch_skips_failures(self):
        """Batch should continue even if one finding fails."""
        engine = RemediationEngine(llm_manager=None)

        # Patch _template_generate_fix to fail on second call
        original_method = engine._template_generate_fix
        call_count = {"n": 0}

        def side_effect(finding):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise ValueError("Simulated failure")
            return original_method(finding)

        with patch.object(engine, "suggest_fix", side_effect=side_effect):
            findings = [
                {"id": f"F-{i}", "type": "xss", "path": "v.js", "line": i, "code_snippet": "c()"}
                for i in range(3)
            ]
            results = engine.generate_batch_fixes(findings)
            # 2 out of 3 should succeed
            assert len(results) == 2


# ============================================================================
# RemediationEngine.export_as_json
# ============================================================================


class TestExportAsJson:
    """Test JSON export."""

    def test_export_produces_valid_json(self):
        """Exported file should be valid JSON with expected structure."""
        engine = RemediationEngine(llm_manager=None)
        suggestions = [
            RemediationSuggestion(
                finding_id="F-100",
                vulnerability_type="sql_injection",
                file_path="app.py",
                line_number=1,
                original_code="bad()",
                fixed_code="good()",
                diff="",
                explanation="Fix applied",
                testing_recommendations=["Test it"],
                confidence="high",
                cwe_references=["CWE-89"],
            )
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            engine.export_as_json(suggestions, f.name)
            f.flush()

            with open(f.name) as rf:
                data = json.load(rf)
            assert data["total_suggestions"] == 1
            assert len(data["suggestions"]) == 1
            assert data["suggestions"][0]["finding_id"] == "F-100"
            assert "generated_at" in data


# ============================================================================
# RemediationEngine._get_finding_attr — dict vs dataclass
# ============================================================================


class TestGetFindingAttr:
    """Test attribute extraction from both dict and dataclass findings."""

    def _engine(self):
        return RemediationEngine(llm_manager=None)

    def test_dict_finding(self):
        finding = {"id": "F-1", "path": "/tmp/app.py"}
        assert self._engine()._get_finding_attr(finding, "id") == "F-1"

    def test_dict_finding_fallback_attrs(self):
        """Should try multiple attribute names in order."""
        finding = {"file_path": "/tmp/app.py"}
        result = self._engine()._get_finding_attr(finding, "path", "file_path")
        assert result == "/tmp/app.py"

    def test_dict_finding_default(self):
        finding = {}
        result = self._engine()._get_finding_attr(finding, "missing", default="fallback")
        assert result == "fallback"

    def test_object_finding(self):
        """Should work with object attributes (dataclass-style)."""

        class Finding:
            def __init__(self):
                self.id = "OBJ-1"
                self.severity = "high"

        finding = Finding()
        assert self._engine()._get_finding_attr(finding, "id") == "OBJ-1"
        assert self._engine()._get_finding_attr(finding, "severity") == "high"

    def test_object_finding_fallback(self):
        class Finding:
            def __init__(self):
                self.file_path = "/tmp/test.py"

        finding = Finding()
        result = self._engine()._get_finding_attr(finding, "path", "file_path")
        assert result == "/tmp/test.py"
