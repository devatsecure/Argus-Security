"""
Tests for Feature 5: Fix Verification Loop (fix_verifier.py).

Tests FixVerifier, FixVerificationResult, FixVerificationStage.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from fix_verifier import (
    FixVerificationResult,
    FixVerificationStage,
    FixVerifier,
    _apply_verification,
    _extract_fix,
)
from pipeline.protocol import PipelineContext


# ============================================================================
# FixVerificationResult
# ============================================================================


class TestFixVerificationResult:
    def test_defaults(self):
        r = FixVerificationResult(
            finding_id="f1",
            fix_applied=True,
            original_vulnerable=True,
            fix_resolves=True,
            verification_method="static_analysis",
            confidence=0.85,
            details="Fix confirmed.",
        )
        assert r.finding_id == "f1"
        assert r.fix_applied
        assert r.fix_resolves
        assert r.original_result is None
        assert r.error is None
        assert r.execution_time_ms == 0

    def test_optional_fields(self):
        r = FixVerificationResult(
            finding_id="f2",
            fix_applied=False,
            original_vulnerable=False,
            fix_resolves=False,
            verification_method="error",
            confidence=0.0,
            details="Failed",
            error="timeout",
            execution_time_ms=500,
        )
        assert r.error == "timeout"
        assert r.execution_time_ms == 500


# ============================================================================
# FixVerifier - Static Analysis
# ============================================================================


class TestFixVerifierStatic:
    def test_sql_injection_fix_verified(self):
        """CWE-89 fix: parameterized query replaces f-string SQL."""
        v = FixVerifier()
        finding = {"id": "sqli-001", "cwe": "CWE-89"}
        suggestion = {
            "finding_id": "sqli-001",
            "original_code": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
            "cwe_references": ["CWE-89"],
            "vulnerability_type": "sql_injection",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is True
        assert result.verification_method == "static_analysis"
        assert result.confidence >= 0.7

    def test_xss_fix_verified(self):
        """CWE-79 fix: html.escape added."""
        v = FixVerifier()
        finding = {"id": "xss-001"}
        suggestion = {
            "finding_id": "xss-001",
            "original_code": 'return f"<div>{user_input}</div>"',
            "fixed_code": 'return f"<div>{html.escape(user_input)}</div>"',
            "cwe_references": ["CWE-79"],
            "vulnerability_type": "xss",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is True
        assert result.verification_method == "static_analysis"

    def test_command_injection_fix_verified(self):
        """CWE-78 fix: shell=True removed, list-form subprocess."""
        v = FixVerifier()
        finding = {"id": "ci-001"}
        suggestion = {
            "finding_id": "ci-001",
            "original_code": 'subprocess.run(f"ls {user_dir}", shell=True)',
            "fixed_code": 'subprocess.run(["ls", user_dir])',
            "cwe_references": ["CWE-78"],
            "vulnerability_type": "command_injection",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is True
        assert result.verification_method == "static_analysis"

    def test_path_traversal_fix_verified(self):
        """CWE-22 fix: path validation added."""
        v = FixVerifier()
        finding = {"id": "pt-001"}
        suggestion = {
            "finding_id": "pt-001",
            "original_code": 'open(f"uploads/{filename}")',
            "fixed_code": (
                'safe = os.path.realpath(os.path.join("uploads", filename))\n'
                'if not safe.startswith(os.path.realpath("uploads")):\n'
                '    raise ValueError("Invalid path")\n'
                'open(safe)'
            ),
            "cwe_references": ["CWE-22"],
            "vulnerability_type": "path_traversal",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is True
        assert result.verification_method == "static_analysis"

    def test_hardcoded_creds_fix_verified(self):
        """CWE-798 fix: env var replaces hardcoded secret."""
        v = FixVerifier()
        finding = {"id": "hc-001"}
        suggestion = {
            "finding_id": "hc-001",
            "original_code": 'api_key = "sk-12345678901234567890"',
            "fixed_code": 'api_key = os.environ.get("API_KEY")',
            "cwe_references": ["CWE-798"],
            "vulnerability_type": "hardcoded_credentials",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is True

    def test_partial_fix_detected(self):
        """Fix adds safe patterns but vulnerable pattern remains."""
        v = FixVerifier()
        finding = {"id": "sqli-002"}
        suggestion = {
            "finding_id": "sqli-002",
            "original_code": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            "fixed_code": (
                '# Added parameterized query\n'
                'query = f"SELECT * FROM users WHERE id={uid}"\n'
                'cursor.execute(query, (uid,))'
            ),
            "cwe_references": ["CWE-89"],
            "vulnerability_type": "sql_injection",
        }
        result = v.verify_fix(finding, suggestion)
        # Has safe patterns but vuln patterns remain -> partial fix
        assert result.verification_method == "static_analysis"
        assert result.confidence < 0.85

    def test_vuln_type_inference(self):
        """CWE inferred from vulnerability_type when cwe_references empty."""
        v = FixVerifier()
        finding = {"id": "sqli-003"}
        suggestion = {
            "finding_id": "sqli-003",
            "original_code": 'cursor.execute(f"SELECT * FROM t WHERE x={v}")',
            "fixed_code": 'cursor.execute("SELECT * FROM t WHERE x=?", (v,))',
            "cwe_references": [],
            "vulnerability_type": "sql_injection",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.verification_method == "static_analysis"
        assert result.fix_resolves is True


# ============================================================================
# FixVerifier - Pattern Match (fallback)
# ============================================================================


class TestFixVerifierPattern:
    def test_code_changed(self):
        """Fallback pattern match detects code changes."""
        v = FixVerifier()
        finding = {"id": "x-001"}
        suggestion = {
            "finding_id": "x-001",
            "original_code": "vulnerable_function(user_input)",
            "fixed_code": "safe_function(sanitize(user_input))",
            "cwe_references": [],
            "vulnerability_type": "custom",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.verification_method == "pattern_match"
        assert result.fix_resolves is True
        assert result.confidence == 0.5

    def test_identical_code(self):
        """No fix applied if code is identical."""
        v = FixVerifier()
        finding = {"id": "x-002"}
        suggestion = {
            "finding_id": "x-002",
            "original_code": "do_something()",
            "fixed_code": "do_something()",
            "cwe_references": [],
            "vulnerability_type": "",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is False
        assert result.fix_applied is False

    def test_no_fixed_code(self):
        """Missing fixed_code returns error result."""
        v = FixVerifier()
        finding = {"id": "x-003"}
        suggestion = {
            "finding_id": "x-003",
            "original_code": "bad()",
            "fixed_code": "",
            "cwe_references": [],
            "vulnerability_type": "",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.fix_resolves is False
        assert result.error == "missing_fixed_code"

    def test_only_removals(self):
        """Lines removed but nothing added."""
        v = FixVerifier()
        finding = {"id": "x-004"}
        suggestion = {
            "finding_id": "x-004",
            "original_code": "line_one()\nline_two()\nline_three()",
            "fixed_code": "line_one()",
            "cwe_references": [],
            "vulnerability_type": "",
        }
        result = v.verify_fix(finding, suggestion)
        assert result.verification_method == "pattern_match"
        assert result.fix_applied is True


# ============================================================================
# FixVerifier - Batch
# ============================================================================


class TestFixVerifierBatch:
    def test_verify_batch(self):
        v = FixVerifier()
        findings = [
            {"id": "f1", "cwe": "CWE-89"},
            {"id": "f2", "cwe": "CWE-79"},
            {"id": "f3"},  # no matching suggestion
        ]
        suggestions = [
            {
                "finding_id": "f1",
                "original_code": 'execute(f"SELECT {x}")',
                "fixed_code": 'execute("SELECT ?", (x,))',
                "cwe_references": ["CWE-89"],
                "vulnerability_type": "sql_injection",
            },
            {
                "finding_id": "f2",
                "original_code": "innerHTML = data",
                "fixed_code": "textContent = data",
                "cwe_references": ["CWE-79"],
                "vulnerability_type": "xss",
            },
        ]
        results = v.verify_batch(findings, suggestions)
        assert len(results) == 2
        assert results[0].finding_id == "f1"
        assert results[1].finding_id == "f2"

    def test_verify_batch_empty(self):
        v = FixVerifier()
        results = v.verify_batch([], [])
        assert results == []


# ============================================================================
# FixVerifier - _get_attr helper
# ============================================================================


class TestGetAttr:
    def test_dict(self):
        v = FixVerifier()
        assert v._get_attr({"id": "x"}, "id") == "x"
        assert v._get_attr({"id": "x"}, "missing", default="d") == "d"

    def test_object(self):
        @dataclass
        class Obj:
            name: str = "foo"

        v = FixVerifier()
        assert v._get_attr(Obj(), "name") == "foo"
        assert v._get_attr(Obj(), "missing", default="bar") == "bar"

    def test_multiple_attrs(self):
        v = FixVerifier()
        assert v._get_attr({"finding_id": "abc"}, "id", "finding_id") == "abc"


# ============================================================================
# _find_matching_cwe
# ============================================================================


class TestFindMatchingCwe:
    def test_direct_match(self):
        v = FixVerifier()
        assert v._find_matching_cwe(["CWE-89"], "") == "CWE-89"

    def test_vuln_type_fallback(self):
        v = FixVerifier()
        assert v._find_matching_cwe([], "sql_injection") == "CWE-89"
        assert v._find_matching_cwe([], "xss") == "CWE-79"

    def test_no_match(self):
        v = FixVerifier()
        assert v._find_matching_cwe([], "unknown_type") is None
        assert v._find_matching_cwe(["CWE-999"], "") is None


# ============================================================================
# _extract_fix helper
# ============================================================================


class TestExtractFix:
    def test_dict_fix_suggestion(self):
        finding = {"fix_suggestion": {"code": "safe()"}}
        assert _extract_fix(finding) == {"code": "safe()"}

    def test_attr_fix_suggestion(self):
        @dataclass
        class F:
            fix_suggestion: str = "use parameterized queries"

        assert _extract_fix(F()) == "use parameterized queries"

    def test_auto_fixable_dict(self):
        finding = {
            "auto_fixable": True,
            "remediation": {"fixed_code": "x"},
        }
        assert _extract_fix(finding) == {"fixed_code": "x"}

    def test_no_fix(self):
        assert _extract_fix({"severity": "high"}) is None


# ============================================================================
# _apply_verification helper
# ============================================================================


class TestApplyVerification:
    def test_dict_finding(self):
        finding: dict = {"id": "f1"}
        result = FixVerificationResult(
            finding_id="f1",
            fix_applied=True,
            original_vulnerable=True,
            fix_resolves=True,
            verification_method="static_analysis",
            confidence=0.85,
            details="OK",
        )
        _apply_verification(finding, result)
        assert finding["fix_confidence"] == 0.85
        assert finding["fix_verified"] is True

    def test_dict_finding_unresolved(self):
        finding: dict = {"id": "f2"}
        result = FixVerificationResult(
            finding_id="f2",
            fix_applied=True,
            original_vulnerable=True,
            fix_resolves=False,
            verification_method="pattern_match",
            confidence=0.6,
            details="Not resolved",
        )
        _apply_verification(finding, result)
        # Confidence halved when fix doesn't resolve
        assert finding["fix_confidence"] == pytest.approx(0.3)
        assert finding["fix_verified"] is False


# ============================================================================
# FixVerificationStage (Pipeline Stage)
# ============================================================================


class TestFixVerificationStage:
    def _make_ctx(self, enable: bool = True) -> PipelineContext:
        return PipelineContext(
            config={"enable_fix_verification": enable},
            target_path="/tmp/repo",
        )

    def test_should_run_enabled(self):
        stage = FixVerificationStage()
        ctx = self._make_ctx(enable=True)
        assert stage.should_run(ctx) is True

    def test_should_run_disabled(self):
        stage = FixVerificationStage()
        ctx = self._make_ctx(enable=False)
        assert stage.should_run(ctx) is False

    def test_name_and_phase(self):
        stage = FixVerificationStage()
        assert stage.name == "phase2_7_fix_verification"
        assert stage.phase_number == 2.7
        assert "phase2_5_remediation" in stage.required_stages

    def test_execute_with_fixable_findings(self):
        stage = FixVerificationStage()
        ctx = self._make_ctx()
        ctx.findings = [
            {
                "id": "sqli-001",
                "fix_suggestion": {
                    "finding_id": "sqli-001",
                    "original_code": 'execute(f"SELECT {x}")',
                    "fixed_code": 'execute("SELECT ?", (x,))',
                    "cwe_references": ["CWE-89"],
                    "vulnerability_type": "sql_injection",
                },
            },
        ]
        result = stage.execute(ctx)
        assert result.success
        assert result.metadata.get("verified") == 1

    def test_execute_no_fixes(self):
        stage = FixVerificationStage()
        ctx = self._make_ctx()
        ctx.findings = [{"id": "f1", "severity": "high"}]
        result = stage.execute(ctx)
        assert result.success
        assert result.metadata.get("verified") == 0
