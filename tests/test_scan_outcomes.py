"""Regression contracts: scanner failure must never look like a clean scan."""

import json
import logging
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from hybrid.models import HybridFinding
from hybrid.phases.phase1_scanning import run_phase1_scanning
from hybrid.phases.phase5_policy import run_phase5_policy
from hybrid.phases.phase6_reporting import run_phase6_reporting
from hybrid.report import save_results
from hybrid.scanner_runners import count_by_severity, count_by_source, run_gitleaks, run_semgrep, run_trivy

LOGGER = logging.getLogger(__name__)


def analyzer_stub(**overrides):
    scanner_names = {
        "semgrep": "semgrep_scanner",
        "trufflehog": "trufflehog_scanner",
        "gitleaks": "gitleaks_scanner",
        "trivy": "trivy_scanner",
        "checkov": "checkov_scanner",
        "api_security": "api_security_scanner",
        "dast": "dast_scanner",
        "supply_chain": "supply_chain_scanner",
        "fuzzing": "fuzzing_scanner",
        "threat_intel": "threat_intel_enricher",
        "runtime_security": "runtime_security_monitor",
        "regression_testing": "regression_tester",
        "nuclei_templates": "nuclei_template_scanner",
        "zap_baseline": "zap_baseline_scanner",
    }
    values = {"config": {}, "requested_scanners": {}, "enable_ai_enrichment": False}
    for flag, attr in scanner_names.items():
        values[f"enable_{flag}"] = False
        values[attr] = None
    values.update(overrides)
    return SimpleNamespace(**values)


def finding(**overrides):
    values = {
        "finding_id": "test-1",
        "source_tool": "semgrep",
        "severity": "medium",
        "category": "security",
        "title": "Test",
        "description": "Test finding",
        "file_path": "app.py",
    }
    values.update(overrides)
    return HybridFinding(**values)


@pytest.mark.parametrize("runner", [run_semgrep, run_gitleaks])
@pytest.mark.parametrize("error", ["timeout", "not_installed", "parse_failed"])
def test_error_response_is_not_empty_success(runner, error):
    scanner = SimpleNamespace(scan=lambda *args, **kwargs: {"findings": [], "error": error})
    with pytest.raises(RuntimeError):
        runner(scanner, ".", LOGGER)


def test_runner_exception_reaches_phase_coordinator():
    def broken(*args, **kwargs):
        raise subprocess.TimeoutExpired("trivy", 300)

    with pytest.raises(RuntimeError):
        run_trivy(SimpleNamespace(scan_filesystem=broken), ".", LOGGER)


@pytest.mark.parametrize("response", [None, {}, {"findings": None}])
def test_malformed_semgrep_result_is_not_clean(response):
    scanner = SimpleNamespace(scan=lambda *args: response)
    with pytest.raises(RuntimeError):
        run_semgrep(scanner, ".", LOGGER)


def test_phase1_distinguishes_requested_but_unavailable():
    analyzer = analyzer_stub(requested_scanners={"Trivy": True})
    findings, _, health = run_phase1_scanning(target_path=".", analyzer=analyzer)
    assert findings == []
    assert health["Trivy"] == "unavailable"
    assert health["Checkov"] == "disabled"


def test_phase1_preserves_trufflehog_error():
    scanner = SimpleNamespace(scan=lambda *args, **kwargs: {"error": "timeout", "findings": []})
    analyzer = analyzer_stub(enable_trufflehog=True, trufflehog_scanner=scanner)
    findings, _, health = run_phase1_scanning(target_path=".", analyzer=analyzer)
    assert findings == []
    assert health["TruffleHog"] == "failed"


def test_phase1_preserves_verified_secret_evidence():
    scanner = SimpleNamespace(
        scan=lambda *args, **kwargs: {
            "findings": [{"file_path": "config.py", "verified": True, "detector_type": "AWS"}]
        }
    )
    analyzer = analyzer_stub(enable_trufflehog=True, trufflehog_scanner=scanner)
    findings, _, _ = run_phase1_scanning(target_path=".", analyzer=analyzer)
    assert findings[0].secret_verified is True


def make_report(tmp_path, health, policy, findings=None, severity_filter=None):
    analyzer = analyzer_stub()
    analyzer._enrich_findings = lambda items, path: items
    analyzer._count_by_severity = count_by_severity
    analyzer._count_by_source = count_by_source
    analyzer._get_enabled_tools = lambda: ["Semgrep", "Trivy"]
    analyzer._save_results = lambda result, output: save_results(result, output, str(tmp_path))
    analyzer._print_summary = lambda result: None
    return run_phase6_reporting(
        all_findings=findings or [],
        target_path=str(tmp_path),
        analyzer=analyzer,
        output_dir=str(tmp_path),
        severity_filter=severity_filter,
        overall_start=time.time(),
        phase_timings={},
        total_cost=0,
        policy_gate_result=policy,
        vulnerability_chains={"total_chains": 0},
        scanner_health=health,
    )


@pytest.mark.parametrize(
    "health,status",
    [
        ({"Semgrep": "clean", "Trivy": "disabled"}, "complete"),
        ({"Semgrep": "clean", "Trivy": "failed"}, "partial"),
        ({"Trivy": "unavailable"}, "failed"),
        ({"Semgrep": "disabled"}, "failed"),
    ],
)
def test_saved_reports_expose_execution_and_policy(tmp_path, health, status):
    policy = {"decision": "pass", "blocks": [], "warnings": [], "reasons": []}
    result = make_report(tmp_path, health, policy)
    payload = json.loads(next(tmp_path.glob("hybrid-scan-*.json")).read_text())
    assert payload["scanner_health"] == health
    assert payload["scan_status"] == status == result.scan_status
    assert payload["policy_gate_result"] == policy
    assert payload["vulnerability_chains"] == {"total_chains": 0}
    sarif = json.loads(next(tmp_path.glob("*.sarif")).read_text())
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is (status == "complete")
    markdown = next(tmp_path.glob("*.md")).read_text()
    assert status in markdown
    assert "Policy" in markdown


def test_empty_scan_still_evaluates_release_requirements(monkeypatch):
    from gate import PolicyGate

    monkeypatch.setattr(PolicyGate, "_check_opa_installed", lambda self: None)

    def evaluate(self, stage, findings, metadata):
        assert stage == "release"
        assert findings == []
        assert metadata == {}
        return {"decision": "fail", "reasons": ["SBOM missing"], "blocks": []}

    monkeypatch.setattr(PolicyGate, "evaluate", evaluate)
    result, _, timings = run_phase5_policy(all_findings=[], analyzer=analyzer_stub(config={"policy_stage": "release"}))
    assert result["decision"] == "fail"
    assert "phase5_policy_gate" in timings


@pytest.mark.parametrize("invalid", [None, {}, {"decision": "unknown"}, {"decision": "pass", "blocks": "bad"}])
def test_invalid_policy_decision_is_reported_as_error(monkeypatch, invalid):
    import hybrid.phases.phase5_policy as phase

    monkeypatch.setattr(phase, "_evaluate_policy_gate", lambda **kwargs: invalid)
    result, _, _ = run_phase5_policy(all_findings=[], analyzer=analyzer_stub())
    assert result["decision"] == "error"


def test_missing_opa_is_error_even_under_pytest(monkeypatch):
    from gate import PolicyGate

    def missing(*args, **kwargs):
        raise FileNotFoundError("opa")

    monkeypatch.setattr(subprocess, "run", missing)
    result, _, _ = run_phase5_policy(all_findings=[], analyzer=analyzer_stub())
    assert result["decision"] == "error"
    with pytest.raises(RuntimeError):
        PolicyGate()


@pytest.mark.parametrize(
    "source,category", [("semgrep", "SAST"), ("trivy", "DEPS"), ("checkov", "IAC"), ("trufflehog", "SECRETS")]
)
def test_policy_receives_normalized_evidence(monkeypatch, source, category):
    from gate import PolicyGate
    from hybrid.phases.phase5_policy import _evaluate_policy_gate

    monkeypatch.setattr(PolicyGate, "_check_opa_installed", lambda self: None)

    def evaluate(self, stage, findings, metadata):
        item = findings[0]
        assert item["category"] == category
        assert item["cvss"] == 9.8
        assert item["secret_verified"] == "true"
        assert item["reachability"] == "unknown"
        assert item["service_tier"] == "unknown"
        return {"decision": "fail", "blocks": ["test-1"], "reasons": []}

    monkeypatch.setattr(PolicyGate, "evaluate", evaluate)
    item = finding(source_tool=source, cvss_score=9.8, secret_verified=True)
    assert _evaluate_policy_gate(all_findings=[item], config={})["decision"] == "fail"


@pytest.mark.parametrize(
    "status,decision,high,expected",
    [
        ("complete", "pass", 0, 0),
        ("complete", "pass", 1, 1),
        ("complete", "fail", 0, 1),
        ("partial", "pass", 0, 2),
        ("failed", "fail", 1, 2),
        ("complete", "error", 0, 2),
        ("complete", None, 0, 2),
    ],
)
def test_cli_exit_contract(monkeypatch, status, decision, high, expected):
    from hybrid.cli import main

    result = SimpleNamespace(
        scan_status=status,
        policy_gate_result={"decision": decision},
        findings_by_severity={"critical": 0, "high": high},
    )
    with patch("hybrid.cli.HybridSecurityAnalyzer") as analyzer:
        analyzer.return_value.analyze.return_value = result
        monkeypatch.setattr("sys.argv", ["argus-scan", "."])
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == expected


def test_severity_filter_does_not_hide_blocking_findings(tmp_path):
    result = make_report(
        tmp_path, {"Semgrep": "ran(1)"}, {"decision": "pass"}, [finding(severity="high")], severity_filter=["low"]
    )
    assert result.findings == []
    assert result.findings_by_severity["high"] == 1


@pytest.mark.skipif(__import__("shutil").which("opa") is None, reason="Requires real OPA")
def test_real_opa_blocks_normalized_verified_secret(monkeypatch):
    monkeypatch.setenv("ENABLE_VULNERABILITY_CHAINING", "false")
    item = finding(source_tool="trufflehog", category="secrets", secret_verified=True)
    result, _, _ = run_phase5_policy(all_findings=[item], analyzer=analyzer_stub())
    assert result["decision"] == "fail"
    assert result["blocks"] == ["test-1"]


@pytest.mark.skipif(__import__("shutil").which("opa") is None, reason="Requires real OPA")
def test_real_opa_blocks_empty_release_without_metadata():
    result, _, _ = run_phase5_policy(all_findings=[], analyzer=analyzer_stub(config={"policy_stage": "release"}))
    assert result["decision"] == "fail"
    assert any("SBOM" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "module,cls", [("gitleaks_scanner", "GitleaksScanner"), ("trufflehog_scanner", "TruffleHogScanner")]
)
def test_malformed_secret_scanner_json_is_not_clean(module, cls):
    import importlib

    scanner_class = getattr(importlib.import_module(module), cls)
    scanner = scanner_class.__new__(scanner_class)
    with pytest.raises(ValueError):
        scanner._parse_output("invalid json")


def test_semgrep_partial_parse_failure_is_not_clean(monkeypatch, tmp_path):
    from semgrep_scanner import SemgrepScanner

    scanner = SemgrepScanner.__new__(SemgrepScanner)
    scanner._semgrep_bin = "semgrep"
    scanner.semgrep_rules = "test-rules"
    scanner.exclude_patterns = []
    scanner.config = {}
    monkeypatch.setattr(scanner, "_check_semgrep_installed", lambda: True)
    monkeypatch.setattr(scanner, "_get_semgrep_version", lambda: "test")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a[0], 0, stdout=json.dumps({"results": [], "errors": [{"type": "ParseError"}]}), stderr=""
        ),
    )
    with pytest.raises(RuntimeError):
        run_semgrep(scanner, str(tmp_path), LOGGER)


def test_unavailable_only_requested_scanner_reaches_reporting(monkeypatch, tmp_path):
    import inspect

    from hybrid_analyzer import HybridSecurityAnalyzer

    def unavailable(*args, **kwargs):
        raise RuntimeError("missing binary")

    monkeypatch.setattr("trivy_scanner.TrivyScanner", unavailable)
    flags = {name: False for name in inspect.signature(HybridSecurityAnalyzer).parameters if name.startswith("enable_")}
    flags["enable_trivy"] = True
    analyzer = HybridSecurityAnalyzer(
        **flags,
        config={
            "enable_findings_store": False,
            "enable_app_context": False,
            "enable_diff_scoping": False,
            "enable_heuristics": False,
            "enable_whole_repo_review": False,
            "enable_skills_knowledge": False,
        },
    )
    analyzer._enrich_findings = lambda findings, path: findings
    result = analyzer.analyze(str(tmp_path), output_dir=str(tmp_path / "out"))
    assert result.scan_status == "failed"
    assert result.scanner_health["Trivy"] == "unavailable"
    assert list((tmp_path / "out").glob("hybrid-scan-*.json"))


def test_verified_scanner_evidence_survives_ai_filtering(monkeypatch, tmp_path):
    import inspect

    from hybrid_analyzer import HybridSecurityAnalyzer

    flags = {name: False for name in inspect.signature(HybridSecurityAnalyzer).parameters if name.startswith("enable_")}
    flags["enable_trufflehog"] = True
    analyzer = HybridSecurityAnalyzer(
        **flags,
        config={
            "enable_findings_store": False,
            "enable_app_context": False,
            "enable_diff_scoping": False,
            "enable_heuristics": False,
            "enable_whole_repo_review": False,
            "enable_skills_knowledge": False,
        },
    )
    evidence = finding(source_tool="trufflehog", category="secrets", severity="critical", secret_verified=True)
    monkeypatch.setattr(
        "hybrid.phases.phase1_scanning.run_phase1_scanning", lambda **kw: ([evidence], 0.0, {"TruffleHog": "ran(1)"})
    )

    def filter_with_ai(**kwargs):
        kwargs["all_findings"][0].severity = "low"
        kwargs["all_findings"][0].secret_verified = False
        return [], {}

    monkeypatch.setattr("hybrid.phases.phase2_enrichment.run_phase2_enrichment", filter_with_ai)
    analyzer._enrich_findings = lambda findings, path: []
    monkeypatch.setenv("ENABLE_VULNERABILITY_CHAINING", "false")
    result = analyzer.analyze(str(tmp_path), output_dir=str(tmp_path / "out"))
    assert len(result.findings) == 1
    assert result.findings[0].secret_verified is True
    assert result.findings_by_severity["critical"] == 1
    assert result.policy_gate_result["decision"] in {"fail", "error"}
