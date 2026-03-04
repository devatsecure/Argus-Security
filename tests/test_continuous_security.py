"""Tests for continuous security testing modules (v3.0)."""
import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from diff_impact_analyzer import (
    DiffClassifier,
    DiffClassification,
    DiffImpactAnalyzer,
    DiffScopeBuilder,
    ScanScope,
)
from agent_chain_discovery import (
    AgentChainDiscovery,
    AttackChain,
    AttackStep,
    CrossComponentAnalyzer,
    CrossComponentRisk,
)
from findings_store import FindingsStore, ScanSummary
from app_context_builder import AppContextBuilder, ApplicationContext
from autofix_pr_generator import (
    AutoFixPRGenerator,
    ClosedLoopOrchestrator,
    FixBranch,
    FixPR,
    LoopResult,
)
import config_loader


# ============================================================================
# 1. DiffClassifier tests
# ============================================================================


class TestDiffClassifier:
    """Tests for DiffClassifier file classification."""

    def test_diff_classifier_skip_docs(self):
        """Markdown and image files should be classified as skippable."""
        classifier = DiffClassifier()
        result = classifier.classify(["README.md", "docs/guide.md", "logo.png"])
        assert result.skippable == ["README.md", "docs/guide.md", "logo.png"]
        assert result.security_relevant == []

    def test_diff_classifier_scan_auth(self):
        """Auth-related files should always be security_relevant."""
        classifier = DiffClassifier()
        result = classifier.classify(["src/auth/handler.py", "lib/session.js"])
        assert "src/auth/handler.py" in result.security_relevant
        assert "lib/session.js" in result.security_relevant
        assert result.skippable == []

    def test_diff_classifier_default_to_scan(self):
        """Unknown file types should default to security_relevant."""
        classifier = DiffClassifier()
        result = classifier.classify(["src/utils/calc.py", "lib/server.go"])
        assert "src/utils/calc.py" in result.security_relevant
        assert "lib/server.go" in result.security_relevant

    def test_diff_classifier_should_scan_false(self):
        """All-docs changes should set should_scan=False."""
        classifier = DiffClassifier()
        result = classifier.classify(["README.md", "CHANGELOG", "docs/notes.txt"])
        assert result.should_scan is False
        assert result.security_relevant == []

    def test_diff_classifier_mixed(self):
        """Mix of security and docs files classifies correctly."""
        classifier = DiffClassifier()
        files = ["README.md", "src/auth/login.py", "logo.png", "app/views.py"]
        result = classifier.classify(files)
        assert "README.md" in result.skippable
        assert "logo.png" in result.skippable
        assert "src/auth/login.py" in result.security_relevant
        assert "app/views.py" in result.security_relevant
        assert result.should_scan is True
        assert result.total_changed == 4


# ============================================================================
# 2. DiffScopeBuilder tests
# ============================================================================


class TestDiffScopeBuilder:
    """Tests for DiffScopeBuilder scope construction."""

    def test_scope_builder_full_project_when_not_scoped(self):
        """With only_changed=False, returns full project scope."""
        builder = DiffScopeBuilder()
        scope = builder.build_scope(
            project_path="/tmp/project",
            changed_files=["foo.py"],
            only_changed=False,
        )
        assert scope.is_scoped is False
        assert scope.files == []

    def test_scope_builder_scoped_mode(self):
        """With only_changed=True and changed_files, returns scoped result."""
        builder = DiffScopeBuilder()
        scope = builder.build_scope(
            project_path="/tmp/project",
            changed_files=["src/auth/handler.py", "README.md"],
            only_changed=True,
        )
        assert scope.is_scoped is True
        assert "src/auth/handler.py" in scope.files
        assert "README.md" in scope.skipped

    def test_semgrep_include_args(self):
        """get_semgrep_include_args returns proper CLI args."""
        scope = ScanScope(
            files=["src/auth.py", "src/api.py"],
            is_scoped=True,
        )
        args = DiffScopeBuilder.get_semgrep_include_args(scope)
        assert args == ["--include", "src/auth.py", "--include", "src/api.py"]

    def test_semgrep_include_args_empty_for_unscoped(self):
        """get_semgrep_include_args returns empty list for unscoped scope."""
        scope = ScanScope(files=[], is_scoped=False)
        args = DiffScopeBuilder.get_semgrep_include_args(scope)
        assert args == []


# ============================================================================
# 3. AgentChainDiscovery tests
# ============================================================================


class TestAgentChainDiscovery:
    """Tests for AgentChainDiscovery LLM response parsing."""

    def test_parse_chains_valid_json(self):
        """Valid JSON response is parsed into AttackChain objects."""
        mock_response = json.dumps([
            {
                "chain_id": "chain-1",
                "finding_ids": ["f1", "f2"],
                "steps": [
                    {"finding_id": "f1", "action": "exploit SQLi", "enables": "data leak"},
                    {"finding_id": "f2", "action": "escalate", "enables": "admin access"},
                ],
                "severity": "critical",
                "complexity": "low",
                "impact": "Full database compromise",
                "description": "SQLi to privilege escalation",
            }
        ])

        def fake_llm(prompt: str) -> str:
            return mock_response

        discoverer = AgentChainDiscovery(llm_call=fake_llm)
        chains = discoverer.discover_chains([
            {"id": "f1", "type": "sqli", "severity": "high", "file": "db.py", "description": "SQL injection"},
            {"id": "f2", "type": "auth", "severity": "medium", "file": "auth.py", "description": "Weak auth"},
        ])

        assert len(chains) == 1
        assert chains[0].chain_id == "chain-1"
        assert chains[0].finding_ids == ["f1", "f2"]
        assert len(chains[0].steps) == 2
        assert chains[0].severity == "critical"
        assert chains[0].complexity == "low"

    def test_parse_chains_markdown_fenced(self):
        """JSON wrapped in ```json ... ``` blocks is parsed."""
        inner = json.dumps([
            {
                "chain_id": "c1",
                "finding_ids": ["a", "b"],
                "steps": [],
                "severity": "high",
                "complexity": "medium",
                "impact": "data leak",
                "description": "chained attack",
            }
        ])
        fenced = f"Here is the analysis:\n```json\n{inner}\n```\nDone."

        def fake_llm(prompt: str) -> str:
            return fenced

        discoverer = AgentChainDiscovery(llm_call=fake_llm)
        chains = discoverer.discover_chains([
            {"id": "a", "type": "xss", "severity": "high", "file": "x.js", "description": "XSS"},
            {"id": "b", "type": "csrf", "severity": "medium", "file": "y.js", "description": "CSRF"},
        ])

        assert len(chains) == 1
        assert chains[0].chain_id == "c1"

    def test_parse_chains_invalid_json(self):
        """Invalid JSON returns empty list."""

        def fake_llm(prompt: str) -> str:
            return "This is not valid JSON at all {{{broken"

        discoverer = AgentChainDiscovery(llm_call=fake_llm)
        chains = discoverer.discover_chains([
            {"id": "x", "type": "test", "severity": "low", "file": "t.py", "description": "test"},
        ])

        assert chains == []


# ============================================================================
# 4. CrossComponentAnalyzer tests
# ============================================================================


class TestCrossComponentAnalyzer:
    """Tests for CrossComponentAnalyzer component classification and risk detection."""

    def test_classify_component_auth(self):
        """Files in auth/ directory classified as auth component."""
        analyzer = CrossComponentAnalyzer(project_path="/tmp/project")
        component = analyzer._classify_component("src/auth/login.py")
        assert component == "auth"

    def test_classify_component_api(self):
        """Files in api/ or routes/ directory classified correctly."""
        analyzer = CrossComponentAnalyzer(project_path="/tmp/project")

        assert analyzer._classify_component("src/api/users.py") == "api"
        assert analyzer._classify_component("app/routes/index.js") == "routes"

    def test_classify_component_other(self):
        """Files not in any known directory classified as other."""
        analyzer = CrossComponentAnalyzer(project_path="/tmp/project")
        component = analyzer._classify_component("scripts/deploy.sh")
        assert component == "other"

    def test_dangerous_combination_auth_api(self):
        """Auth + API findings trigger broken access control risk."""
        analyzer = CrossComponentAnalyzer(project_path="/tmp/project")
        findings = [
            {"id": "f1", "file": "src/auth/handler.py", "severity": "high"},
            {"id": "f2", "file": "src/api/users.py", "severity": "medium"},
        ]
        risks = analyzer.analyze(findings)
        assert len(risks) >= 1
        risk_types = [r["risk_type"] for r in risks]
        assert "broken_access_control" in risk_types

        # Verify the risk has the right structure
        bac_risk = [r for r in risks if r["risk_type"] == "broken_access_control"][0]
        assert bac_risk["severity"] == "critical"
        assert "f1" in bac_risk["findings_a"] or "f1" in bac_risk["findings_b"]

    def test_no_dangerous_combinations(self):
        """Findings in the same component should not trigger cross-component risks."""
        analyzer = CrossComponentAnalyzer(project_path="/tmp/project")
        findings = [
            {"id": "f1", "file": "src/utils/helper.py"},
            {"id": "f2", "file": "src/utils/parser.py"},
        ]
        risks = analyzer.analyze(findings)
        assert risks == []


# ============================================================================
# 5. FindingsStore tests
# ============================================================================


class TestFindingsStore:
    """Tests for FindingsStore persistence and analytics."""

    def test_findings_store_init(self, tmp_path):
        """Store creates db file and tables on init."""
        db_path = str(tmp_path / "test.db")
        store = FindingsStore(db_path=db_path)
        assert os.path.isfile(db_path)

        # Verify tables exist by querying them
        cur = store._conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cur.fetchall()}
        assert "findings" in tables
        assert "scan_history" in tables
        assert "fix_history" in tables
        store.close()

    def test_record_and_retrieve(self, tmp_path):
        """Record a scan and retrieve findings."""
        db_path = str(tmp_path / "test.db")
        store = FindingsStore(db_path=db_path)

        findings = [
            {
                "id": "finding-001",
                "vuln_type": "sql_injection",
                "severity": "critical",
                "file_path": "src/db.py",
                "line_number": 42,
                "cwe": "CWE-89",
                "description": "SQL injection in query builder",
            },
            {
                "id": "finding-002",
                "vuln_type": "xss",
                "severity": "high",
                "file_path": "src/template.py",
                "line_number": 15,
                "cwe": "CWE-79",
                "description": "Reflected XSS",
            },
        ]

        summary = store.record_scan("scan-1", findings, commit_sha="abc123")
        assert isinstance(summary, ScanSummary)
        assert summary.total_findings == 2
        assert summary.new_findings == 2
        assert summary.by_severity["critical"] == 1
        assert summary.by_severity["high"] == 1

        # Retrieve individual finding
        f = store.get_finding("finding-001")
        assert f is not None
        assert f["vuln_type"] == "sql_injection"
        assert f["severity"] == "critical"
        assert f["status"] == "open"
        store.close()

    def test_fingerprinting_consistency(self):
        """Same finding always produces same fingerprint."""
        finding = {
            "vuln_type": "sql_injection",
            "file_path": "src/db.py",
            "code_snippet": "cursor.execute(query)",
            "cwe": "CWE-89",
        }
        fp1 = FindingsStore.fingerprint_finding(finding)
        fp2 = FindingsStore.fingerprint_finding(finding)
        assert fp1 == fp2
        assert len(fp1) == 16  # 16 hex chars

        # Different finding produces different fingerprint
        different = {
            "vuln_type": "xss",
            "file_path": "src/template.py",
            "code_snippet": "render(html)",
            "cwe": "CWE-79",
        }
        fp3 = FindingsStore.fingerprint_finding(different)
        assert fp3 != fp1

    def test_regression_detection(self, tmp_path):
        """Previously-fixed findings are flagged as regressions."""
        db_path = str(tmp_path / "test.db")
        store = FindingsStore(db_path=db_path)

        finding = {
            "id": "reg-001",
            "vuln_type": "sql_injection",
            "severity": "high",
            "file_path": "src/db.py",
            "cwe": "CWE-89",
        }

        # First scan: record the finding
        store.record_scan("scan-1", [finding])

        # Mark the finding as fixed
        store.record_fix("reg-001", fix_commit="fix123", retest_passed=True)

        # Verify it is now marked fixed
        f = store.get_finding("reg-001")
        assert f["status"] == "fixed"

        # Second scan: same finding reappears -> regression
        summary = store.record_scan("scan-2", [finding])
        assert summary.regressions == 1

        # The finding should be reset to open
        f2 = store.get_finding("reg-001")
        assert f2["status"] == "open"
        store.close()

    def test_trending(self, tmp_path):
        """Trending returns severity data from scan history."""
        db_path = str(tmp_path / "test.db")
        store = FindingsStore(db_path=db_path)

        findings = [
            {"vuln_type": "sqli", "severity": "critical", "file_path": "a.py"},
            {"vuln_type": "xss", "severity": "high", "file_path": "b.py"},
        ]
        store.record_scan("scan-1", findings)

        weeks = store.trending(days=90)
        # Should have at least one week entry with our data
        assert isinstance(weeks, dict)
        if weeks:
            # Verify that at least one week has our severity counts
            some_week = next(iter(weeks.values()))
            assert "critical" in some_week
            assert "high" in some_week
        store.close()

    def test_historical_context(self, tmp_path):
        """get_historical_context returns correct data for known finding."""
        db_path = str(tmp_path / "test.db")
        store = FindingsStore(db_path=db_path)

        finding = {
            "vuln_type": "sqli",
            "severity": "high",
            "file_path": "src/db.py",
            "cwe": "CWE-89",
        }

        # Record finding once
        store.record_scan("scan-1", [finding])

        # Get historical context
        ctx = store.get_historical_context(finding)
        assert ctx["times_seen"] == 1
        assert ctx["first_seen"] is not None
        assert ctx["previous_status"] == "open"
        assert ctx["is_regression"] is False
        assert isinstance(ctx["fp_rate_for_type"], float)
        assert isinstance(ctx["related_in_file"], int)

        # Unknown finding returns zeroed context
        unknown = {
            "vuln_type": "unknown_vuln",
            "file_path": "nowhere.py",
            "cwe": "CWE-000",
        }
        ctx2 = store.get_historical_context(unknown)
        assert ctx2["times_seen"] == 0
        assert ctx2["first_seen"] is None
        assert ctx2["is_regression"] is False
        store.close()


# ============================================================================
# 6. AppContextBuilder tests
# ============================================================================


class TestAppContextBuilder:
    """Tests for AppContextBuilder language/framework detection and context formatting."""

    def test_detect_language_python(self, tmp_path):
        """Directory with .py files detected as python."""
        # Create several .py files
        for name in ("app.py", "utils.py", "models.py", "views.py", "tests.py"):
            (tmp_path / name).write_text("# python file\n")
        builder = AppContextBuilder(str(tmp_path))
        ctx = builder.build()
        assert ctx.language == "python"

    def test_detect_framework_django(self, tmp_path):
        """manage.py presence detected as django."""
        (tmp_path / "manage.py").write_text("#!/usr/bin/env python\nimport django\n")
        (tmp_path / "app.py").write_text("# app\n")
        builder = AppContextBuilder(str(tmp_path))
        ctx = builder.build()
        assert ctx.framework == "django"

    def test_detect_language_unknown_empty(self, tmp_path):
        """Empty directory returns unknown language."""
        builder = AppContextBuilder(str(tmp_path))
        ctx = builder.build()
        assert ctx.language == "unknown"

    def test_to_prompt_context(self):
        """to_prompt_context returns formatted string."""
        ctx = ApplicationContext(
            language="python",
            framework="django",
            auth_mechanism="jwt",
            cloud_provider="aws",
            has_dockerfile=True,
            has_k8s=False,
        )
        prompt = ctx.to_prompt_context()
        assert "Application Context:" in prompt
        assert "python" in prompt
        assert "django" in prompt
        assert "jwt" in prompt
        assert "aws" in prompt
        assert "Has Dockerfile: yes" in prompt
        assert "Has Kubernetes: no" in prompt


# ============================================================================
# 7. AutoFixPRGenerator tests
# ============================================================================


class TestAutoFixPRGenerator:
    """Tests for AutoFixPRGenerator commit messages, PR bodies, and fixability checks."""

    def test_generate_commit_message(self):
        """Commit message follows conventional format."""
        generator = AutoFixPRGenerator(project_path="/tmp/project")
        suggestion = {
            "vulnerability_type": "sql_injection",
            "finding_id": "finding-12345678",
            "cwe": "CWE-89",
            "file_path": "src/db.py",
            "line_number": 42,
            "explanation": "Use parameterized queries instead of string concatenation.",
        }
        msg = generator._generate_commit_message(suggestion)
        assert msg.startswith("fix(sql_injection):")
        assert "Finding: finding-12345678" in msg
        assert "CWE: CWE-89" in msg
        assert "File: src/db.py:42" in msg
        assert "Generated by Argus Security AutoFix" in msg

    def test_generate_pr_body(self):
        """PR body includes all required sections."""
        generator = AutoFixPRGenerator(project_path="/tmp/project")
        suggestion = {
            "vulnerability_type": "sql_injection",
            "finding_id": "finding-001",
            "cwe": "CWE-89",
            "severity": "critical",
            "file_path": "src/db.py",
            "line_number": 42,
            "explanation": "Use parameterized queries.",
            "diff": "--- a/src/db.py\n+++ b/src/db.py\n@@ -42 +42 @@\n-bad\n+good",
            "testing_recommendations": ["Run unit tests", "Check query output"],
        }
        body = generator.generate_pr_body(suggestion)
        assert "## Summary" in body
        assert "## Vulnerability Details" in body
        assert "sql_injection" in body
        assert "CWE-89" in body
        assert "## What Changed" in body
        assert "## Diff" in body
        assert "## Testing Recommendations" in body
        assert "Run unit tests" in body
        assert "Argus Security" in body

    def test_is_fixable(self):
        """Findings with proper context are marked fixable."""
        orchestrator = ClosedLoopOrchestrator(project_path="/tmp/project")
        finding = {
            "file_path": "src/db.py",
            "vulnerability_type": "sql_injection",
            "severity": "critical",
            "line_number": 42,
        }
        assert orchestrator._is_fixable(finding) is True

    def test_not_fixable_missing_file(self):
        """Findings without file_path are not fixable."""
        orchestrator = ClosedLoopOrchestrator(project_path="/tmp/project")
        finding = {
            "vulnerability_type": "sql_injection",
            "severity": "critical",
            "line_number": 42,
        }
        assert orchestrator._is_fixable(finding) is False

    def test_not_fixable_missing_type(self):
        """Findings without vulnerability type are not fixable."""
        orchestrator = ClosedLoopOrchestrator(project_path="/tmp/project")
        finding = {
            "file_path": "src/db.py",
            "severity": "critical",
            "line_number": 42,
        }
        assert orchestrator._is_fixable(finding) is False

    def test_loop_result_success_rate(self):
        """LoopResult.success_rate computes correctly."""
        result = LoopResult(total_findings=10, fixable=4)
        # No fixed yet
        assert result.success_rate == 0.0

        # Add some fixed PRs
        result.fixed.append(
            FixPR(
                branch_name="argus/fix-sqli-abc",
                finding_id="f1",
                vulnerability_type="sqli",
                file_path="db.py",
                title="fix",
                body="body",
                commit_sha="sha1",
                pushed=False,
                success=True,
            )
        )
        result.fixed.append(
            FixPR(
                branch_name="argus/fix-xss-def",
                finding_id="f2",
                vulnerability_type="xss",
                file_path="tmpl.py",
                title="fix",
                body="body",
                commit_sha="sha2",
                pushed=False,
                success=True,
            )
        )
        # 2 fixed out of 4 fixable = 0.5
        assert result.success_rate == pytest.approx(0.5)

    def test_loop_result_success_rate_zero_fixable(self):
        """LoopResult.success_rate returns 0.0 when no fixable findings."""
        result = LoopResult(total_findings=5, fixable=0)
        assert result.success_rate == 0.0


# ============================================================================
# 8. Config integration tests
# ============================================================================


class TestConfigIntegration:
    """Tests that v3.0 continuous security config keys are properly wired."""

    V3_CONFIG_KEYS = [
        "enable_diff_scoping",
        "diff_expand_impact_radius",
        "enable_autofix_pr",
        "autofix_confidence_threshold",
        "autofix_max_prs_per_scan",
        "enable_findings_store",
        "findings_db_path",
        "inject_historical_context",
        "enable_agent_chain_discovery",
        "enable_cross_component_analysis",
        "enable_app_context",
        "enable_live_validation",
        "live_validation_environment",
        "only_changed",
    ]

    def test_new_config_keys_in_defaults(self):
        """All v3.0 config keys exist in get_default_config."""
        defaults = config_loader.get_default_config()
        for key in self.V3_CONFIG_KEYS:
            assert key in defaults, f"Missing v3.0 config key in defaults: {key}"

    def test_env_var_mappings_exist(self):
        """All v3.0 config keys have env var mappings."""
        # Collect all config keys that have env var mappings
        mapped_config_keys = {
            config_key for _, config_key, _ in config_loader._ENV_MAPPINGS
        }
        for key in self.V3_CONFIG_KEYS:
            assert key in mapped_config_keys, (
                f"Missing env var mapping for v3.0 config key: {key}"
            )
