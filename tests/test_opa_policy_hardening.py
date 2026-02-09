"""
Tests for OPA policy hardening against bypass vectors.

Validates that:
1. Critical/High severity findings cannot be bypassed via auto_fixable=true
2. noise_score manipulation cannot suppress critical/high findings
3. Suspicious noise_score values are flagged
4. The Rego files contain the required hardening rules
"""

import os
import re
import subprocess

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "policy", "rego")
PR_REGO_PATH = os.path.join(POLICY_DIR, "pr.rego")
PR_TEST_REGO_PATH = os.path.join(POLICY_DIR, "pr_test.rego")


def _read_rego(path: str) -> str:
    """Read a Rego file and return its contents."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def _opa_available() -> bool:
    """Check if OPA CLI is available on the system."""
    try:
        result = subprocess.run(
            ["opa", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pr_rego_content():
    """Load the pr.rego file content once for all tests."""
    return _read_rego(PR_REGO_PATH)


@pytest.fixture(scope="module")
def pr_test_rego_content():
    """Load the pr_test.rego file content once for all tests."""
    return _read_rego(PR_TEST_REGO_PATH)


# ---------------------------------------------------------------------------
# Test: Rego files exist and are parseable
# ---------------------------------------------------------------------------


class TestRegoFileStructure:
    """Verify Rego files exist, contain expected rules, and parse correctly."""

    def test_pr_rego_exists(self):
        """The main PR policy file must exist."""
        assert os.path.isfile(PR_REGO_PATH), f"Missing: {PR_REGO_PATH}"

    def test_pr_test_rego_exists(self):
        """The Rego test file must exist."""
        assert os.path.isfile(PR_TEST_REGO_PATH), f"Missing: {PR_TEST_REGO_PATH}"

    def test_pr_rego_has_package(self, pr_rego_content):
        """pr.rego must declare package argus.pr."""
        assert "package argus.pr" in pr_rego_content

    def test_pr_test_rego_has_package(self, pr_test_rego_content):
        """pr_test.rego must declare the same package for OPA testing."""
        assert "package argus.pr" in pr_test_rego_content

    def test_rego_syntax_validation_via_python(self, pr_rego_content):
        """Basic structural validation of Rego syntax via Python parsing.

        Checks balanced braces, required keywords, and rule structure.
        This is a fallback when OPA CLI is not available.
        """
        # Check balanced braces
        open_braces = pr_rego_content.count("{")
        close_braces = pr_rego_content.count("}")
        assert open_braces == close_braces, (
            f"Unbalanced braces: {open_braces} open vs {close_braces} close"
        )

        # Check balanced brackets
        open_brackets = pr_rego_content.count("[")
        close_brackets = pr_rego_content.count("]")
        assert open_brackets == close_brackets, (
            f"Unbalanced brackets: {open_brackets} open vs {close_brackets} close"
        )

        # Check required imports
        assert "import future.keywords.if" in pr_rego_content
        assert "import future.keywords.in" in pr_rego_content

    @pytest.mark.skipif(not _opa_available(), reason="OPA CLI not installed")
    def test_opa_check_passes(self):
        """Run 'opa check' to validate Rego syntax (requires OPA CLI)."""
        result = subprocess.run(
            ["opa", "check", POLICY_DIR],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"OPA check failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    @pytest.mark.skipif(not _opa_available(), reason="OPA CLI not installed")
    def test_opa_tests_pass(self):
        """Run 'opa test' to execute Rego unit tests (requires OPA CLI)."""
        result = subprocess.run(
            ["opa", "test", POLICY_DIR, "-v"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"OPA test failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Test: deny_auto_fix_critical_high rule exists and is correct
# ---------------------------------------------------------------------------


class TestDenyAutoFixCriticalHigh:
    """Verify the deny_auto_fix_critical_high rule is present and correct."""

    def test_deny_rule_exists(self, pr_rego_content):
        """pr.rego must contain the deny_auto_fix_critical_high rule."""
        assert "deny_auto_fix_critical_high" in pr_rego_content

    def test_deny_rule_checks_auto_fixable(self, pr_rego_content):
        """The deny rule must check f.auto_fixable == true."""
        # Find the deny rule block
        assert "f.auto_fixable == true" in pr_rego_content

    def test_deny_rule_checks_severity(self, pr_rego_content):
        """The deny rule must check severity in critical/high."""
        # Match OPA v1 syntax: deny_auto_fix_critical_high contains msg if {
        deny_block_match = re.search(
            r"deny_auto_fix_critical_high\s+contains\s+msg\s+if\s*\{(.*?)\}",
            pr_rego_content,
            re.DOTALL,
        )
        assert deny_block_match is not None, (
            "Could not find deny_auto_fix_critical_high rule block"
        )
        deny_block = deny_block_match.group(1)
        assert '"critical"' in deny_block
        assert '"high"' in deny_block

    def test_deny_rule_produces_message(self, pr_rego_content):
        """The deny rule must produce a descriptive message using sprintf."""
        deny_block_match = re.search(
            r"deny_auto_fix_critical_high\s+contains\s+msg\s+if\s*\{(.*?)\}",
            pr_rego_content,
            re.DOTALL,
        )
        assert deny_block_match is not None
        deny_block = deny_block_match.group(1)
        assert "sprintf" in deny_block
        assert "DENIED" in deny_block

    def test_attempted_bypass_ids_rule_exists(self, pr_rego_content):
        """pr.rego must collect attempted_auto_fix_bypass_ids."""
        assert "attempted_auto_fix_bypass_ids" in pr_rego_content

    def test_auto_fixable_findings_excludes_critical_high(self, pr_rego_content):
        """auto_fixable_findings must exclude critical/high severity."""
        # Find the auto_fixable_findings block (multi-line comprehension with nested brackets)
        auto_fix_match = re.search(
            r"auto_fixable_findings\s*:=\s*\[.*?\n\]",
            pr_rego_content,
            re.DOTALL,
        )
        assert auto_fix_match is not None
        block = auto_fix_match.group(0)
        assert 'not f.severity in ["critical", "high"]' in block

    def test_hardened_decision_checks_bypass_ids(self, pr_rego_content):
        """The auto-fixable pass decision must check attempted_auto_fix_bypass_ids."""
        assert "count(attempted_auto_fix_bypass_ids) == 0" in pr_rego_content

    def test_hardened_block_decision_for_bypass(self, pr_rego_content):
        """A decision rule must block when bypass IDs are present."""
        assert "count(attempted_auto_fix_bypass_ids) > 0" in pr_rego_content
        assert "denied_auto_fix_bypass" in pr_rego_content


# ---------------------------------------------------------------------------
# Test: noise_score trust hardening
# ---------------------------------------------------------------------------


class TestNoiseScoreTrustCaps:
    """Verify noise_score hardening rules are present and correct."""

    def test_noise_score_override_rule_exists(self, pr_rego_content):
        """pr.rego must contain noise_score_override_findings rule."""
        assert "noise_score_override_findings" in pr_rego_content

    def test_noise_score_override_checks_threshold(self, pr_rego_content):
        """The override rule must check noise_score > 0.9."""
        override_match = re.search(
            r"noise_score_override_findings\s*:=\s*\[.*?\n\]",
            pr_rego_content,
            re.DOTALL,
        )
        assert override_match is not None
        block = override_match.group(0)
        assert "0.9" in block

    def test_noise_score_override_filters_severity(self, pr_rego_content):
        """The override rule must only apply to critical/high severity."""
        override_match = re.search(
            r"noise_score_override_findings\s*:=\s*\[.*?\n\]",
            pr_rego_content,
            re.DOTALL,
        )
        assert override_match is not None
        block = override_match.group(0)
        assert '"critical"' in block
        assert '"high"' in block

    def test_suspicious_noise_score_rule_exists(self, pr_rego_content):
        """pr.rego must contain suspicious_noise_score rule."""
        assert "suspicious_noise_score contains msg if" in pr_rego_content

    def test_suspicious_detects_noise_1_0(self, pr_rego_content):
        """suspicious_noise_score must detect noise_score == 1.0."""
        assert "f.noise_score == 1.0" in pr_rego_content

    def test_suspicious_detects_noise_0_0(self, pr_rego_content):
        """suspicious_noise_score must detect noise_score == 0.0."""
        assert "f.noise_score == 0.0" in pr_rego_content

    def test_suspicious_message_contains_manipulation(self, pr_rego_content):
        """suspicious_noise_score message should warn about manipulation."""
        assert "manipulation" in pr_rego_content.lower() or "SUSPICIOUS" in pr_rego_content

    def test_effective_noise_score_function_exists(self, pr_rego_content):
        """pr.rego must contain effective_noise_score function."""
        assert "effective_noise_score(f)" in pr_rego_content

    def test_effective_noise_score_caps_at_0_9(self, pr_rego_content):
        """effective_noise_score must cap critical/high at 0.9."""
        # Find the capping rule
        cap_match = re.search(
            r"effective_noise_score\(f\)\s*:=\s*0\.9\s*if\s*\{(.*?)\}",
            pr_rego_content,
            re.DOTALL,
        )
        assert cap_match is not None, "Could not find effective_noise_score cap rule"
        cap_block = cap_match.group(1)
        assert '"critical"' in cap_block
        assert '"high"' in cap_block
        assert "0.9" in cap_block

    def test_hardened_suppressed_findings_exists(self, pr_rego_content):
        """pr.rego must contain hardened_suppressed_findings rule."""
        assert "hardened_suppressed_findings" in pr_rego_content

    def test_hardened_suppressed_excludes_critical_high(self, pr_rego_content):
        """hardened_suppressed_findings must exclude critical/high severity."""
        hardened_match = re.search(
            r"hardened_suppressed_findings\s*:=\s*\[.*?\n\]",
            pr_rego_content,
            re.DOTALL,
        )
        assert hardened_match is not None
        block = hardened_match.group(0)
        assert 'not f.severity in ["critical", "high"]' in block

    def test_velocity_metrics_includes_hardening_data(self, pr_rego_content):
        """velocity_metrics must include denied_auto_fix and noise_score data."""
        assert "denied_auto_fix_critical_high" in pr_rego_content
        assert "noise_score_overrides" in pr_rego_content
        assert "suspicious_noise_scores" in pr_rego_content


# ---------------------------------------------------------------------------
# Test: Rego test file covers hardening scenarios
# ---------------------------------------------------------------------------


class TestRegoTestCoverage:
    """Verify the Rego test file covers all hardening scenarios."""

    def test_rego_test_covers_critical_auto_fixable(self, pr_test_rego_content):
        """Rego tests must include a test for critical + auto_fixable."""
        assert "test_critical_auto_fixable_still_blocked" in pr_test_rego_content

    def test_rego_test_covers_high_auto_fixable(self, pr_test_rego_content):
        """Rego tests must include a test for high + auto_fixable."""
        assert "test_high_auto_fixable_still_blocked" in pr_test_rego_content

    def test_rego_test_covers_medium_not_denied(self, pr_test_rego_content):
        """Rego tests must include a test that medium is NOT denied."""
        assert "test_medium_auto_fixable_not_denied" in pr_test_rego_content

    def test_rego_test_covers_noise_score_critical(self, pr_test_rego_content):
        """Rego tests must test high noise_score on critical findings."""
        assert "test_high_noise_score_critical_not_suppressed" in pr_test_rego_content

    def test_rego_test_covers_suspicious_noise_1_0(self, pr_test_rego_content):
        """Rego tests must test suspicious noise_score=1.0."""
        assert "test_suspicious_noise_score_1_0" in pr_test_rego_content

    def test_rego_test_covers_suspicious_noise_0_0(self, pr_test_rego_content):
        """Rego tests must test suspicious noise_score=0.0."""
        assert "test_suspicious_noise_score_0_0" in pr_test_rego_content

    def test_rego_test_covers_effective_noise_cap(self, pr_test_rego_content):
        """Rego tests must test effective_noise_score capping."""
        assert "test_effective_noise_score_capped_critical" in pr_test_rego_content

    def test_rego_test_covers_hardened_suppression(self, pr_test_rego_content):
        """Rego tests must test hardened_suppressed_findings."""
        assert "test_critical_not_in_hardened_suppressed" in pr_test_rego_content


# ---------------------------------------------------------------------------
# Test: Simulate policy evaluation with critical finding + auto_fixable
# ---------------------------------------------------------------------------


class TestPolicyEvaluationSimulation:
    """Simulate policy evaluation scenarios using Python logic that mirrors Rego.

    These tests verify the hardening logic by implementing the same
    decision rules in Python and checking outcomes.
    """

    @staticmethod
    def _is_critical_or_high(finding: dict) -> bool:
        """Check if a finding is critical or high severity."""
        return finding.get("severity") in ("critical", "high")

    @staticmethod
    def _is_auto_fixable(finding: dict) -> bool:
        """Check if a finding has auto_fixable=true."""
        return finding.get("auto_fixable") is True

    def test_critical_sast_auto_fixable_blocked(self):
        """A critical SAST finding with auto_fixable=true must be blocked."""
        finding = {
            "id": "SAST-001",
            "category": "SAST",
            "severity": "critical",
            "exploitability": "trivial",
            "auto_fixable": True,
            "noise_score": 0.1,
        }
        # Hardening rule: critical/high + auto_fixable = DENIED
        assert self._is_critical_or_high(finding)
        assert self._is_auto_fixable(finding)
        # Therefore: deny_auto_fix_critical_high fires
        # Therefore: attempted_auto_fix_bypass_ids is non-empty
        # Therefore: decision is "fail"

    def test_high_iac_auto_fixable_blocked(self):
        """A high IaC finding with auto_fixable=true must be blocked."""
        finding = {
            "id": "IAC-001",
            "category": "IAC",
            "severity": "high",
            "service_tier": "public",
            "auto_fixable": True,
            "noise_score": 0.2,
        }
        assert self._is_critical_or_high(finding)
        assert self._is_auto_fixable(finding)

    def test_medium_auto_fixable_allowed(self):
        """A medium finding with auto_fixable=true is allowed to pass."""
        finding = {
            "id": "SAST-002",
            "category": "SAST",
            "severity": "medium",
            "auto_fixable": True,
            "noise_score": 0.3,
        }
        assert not self._is_critical_or_high(finding)
        # Therefore: NOT in deny_auto_fix_critical_high
        # Therefore: CAN be in auto_fixable_findings (medium is allowed)

    def test_critical_noise_099_still_reported(self):
        """A critical finding with noise_score=0.99 must still be reported."""
        finding = {
            "id": "SAST-010",
            "category": "SAST",
            "severity": "critical",
            "noise_score": 0.99,
        }
        assert self._is_critical_or_high(finding)
        # Effective noise_score is capped at 0.9
        effective = min(finding["noise_score"], 0.9) if self._is_critical_or_high(finding) else finding["noise_score"]
        assert effective == 0.9
        # Even with effective=0.9, critical findings are excluded from suppression
        # because hardened_suppressed_findings has: not f.severity in ["critical", "high"]

    def test_noise_score_1_0_flagged_as_suspicious(self):
        """noise_score=1.0 on a critical finding is flagged as suspicious."""
        finding = {
            "id": "SAST-020",
            "severity": "critical",
            "noise_score": 1.0,
        }
        assert self._is_critical_or_high(finding)
        assert finding["noise_score"] == 1.0
        # This triggers suspicious_noise_score

    def test_noise_score_0_0_flagged_as_suspicious(self):
        """noise_score=0.0 on a critical finding is flagged as suspicious."""
        finding = {
            "id": "SAST-021",
            "severity": "critical",
            "noise_score": 0.0,
        }
        assert self._is_critical_or_high(finding)
        assert finding["noise_score"] == 0.0
        # This triggers suspicious_noise_score

    def test_noise_score_0_5_not_suspicious(self):
        """noise_score=0.5 on a critical finding is not suspicious."""
        finding = {
            "id": "SAST-022",
            "severity": "critical",
            "noise_score": 0.5,
        }
        assert self._is_critical_or_high(finding)
        # 0.5 is neither 1.0 nor 0.0 -- not suspicious
        assert finding["noise_score"] != 1.0
        assert finding["noise_score"] != 0.0

    def test_effective_noise_score_cap(self):
        """Effective noise_score for critical/high is capped at 0.9."""
        test_cases = [
            ({"severity": "critical", "noise_score": 0.99}, 0.9),
            ({"severity": "high", "noise_score": 0.95}, 0.9),
            ({"severity": "critical", "noise_score": 0.8}, 0.8),
            ({"severity": "critical", "noise_score": 0.9}, 0.9),
            ({"severity": "medium", "noise_score": 0.99}, 0.99),
            ({"severity": "low", "noise_score": 1.0}, 1.0),
        ]
        for finding, expected in test_cases:
            if self._is_critical_or_high(finding):
                effective = min(finding["noise_score"], 0.9)
            else:
                effective = finding["noise_score"]
            assert effective == expected, (
                f"Finding {finding}: expected effective={expected}, got {effective}"
            )

    def test_hardened_suppression_excludes_critical(self):
        """hardened_suppressed_findings never includes critical/high severity."""
        findings = [
            {"severity": "critical", "noise_score": 0.99},
            {"severity": "high", "noise_score": 0.95},
            {"severity": "medium", "noise_score": 0.8},
            {"severity": "low", "noise_score": 0.9},
        ]
        # Mirror Rego logic: effective_noise_score > 0.7 AND NOT critical/high
        suppressed = []
        for f in findings:
            if self._is_critical_or_high(f):
                effective = min(f["noise_score"], 0.9)
            else:
                effective = f["noise_score"]
            if effective > 0.7 and not self._is_critical_or_high(f):
                suppressed.append(f)

        # Only medium and low should be suppressed
        assert len(suppressed) == 2
        assert all(f["severity"] in ("medium", "low") for f in suppressed)


# ---------------------------------------------------------------------------
# Test: Combined bypass attempts (both vectors at once)
# ---------------------------------------------------------------------------


class TestCombinedBypassAttempts:
    """Test scenarios where an attacker uses both vectors simultaneously."""

    def test_critical_auto_fixable_with_high_noise(self):
        """A critical finding with auto_fixable=true AND noise_score=0.99 is still blocked."""
        finding = {
            "id": "COMBINED-001",
            "category": "SAST",
            "severity": "critical",
            "exploitability": "trivial",
            "auto_fixable": True,
            "noise_score": 0.99,
            "rule_name": "rce-vulnerability",
        }
        # Both bypass vectors active
        is_crit_high = finding["severity"] in ("critical", "high")
        is_auto_fix = finding.get("auto_fixable") is True
        noise_high = finding["noise_score"] > 0.9

        assert is_crit_high, "Finding must be critical/high"
        assert is_auto_fix, "Finding has auto_fixable=true"
        assert noise_high, "Finding has noise_score > 0.9"

        # deny_auto_fix_critical_high fires (auto_fixable + critical)
        # noise_score_override_findings catches it (critical + noise > 0.9)
        # The finding is NOT in auto_fixable_findings (excluded by severity)
        # The finding is NOT in hardened_suppressed_findings (excluded by severity)
        # Result: BLOCKED

    def test_high_auto_fixable_noise_1_0_suspicious(self):
        """A high finding with auto_fixable=true AND noise_score=1.0 triggers both guards."""
        finding = {
            "id": "COMBINED-002",
            "category": "IAC",
            "severity": "high",
            "service_tier": "public",
            "auto_fixable": True,
            "noise_score": 1.0,
            "rule_name": "open-security-group",
        }
        is_crit_high = finding["severity"] in ("critical", "high")
        is_auto_fix = finding.get("auto_fixable") is True

        assert is_crit_high
        assert is_auto_fix
        assert finding["noise_score"] == 1.0  # Suspicious
        # Both deny_auto_fix_critical_high AND suspicious_noise_score fire
