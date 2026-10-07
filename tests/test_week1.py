"""
Week 1 Tests - Normalizer + Policy Engine
Tests the core Week 1 deliverables
"""

import sys
from pathlib import Path

import pytest

# Add scripts to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from gate import PolicyGate  # noqa: E402
from normalizer import Finding, UnifiedNormalizer  # noqa: E402
from normalizer.semgrep import SemgrepNormalizer  # noqa: E402
from normalizer.trufflehog import TruffleHogNormalizer  # noqa: E402


class TestFindingSchema:
    """Test Finding dataclass"""

    def test_finding_creation(self):
        """Test basic Finding creation"""
        finding = Finding(
            id="test123",
            origin="semgrep",
            repo="test/repo",
            commit_sha="abc123",
            branch="main",
            asset_type="code",
            path="src/test.py",
            line=42,
            rule_id="test-rule",
            rule_name="Test Rule",
            category="SAST",
            severity="high",
        )

        assert finding.id == "test123"
        assert finding.severity == "high"
        assert finding.status == "open"

    def test_dedup_key_generation(self):
        """Test deduplication key generation"""
        finding1 = Finding(
            id="test1",
            origin="semgrep",
            repo="test/repo",
            commit_sha="abc123",
            branch="main",
            asset_type="code",
            path="src/test.py",
            line=42,
            rule_id="sql-injection",
            rule_name="SQL Injection",
            category="SAST",
            severity="critical",
        )

        finding2 = Finding(
            id="test2",  # Different ID
            origin="semgrep",
            repo="test/repo",
            commit_sha="def456",  # Different commit
            branch="main",
            asset_type="code",
            path="src/test.py",  # Same path
            line=42,  # Same line
            rule_id="sql-injection",  # Same rule
            rule_name="SQL Injection",
            category="SAST",
            severity="critical",
        )

        # Should have same dedup key (same repo, path, rule, line)
        assert finding1.dedup_key() == finding2.dedup_key()

    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # High severity + verified secret = high risk
        finding = Finding(
            id="test",
            origin="trufflehog",
            repo="test/repo",
            commit_sha="abc123",
            branch="main",
            asset_type="code",
            path="src/config.py",
            rule_id="aws-key",
            rule_name="AWS Access Key",
            category="SECRETS",
            severity="critical",
            secret_verified="true",
        )

        score = finding.calculate_risk_score()
        assert score >= 9.0  # Verified secret should be high risk


class TestNormalizers:
    """Test individual normalizers"""

    def test_semgrep_normalizer(self):
        """Test Semgrep SARIF normalization"""
        sarif_output = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "python.lang.security.sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/api.py"},
                                        "region": {
                                            "startLine": 42,
                                            "snippet": {"text": "query = 'SELECT * FROM users WHERE id=' + user_id"},
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "python.lang.security.sql-injection",
                                    "name": "SQL Injection",
                                    "properties": {"tags": ["CWE-89"]},
                                }
                            ]
                        }
                    },
                }
            ]
        }

        normalizer = SemgrepNormalizer()
        findings = normalizer.normalize(sarif_output)

        assert len(findings) == 1
        assert findings[0].category == "SAST"
        assert findings[0].severity == "high"
        assert findings[0].cwe == "CWE-89"

    def test_trufflehog_normalizer_verified_only(self):
        """Test TruffleHog only returns VERIFIED secrets"""
        trufflehog_output = [
            {
                "verified": True,  # Verified - should be included
                "detector_type": "AWS",
                "detector_name": "AWS Access Key",
                "raw": "AKIAIOSFODNN7EXAMPLE",
                "source_metadata": {"data": {"Git": {"file": "src/config.py", "line": 10, "commit": "abc123"}}},
            },
            {
                "verified": False,  # Unverified - should be SKIPPED
                "detector_type": "Generic",
                "detector_name": "Generic Secret",
                "raw": "some_suspicious_string",
            },
        ]

        normalizer = TruffleHogNormalizer()
        findings = normalizer.normalize(trufflehog_output)

        # Should only have 1 finding (verified one)
        assert len(findings) == 1
        assert findings[0].secret_verified == "true"
        assert findings[0].severity == "critical"


class TestUnifiedNormalizer:
    """Test unified normalizer"""

    def test_normalize_all(self):
        """Test normalizing multiple tool outputs"""
        tool_outputs = {
            "semgrep": {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "test-rule",
                                "level": "error",
                                "message": {"text": "Test finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "test.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                        "tool": {"driver": {"rules": []}},
                    }
                ]
            }
        }

        normalizer = UnifiedNormalizer()
        findings = normalizer.normalize_all(tool_outputs)

        assert len(findings) >= 1
        assert all(isinstance(f, Finding) for f in findings)

    def test_deduplication(self):
        """Test findings are deduplicated"""
        # Create duplicate findings
        tool_outputs = {
            "semgrep": {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "same-rule",
                                "level": "error",
                                "message": {"text": "Finding 1"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "test.py"},
                                            "region": {"startLine": 42},
                                        }
                                    }
                                ],
                            },
                            {
                                "ruleId": "same-rule",
                                "level": "error",
                                "message": {"text": "Finding 2 (duplicate)"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "test.py"},
                                            "region": {"startLine": 42},  # Same line
                                        }
                                    }
                                ],
                            },
                        ],
                        "tool": {"driver": {"rules": []}},
                    }
                ]
            }
        }

        normalizer = UnifiedNormalizer()
        findings = normalizer.normalize_all(tool_outputs)

        # Should be deduplicated to 1 finding
        assert len(findings) == 1


@pytest.mark.skipif(__import__("shutil").which("opa") is None, reason="OPA executable required for real policy tests")
class TestPolicyGate:
    """Test policy gate evaluation"""

    def test_pr_policy_verified_secret_blocks(self):
        """Test PR policy blocks verified secrets"""
        findings = [
            {
                "id": "secret123",
                "category": "SECRETS",
                "severity": "critical",
                "secret_verified": "true",  # Verified secret
                "path": "src/config.py",
                "line": 10,
            }
        ]

        gate = PolicyGate()
        decision = gate.evaluate("pr", findings)

        assert decision["decision"] == "fail"
        assert len(decision["blocks"]) == 1
        assert "secret" in decision["reasons"][0].lower()

    def test_pr_policy_unverified_secret_warns(self):
        """Test PR policy warns but doesn't block unverified secrets"""
        findings = [
            {
                "id": "secret123",
                "category": "SECRETS",
                "severity": "high",
                "secret_verified": "false",  # Unverified
                "path": "src/config.py",
                "line": 10,
            }
        ]

        gate = PolicyGate()
        decision = gate.evaluate("pr", findings)

        # Should PASS with warning
        assert decision["decision"] == "pass"
        assert len(decision["warnings"]) == 1

    def test_pr_policy_critical_iac_blocks(self):
        """Test PR policy blocks critical IaC with public exposure"""
        findings = [
            {
                "id": "iac123",
                "category": "IAC",
                "severity": "critical",
                "service_tier": "public",  # Public exposure
                "path": "terraform/security_group.tf",
                "line": 5,
            }
        ]

        gate = PolicyGate()
        decision = gate.evaluate("pr", findings)

        assert decision["decision"] == "fail"
        assert len(decision["blocks"]) == 1

    def test_pr_policy_clean_pass(self):
        """Test PR policy passes with no findings"""
        findings = []

        gate = PolicyGate()
        decision = gate.evaluate("pr", findings)

        assert decision["decision"] == "pass"
        assert len(decision["blocks"]) == 0

    def test_release_policy_requires_sbom(self):
        """Test release policy requires SBOM"""
        findings = []
        metadata = {"sbom_present": False, "signature_verified": True, "provenance_present": True}  # No SBOM

        gate = PolicyGate()
        decision = gate.evaluate("release", findings, metadata)

        assert decision["decision"] == "fail"
        assert "SBOM" in decision["reasons"][0]

    def test_release_policy_requires_signature(self):
        """Test release policy requires signature"""
        findings = []
        metadata = {"sbom_present": True, "signature_verified": False, "provenance_present": True}  # No signature

        gate = PolicyGate()
        decision = gate.evaluate("release", findings, metadata)

        assert decision["decision"] == "fail"
        assert "Signature" in decision["reasons"][0]

    def test_release_policy_clean_pass(self):
        """Test release policy passes with SBOM + signature"""
        findings = []
        metadata = {"sbom_present": True, "signature_verified": True, "provenance_present": True}

        gate = PolicyGate()
        decision = gate.evaluate("release", findings, metadata)

        assert decision["decision"] == "pass"
        assert len(decision["blocks"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
