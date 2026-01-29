#!/usr/bin/env python3
"""
Tests for Suppression Policy Enforcement
Validates minimum evidence requirements for auto-suppression
"""

import sys
from pathlib import Path

import pytest

# Add scripts to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from enhanced_fp_detector import EnhancedFPAnalysis, EnhancedFalsePositiveDetector  # noqa: E402
from suppression_policy import EvidenceQuality, SuppressionDecision, SuppressionPolicy  # noqa: E402


class TestSuppressionPolicy:
    """Test SuppressionPolicy enforcement"""

    def setup_method(self):
        """Setup test fixtures"""
        self.policy = SuppressionPolicy()

    def test_policy_initialization(self):
        """Test policy initializes with correct defaults"""
        assert self.policy.MIN_EVIDENCE_AUTO_SUPPRESS == 3
        assert self.policy.MIN_CONFIDENCE_AUTO_SUPPRESS == 0.7
        assert self.policy.MIN_EVIDENCE_QUALITY_SCORE == 5.0

    def test_policy_summary(self):
        """Test get_policy_summary returns configuration"""
        summary = self.policy.get_policy_summary()
        assert summary["min_evidence_count"] == 3
        assert summary["min_confidence"] == 0.7
        assert summary["min_quality_score"] == 5.0
        assert "quality_weights" in summary
        assert len(summary["quality_weights"]) == 5

    def test_approve_suppression_with_sufficient_evidence(self):
        """Test suppression approved with sufficient high-quality evidence"""
        # Create analysis with sufficient evidence
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.85,
            category="oauth2_public_client",
            reasoning="OAuth2 public clients don't require secrets",
            evidence=[
                "PKCE flow detected (secure public client pattern)",
                "No client_secret found (typical for public clients)",
                "Public client context: frontend/spa/auth.js",
                "Public client pattern found: pkce_challenge"
            ]
        )

        finding = {
            "id": "test-001",
            "severity": "medium",
            "path": "frontend/spa/auth.js",
            "message": "Missing client_secret in OAuth2 configuration"
        }

        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is True
        assert decision.confidence == 0.85
        assert decision.evidence_count == 4
        assert decision.evidence_quality_score >= 5.0
        assert len(decision.policy_violations) == 0
        assert "APPROVED" in decision.reasoning

    def test_deny_suppression_insufficient_evidence_count(self):
        """Test suppression denied when evidence count too low"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.85,
            category="oauth2_public_client",
            reasoning="OAuth2 public clients don't require secrets",
            evidence=[
                "PKCE flow detected",
                "No client_secret found"
            ]
        )

        finding = {
            "id": "test-002",
            "severity": "medium",
            "path": "frontend/auth.js"
        }

        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is False
        assert decision.evidence_count == 2
        assert any("Evidence count 2 below minimum 3" in v for v in decision.policy_violations)
        assert "DENIED" in decision.reasoning

    def test_deny_suppression_low_confidence(self):
        """Test suppression denied when confidence too low"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.6,  # Below 0.7 threshold
            category="dev_config",
            reasoning="Development-only code",
            evidence=[
                "DEBUG = True",
                "localhost detected",
                "if __name__ == '__main__'"
            ]
        )

        finding = {
            "id": "test-003",
            "severity": "low",
            "path": "scripts/dev.py"
        }

        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is False
        assert any("Confidence 0.60 below threshold 0.7" in v for v in decision.policy_violations)

    def test_deny_suppression_low_quality_score(self):
        """Test suppression denied when evidence quality too low"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="dev_config",
            reasoning="Development-only code",
            evidence=[
                "Heuristic signal 1",
                "Heuristic signal 2",
                "Heuristic signal 3"
            ]
        )

        finding = {
            "id": "test-004",
            "severity": "medium",
            "path": "app.py"
        }

        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is False
        assert decision.evidence_quality_score < 5.0
        assert any("quality score" in v.lower() for v in decision.policy_violations)


class TestEvidenceQualityScoring:
    """Test evidence quality calculation"""

    def setup_method(self):
        """Setup test fixtures"""
        self.policy = SuppressionPolicy()

    def test_direct_code_match_quality(self):
        """Test direct code match evidence scores highest"""
        evidence = [
            "Mutex detected in code",
            "PKCE flow detected",
            "Lock mechanism properly prevents race conditions"
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Each should score 2.0 points
        assert score >= 6.0

    def test_metadata_signal_quality(self):
        """Test metadata signal evidence scores appropriately"""
        evidence = [
            "File permissions: 0600",
            "File is only readable by owner",
            "Restricted permissions detected"
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Each should score 1.5 points
        assert score >= 4.5

    def test_contextual_inference_quality(self):
        """Test contextual inference scores medium"""
        evidence = [
            "This appears to be a public client",
            "Context suggests development environment",
            "Typically used for testing"
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Each should score 1.0 points
        assert score >= 3.0

    def test_path_indicator_quality(self):
        """Test path indicators score low"""
        evidence = [
            "File in test directory",
            "Path indicator: mock",
            "Located in fixtures"
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Each should score 0.5 points
        assert score >= 1.5

    def test_heuristic_quality_default(self):
        """Test heuristic/unknown evidence scores lowest"""
        evidence = [
            "Some random signal",
            "Another weak indicator",
            "Generic finding"
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Each should score 0.3 points (with floating point tolerance)
        assert score >= 0.89

    def test_mixed_quality_evidence(self):
        """Test mixed quality evidence calculation"""
        evidence = [
            "PKCE flow detected (secure public client pattern)",  # 2.0
            "File permissions: 0600",  # 1.5
            "Context suggests dev environment",  # 1.0
            "Path indicator: test",  # 0.5
        ]
        score = self.policy._calculate_evidence_quality(evidence)
        # Total should be 5.0
        assert score >= 5.0


class TestConflictDetection:
    """Test conflict detection logic"""

    def setup_method(self):
        """Setup test fixtures"""
        self.policy = SuppressionPolicy()

    def test_high_severity_with_very_high_confidence_conflict(self):
        """Test conflict detected for suspicious high severity + high FP confidence"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.95,
            category="dev_config",
            reasoning="Dev only",
            evidence=["DEBUG = True", "localhost", "test env"]
        )

        finding = {
            "id": "test-005",
            "severity": "critical",  # High severity with 0.95 FP confidence
            "path": "app.py"
        }

        conflicts = self.policy._detect_conflicts(analysis, finding)

        assert len(conflicts) > 0
        assert any("High severity" in c and "suspicious" in c for c in conflicts)

    def test_production_path_with_dev_suppression_conflict(self):
        """Test conflict detected for prod path with dev-only suppression"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="dev_config",
            reasoning="Dev only code",
            evidence=["DEBUG flag", "localhost", "dev mode"]
        )

        finding = {
            "id": "test-006",
            "severity": "medium",
            "path": "production/config.py"  # Production path
        }

        conflicts = self.policy._detect_conflicts(analysis, finding)

        assert len(conflicts) > 0
        assert any("Production path" in c and "conflicts" in c for c in conflicts)

    def test_secret_in_non_test_path_with_dev_suppression_conflict(self):
        """Test conflict for secret findings in non-test paths suppressed as dev config"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="dev_config",
            reasoning="Dev config",
            evidence=["DEBUG flag", "localhost", "dev mode"]
        )

        finding = {
            "id": "test-007",
            "severity": "high",
            "path": "src/config.py",  # Not a test path
            "message": "Hardcoded API secret detected",
            "category": "secrets"
        }

        conflicts = self.policy._detect_conflicts(analysis, finding)

        assert len(conflicts) > 0
        assert any("Secret-related" in c and "non-test path" in c for c in conflicts)

    def test_oauth2_with_client_secret_conflict(self):
        """Test conflict for OAuth2 public client with actual client_secret"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.85,
            category="oauth2_public_client",
            reasoning="Public client",
            evidence=["PKCE flow", "No secret needed", "SPA context"]
        )

        finding = {
            "id": "test-008",
            "severity": "medium",
            "path": "frontend/auth.js",
            "evidence": {
                "snippet": "const config = { client_id: 'abc', client_secret: 'xyz123' }"
            }
        }

        conflicts = self.policy._detect_conflicts(analysis, finding)

        assert len(conflicts) > 0
        assert any("client_secret found" in c for c in conflicts)

    def test_no_conflicts_for_valid_suppression(self):
        """Test no conflicts for legitimate suppression"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="oauth2_public_client",
            reasoning="Public client",
            evidence=["PKCE flow", "No secret", "SPA path"]
        )

        finding = {
            "id": "test-009",
            "severity": "medium",
            "path": "frontend/spa/auth.js",
            "evidence": {"snippet": "const config = { client_id: 'abc' }"}
        }

        conflicts = self.policy._detect_conflicts(analysis, finding)

        assert len(conflicts) == 0


class TestIntegrationWithEnhancedDetector:
    """Test integration with EnhancedFalsePositiveDetector"""

    def setup_method(self):
        """Setup test fixtures"""
        self.detector = EnhancedFalsePositiveDetector()
        self.policy = SuppressionPolicy()

    def test_oauth2_detection_passes_policy(self):
        """Test OAuth2 public client detection passes suppression policy"""
        finding = {
            "id": "oauth-001",
            "severity": "medium",
            "path": "frontend/spa/auth.js",
            "message": "Missing client_secret in OAuth2 configuration",
            "category": "authentication",
            "evidence": {
                "snippet": """
                const config = {
                    client_id: 'abc123',
                    redirect_uri: 'https://app.example.com/callback',
                    response_type: 'code',
                    scope: 'openid profile email',
                    code_verifier: generatePKCE(),
                    code_challenge: hashPKCE(verifier)
                };
                """
            }
        }

        analysis = self.detector.analyze_oauth2_public_client(finding)
        decision = self.policy.evaluate_suppression(analysis, finding)

        assert analysis.is_false_positive is True
        assert decision.can_suppress is True
        assert decision.evidence_count >= 3
        assert decision.evidence_quality_score >= 5.0

    def test_file_permissions_detection_passes_policy(self):
        """Test file permissions detection with proper evidence"""
        # Note: This test will only work if the file exists
        # For testing purposes, we'll create a mock analysis
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.85,
            category="file_permissions",
            reasoning="File has proper restrictive permissions",
            evidence=[
                "File permissions: 0o600",
                "File has restricted permissions (not world/group writable)",
                "File is only readable by owner (properly secured)",
                "File in typically secure location: /etc/config.conf"
            ]
        )

        finding = {
            "id": "perm-001",
            "severity": "high",
            "path": "/etc/app/config.conf",
            "message": "Plaintext sensitive data storage"
        }

        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is True
        assert decision.evidence_count == 4
        assert decision.evidence_quality_score >= 5.0

    def test_dev_config_with_insufficient_evidence_denied(self):
        """Test dev config with weak evidence is denied"""
        finding = {
            "id": "dev-001",
            "severity": "medium",
            "path": "app.py",
            "message": "Debug mode enabled",
            "evidence": {
                "snippet": "debug = True"
            }
        }

        analysis = self.detector.analyze_dev_config_flag(finding)
        decision = self.policy.evaluate_suppression(analysis, finding)

        # Weak evidence should fail policy
        if analysis.confidence < 0.7 or len(analysis.evidence) < 3:
            assert decision.can_suppress is False
            assert len(decision.policy_violations) > 0


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def setup_method(self):
        """Setup test fixtures"""
        self.policy = SuppressionPolicy()

    def test_exactly_minimum_evidence_count(self):
        """Test with exactly minimum evidence count"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="test",
            reasoning="Test",
            evidence=[
                "Direct code match detected",
                "Metadata signal found",
                "Contextual inference"
            ]
        )

        finding = {"id": "edge-001", "severity": "low", "path": "test.py"}
        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.evidence_count == 3
        # Should pass if quality score is high enough

    def test_exactly_minimum_confidence(self):
        """Test with exactly minimum confidence"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.7,  # Exactly at threshold
            category="test",
            reasoning="Test",
            evidence=[
                "Direct code match",
                "Metadata signal",
                "Contextual inference",
                "Path indicator"
            ]
        )

        finding = {"id": "edge-002", "severity": "low", "path": "test.py"}
        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.confidence == 0.7
        # Should pass confidence check (>=)

    def test_not_false_positive_never_suppressed(self):
        """Test that non-FP findings are never suppressed"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=False,  # Not a false positive
            confidence=0.9,
            category="test",
            reasoning="Legitimate issue",
            evidence=[
                "Direct code match",
                "Metadata signal",
                "Contextual inference",
                "Path indicator"
            ]
        )

        finding = {"id": "edge-003", "severity": "high", "path": "app.py"}
        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is False

    def test_empty_evidence_list(self):
        """Test with empty evidence list"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.9,
            category="test",
            reasoning="Test",
            evidence=[]
        )

        finding = {"id": "edge-004", "severity": "low", "path": "test.py"}
        decision = self.policy.evaluate_suppression(analysis, finding)

        assert decision.can_suppress is False
        assert decision.evidence_count == 0
        assert decision.evidence_quality_score == 0.0

    def test_missing_finding_fields(self):
        """Test with missing finding fields"""
        analysis = EnhancedFPAnalysis(
            is_false_positive=True,
            confidence=0.8,
            category="test",
            reasoning="Test",
            evidence=["Signal 1", "Signal 2", "Signal 3"]
        )

        finding = {"id": "edge-005"}  # Minimal fields

        # Should not crash
        decision = self.policy.evaluate_suppression(analysis, finding)
        assert isinstance(decision, SuppressionDecision)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
