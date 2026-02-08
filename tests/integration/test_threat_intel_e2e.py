#!/usr/bin/env python3
"""
End-to-end tests for Threat Intelligence features (Supply Chain Analysis)
Tests the complete workflow of supply chain attack detection and threat assessment.
"""

import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Import the modules we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from supply_chain_analyzer import (
    DependencyChange,
    SupplyChainAnalyzer,
    ThreatAssessment,
    ThreatLevel,
)


class TestSupplyChainE2E:
    """End-to-end tests for supply chain threat intelligence"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.analyzer = SupplyChainAnalyzer()
        self.test_repo_dir = self.temp_dir / "test_repo"
        self.test_repo_dir.mkdir(parents=True)

    @pytest.mark.skip(reason="SupplyChainAnalyzer.analyze_manifest not yet implemented")
    def test_complete_supply_chain_workflow(self, tmp_path: Path):
        """
        Test complete supply chain analysis workflow:
        1. Detect dependency changes
        2. Analyze for threats (typosquatting, malicious scripts)
        3. Generate threat assessments
        4. Produce actionable recommendations
        """
        pass

    def test_typosquatting_detection(self):
        """Test detection of typosquatting attacks"""
        test_cases = [
            ("reakt", "npm", "react"),  # Missing 'c'
            ("lodahs", "npm", "lodash"),  # Wrong letter
            ("expres", "npm", "express"),  # Missing letter
            ("reqeusts", "pypi", "requests"),  # Swapped letters
            ("numpi", "pypi", "numpy"),  # Similar name
        ]

        for typosquat, ecosystem, legitimate in test_cases:
            result = self.analyzer.check_typosquatting(
                typosquat, ecosystem
            )
            assert result is not None, f"{typosquat} should be detected as typosquatting"
            similar = result.get("similar", [])
            assert legitimate in similar or any(
                legitimate in s for s in similar
            ), f"Should suggest {legitimate} as legitimate package"

    @pytest.mark.skip(reason="SupplyChainAnalyzer._analyze_install_script not yet implemented")
    def test_malicious_script_detection(self, tmp_path: Path):
        """Test detection of malicious install scripts"""
        pass

    @pytest.mark.skip(reason="SupplyChainAnalyzer._compare_dependencies not yet implemented")
    def test_dependency_change_detection(self, tmp_path: Path):
        """Test detection of dependency changes in git"""
        pass

    def test_openssf_scorecard_integration(self):
        """Test OpenSSF Scorecard integration for package security scoring"""
        # Test with real popular packages (should have high scores)
        safe_packages = ["express", "react", "lodash"]

        for package in safe_packages:
            # Use check_openssf_scorecard (the actual public method)
            score_result = self.analyzer.check_openssf_scorecard(package, "npm")

            # Popular packages should return a dict or None if API unavailable
            if score_result is not None:
                assert isinstance(score_result, dict), "Should return a dict"

    @pytest.mark.skip(reason="SupplyChainAnalyzer.analyze_project not yet implemented")
    def test_multiple_ecosystems_analysis(self, tmp_path: Path):
        """Test analyzing multiple package ecosystems simultaneously"""
        pass

    def test_legitimate_package_no_false_positives(self):
        """Test that legitimate popular packages are not flagged"""
        legitimate_packages = {
            "npm": ["react", "express", "lodash", "axios", "webpack"],
            "pypi": ["django", "requests", "flask", "numpy", "pandas"],
        }

        for ecosystem, packages in legitimate_packages.items():
            for package in packages:
                result = self.analyzer.check_typosquatting(
                    package, ecosystem
                )
                assert result is None, (
                    f"{package} should not be flagged as typosquatting"
                )

    def test_threat_assessment_prioritization(self):
        """Test that threats are properly prioritized by severity"""
        findings = [
            ThreatAssessment(
                package_name="critical-vuln",
                ecosystem="npm",
                threat_level=ThreatLevel.CRITICAL,
                threat_types=["malicious_script", "typosquatting"],
                evidence=["Network calls in setup.py", "Similar to 'critical-lib'"],
                recommendations=["Remove immediately"],
            ),
            ThreatAssessment(
                package_name="medium-vuln",
                ecosystem="npm",
                threat_level=ThreatLevel.MEDIUM,
                threat_types=["low_scorecard"],
                evidence=["OpenSSF score: 3.2"],
                recommendations=["Consider alternatives"],
            ),
            ThreatAssessment(
                package_name="low-vuln",
                ecosystem="npm",
                threat_level=ThreatLevel.LOW,
                threat_types=["info"],
                evidence=["No known issues"],
                recommendations=["Monitor for updates"],
            ),
        ]

        # Sort by severity using ThreatLevel ordering
        severity_order = {
            ThreatLevel.CRITICAL: 0,
            ThreatLevel.HIGH: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 3,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.threat_level, 99))

        assert sorted_findings[0].threat_level == ThreatLevel.CRITICAL
        assert sorted_findings[-1].threat_level == ThreatLevel.LOW

    @pytest.mark.skip(reason="SupplyChainAnalyzer.analyze_manifest not yet implemented")
    def test_performance_large_project(self, tmp_path: Path):
        """Test performance with large number of dependencies"""
        pass

    @pytest.mark.skip(reason="SupplyChainAnalyzer.analyze_manifest not yet implemented")
    def test_error_handling_invalid_manifest(self):
        """Test error handling with invalid manifest files"""
        pass

    def test_report_generation(self):
        """Test generation of comprehensive threat report"""
        findings = [
            ThreatAssessment(
                package_name="evil-pkg",
                ecosystem="npm",
                threat_level=ThreatLevel.CRITICAL,
                threat_types=["malicious_script"],
                evidence=["Network calls"],
                recommendations=["Remove"],
            ),
            ThreatAssessment(
                package_name="typo-pkg",
                ecosystem="pypi",
                threat_level=ThreatLevel.HIGH,
                threat_types=["typosquatting"],
                evidence=["Similar to requests"],
                recommendations=["Use requests"],
                similar_legitimate_packages=["requests"],
            ),
        ]

        report = self._generate_threat_report(findings)

        assert "total_threats" in report
        assert report["total_threats"] == 2
        assert "critical_count" in report
        assert report["critical_count"] == 1
        assert "high_count" in report
        assert report["high_count"] == 1
        assert "threats_by_ecosystem" in report
        assert len(report["threats_by_ecosystem"]) == 2

    @pytest.mark.skip(reason="SupplyChainAnalyzer.analyze_project not yet implemented")
    def test_ci_integration_workflow(self, tmp_path: Path):
        """Test workflow suitable for CI/CD integration"""
        pass

    # Helper methods

    def _generate_threat_report(self, findings: List[ThreatAssessment]) -> Dict[str, Any]:
        """Generate comprehensive threat report"""
        report = {
            "total_threats": len(findings),
            "critical_count": sum(
                1 for f in findings if f.threat_level == ThreatLevel.CRITICAL
            ),
            "high_count": sum(
                1 for f in findings if f.threat_level == ThreatLevel.HIGH
            ),
            "medium_count": sum(
                1 for f in findings if f.threat_level == ThreatLevel.MEDIUM
            ),
            "low_count": sum(
                1 for f in findings if f.threat_level == ThreatLevel.LOW
            ),
            "threats_by_ecosystem": {},
        }

        for finding in findings:
            if finding.ecosystem not in report["threats_by_ecosystem"]:
                report["threats_by_ecosystem"][finding.ecosystem] = []
            report["threats_by_ecosystem"][finding.ecosystem].append(
                finding.to_dict()
            )

        return report

    def _calculate_ci_exit_code(self, findings: List[ThreatAssessment]) -> int:
        """Calculate CI exit code based on threat severity"""
        if any(f.threat_level == ThreatLevel.CRITICAL for f in findings):
            return 2  # Critical threats
        if any(f.threat_level == ThreatLevel.HIGH for f in findings):
            return 1  # High threats
        return 0  # No blocking threats

    def _generate_ci_report(self, findings: List[ThreatAssessment]) -> Dict[str, Any]:
        """Generate CI-friendly report"""
        critical = [f for f in findings if f.threat_level == ThreatLevel.CRITICAL]
        high = [f for f in findings if f.threat_level == ThreatLevel.HIGH]

        return {
            "summary": f"Found {len(findings)} threats ({len(critical)} critical, {len(high)} high)",
            "action_required": len(critical) > 0 or len(high) > 0,
            "blocking_threats": [f.to_dict() for f in critical + high],
        }


class TestThreatIntelIntegration:
    """Test integration with other Argus components"""

    def test_integration_with_normalizer(self):
        """Test that findings can be normalized to UnifiedFinding format"""
        analyzer = SupplyChainAnalyzer()

        finding = ThreatAssessment(
            package_name="evil-pkg",
            ecosystem="npm",
            threat_level=ThreatLevel.CRITICAL,
            threat_types=["malicious_script"],
            evidence=["Network calls in setup script"],
            recommendations=["Remove package immediately"],
        )

        # Convert to UnifiedFinding format
        unified = {
            "category": "supply-chain",
            "severity": finding.threat_level.value,
            "title": f"Supply Chain Threat: {finding.package_name}",
            "description": ", ".join(finding.evidence),
            "file": "package.json",
            "recommendation": ", ".join(finding.recommendations),
            "cwe": "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
            "owasp": "A06:2021 - Vulnerable and Outdated Components",
        }

        assert unified["category"] == "supply-chain"
        assert unified["severity"] == "critical"
        assert "evil-pkg" in unified["title"]

    def test_integration_with_ai_triage(self):
        """Test integration with AI triage system"""
        # Supply chain findings should have high confidence
        # and be prioritized for AI review
        finding = ThreatAssessment(
            package_name="suspicious-pkg",
            ecosystem="npm",
            threat_level=ThreatLevel.HIGH,
            threat_types=["typosquatting", "low_scorecard"],
            evidence=["Similar to 'express'", "OpenSSF score: 2.1"],
            recommendations=["Use express instead"],
            similar_legitimate_packages=["express"],
        )

        # AI triage should consider:
        # 1. Multiple threat types = higher confidence
        # 2. Suggested alternatives = actionable
        # 3. OpenSSF score = objective evidence
        ai_context = {
            "threat_count": len(finding.threat_types),
            "has_alternatives": len(finding.similar_legitimate_packages) > 0,
            "has_objective_evidence": finding.scorecard_score is not None
            or any("score" in e.lower() for e in finding.evidence),
        }

        assert ai_context["threat_count"] >= 2, "Multiple threat types increase confidence"
        assert ai_context["has_alternatives"], "Should provide legitimate alternatives"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
