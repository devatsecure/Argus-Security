#!/usr/bin/env python3
"""
Integration tests for DAST Phase 1 MVP
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from dast_orchestrator import DASTOrchestrator, OrchestratorConfig
from agents.nuclei_agent import NucleiAgent, NucleiConfig
from agents.zap_agent import ZAPAgent, ZAPConfig, ScanProfile
from sast_dast_correlation_v2 import SASTDASTCorrelator, CorrelationRule


class TestNucleiAgent(unittest.TestCase):
    """Test Nuclei agent"""
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        config = NucleiConfig(
            severity=["critical", "high"],
            rate_limit=200,
        )
        agent = NucleiAgent(config=config)
        
        self.assertEqual(agent.config.rate_limit, 200)
        self.assertEqual(agent.config.severity, ["critical", "high"])
    
    def test_tech_stack_detection(self):
        """Test tech stack detection"""
        # Create temporary Django project structure
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            (tmppath / "manage.py").touch()
            (tmppath / "settings.py").touch()
            
            agent = NucleiAgent(project_path=str(tmppath))
            
            # Should detect Django
            detected_names = [s.name for s in agent.detected_stack]
            self.assertIn("Django", detected_names)
    
    def test_template_list_building(self):
        """Test intelligent template selection"""
        agent = NucleiAgent()
        templates = agent._build_template_list()
        
        # Should include core templates
        self.assertIn("cves/", templates)
        self.assertIn("vulnerabilities/", templates)
        self.assertIn("misconfiguration/", templates)
    
    @patch("subprocess.run")
    def test_scan_execution(self, mock_run):
        """Test scan execution"""
        # Mock Nuclei output
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"template-id":"test-001","info":{"name":"Test","severity":"high"},"matched-at":"https://example.com"}\n',
        )
        
        agent = NucleiAgent()
        result = agent.scan(targets=["https://example.com"])
        
        self.assertEqual(result["agent"], "nuclei")
        self.assertGreaterEqual(result["total_findings"], 0)
        self.assertIn("findings", result)


class TestZAPAgent(unittest.TestCase):
    """Test ZAP agent"""
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        config = ZAPConfig(
            profile=ScanProfile.BALANCED,
            spider_max_depth=5,
        )
        agent = ZAPAgent(config=config)
        
        self.assertEqual(agent.config.profile, ScanProfile.BALANCED)
        self.assertEqual(agent.config.spider_max_depth, 5)
    
    def test_zap_output_parsing(self):
        """Test ZAP JSON output parsing"""
        agent = ZAPAgent()
        
        # Mock ZAP output
        zap_data = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "SQL Injection",
                            "riskdesc": "High (Medium)",
                            "confidence": "High",
                            "url": "https://example.com",
                            "cweid": 89,
                            "instances": [
                                {
                                    "uri": "https://example.com/api/users?id=1",
                                    "method": "GET",
                                    "param": "id",
                                    "attack": "1' OR '1'='1",
                                    "evidence": "SQL syntax error",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        
        findings = agent._parse_zap_output(zap_data)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["alert"], "SQL Injection")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["cwe_id"], 89)


class TestDASTOrchestrator(unittest.TestCase):
    """Test DAST orchestrator"""
    
    def test_orchestrator_initialization(self):
        """Test orchestrator initialization"""
        config = OrchestratorConfig(
            parallel_agents=True,
            enable_nuclei=True,
            enable_zap=True,
        )
        orchestrator = DASTOrchestrator(config=config)
        
        self.assertTrue(orchestrator.config.parallel_agents)
        self.assertIsNotNone(orchestrator.nuclei_agent)
        self.assertIsNotNone(orchestrator.zap_agent)
    
    def test_findings_aggregation(self):
        """Test findings aggregation"""
        orchestrator = DASTOrchestrator()
        
        nuclei_results = {
            "findings": [
                {"severity": "high", "name": "SQLi", "matched_at": "https://example.com"}
            ]
        }
        
        zap_results = {
            "findings": [
                {"severity": "medium", "alert": "XSS", "url": "https://example.com"}
            ]
        }
        
        aggregated = orchestrator._aggregate_findings(nuclei_results, zap_results)
        
        self.assertEqual(len(aggregated), 2)
        self.assertEqual(aggregated[0]["source"], "nuclei")
        self.assertEqual(aggregated[1]["source"], "zap")
    
    def test_deduplication(self):
        """Test finding deduplication"""
        orchestrator = DASTOrchestrator()
        
        findings = [
            {"name": "SQLi", "url": "https://example.com", "severity": "high"},
            {"name": "SQLi", "url": "https://example.com", "severity": "high"},  # Duplicate
            {"name": "XSS", "url": "https://example.com", "severity": "medium"},
        ]
        
        deduplicated = orchestrator._deduplicate_findings(findings)
        
        self.assertEqual(len(deduplicated), 2)


class TestCorrelation(unittest.TestCase):
    """Test SAST-DAST correlation"""
    
    def test_correlation_rules(self):
        """Test correlation rules"""
        correlator = SASTDASTCorrelator()
        
        # Should have default rules
        self.assertGreater(len(correlator.rules), 0)
        
        # Check SQL injection rule exists
        sqli_rules = [r for r in correlator.rules if r.vuln_type == "SQL Injection"]
        self.assertEqual(len(sqli_rules), 1)
    
    def test_pattern_matching(self):
        """Test pattern matching"""
        correlator = SASTDASTCorrelator()
        
        finding = {
            "rule_id": "python.sql-injection",
            "name": "SQL Injection vulnerability",
        }
        
        patterns = [r".*sql.*injection.*"]
        
        match_strength = correlator._matches_patterns(finding, patterns)
        self.assertEqual(match_strength, 1.0)
    
    def test_correlation_execution(self):
        """Test correlation execution"""
        correlator = SASTDASTCorrelator(confidence_threshold=0.7)
        
        sast_findings = [
            {
                "id": "sast-001",
                "rule_id": "python.sql-injection",
                "severity": "high",
                "path": "api/users.py",
                "line": 42,
            }
        ]
        
        dast_findings = [
            {
                "id": "dast-001",
                "name": "SQL Injection",
                "severity": "high",
                "url": "https://example.com/api/users",
                "confidence": "high",
            }
        ]
        
        result = correlator.correlate(sast_findings, dast_findings)
        
        self.assertIn("correlated_findings", result)
        self.assertIn("stats", result)
        self.assertGreaterEqual(result["stats"]["total_sast"], 1)
        self.assertGreaterEqual(result["stats"]["total_dast"], 1)
    
    def test_severity_upgrade(self):
        """Test severity upgrade for correlated findings"""
        rule = CorrelationRule(
            vuln_type="SQL Injection",
            sast_patterns=[r".*sql.*injection.*"],
            dast_patterns=[r".*sql.*injection.*"],
            confidence_boost=0.9,
            severity_upgrade="critical",
        )
        
        self.assertEqual(rule.severity_upgrade, "critical")
        self.assertEqual(rule.confidence_boost, 0.9)


class TestConfiguration(unittest.TestCase):
    """Test configuration system"""
    
    def test_nuclei_config(self):
        """Test Nuclei configuration"""
        config = NucleiConfig(
            severity=["critical", "high"],
            rate_limit=200,
            concurrency=30,
            max_duration=600,
        )
        
        self.assertEqual(config.severity, ["critical", "high"])
        self.assertEqual(config.rate_limit, 200)
        self.assertEqual(config.concurrency, 30)
        self.assertEqual(config.max_duration, 600)
    
    def test_zap_config(self):
        """Test ZAP configuration"""
        config = ZAPConfig(
            profile=ScanProfile.COMPREHENSIVE,
            spider_max_depth=5,
            ajax_spider=True,
            active_scan=True,
        )
        
        self.assertEqual(config.profile, ScanProfile.COMPREHENSIVE)
        self.assertEqual(config.spider_max_depth, 5)
        self.assertTrue(config.ajax_spider)
        self.assertTrue(config.active_scan)
    
    def test_orchestrator_config(self):
        """Test orchestrator configuration"""
        config = OrchestratorConfig(
            max_duration=900,
            parallel_agents=True,
            enable_nuclei=True,
            enable_zap=True,
            enable_correlation=True,
        )
        
        self.assertEqual(config.max_duration, 900)
        self.assertTrue(config.parallel_agents)
        self.assertTrue(config.enable_nuclei)
        self.assertTrue(config.enable_zap)
        self.assertTrue(config.enable_correlation)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestNucleiAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestZAPAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestDASTOrchestrator))
    suite.addTests(loader.loadTestsFromTestCase(TestCorrelation))
    suite.addTests(loader.loadTestsFromTestCase(TestConfiguration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
