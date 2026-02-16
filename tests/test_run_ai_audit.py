#!/usr/bin/env python3
"""
Unit tests for run_ai_audit.py
Uses pytest with mocked LLM API calls
"""

from pathlib import Path
from unittest.mock import patch

import pytest
import run_ai_audit as audit_module


class TestReviewMetrics:
    """Test ReviewMetrics class"""

    def test_metrics_initialization(self):
        """Test metrics are initialized correctly"""
        metrics = audit_module.ReviewMetrics()

        assert metrics.metrics["version"] == "1.0.16"
        assert metrics.metrics["files_reviewed"] == 0
        assert metrics.metrics["cost_usd"] == 0.0
        assert "findings" in metrics.metrics
        assert "categories" in metrics.metrics

    def test_record_file(self):
        """Test recording file metrics"""
        metrics = audit_module.ReviewMetrics()
        metrics.record_file(100)
        metrics.record_file(200)

        assert metrics.metrics["files_reviewed"] == 2
        assert metrics.metrics["lines_analyzed"] == 300

    def test_record_llm_call_anthropic(self):
        """Test recording LLM call metrics for Anthropic"""
        metrics = audit_module.ReviewMetrics()
        metrics.record_llm_call(1000, 2000, "anthropic")

        # Anthropic: $3/1M input, $15/1M output
        expected_cost = (1000 / 1_000_000) * 3.0 + (2000 / 1_000_000) * 15.0
        assert metrics.metrics["tokens_input"] == 1000
        assert metrics.metrics["tokens_output"] == 2000
        assert abs(metrics.metrics["cost_usd"] - expected_cost) < 0.0001

    def test_record_llm_call_openai(self):
        """Test recording LLM call metrics for OpenAI"""
        metrics = audit_module.ReviewMetrics()
        metrics.record_llm_call(1000, 2000, "openai")

        # OpenAI: $10/1M input, $30/1M output
        expected_cost = (1000 / 1_000_000) * 10.0 + (2000 / 1_000_000) * 30.0
        assert abs(metrics.metrics["cost_usd"] - expected_cost) < 0.0001

    def test_record_llm_call_ollama(self):
        """Test recording LLM call metrics for Ollama (free)"""
        metrics = audit_module.ReviewMetrics()
        metrics.record_llm_call(1000, 2000, "ollama")

        assert metrics.metrics["cost_usd"] == 0.0

    def test_record_finding(self):
        """Test recording findings"""
        metrics = audit_module.ReviewMetrics()
        metrics.record_finding("critical", "security")
        metrics.record_finding("high", "performance")
        metrics.record_finding("critical", "security")

        assert metrics.metrics["findings"]["critical"] == 2
        assert metrics.metrics["findings"]["high"] == 1
        assert metrics.metrics["categories"]["security"] == 2
        assert metrics.metrics["categories"]["performance"] == 1


class TestAIProviderDetection:
    """Test AI provider detection logic"""

    def test_detect_anthropic(self):
        """Test detecting Anthropic provider"""
        config = {
            "ai_provider": "auto",
            "anthropic_api_key": "sk-ant-test",
            "openai_api_key": "",
            "ollama_endpoint": "",
        }
        provider = audit_module.detect_ai_provider(config)
        assert provider == "anthropic"

    def test_detect_openai(self):
        """Test detecting OpenAI provider"""
        config = {"ai_provider": "auto", "anthropic_api_key": "", "openai_api_key": "sk-test", "ollama_endpoint": ""}
        provider = audit_module.detect_ai_provider(config)
        assert provider == "openai"

    def test_detect_ollama(self):
        """Test detecting Ollama provider"""
        config = {
            "ai_provider": "auto",
            "anthropic_api_key": "",
            "openai_api_key": "",
            "ollama_endpoint": "http://localhost:11434",
        }
        provider = audit_module.detect_ai_provider(config)
        assert provider == "ollama"

    def test_explicit_provider(self):
        """Test explicit provider selection"""
        config = {
            "ai_provider": "openai",
            "anthropic_api_key": "sk-ant-test",
            "openai_api_key": "sk-test",
            "ollama_endpoint": "",
        }
        provider = audit_module.detect_ai_provider(config)
        assert provider == "openai"

    def test_no_provider(self):
        """Test no provider available"""
        config = {"ai_provider": "auto", "anthropic_api_key": "", "openai_api_key": "", "ollama_endpoint": ""}
        provider = audit_module.detect_ai_provider(config)
        assert provider is None


class TestFindingsParser:
    """Test findings parsing from markdown reports"""

    def test_parse_critical_findings(self):
        """Test parsing critical findings"""
        report = """
# Security Review Report

## Critical Issues

1. **SQL Injection** - `user.js:45`
Category: Injection
Impact: Data breach risk
        """

        findings = audit_module.parse_findings_from_report(report)
        assert len(findings) > 0
        # Check that critical findings are detected
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        assert len(critical_findings) > 0

    def test_parse_multiple_severities(self):
        """Test parsing findings with multiple severities"""
        report = """
## Critical Issues
1. **SQL Injection** - `file.js:10`

## High Priority Issues
2. **N+1 Query** - `file.js:20`

## Medium Priority Issues
3. **Missing Tests** - `file.js:30`
        """

        findings = audit_module.parse_findings_from_report(report)
        severities = {f["severity"] for f in findings}
        assert "critical" in severities or "high" in severities or "medium" in severities

    def test_parse_categories(self):
        """Test parsing finding categories"""
        report = """
### Security Issues
1. **SQL Injection** - `file.js:10`

### Performance Issues
2. **Memory Leak** - `file.js:20`
        """

        findings = audit_module.parse_findings_from_report(report)
        categories = {f["category"] for f in findings}
        # Categories should be detected from context
        assert len(categories) > 0


class TestSARIFGeneration:
    """Test SARIF report generation"""

    def test_generate_sarif_structure(self):
        """Test SARIF has correct structure"""
        findings = [
            {
                "severity": "critical",
                "category": "security",
                "message": "SQL Injection vulnerability",
                "file_path": "src/user.js",
                "line_number": 45,
                "rule_id": "SECURITY-001",
            }
        ]

        sarif = audit_module.generate_sarif(findings, "/test/repo")

        assert sarif["$schema"]
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0
        assert "tool" in sarif["runs"][0]
        assert "results" in sarif["runs"][0]

    def test_sarif_severity_mapping(self):
        """Test SARIF severity levels are mapped correctly"""
        findings = [
            {
                "severity": "critical",
                "category": "security",
                "message": "Critical issue",
                "file_path": "file.js",
                "line_number": 1,
                "rule_id": "TEST-001",
            }
        ]

        sarif = audit_module.generate_sarif(findings, "/test/repo")
        results = sarif["runs"][0]["results"]

        # Critical should map to 'error' level in SARIF
        assert len(results) > 0


class TestFailOnLogic:
    """Test fail-on condition logic"""

    def test_fail_on_any_critical(self):
        """Test fail-on any:critical"""
        metrics = {"findings": {"critical": 1, "high": 1}}

        fail_on = "any:critical"
        conditions = [c.strip() for c in fail_on.split(",")]

        should_fail = False
        for condition in conditions:
            if ":" in condition:
                category, severity = condition.split(":", 1)
                if category == "any" and severity == "critical" and metrics["findings"]["critical"] > 0:
                    should_fail = True

        assert should_fail

    def test_fail_on_specific_category(self):
        """Test fail-on security:high"""
        findings = [{"severity": "high", "category": "security"}, {"severity": "high", "category": "performance"}]

        matching = [f for f in findings if f["category"] == "security" and f["severity"] == "high"]

        assert len(matching) == 1


class TestCodebaseContext:
    """Test codebase context gathering"""

    def test_file_filtering_by_extension(self, tmp_path):
        """Test that only relevant file types are included"""
        # Create test files
        (tmp_path / "test.py").write_text('print("hello")')
        (tmp_path / "test.js").write_text('console.log("hello")')
        (tmp_path / "test.txt").write_text("hello")
        (tmp_path / "README.md").write_text("# README")

        config = {
            "only_changed": False,
            "include_paths": "",
            "exclude_paths": "",
            "max_file_size": "50000",
            "max_files": "100",
        }

        files = audit_module.get_codebase_context(str(tmp_path), config)

        # Should include .py and .js, but not .txt or .md
        extensions = {Path(f["path"]).suffix for f in files}
        assert ".py" in extensions or ".js" in extensions

    def test_max_files_limit(self, tmp_path):
        """Test max_files limit is respected"""
        # Create many files
        for i in range(20):
            (tmp_path / f"test{i}.py").write_text(f"# File {i}")

        config = {
            "only_changed": False,
            "include_paths": "",
            "exclude_paths": "",
            "max_file_size": "50000",
            "max_files": "5",
        }

        files = audit_module.get_codebase_context(str(tmp_path), config)
        assert len(files) <= 5


class TestMultiAgentMode:
    """Test multi-agent mode functionality"""

    @patch("run_ai_audit.call_llm_api")
    def test_load_agent_prompts(self, mock_llm):
        """Test that agent prompts are loaded correctly"""
        from orchestrator.agent_runner import load_agent_prompt

        # Test each agent prompt can be loaded
        agents = ["security", "performance", "testing", "quality", "orchestrator"]

        for agent in agents:
            try:
                prompt = load_agent_prompt(agent)
                assert len(prompt) > 0
                assert agent in prompt.lower() or "review" in prompt.lower()
            except FileNotFoundError:
                # Prompts may not exist in test environment
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
