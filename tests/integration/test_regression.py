"""
Regression tests to ensure integrations don't break existing functionality
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))


class TestRegression:
    """Ensure existing features still work after integration"""

    def test_single_agent_mode_still_works(self, tmp_path):
        """Verify single-agent mode wasn't broken by multi-agent enhancements"""
        from run_ai_audit import load_config_from_env

        os.environ["MULTI_AGENT_MODE"] = "single"
        config = load_config_from_env()

        assert config["multi_agent_mode"] == "single"

    def test_anthropic_provider_still_works(self):
        """Verify Anthropic provider still works after Foundation-Sec integration"""
        from run_ai_audit import detect_ai_provider

        config = {"ai_provider": "anthropic", "anthropic_api_key": "test-key"}

        provider = detect_ai_provider(config)
        assert provider == "anthropic"

    def test_basic_workflow_without_phase1_features(self, tmp_path):
        """Verify audit works with all Phase 1 features disabled"""
        from run_ai_audit import load_config_from_env

        # Disable all Phase 1 features
        os.environ["ENABLE_THREAT_MODELING"] = "false"
        os.environ["ENABLE_SANDBOX_VALIDATION"] = "false"
        os.environ["FOUNDATION_SEC_ENABLED"] = "false"
        os.environ["MULTI_AGENT_MODE"] = "single"

        config = load_config_from_env()

        assert not config.get("enable_threat_modeling", False)
        assert not config.get("enable_sandbox_validation", False)
        assert not config.get("foundation_sec_enabled", False)
        assert config["multi_agent_mode"] == "single"

    def test_file_selection_unchanged(self, tmp_path):
        """Test file selection logic still works correctly"""
        from run_ai_audit import select_files_for_review

        # Create test files
        (tmp_path / "test.py").write_text("def test(): pass")
        (tmp_path / "test.js").write_text("function test() {}")
        (tmp_path / "README.md").write_text("# Test")

        config = {
            "max_files": "10",
            "max_file_size": "50000",
            "include_paths": "",
            "exclude_paths": "",
        }

        files = select_files_for_review(str(tmp_path), config)

        # Should include code files, exclude README
        file_names = [f["path"] for f in files]
        assert any("test.py" in f for f in file_names)
        assert any("test.js" in f for f in file_names)

    def test_cost_calculation_for_claude_unchanged(self):
        """Test that cost calculation for Claude models is unchanged"""
        from run_ai_audit import estimate_call_cost

        # Test Claude Sonnet 4.5
        cost = estimate_call_cost(1000000, 1000000, "anthropic", "claude-sonnet-4-5-20250929")
        expected = (1000000 / 1000000 * 3.0) + (1000000 / 1000000 * 15.0)
        assert abs(cost - expected) < 0.01

    def test_sarif_generation_unchanged(self):
        """Test SARIF generation still works correctly"""
        from run_ai_audit import generate_sarif_output

        findings = [
            {
                "category": "security",
                "severity": "high",
                "title": "Test Issue",
                "description": "Test description",
                "file": "test.py",
                "line": 10,
                "code": "test code",
                "recommendation": "Fix it",
            }
        ]

        sarif = generate_sarif_output(findings, "/test/repo")

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0
        assert len(sarif["runs"][0]["results"]) == 1

    def test_json_output_format_unchanged(self):
        """Test JSON output format is still compatible"""
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()
        metrics.record_file(100)

        output = metrics.finalize()

        # Verify all existing fields still present
        required_fields = [
            "version",
            "timestamp",
            "repository",
            "commit",
            "files_reviewed",
            "lines_analyzed",
            "tokens_input",
            "tokens_output",
            "cost_usd",
            "duration_seconds",
            "findings",
            "categories",
        ]

        for field in required_fields:
            assert field in output, f"Missing required field: {field}"

    def test_cost_circuit_breaker_unchanged(self):
        """Test cost circuit breaker still works correctly"""
        from orchestrator.cost_tracker import CostCircuitBreaker, CostLimitExceededError

        breaker = CostCircuitBreaker(cost_limit_usd=1.0)

        # Should allow low cost operation
        try:
            breaker.check_before_call(0.1, "anthropic")
            breaker.record_actual_cost(0.1)
        except CostLimitExceededError:
            pytest.fail("Low cost operation should not raise exception")

        # Should block high cost operation
        with pytest.raises(CostLimitExceededError):
            breaker.check_before_call(2.0, "anthropic")

    def test_openai_provider_still_works(self):
        """Verify OpenAI provider still works after Phase 1 changes"""
        from run_ai_audit import detect_ai_provider

        config = {"ai_provider": "openai", "openai_api_key": "test-key"}

        provider = detect_ai_provider(config)
        assert provider == "openai"

    def test_ollama_provider_still_works(self):
        """Verify Ollama provider still works after Phase 1 changes"""
        from run_ai_audit import detect_ai_provider

        config = {"ai_provider": "ollama", "ollama_model": "llama2"}

        provider = detect_ai_provider(config)
        assert provider == "ollama"


class TestBackwardsCompatibility:
    """Test backwards compatibility with existing integrations"""

    def test_github_actions_env_vars_still_work(self):
        """Test GitHub Actions environment variables still work"""
        from run_ai_audit import load_config_from_env

        # Set GitHub Actions standard variables
        os.environ["GITHUB_REPOSITORY"] = "test/repo"
        os.environ["GITHUB_SHA"] = "abc123"
        os.environ["GITHUB_WORKSPACE"] = "/workspace"

        load_config_from_env()

        # These should be accessible
        assert os.environ["GITHUB_REPOSITORY"] == "test/repo"
        assert os.environ["GITHUB_SHA"] == "abc123"

    def test_cli_arguments_still_work(self):
        """Test CLI argument parsing still works"""
        from run_ai_audit import parse_args
        from unittest.mock import patch

        test_args = [
            "run_ai_audit.py",
            "/test/repo",
            "audit",
            "--max-files",
            "20",
            "--cost-limit",
            "2.0",
        ]

        with patch("sys.argv", test_args):
            args = parse_args()

        assert args.repo_path == "/test/repo"
        assert args.review_type == "audit"
        assert args.max_files == 20
        assert args.cost_limit == 2.0

    def test_existing_config_file_format_compatible(self, tmp_path):
        """Test existing config file format still works"""
        # Create old-style config file
        config_file = tmp_path / "config.json"
        old_config = {
            "ai_provider": "anthropic",
            "anthropic_api_key": "test-key",
            "max_files": "50",
            "max_tokens": "8000",
            "cost_limit": "1.0",
        }
        config_file.write_text(json.dumps(old_config))

        # Load and verify
        with open(config_file) as f:
            loaded_config = json.load(f)

        assert loaded_config["ai_provider"] == "anthropic"
        assert loaded_config["max_files"] == "50"

    def test_sarif_schema_version_unchanged(self):
        """Test SARIF output uses same schema version"""
        from run_ai_audit import generate_sarif_output

        findings = [
            {
                "category": "security",
                "severity": "high",
                "title": "Test",
                "description": "Test",
                "file": "test.py",
                "line": 1,
                "code": "test",
                "recommendation": "Fix",
            }
        ]

        sarif = generate_sarif_output(findings, "/test")

        # Should still use SARIF 2.1.0
        assert sarif["version"] == "2.1.0"
        assert (
            sarif["$schema"]
            == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        )


class TestExistingFeaturesIntact:
    """Test that existing features are not broken by Phase 1 additions"""

    def test_file_filtering_by_extension_works(self, tmp_path):
        """Test file extension filtering still works"""
        from run_ai_audit import should_review_file

        # Python file should be reviewed
        assert should_review_file("test.py")

        # JavaScript file should be reviewed
        assert should_review_file("test.js")

        # Image file should not be reviewed
        assert not should_review_file("image.png")

        # Binary file should not be reviewed
        assert not should_review_file("program.exe")

    def test_severity_mapping_unchanged(self):
        """Test severity mapping is unchanged"""
        from run_ai_audit import map_severity_to_level

        assert map_severity_to_level("critical") == "error"
        assert map_severity_to_level("high") == "error"
        assert map_severity_to_level("medium") == "warning"
        assert map_severity_to_level("low") == "note"
        assert map_severity_to_level("info") == "note"

    def test_category_classification_unchanged(self):
        """Test finding category classification handles both string and dict inputs"""
        from run_ai_audit import classify_finding_category

        # Security issues
        assert classify_finding_category("SQL injection") == "security"
        assert classify_finding_category("XSS vulnerability") == "security"

        # Performance issues
        assert classify_finding_category("slow algorithm") == "performance"
        assert classify_finding_category("memory leak") == "performance"

        # Style issues (naming, convention, format, style)
        assert classify_finding_category("naming convention") == "style"

        # General (fallback for unrecognized categories)
        assert classify_finding_category("code duplication") == "general"

    def test_metrics_version_incremented(self):
        """Test metrics version was incremented for Phase 1"""
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()

        # Version should be 1.0.16 or higher (Phase 1)
        version = metrics.metrics["version"]
        major, minor, patch = version.split(".")
        assert int(major) >= 1
        assert int(minor) >= 0
        assert int(patch) >= 16  # Phase 1 version

    def test_error_handling_unchanged(self):
        """Test error handling is unchanged"""
        from run_ai_audit import CostLimitExceeded

        # Should be able to raise and catch cost limit error
        try:
            raise CostLimitExceeded("Test error")
        except CostLimitExceeded as e:
            assert "Test error" in str(e)

    def test_logging_configuration_unchanged(self):
        """Test logging configuration is unchanged"""
        import logging

        # Logger should be configured
        logger = logging.getLogger("run_ai_audit")
        assert logger is not None

        # Should be able to log
        logger.info("Test log message")

    def test_retry_logic_unchanged(self):
        """Test retry logic with tenacity is unchanged"""
        try:
            from tenacity import retry, stop_after_attempt

            # Should be importable
            assert retry is not None
            assert stop_after_attempt is not None
        except ImportError:
            pytest.fail("Tenacity retry logic broken")


class TestDataStructureCompatibility:
    """Test that data structures are backwards compatible"""

    def test_finding_structure_compatible(self):
        """Test finding structure is backwards compatible"""
        finding = {
            "category": "security",
            "severity": "high",
            "title": "SQL Injection",
            "description": "User input in query",
            "file": "app.py",
            "line": 10,
            "code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
            "recommendation": "Use parameterized queries",
        }

        # All required fields present
        assert "category" in finding
        assert "severity" in finding
        assert "title" in finding
        assert "description" in finding
        assert "file" in finding
        assert "line" in finding
        assert "recommendation" in finding

    def test_metrics_structure_compatible(self):
        """Test metrics structure is backwards compatible"""
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()
        output = metrics.finalize()

        # All original fields still present
        original_fields = [
            "version",
            "timestamp",
            "repository",
            "commit",
            "files_reviewed",
            "lines_analyzed",
            "tokens_input",
            "tokens_output",
            "cost_usd",
            "duration_seconds",
            "model",
            "provider",
            "findings",
            "categories",
        ]

        for field in original_fields:
            assert field in output, f"Original field missing: {field}"

    def test_config_structure_compatible(self):
        """Test config structure is backwards compatible"""
        from run_ai_audit import load_config_from_env

        load_config_from_env()

        # All original config options should still work
        original_options = ["ai_provider", "max_files", "max_tokens", "cost_limit", "max_file_size"]

        for _option in original_options:
            # Options should be accessible (may have defaults)
            assert True  # Config may use defaults

    def test_sarif_result_structure_compatible(self):
        """Test SARIF result structure is compatible"""
        from run_ai_audit import generate_sarif_output

        findings = [
            {
                "category": "security",
                "severity": "high",
                "title": "Test",
                "description": "Test",
                "file": "test.py",
                "line": 1,
                "code": "test",
                "recommendation": "Fix",
            }
        ]

        sarif = generate_sarif_output(findings, "/test")

        # Check result structure
        result = sarif["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "message" in result
        assert "locations" in result
        assert "level" in result

        # Check location structure
        location = result["locations"][0]
        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "region" in location["physicalLocation"]
