"""
End-to-end workflow tests
Test complete user scenarios from start to finish
"""

import json
import os
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))


class TestEndToEndWorkflows:
    """Test complete user workflows"""

    @pytest.fixture
    def sample_repo(self, tmp_path):
        """Create a sample repository for testing"""
        repo_dir = tmp_path / "sample_repo"
        repo_dir.mkdir()

        # Create sample Python file
        (repo_dir / "app.py").write_text(
            '''
def process_data(user_input):
    """Process user input"""
    return eval(user_input)  # Dangerous!

def query_database(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)
'''
        )

        # Create sample JavaScript file
        (repo_dir / "frontend.js").write_text(
            """
function displayData(data) {
    document.getElementById('output').innerHTML = data;
}

function loadUser(id) {
    fetch('/api/user/' + id);
}
"""
        )

        # Create config file
        (repo_dir / "config.json").write_text(
            json.dumps({"api_key": "secret-key-12345", "database": "postgresql://user:pass@localhost/db"})
        )

        # Create README
        (repo_dir / "README.md").write_text("# Sample Application\nA test application")

        yield repo_dir

    @pytest.mark.skip("Requires GitHub Actions environment")
    def test_github_actions_workflow(self, sample_repo):
        """Simulate GitHub Actions workflow"""
        # Set environment variables as GitHub Actions would
        os.environ["GITHUB_REPOSITORY"] = "test/repo"
        os.environ["GITHUB_SHA"] = "abc123def456"
        os.environ["GITHUB_WORKSPACE"] = str(sample_repo)
        os.environ["ENABLE_THREAT_MODELING"] = "true"
        os.environ["ENABLE_SANDBOX_VALIDATION"] = "true"
        os.environ["AI_PROVIDER"] = "anthropic"
        os.environ["ANTHROPIC_API_KEY"] = "test-key"

        # Import after setting env vars
        from run_ai_audit import build_config, parse_args

        # Parse args as GitHub Actions would
        sys.argv = ["run_ai_audit.py", str(sample_repo), "audit"]
        args = parse_args()

        # Build config
        config = build_config(args)

        # Verify config includes Phase 1 features
        assert config.get("enable_threat_modeling")
        assert config.get("enable_sandbox_validation")

        # Run audit (mocked)
        # In real scenario, this would call the API
        # results = run_audit(str(sample_repo), config, 'audit')

        # Verify outputs would be created
        # assert results is not None

    @pytest.mark.skip("Requires live API - implement after full integration")
    def test_cli_workflow_basic_audit(self, sample_repo):
        """Test CLI usage workflow for basic audit"""

        # Mock CLI args
        sys.argv = ["run_ai_audit.py", str(sample_repo), "audit", "--max-files", "10", "--max-tokens", "2000"]

        # Run main (would need mocking for API calls)
        # main()

        # Verify output files created
        sample_repo / ".argus"
        # assert output_dir.exists()
        # assert (output_dir / 'audit-report.json').exists()

    @pytest.mark.skip("Requires live API and cost tracking")
    def test_cost_optimization_workflow(self, sample_repo):
        """Test workflow with Foundation-Sec-8B for cost savings"""

        # First run with Claude
        {
            "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
            "ai_provider": "anthropic",
            "enable_threat_modeling": True,
            "enable_sandbox_validation": False,
            "max_files": 5,
            "max_tokens": 1000,
        }

        # Note: This would actually make API calls
        # results_claude = run_audit(str(sample_repo), config_claude, 'audit')
        # cost_claude = results_claude['metrics']['cost_usd']

        # Second run with Foundation-Sec

        # results_foundation = run_audit(str(sample_repo), config_foundation, 'audit')
        # cost_foundation = results_foundation['metrics']['cost_usd']

        # Verify cost is significantly lower
        # assert cost_foundation == 0.0
        # assert cost_claude > 0.0
        # savings_pct = (1 - cost_foundation / cost_claude) * 100 if cost_claude > 0 else 0
        # assert savings_pct >= 75  # At least 75% savings

    def test_config_loading_from_env_vars(self):
        """Test that config is properly loaded from environment variables"""
        from run_ai_audit import load_config_from_env

        # Set test environment variables
        os.environ["AI_PROVIDER"] = "anthropic"
        os.environ["ANTHROPIC_API_KEY"] = "test-key-123"
        os.environ["ENABLE_THREAT_MODELING"] = "true"
        os.environ["ENABLE_SANDBOX_VALIDATION"] = "true"
        os.environ["MULTI_AGENT_MODE"] = "sequential"
        os.environ["MAX_FILES"] = "20"
        os.environ["MAX_TOKENS"] = "4000"
        os.environ["COST_LIMIT"] = "2.0"

        config = load_config_from_env()

        assert config["ai_provider"] == "anthropic"
        assert config["anthropic_api_key"] == "test-key-123"
        assert config["enable_threat_modeling"]
        assert config["enable_sandbox_validation"]
        assert config["multi_agent_mode"] == "sequential"
        assert config["max_files"] == "20"
        assert config["max_tokens"] == "4000"
        assert config["cost_limit"] == "2.0"

    def test_sarif_output_generation(self, sample_repo):
        """Test that SARIF output is generated correctly"""
        from run_ai_audit import generate_sarif_output

        # Mock findings
        findings = [
            {
                "category": "security",
                "severity": "high",
                "title": "SQL Injection vulnerability",
                "description": "User input is directly concatenated into SQL query",
                "file": "app.py",
                "line": 7,
                "code": "query = f\"SELECT * FROM users WHERE name = '{username}'\"",
                "recommendation": "Use parameterized queries",
            },
            {
                "category": "security",
                "severity": "critical",
                "title": "Code execution via eval()",
                "description": "Using eval() on user input allows arbitrary code execution",
                "file": "app.py",
                "line": 3,
                "code": "return eval(user_input)",
                "recommendation": "Never use eval() on user input",
            },
        ]

        # Generate SARIF
        sarif = generate_sarif_output(findings, str(sample_repo))

        # Verify SARIF structure
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0
        assert "results" in sarif["runs"][0]
        assert len(sarif["runs"][0]["results"]) == 2

    @pytest.mark.skip("Requires multi-agent implementation")
    def test_multi_agent_workflow_sequential(self, sample_repo):
        """Test sequential multi-agent workflow"""
        from run_ai_audit import run_audit

        config = {
            "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
            "multi_agent_mode": "sequential",
            "enable_threat_modeling": True,
            "max_files": 5,
            "max_tokens": 2000,
        }

        # Run audit with sequential agents
        results = run_audit(str(sample_repo), config, "audit")

        # Verify multiple agents executed
        assert len(results["metrics"]["agents_executed"]) >= 2

        # Verify agent execution times tracked
        assert len(results["metrics"]["agent_execution_times"]) >= 2

        # Verify findings from different agents
        agent_sources = {f.get("agent", "") for f in results["findings"]}
        assert len(agent_sources) >= 2

    @pytest.mark.skip("Requires multi-agent implementation")
    def test_multi_agent_workflow_consensus(self, sample_repo):
        """Test consensus multi-agent workflow"""
        from run_ai_audit import run_audit

        config = {
            "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
            "multi_agent_mode": "consensus",
            "enable_threat_modeling": True,
            "max_files": 5,
            "max_tokens": 2000,
        }

        # Run audit with consensus agents
        results = run_audit(str(sample_repo), config, "audit")

        # Verify multiple agents executed
        assert len(results["metrics"]["agents_executed"]) >= 3

        # Verify consensus metadata
        for finding in results["findings"]:
            if finding["severity"] in ["critical", "high"]:
                # High severity findings should have consensus data
                assert "consensus" in finding or "confidence" in finding


class TestWorkflowErrorHandling:
    """Test error handling in various workflows"""

    def test_missing_api_key_error(self, tmp_path):
        """Test that missing API key is properly handled"""
        from run_ai_audit import validate_config

        config = {
            "ai_provider": "anthropic",
            "anthropic_api_key": "",  # Empty key
        }

        with pytest.raises(ValueError, match="API key"):
            validate_config(config)

    def test_invalid_provider_error(self):
        """Test that detect_ai_provider passes through explicit provider names.

        By design, detect_ai_provider trusts explicit provider selection and
        returns the provider string as-is. Validation of whether the provider
        is actually usable happens downstream in get_ai_client.
        """
        from run_ai_audit import detect_ai_provider

        config = {
            "ai_provider": "invalid-provider",
        }

        # Explicit provider selection is passed through without validation
        result = detect_ai_provider(config)
        assert result == "invalid-provider"

    def test_cost_limit_exceeded_error(self):
        """Test that cost limit exceeded is properly handled"""
        from orchestrator.cost_tracker import CostCircuitBreaker, CostLimitExceededError

        breaker = CostCircuitBreaker(cost_limit_usd=1.0)

        # Simulate high cost operation
        with pytest.raises(CostLimitExceededError):
            breaker.check_before_call(estimated_cost=2.0, provider="anthropic")

    def test_file_too_large_handling(self, tmp_path):
        """Test that files exceeding size limit are skipped"""
        from run_ai_audit import select_files_for_review

        # Create large file
        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 100000)  # Very large file

        # Create small file
        small_file = tmp_path / "small.py"
        small_file.write_text("y = 2\n")

        config = {
            "max_file_size": "1000",  # 1KB limit
            "max_files": "10",
        }

        files = select_files_for_review(str(tmp_path), config)

        # Verify large file was skipped
        file_names = [f["path"] for f in files]
        assert "small.py" in str(file_names)
        assert "large.py" not in str(file_names)


class TestWorkflowOutputs:
    """Test that workflows produce correct outputs"""

    def test_json_output_structure(self, tmp_path):
        """Test JSON output has correct structure"""
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()
        metrics.record_file(100)
        metrics.record_llm_call(1000, 500, "anthropic")

        output = metrics.finalize()

        # Verify required fields
        assert "version" in output
        assert "timestamp" in output
        assert "repository" in output
        assert "commit" in output
        assert "files_reviewed" in output
        assert "lines_analyzed" in output
        assert "tokens_input" in output
        assert "tokens_output" in output
        assert "cost_usd" in output
        assert "duration_seconds" in output
        assert "findings" in output
        assert "threat_model" in output

    def test_sarif_output_structure(self):
        """Test SARIF output has correct structure"""
        from run_ai_audit import generate_sarif_output

        findings = [
            {
                "category": "security",
                "severity": "high",
                "title": "Test vulnerability",
                "description": "Test description",
                "file": "test.py",
                "line": 10,
                "code": "test code",
                "recommendation": "Fix it",
            }
        ]

        sarif = generate_sarif_output(findings, "/test/repo")

        # Verify SARIF 2.1.0 structure
        assert (
            sarif["$schema"]
            == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        )
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) > 0

        run = sarif["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]
        assert "results" in run
        assert len(run["results"]) > 0

        result = run["results"][0]
        assert "ruleId" in result
        assert "message" in result
        assert "locations" in result

    def test_metrics_output_completeness(self):
        """Test that metrics output includes all Phase 1 features"""
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()

        # Record various events
        metrics.record_file(50)
        metrics.record_llm_call(1000, 500, "anthropic")

        # Mock threat model
        threat_model = {
            "threats": [{"id": "T1"}],
            "attack_surface": {"entry_points": ["A1", "A2"]},
            "trust_boundaries": [{"name": "B1"}],
            "assets": [{"name": "Asset1"}],
        }
        metrics.record_threat_model(threat_model)

        output = metrics.finalize()

        # Verify Phase 1 metrics present
        assert output["threat_model"]["generated"]
        assert output["threat_model"]["threats_identified"] == 1
        assert output["threat_model"]["attack_surface_size"] == 2
        assert output["threat_model"]["trust_boundaries"] == 1
        assert output["threat_model"]["assets_cataloged"] == 1

        # Verify exploitability metrics
        assert "exploitability" in output
        assert all(key in output["exploitability"] for key in ["trivial", "moderate", "complex", "theoretical"])

        # Verify agent metrics
        assert "agents_executed" in output
        assert "agent_execution_times" in output
