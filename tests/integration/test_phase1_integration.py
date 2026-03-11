"""
Integration tests for Phase 1 features
Tests that modules work together in actual execution flow.

NOTE: Fixtures that write vulnerable code to disk (e.g. sql_injection.py, xss_vuln.js)
are for scanner tests only. That content is vulnerable-by-design and must never
be executed with untrusted input. When adding or changing such fixtures, keep this in mind.
"""

import os
import sys
from pathlib import Path

import pytest

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from run_ai_audit import ReviewMetrics, detect_ai_provider, estimate_call_cost  # noqa: E402


class TestPhase1Integration:
    """Integration tests for Phase 1 complete workflow"""

    @pytest.fixture
    def sample_vulnerable_repo(self, tmp_path):
        """Create a temporary repo with known vulnerabilities for testing.

        Content written to disk is vulnerable-by-design for scanners only;
        do not execute with untrusted input.
        """
        repo_dir = tmp_path / "vulnerable_repo"
        repo_dir.mkdir()

        # Create SQL injection vulnerability
        (repo_dir / "sql_injection.py").write_text(
            """
def search_users(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return execute_query(query)

def login(username, password):
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    return db.execute(query)
"""
        )

        # Create XSS vulnerability
        (repo_dir / "xss_vuln.js").write_text(
            """
function displayMessage(userMessage) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userMessage;
}

function showAlert(msg) {
    document.write(msg);
}
"""
        )

        # Create command injection vulnerability
        (repo_dir / "command_injection.py").write_text(
            """
import os
import subprocess

def ping_host(hostname):
    # Command injection vulnerability
    os.system(f"ping -c 1 {hostname}")

def run_script(script_name):
    subprocess.call("bash " + script_name, shell=True)
"""
        )

        # Create safe file
        (repo_dir / "safe.py").write_text(
            '''
def safe_function(data):
    """This function is safe"""
    return data.strip().lower()
'''
        )

        # Create README
        (repo_dir / "README.md").write_text("# Test Repository\nA test project for security scanning")

        yield repo_dir

    @pytest.fixture
    def mock_api_key(self):
        """Provide test API key"""
        return os.getenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")

    def test_foundation_sec_provider_detection(self):
        """Test Foundation-Sec-8B provider is detected when enabled"""
        config = {"ai_provider": "foundation-sec", "foundation_sec_enabled": True}
        provider = detect_ai_provider(config)
        assert provider == "foundation-sec"

    def test_anthropic_provider_detection(self):
        """Test Anthropic provider is detected by default"""
        config = {"ai_provider": "anthropic", "anthropic_api_key": "test-key"}
        provider = detect_ai_provider(config)
        assert provider == "anthropic"

    def test_foundation_sec_cost_is_zero(self):
        """Verify Foundation-Sec-8B costs $0"""
        # Test with various token counts
        cost = estimate_call_cost(1000, 500, "foundation-sec")
        assert cost == 0.0

        cost = estimate_call_cost(100000, 50000, "foundation-sec")
        assert cost == 0.0

    def test_anthropic_cost_calculation(self):
        """Verify Anthropic cost is calculated correctly"""
        # Claude Sonnet 4.5 pricing: $3/$15 per million tokens
        cost = estimate_call_cost(1000000, 1000000, "anthropic", model="claude-sonnet-4-5-20250929")
        expected = (1000000 / 1000000 * 3.0) + (1000000 / 1000000 * 15.0)
        assert abs(cost - expected) < 0.01

    @pytest.mark.skip("Requires live API - implement after integration complete")
    def test_full_workflow_with_all_phase1_features(self, sample_vulnerable_repo, mock_api_key):
        """
        Test complete workflow with:
        - Threat model generation
        - Foundation-Sec-8B provider (if available)
        - Sandbox validation
        - Multi-agent analysis
        """
        from run_ai_audit import run_audit

        config = {
            "anthropic_api_key": mock_api_key,
            "enable_threat_modeling": True,
            "foundation_sec_enabled": False,  # Don't require model download
            "enable_sandbox_validation": True,
            "multi_agent_mode": "sequential",
            "max_files": 10,
            "max_tokens": 2000,
            "cost_limit": 1.0,
        }

        # Run full audit
        results = run_audit(str(sample_vulnerable_repo), config, review_type="audit")

        # Verify threat model was generated
        assert results["metrics"]["threat_model"]["generated"]
        assert results["metrics"]["threat_model"]["threats_identified"] > 0

        # Verify findings include security issues
        assert len(results["findings"]) > 0
        security_findings = [f for f in results["findings"] if f["category"] == "security"]
        assert len(security_findings) > 0

        # Verify sandbox validation ran (if exploits generated)
        if results["metrics"].get("sandbox", {}).get("validations_run", 0) > 0:
            assert results["metrics"]["sandbox"]["exploitable"] >= 0

    def test_threat_model_metrics_tracking(self):
        """Test that threat model metrics are properly tracked"""
        metrics = ReviewMetrics()

        # Verify initial state
        assert not metrics.metrics["threat_model"]["generated"]
        assert metrics.metrics["threat_model"]["threats_identified"] == 0

        # Mock threat model
        threat_model = {
            "threats": [
                {"id": "T1", "name": "SQL Injection"},
                {"id": "T2", "name": "XSS"},
                {"id": "T3", "name": "CSRF"},
            ],
            "attack_surface": {"entry_points": ["API1", "API2", "Web1"]},
            "trust_boundaries": [{"name": "Public/Private"}, {"name": "Client/Server"}],
            "assets": [{"name": "User Data"}, {"name": "Session Tokens"}],
        }

        # Record threat model
        metrics.record_threat_model(threat_model)

        # Verify metrics updated
        assert metrics.metrics["threat_model"]["generated"]
        assert metrics.metrics["threat_model"]["threats_identified"] == 3
        assert metrics.metrics["threat_model"]["attack_surface_size"] == 3
        assert metrics.metrics["threat_model"]["trust_boundaries"] == 2
        assert metrics.metrics["threat_model"]["assets_cataloged"] == 2

    @pytest.mark.skip("Requires threat model integration - implement after Agent 1 completes")
    def test_threat_model_passed_to_agents(self, sample_vulnerable_repo, mock_api_key):
        """Verify threat model context is actually used by agents"""
        # This test will check agent prompts include threat model
        from run_ai_audit import build_agent_prompt
        from threat_model_generator import ThreatModelGenerator

        # Generate threat model
        generator = ThreatModelGenerator(mock_api_key)
        repo_context = generator.analyze_repository(str(sample_vulnerable_repo))
        threat_model = generator.generate_threat_model(repo_context)

        # Build agent prompt
        prompt = build_agent_prompt(
            files=[{"path": "test.py", "content": "test"}], review_type="audit", threat_model=threat_model
        )

        # Verify threat model content is in prompt
        assert "threat model" in prompt.lower() or "threats" in prompt.lower()
        assert len(threat_model["threats"]) > 0

    @pytest.mark.skip("Requires sandbox integration - implement after Agent 2 completes")
    def test_sandbox_validation_eliminates_false_positives(self, sample_vulnerable_repo):
        """Test that sandbox validation filters out non-exploitable findings"""
        from sandbox_validator import SandboxValidator

        # Create mock finding (non-exploitable)
        finding = {
            "vulnerability": "SQL Injection",
            "file": "test.py",
            "line": 10,
            "code": "query = f'SELECT * FROM users'",
            "severity": "high",
        }

        validator = SandboxValidator()

        # Mock exploit attempt
        exploit_code = "SELECT * FROM users WHERE 1=1"

        # Validate (should fail because it's not actually exploitable without DB)
        result = validator.validate_exploit(exploit_code, finding)

        # Verify result
        assert "exploitable" in result
        assert isinstance(result["exploitable"], bool)

    def test_metrics_initialization_includes_phase1_features(self):
        """Test that ReviewMetrics includes all Phase 1 metric fields"""
        metrics = ReviewMetrics()

        # Verify threat model metrics exist
        assert "threat_model" in metrics.metrics
        assert "generated" in metrics.metrics["threat_model"]
        assert "threats_identified" in metrics.metrics["threat_model"]
        assert "attack_surface_size" in metrics.metrics["threat_model"]
        assert "trust_boundaries" in metrics.metrics["threat_model"]
        assert "assets_cataloged" in metrics.metrics["threat_model"]

        # Verify exploitability metrics exist
        assert "exploitability" in metrics.metrics
        assert "trivial" in metrics.metrics["exploitability"]
        assert "moderate" in metrics.metrics["exploitability"]
        assert "complex" in metrics.metrics["exploitability"]
        assert "theoretical" in metrics.metrics["exploitability"]

        # Verify agent metrics exist
        assert "agents_executed" in metrics.metrics
        assert "agent_execution_times" in metrics.metrics

    def test_cost_tracking_for_different_providers(self):
        """Test that cost tracking works correctly for different providers"""
        metrics = ReviewMetrics()

        # Test Anthropic
        metrics.record_llm_call(1000, 500, "anthropic")
        anthropic_cost = metrics.metrics["cost_usd"]
        assert anthropic_cost > 0

        # Reset
        metrics = ReviewMetrics()

        # Test Foundation-Sec
        metrics.record_llm_call(1000, 500, "foundation-sec")
        foundation_cost = metrics.metrics["cost_usd"]
        assert foundation_cost == 0.0

    @pytest.mark.skip("Requires multi-agent integration - implement after full integration")
    def test_multi_agent_mode_with_phase1_features(self, sample_vulnerable_repo, mock_api_key):
        """Test multi-agent mode uses all Phase 1 features"""
        from run_ai_audit import run_audit

        config = {
            "anthropic_api_key": mock_api_key,
            "enable_threat_modeling": True,
            "enable_sandbox_validation": True,
            "multi_agent_mode": "sequential",
            "max_files": 5,
            "max_tokens": 2000,
        }

        results = run_audit(str(sample_vulnerable_repo), config, review_type="audit")

        # Verify multiple agents executed
        assert len(results["metrics"]["agents_executed"]) > 1

        # Verify threat model was used
        assert results["metrics"]["threat_model"]["generated"]

        # Verify sandbox validation ran
        if results["metrics"].get("sandbox", {}).get("validations_run", 0) > 0:
            assert "sandbox" in results["metrics"]


class TestFoundationSecIntegration:
    """Test Foundation-Sec-8B provider integration"""

    def test_foundation_sec_provider_imports(self):
        """Test that Foundation-Sec provider can be imported"""
        try:
            from providers.foundation_sec import FoundationSecProvider

            assert FoundationSecProvider is not None
        except ImportError as e:
            pytest.skip(f"Foundation-Sec provider not available: {e}")

    @pytest.mark.skip("Requires Foundation-Sec-8B model download")
    def test_foundation_sec_provider_initialization(self):
        """Test Foundation-Sec provider can be initialized"""
        from providers.foundation_sec import FoundationSecProvider

        provider = FoundationSecProvider()
        assert provider is not None
        assert hasattr(provider, "generate")
        assert hasattr(provider, "estimate_cost")

    @pytest.mark.skip("Requires Foundation-Sec-8B model download")
    def test_foundation_sec_provider_generation(self):
        """Test Foundation-Sec provider can generate responses"""
        from providers.foundation_sec import FoundationSecProvider

        provider = FoundationSecProvider()

        prompt = """
        Review this code for security vulnerabilities:

        ```python
        def login(username, password):
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            return db.execute(query)
        ```
        """

        response = provider.generate(prompt)

        assert response is not None
        assert len(response) > 0
        assert "sql injection" in response.lower() or "vulnerability" in response.lower()


class TestThreatModelIntegration:
    """Test threat model generator integration"""

    def test_threat_model_generator_imports(self):
        """Test that threat model generator can be imported"""
        from threat_model_generator import ThreatModelGenerator

        assert ThreatModelGenerator is not None

    @pytest.mark.skip("Requires live API - implement after integration")
    def test_threat_model_generation_workflow(self, tmp_path):
        """Test complete threat model generation workflow"""
        from threat_model_generator import ThreatModelGenerator

        # Create sample repo
        repo_dir = tmp_path / "test_repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("def main(): pass")
        (repo_dir / "README.md").write_text("# Test App")

        api_key = os.getenv("ANTHROPIC_API_KEY", "test-key")
        generator = ThreatModelGenerator(api_key)

        # Analyze repository
        repo_context = generator.analyze_repository(str(repo_dir))
        assert repo_context["name"] == "test_repo"
        assert len(repo_context["languages"]) > 0

        # Generate threat model
        threat_model = generator.generate_threat_model(repo_context)
        assert "version" in threat_model
        assert "threats" in threat_model
        assert "attack_surface" in threat_model

        # Save threat model
        output_path = tmp_path / "threat-model.json"
        generator.save_threat_model(threat_model, str(output_path))
        assert output_path.exists()


class TestSandboxIntegration:
    """Test sandbox validator integration"""

    def test_sandbox_imports(self):
        """Test that sandbox modules can be imported"""
        try:
            from sandbox_validator import SandboxValidator

            assert SandboxValidator is not None
        except ImportError as e:
            pytest.skip(f"Sandbox validator not available: {e}")

    @pytest.mark.skip("Requires Docker - implement after Agent 2 completes")
    def test_sandbox_validator_initialization(self):
        """Test sandbox validator can be initialized"""
        from sandbox_validator import SandboxValidator

        validator = SandboxValidator()
        assert validator is not None
        assert hasattr(validator, "validate_exploit")

    @pytest.mark.skip("Requires Docker - implement after Agent 2 completes")
    def test_sandbox_validation_workflow(self):
        """Test complete sandbox validation workflow"""
        from sandbox_validator import SandboxValidator

        validator = SandboxValidator()

        # Mock exploit
        exploit_code = """
        import subprocess
        result = subprocess.run(['echo', 'test'], capture_output=True)
        print(result.stdout)
        """

        finding = {"vulnerability": "Command Injection", "severity": "high"}

        # Validate
        result = validator.validate_exploit(exploit_code, finding)

        assert "exploitable" in result
        assert "output" in result or "error" in result
