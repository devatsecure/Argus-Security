"""Tests for Feature C: Parallel Phase 3 Agents.

Validates that quality agents (performance, testing, quality) can run
concurrently while security agents remain sequential, and that the
CostCircuitBreaker is thread-safe under concurrent access.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure scripts/ is on the path so imports resolve
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from orchestrator.cost_tracker import CostCircuitBreaker, CostLimitExceededError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_metrics():
    """Return a mock ReviewMetrics with all methods the runner calls."""
    m = MagicMock()
    m.metrics = {
        "exploitability": {"trivial": 0, "moderate": 0, "complex": 0, "theoretical": 0},
        "exploit_chains_found": 0,
        "tests_generated": 0,
        "sandbox": {"false_positives_eliminated": 0},
    }
    return m


def _make_config(enable_parallel=True, parallel_workers=3, **extra):
    """Build a minimal config dict for run_multi_agent_sequential."""
    cfg = {
        "enable_parallel_agents": enable_parallel,
        "parallel_agent_workers": parallel_workers,
        "enable_audit_trail": False,
        "enable_sandbox_validation": False,
        "enable_consensus": False,
    }
    cfg.update(extra)
    return cfg


# A reusable fake LLM response tuple
_FAKE_REPORT = "# Report\n\n## Summary\nNo issues.\n"
_FAKE_LLM_RESPONSE = (_FAKE_REPORT, 100, 50)


# ---------------------------------------------------------------------------
# CostCircuitBreaker thread-safety tests
# ---------------------------------------------------------------------------


class TestCostCircuitBreakerThreadSafety:
    """Verify CostCircuitBreaker behaves correctly under concurrent access."""

    def test_concurrent_record_actual_cost(self):
        """Many threads recording costs should not lose any updates."""
        breaker = CostCircuitBreaker(cost_limit_usd=100.0)
        num_threads = 50
        cost_per_thread = 0.10

        def _record():
            breaker.record_actual_cost(cost_per_thread)

        threads = [threading.Thread(target=_record) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = num_threads * cost_per_thread
        assert abs(breaker.current_cost - expected) < 1e-9, (
            f"Expected {expected}, got {breaker.current_cost}"
        )

    def test_concurrent_check_before_call(self):
        """Concurrent check_before_call should not corrupt internal state."""
        breaker = CostCircuitBreaker(cost_limit_usd=10.0)
        errors = []

        def _check():
            try:
                breaker.check_before_call(0.01, "test", "unit-test")
            except CostLimitExceededError:
                pass
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_check) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Unexpected errors: {errors}"

    def test_cost_limit_raised_under_contention(self):
        """When budget is nearly exhausted, at most one thread should proceed."""
        breaker = CostCircuitBreaker(cost_limit_usd=1.0, safety_buffer_percent=0.0)
        # Fill up most of the budget
        breaker.record_actual_cost(0.95)

        exceeded_count = 0
        lock = threading.Lock()

        def _try_check():
            nonlocal exceeded_count
            try:
                breaker.check_before_call(0.10, "test", "race-test")
            except CostLimitExceededError:
                with lock:
                    exceeded_count += 1

        threads = [threading.Thread(target=_try_check) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 10 threads should hit the limit because 0.95 + 0.10 > 1.0
        assert exceeded_count == 10


# ---------------------------------------------------------------------------
# Parallel agent execution tests
# ---------------------------------------------------------------------------


class TestParallelAgentExecution:
    """Integration-level tests for parallel quality agent execution."""

    @patch("orchestrator.agent_runner.call_llm_api", return_value=_FAKE_LLM_RESPONSE)
    @patch("orchestrator.agent_runner.load_agent_prompt", return_value="You are a reviewer.")
    def test_parallel_completes_all_quality_agents(self, mock_prompt, mock_llm):
        """All 3 quality agents should produce reports when run in parallel."""
        from orchestrator.agent_runner import run_multi_agent_sequential

        config = _make_config(enable_parallel=True, parallel_workers=3)
        metrics = _make_mock_metrics()
        breaker = CostCircuitBreaker(cost_limit_usd=10.0)

        report = run_multi_agent_sequential(
            repo_path="/tmp/fake-repo",
            config=config,
            review_type="audit",
            client=MagicMock(),
            provider="anthropic",
            model="claude-sonnet-4",
            max_tokens=4000,
            files=[{"path": "app.py", "content": "print('hello')"}],
            metrics=metrics,
            circuit_breaker=breaker,
        )

        # The final report should contain content (not empty)
        assert len(report) > 100
        # All 6 agents + orchestrator = 7 calls to call_llm_api
        assert mock_llm.call_count == 7

    @patch("orchestrator.agent_runner.call_llm_api", return_value=_FAKE_LLM_RESPONSE)
    @patch("orchestrator.agent_runner.load_agent_prompt", return_value="You are a reviewer.")
    def test_sequential_fallback_when_disabled(self, mock_prompt, mock_llm):
        """When enable_parallel_agents=False, all agents run sequentially."""
        from orchestrator.agent_runner import run_multi_agent_sequential

        config = _make_config(enable_parallel=False)
        metrics = _make_mock_metrics()
        breaker = CostCircuitBreaker(cost_limit_usd=10.0)

        report = run_multi_agent_sequential(
            repo_path="/tmp/fake-repo",
            config=config,
            review_type="audit",
            client=MagicMock(),
            provider="anthropic",
            model="claude-sonnet-4",
            max_tokens=4000,
            files=[{"path": "app.py", "content": "print('hello')"}],
            metrics=metrics,
            circuit_breaker=breaker,
        )

        assert len(report) > 100
        assert mock_llm.call_count == 7

    @patch("orchestrator.agent_runner.load_agent_prompt", return_value="You are a reviewer.")
    def test_one_agent_failure_does_not_block_others(self, mock_prompt):
        """If one quality agent raises, the other two should still complete."""
        from orchestrator.agent_runner import run_multi_agent_sequential

        call_count = {"n": 0}
        call_lock = threading.Lock()

        def _side_effect(client, provider, model, prompt, max_tokens, **kwargs):
            with call_lock:
                call_count["n"] += 1
                current = call_count["n"]

            # Fail on the 4th call (first quality agent = "performance")
            if current == 4:
                raise RuntimeError("Simulated LLM failure for performance agent")
            return _FAKE_LLM_RESPONSE

        with patch("orchestrator.agent_runner.call_llm_api", side_effect=_side_effect):
            config = _make_config(enable_parallel=True, parallel_workers=3)
            metrics = _make_mock_metrics()
            breaker = CostCircuitBreaker(cost_limit_usd=10.0)

            report = run_multi_agent_sequential(
                repo_path="/tmp/fake-repo",
                config=config,
                review_type="audit",
                client=MagicMock(),
                provider="anthropic",
                model="claude-sonnet-4",
                max_tokens=4000,
                files=[{"path": "app.py", "content": "print('hello')"}],
                metrics=metrics,
                circuit_breaker=breaker,
            )

        # Report should still be generated (orchestrator ran)
        assert len(report) > 50
        # The multi-agent summary appended to the report should show
        # that the performance agent errored (N/A duration, error status icon).
        # The _status() helper emits a cross-mark for agents with "error" in
        # their metrics dict, and the duration shows "N/A".
        assert "N/A" in report, "Performance agent should show N/A duration indicating failure"

    @patch("orchestrator.agent_runner.call_llm_api", return_value=_FAKE_LLM_RESPONSE)
    @patch("orchestrator.agent_runner.load_agent_prompt", return_value="You are a reviewer.")
    def test_agent_results_merged_into_reports(self, mock_prompt, mock_llm):
        """Each agent's report should be individually saved and merged."""
        from orchestrator.agent_runner import run_multi_agent_sequential

        config = _make_config(enable_parallel=True, parallel_workers=3)
        metrics = _make_mock_metrics()
        breaker = CostCircuitBreaker(cost_limit_usd=10.0)

        # Use tmp_path-like dir
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            run_multi_agent_sequential(
                repo_path=tmpdir,
                config=config,
                review_type="audit",
                client=MagicMock(),
                provider="anthropic",
                model="claude-sonnet-4",
                max_tokens=4000,
                files=[{"path": "app.py", "content": "x = 1"}],
                metrics=metrics,
                circuit_breaker=breaker,
            )

            # Individual agent report files should be saved
            agents_dir = Path(tmpdir) / ".argus" / "reviews" / "agents"
            assert agents_dir.exists()

            # Check that all 6 agent reports were written
            report_files = list(agents_dir.glob("*-report.md"))
            assert len(report_files) == 6, (
                f"Expected 6 agent reports, got {len(report_files)}: "
                f"{[f.name for f in report_files]}"
            )

            # Metrics JSON should exist
            metrics_file = agents_dir / "metrics.json"
            assert metrics_file.exists()

    @patch("orchestrator.agent_runner.call_llm_api", return_value=_FAKE_LLM_RESPONSE)
    @patch("orchestrator.agent_runner.load_agent_prompt", return_value="You are a reviewer.")
    def test_parallel_agents_run_concurrently(self, mock_prompt, mock_llm):
        """Quality agents should overlap in time when parallel is enabled."""
        from orchestrator.agent_runner import run_multi_agent_sequential

        # Track which threads each agent runs on
        agent_threads = {}
        agent_lock = threading.Lock()

        def _tracking_llm(client, provider, model, prompt, max_tokens, **kwargs):
            op = kwargs.get("operation", "")
            tid = threading.current_thread().ident
            with agent_lock:
                agent_threads[op] = tid
            # Small sleep to ensure overlap window
            time.sleep(0.05)
            return _FAKE_LLM_RESPONSE

        mock_llm.side_effect = _tracking_llm

        config = _make_config(enable_parallel=True, parallel_workers=3)
        metrics = _make_mock_metrics()
        breaker = CostCircuitBreaker(cost_limit_usd=10.0)

        run_multi_agent_sequential(
            repo_path="/tmp/fake-repo",
            config=config,
            review_type="audit",
            client=MagicMock(),
            provider="anthropic",
            model="claude-sonnet-4",
            max_tokens=4000,
            files=[{"path": "app.py", "content": "x = 1"}],
            metrics=metrics,
            circuit_breaker=breaker,
        )

        # Extract thread IDs for quality agents
        quality_ops = [
            op for op in agent_threads
            if any(q in op for q in ["performance", "testing", "quality"])
        ]
        quality_tids = {agent_threads[op] for op in quality_ops}

        # With 3 workers, we expect at least 2 different thread IDs
        # (proving concurrency actually happened)
        assert len(quality_tids) >= 2, (
            f"Expected at least 2 distinct threads for quality agents, "
            f"got {len(quality_tids)}: {quality_tids}"
        )


# ---------------------------------------------------------------------------
# Config toggle tests
# ---------------------------------------------------------------------------


class TestConfigToggles:
    """Verify config_loader has the new parallel agent settings."""

    def test_default_config_has_parallel_keys(self):
        from config_loader import get_default_config

        defaults = get_default_config()
        assert "enable_parallel_agents" in defaults
        assert defaults["enable_parallel_agents"] is True
        assert "parallel_agent_workers" in defaults
        assert defaults["parallel_agent_workers"] == 3

    def test_build_unified_config_includes_parallel_keys(self):
        from config_loader import build_unified_config

        config = build_unified_config()
        assert "enable_parallel_agents" in config
        assert "parallel_agent_workers" in config
