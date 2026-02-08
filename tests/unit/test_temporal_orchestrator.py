"""Tests for temporal_orchestrator module.

These tests validate the Temporal orchestration layer without requiring
the ``temporalio`` package to be installed.  All Temporal-specific code
paths are tested via mocking.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure scripts directory is on the import path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

from temporal_orchestrator import (  # noqa: E402
    NON_RETRYABLE_ERRORS,
    PIPELINE_PHASES,
    RETRY_POLICIES,
    TEMPORAL_AVAILABLE,
    AuditWorkflowRunner,
    PhaseInput,
    PhaseResult,
    PipelineActivities,
    create_temporal_client,
    get_temporal_retry_policy,
)

# =========================================================================
# PhaseInput tests
# =========================================================================


class TestPhaseInput:
    """Tests for the PhaseInput dataclass."""

    def test_creation_with_defaults(self):
        """PhaseInput should initialise with sensible defaults."""
        pi = PhaseInput(repo_path="/tmp/repo")
        assert pi.repo_path == "/tmp/repo"
        assert pi.config == {}
        assert pi.previous_output == {}
        assert pi.phase_name == ""

    def test_creation_with_all_fields(self):
        """PhaseInput should accept all fields explicitly."""
        pi = PhaseInput(
            repo_path="/workspace",
            config={"enable_semgrep": True},
            previous_output={"findings": [1, 2]},
            phase_name="scanner_orchestration",
        )
        assert pi.repo_path == "/workspace"
        assert pi.config == {"enable_semgrep": True}
        assert pi.previous_output == {"findings": [1, 2]}
        assert pi.phase_name == "scanner_orchestration"

    def test_default_factory_independence(self):
        """Each instance should have its own dict, not a shared reference."""
        a = PhaseInput(repo_path="/a")
        b = PhaseInput(repo_path="/b")
        a.config["key"] = "val"
        assert "key" not in b.config

    def test_repo_path_is_required(self):
        """PhaseInput must have a repo_path."""
        with pytest.raises(TypeError):
            PhaseInput()  # type: ignore[call-arg]


# =========================================================================
# PhaseResult tests
# =========================================================================


class TestPhaseResult:
    """Tests for the PhaseResult dataclass."""

    def test_creation_with_defaults(self):
        """Default status should be 'pending'."""
        pr = PhaseResult(phase_name="test_phase")
        assert pr.phase_name == "test_phase"
        assert pr.status == "pending"
        assert pr.data == {}
        assert pr.error == ""
        assert pr.duration_seconds == 0.0

    def test_success_result(self):
        """A successful PhaseResult carries data."""
        pr = PhaseResult(
            phase_name="ai_enrichment",
            status="success",
            data={"enriched": True},
            duration_seconds=1.5,
        )
        assert pr.status == "success"
        assert pr.data == {"enriched": True}
        assert pr.duration_seconds == 1.5
        assert pr.error == ""

    def test_failed_result_with_error(self):
        """A failed PhaseResult carries an error message."""
        pr = PhaseResult(
            phase_name="policy_gates",
            status="failed",
            error="OPA policy violation",
        )
        assert pr.status == "failed"
        assert pr.error == "OPA policy violation"
        assert pr.data == {}

    def test_skipped_result(self):
        """PhaseResult can represent a skipped phase."""
        pr = PhaseResult(phase_name="sandbox_validation", status="skipped")
        assert pr.status == "skipped"

    def test_default_factory_independence(self):
        """Each PhaseResult should have its own data dict."""
        a = PhaseResult(phase_name="a")
        b = PhaseResult(phase_name="b")
        a.data["x"] = 1
        assert "x" not in b.data


# =========================================================================
# PipelineActivities tests
# =========================================================================


class TestPipelineActivities:
    """Tests for the PipelineActivities class."""

    def setup_method(self):
        """Create a fresh activities instance for each test."""
        self._activities = PipelineActivities()

    def test_init_default_config(self):
        """PipelineActivities should default to an empty config."""
        assert self._activities._config == {}

    def test_init_custom_config(self):
        """PipelineActivities should store the provided config."""
        acts = PipelineActivities(config={"key": "val"})
        assert acts._config == {"key": "val"}

    def test_all_six_phase_methods_exist(self):
        """Every pipeline phase should have a corresponding method."""
        expected_methods = [
            "run_scanner_orchestration",
            "run_ai_enrichment",
            "run_multi_agent_review",
            "run_sandbox_validation",
            "run_policy_gates",
            "run_reporting",
        ]
        for method_name in expected_methods:
            assert hasattr(self._activities, method_name), (
                f"Missing method: {method_name}"
            )
            assert callable(getattr(self._activities, method_name))

    def test_scanner_orchestration_returns_phase_result(self):
        """Phase 1 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_scanner_orchestration(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "scanner_orchestration"
        assert result.status == "success"

    def test_ai_enrichment_returns_phase_result(self):
        """Phase 2 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_ai_enrichment(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "ai_enrichment"
        assert result.status == "success"

    def test_multi_agent_review_returns_phase_result(self):
        """Phase 3 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_multi_agent_review(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "multi_agent_review"
        assert result.status == "success"

    def test_sandbox_validation_returns_phase_result(self):
        """Phase 4 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_sandbox_validation(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "sandbox_validation"
        assert result.status == "success"

    def test_policy_gates_returns_phase_result(self):
        """Phase 5 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_policy_gates(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "policy_gates"
        assert result.status == "success"

    def test_reporting_returns_phase_result(self):
        """Phase 6 should return a PhaseResult with correct phase_name."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_reporting(inp)
        assert isinstance(result, PhaseResult)
        assert result.phase_name == "reporting"
        assert result.status == "success"

    def test_phase_passes_previous_output_through(self):
        """Activities should propagate previous_output as result data."""
        prev = {"findings": [{"id": "F001"}]}
        inp = PhaseInput(repo_path="/repo", previous_output=prev)
        result = self._activities.run_scanner_orchestration(inp)
        assert result.data == prev

    def test_duration_is_recorded(self):
        """Activities should record a non-negative duration."""
        inp = PhaseInput(repo_path="/repo")
        result = self._activities.run_scanner_orchestration(inp)
        assert result.duration_seconds >= 0.0


# =========================================================================
# AuditWorkflowRunner tests
# =========================================================================


class TestAuditWorkflowRunner:
    """Tests for the AuditWorkflowRunner class."""

    def test_run_executes_all_six_phases(self):
        """All 6 phases should execute when the pipeline runs."""
        runner = AuditWorkflowRunner()
        results = runner.run("/tmp/repo")
        assert len(results) == 6
        for phase_name in PIPELINE_PHASES:
            assert phase_name in results

    def test_all_phases_succeed_by_default(self):
        """Default activities should all succeed."""
        runner = AuditWorkflowRunner()
        results = runner.run("/tmp/repo")
        for phase_name, result in results.items():
            assert result.status == "success", (
                f"Phase {phase_name} should be success but is {result.status}"
            )

    def test_phase_results_stored_correctly(self):
        """The phase_results property should match run() output."""
        runner = AuditWorkflowRunner()
        run_output = runner.run("/tmp/repo")
        prop_output = runner.phase_results
        assert run_output == prop_output

    def test_phase_results_is_copy(self):
        """The phase_results property should return a copy, not internal state."""
        runner = AuditWorkflowRunner()
        runner.run("/tmp/repo")
        results_a = runner.phase_results
        results_b = runner.phase_results
        assert results_a is not results_b

    def test_previous_output_passed_to_next_phase(self):
        """Each phase should receive the previous phase's data output."""
        received_inputs: list[PhaseInput] = []

        class SpyActivities(PipelineActivities):
            def run_scanner_orchestration(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="scanner_orchestration",
                    status="success",
                    data={"scanners_done": True},
                )

            def run_ai_enrichment(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="ai_enrichment",
                    status="success",
                    data={"enriched": True},
                )

            def run_multi_agent_review(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="multi_agent_review",
                    status="success",
                    data={"reviewed": True},
                )

            def run_sandbox_validation(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="sandbox_validation",
                    status="success",
                    data={"validated": True},
                )

            def run_policy_gates(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="policy_gates",
                    status="success",
                    data={"gated": True},
                )

            def run_reporting(self, phase_input: PhaseInput) -> PhaseResult:
                received_inputs.append(phase_input)
                return PhaseResult(
                    phase_name="reporting",
                    status="success",
                    data={"reported": True},
                )

        runner = AuditWorkflowRunner(activities=SpyActivities())
        runner.run("/tmp/repo")

        # First phase gets empty previous_output
        assert received_inputs[0].previous_output == {}
        # Second phase gets first phase's data
        assert received_inputs[1].previous_output == {"scanners_done": True}
        # Third phase gets second phase's data
        assert received_inputs[2].previous_output == {"enriched": True}
        # Fourth phase gets third phase's data
        assert received_inputs[3].previous_output == {"reviewed": True}
        # Fifth gets fourth
        assert received_inputs[4].previous_output == {"validated": True}
        # Sixth gets fifth
        assert received_inputs[5].previous_output == {"gated": True}

    def test_non_retryable_error_stops_pipeline(self):
        """A non-retryable error should halt the pipeline immediately."""

        class FailingActivities(PipelineActivities):
            def run_ai_enrichment(self, phase_input: PhaseInput) -> PhaseResult:
                raise PermissionError("Access denied")

        runner = AuditWorkflowRunner(activities=FailingActivities())
        results = runner.run("/tmp/repo")

        # scanner_orchestration should succeed
        assert results["scanner_orchestration"].status == "success"
        # ai_enrichment should be failed
        assert results["ai_enrichment"].status == "failed"
        assert "Access denied" in results["ai_enrichment"].error
        # Later phases should not have run
        assert "multi_agent_review" not in results
        assert "sandbox_validation" not in results
        assert "policy_gates" not in results
        assert "reporting" not in results

    def test_retryable_error_propagates(self):
        """A retryable error should be re-raised (for Temporal to handle)."""

        class RetryableActivities(PipelineActivities):
            def run_scanner_orchestration(self, phase_input: PhaseInput) -> PhaseResult:
                raise ConnectionError("Temporary network failure")

        runner = AuditWorkflowRunner(activities=RetryableActivities())
        with pytest.raises(ConnectionError, match="Temporary network failure"):
            runner.run("/tmp/repo")

    def test_strict_mode_stops_on_failure(self):
        """With phase_gate_strict, a failed phase should halt the pipeline."""

        class FailPhase3Activities(PipelineActivities):
            def run_multi_agent_review(self, phase_input: PhaseInput) -> PhaseResult:
                return PhaseResult(
                    phase_name="multi_agent_review",
                    status="failed",
                    error="Agent consensus timeout",
                )

        runner = AuditWorkflowRunner(activities=FailPhase3Activities())
        results = runner.run("/tmp/repo", config={"phase_gate_strict": True})

        assert results["scanner_orchestration"].status == "success"
        assert results["ai_enrichment"].status == "success"
        assert results["multi_agent_review"].status == "failed"
        # Strict mode should stop; later phases not executed
        assert "sandbox_validation" not in results
        assert "policy_gates" not in results
        assert "reporting" not in results

    def test_non_strict_mode_continues_on_failure(self):
        """Without phase_gate_strict, a failed phase should not halt."""

        class FailPhase3Activities(PipelineActivities):
            def run_multi_agent_review(self, phase_input: PhaseInput) -> PhaseResult:
                return PhaseResult(
                    phase_name="multi_agent_review",
                    status="failed",
                    error="Agent consensus timeout",
                )

        runner = AuditWorkflowRunner(activities=FailPhase3Activities())
        results = runner.run("/tmp/repo", config={"phase_gate_strict": False})

        assert results["scanner_orchestration"].status == "success"
        assert results["ai_enrichment"].status == "success"
        assert results["multi_agent_review"].status == "failed"
        # Pipeline should continue in non-strict mode
        assert results["sandbox_validation"].status == "success"
        assert results["policy_gates"].status == "success"
        assert results["reporting"].status == "success"

    def test_get_summary_returns_correct_counts(self):
        """get_summary should accurately count success/failed phases."""
        runner = AuditWorkflowRunner()
        runner.run("/tmp/repo")
        summary = runner.get_summary()

        assert summary["total_phases"] == 6
        assert summary["completed_phases"] == 6
        assert summary["failed_phases"] == 0
        assert len(summary["phases"]) == 6
        assert "retry_policy" in summary

    def test_get_summary_with_failures(self):
        """get_summary should reflect failures."""

        class FailPhase5Activities(PipelineActivities):
            def run_policy_gates(self, phase_input: PhaseInput) -> PhaseResult:
                return PhaseResult(
                    phase_name="policy_gates",
                    status="failed",
                    error="Policy violation",
                )

        runner = AuditWorkflowRunner(activities=FailPhase5Activities())
        runner.run("/tmp/repo")
        summary = runner.get_summary()

        assert summary["completed_phases"] == 5
        assert summary["failed_phases"] == 1
        assert summary["phases"]["policy_gates"]["status"] == "failed"
        assert summary["phases"]["policy_gates"]["error"] == "Policy violation"

    def test_get_summary_phase_details(self):
        """Summary phase details should include status, error, duration."""
        runner = AuditWorkflowRunner()
        runner.run("/tmp/repo")
        summary = runner.get_summary()

        for phase_name in PIPELINE_PHASES:
            phase_detail = summary["phases"][phase_name]
            assert "status" in phase_detail
            assert "error" in phase_detail
            assert "duration_seconds" in phase_detail

    def test_get_summary_includes_retry_policy(self):
        """Summary should embed the active retry policy."""
        runner = AuditWorkflowRunner(retry_mode="testing")
        runner.run("/tmp/repo")
        summary = runner.get_summary()

        assert summary["retry_policy"] == RETRY_POLICIES["testing"]

    def test_default_retry_mode_is_production(self):
        """Default runner should use the production retry policy."""
        runner = AuditWorkflowRunner()
        summary_before = runner.get_summary()
        assert summary_before["retry_policy"] == RETRY_POLICIES["production"]

    def test_custom_activities_are_used(self):
        """Runner should use the provided activities instance."""
        call_log = []

        class LoggingActivities(PipelineActivities):
            def run_scanner_orchestration(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("scanner_orchestration")
                return PhaseResult(phase_name="scanner_orchestration", status="success")

            def run_ai_enrichment(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("ai_enrichment")
                return PhaseResult(phase_name="ai_enrichment", status="success")

            def run_multi_agent_review(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("multi_agent_review")
                return PhaseResult(phase_name="multi_agent_review", status="success")

            def run_sandbox_validation(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("sandbox_validation")
                return PhaseResult(phase_name="sandbox_validation", status="success")

            def run_policy_gates(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("policy_gates")
                return PhaseResult(phase_name="policy_gates", status="success")

            def run_reporting(self, phase_input: PhaseInput) -> PhaseResult:
                call_log.append("reporting")
                return PhaseResult(phase_name="reporting", status="success")

        runner = AuditWorkflowRunner(activities=LoggingActivities())
        runner.run("/tmp/repo")

        assert call_log == PIPELINE_PHASES

    def test_run_with_none_config(self):
        """run() should handle None config gracefully."""
        runner = AuditWorkflowRunner()
        results = runner.run("/tmp/repo", config=None)
        assert len(results) == 6

    def test_run_with_empty_config(self):
        """run() should handle empty config dict."""
        runner = AuditWorkflowRunner()
        results = runner.run("/tmp/repo", config={})
        assert len(results) == 6

    def test_phase_input_carries_config(self):
        """The config dict should be passed through to each phase."""
        captured_config = {}

        class ConfigCapture(PipelineActivities):
            def run_scanner_orchestration(self, phase_input: PhaseInput) -> PhaseResult:
                captured_config.update(phase_input.config)
                return PhaseResult(phase_name="scanner_orchestration", status="success")

        runner = AuditWorkflowRunner(activities=ConfigCapture())
        test_config = {"enable_semgrep": False, "max_files": 10}
        runner.run("/tmp/repo", config=test_config)

        assert captured_config["enable_semgrep"] is False
        assert captured_config["max_files"] == 10

    def test_phase_input_carries_repo_path(self):
        """The repo_path should be passed to every phase."""
        captured_paths = []

        class PathCapture(PipelineActivities):
            def run_scanner_orchestration(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="scanner_orchestration", status="success")

            def run_ai_enrichment(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="ai_enrichment", status="success")

            def run_multi_agent_review(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="multi_agent_review", status="success")

            def run_sandbox_validation(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="sandbox_validation", status="success")

            def run_policy_gates(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="policy_gates", status="success")

            def run_reporting(self, phase_input: PhaseInput) -> PhaseResult:
                captured_paths.append(phase_input.repo_path)
                return PhaseResult(phase_name="reporting", status="success")

        runner = AuditWorkflowRunner(activities=PathCapture())
        runner.run("/my/project")
        assert all(p == "/my/project" for p in captured_paths)
        assert len(captured_paths) == 6


# =========================================================================
# Retry policy tests
# =========================================================================


class TestRetryPolicies:
    """Tests for the RETRY_POLICIES configuration."""

    def test_production_policy_exists(self):
        """Production retry policy should be defined."""
        assert "production" in RETRY_POLICIES

    def test_production_policy_values(self):
        """Production policy should have aggressive retry settings."""
        prod = RETRY_POLICIES["production"]
        assert prod["initial_interval_seconds"] == 300
        assert prod["max_interval_seconds"] == 1800
        assert prod["backoff_coefficient"] == 2.0
        assert prod["max_attempts"] == 50

    def test_testing_policy_exists(self):
        """Testing retry policy should be defined."""
        assert "testing" in RETRY_POLICIES

    def test_testing_policy_has_lower_values(self):
        """Testing policy should have lower intervals and fewer attempts."""
        test_pol = RETRY_POLICIES["testing"]
        prod_pol = RETRY_POLICIES["production"]
        assert test_pol["initial_interval_seconds"] < prod_pol["initial_interval_seconds"]
        assert test_pol["max_interval_seconds"] < prod_pol["max_interval_seconds"]
        assert test_pol["max_attempts"] < prod_pol["max_attempts"]

    def test_development_policy_exists(self):
        """Development retry policy should be defined."""
        assert "development" in RETRY_POLICIES

    def test_development_policy_values(self):
        """Development policy should have moderate settings."""
        dev = RETRY_POLICIES["development"]
        assert dev["initial_interval_seconds"] == 5
        assert dev["max_interval_seconds"] == 60
        assert dev["backoff_coefficient"] == 2.0
        assert dev["max_attempts"] == 10

    def test_all_policies_have_required_keys(self):
        """Every policy should define the four required retry parameters."""
        required_keys = {
            "initial_interval_seconds",
            "max_interval_seconds",
            "backoff_coefficient",
            "max_attempts",
        }
        for mode, policy in RETRY_POLICIES.items():
            assert required_keys.issubset(policy.keys()), (
                f"Policy '{mode}' missing keys: "
                f"{required_keys - set(policy.keys())}"
            )

    def test_get_temporal_retry_policy_returns_correct_policy(self):
        """get_temporal_retry_policy should return the matching policy."""
        assert get_temporal_retry_policy("production") == RETRY_POLICIES["production"]
        assert get_temporal_retry_policy("testing") == RETRY_POLICIES["testing"]
        assert get_temporal_retry_policy("development") == RETRY_POLICIES["development"]

    def test_get_temporal_retry_policy_unknown_mode_falls_back(self):
        """Unknown mode should fall back to production policy."""
        result = get_temporal_retry_policy("nonexistent_mode")
        assert result == RETRY_POLICIES["production"]

    def test_get_temporal_retry_policy_empty_string_falls_back(self):
        """Empty string mode should fall back to production policy."""
        result = get_temporal_retry_policy("")
        assert result == RETRY_POLICIES["production"]

    def test_backoff_coefficients_are_positive(self):
        """Backoff coefficients must be >= 1.0."""
        for mode, policy in RETRY_POLICIES.items():
            assert policy["backoff_coefficient"] >= 1.0, (
                f"Policy '{mode}' has invalid backoff_coefficient"
            )

    def test_max_attempts_are_positive(self):
        """Max attempts must be at least 1."""
        for mode, policy in RETRY_POLICIES.items():
            assert policy["max_attempts"] >= 1, (
                f"Policy '{mode}' has invalid max_attempts"
            )


# =========================================================================
# Non-retryable errors tests
# =========================================================================


class TestNonRetryableErrors:
    """Tests for the NON_RETRYABLE_ERRORS list."""

    def test_list_is_non_empty(self):
        """There should be at least one non-retryable error type."""
        assert len(NON_RETRYABLE_ERRORS) > 0

    def test_authentication_error_is_non_retryable(self):
        """AuthenticationError should not be retried."""
        assert "AuthenticationError" in NON_RETRYABLE_ERRORS

    def test_permission_error_is_non_retryable(self):
        """PermissionError should not be retried."""
        assert "PermissionError" in NON_RETRYABLE_ERRORS

    def test_configuration_error_is_non_retryable(self):
        """ConfigurationError should not be retried."""
        assert "ConfigurationError" in NON_RETRYABLE_ERRORS

    def test_invalid_target_error_is_non_retryable(self):
        """InvalidTargetError should not be retried."""
        assert "InvalidTargetError" in NON_RETRYABLE_ERRORS

    def test_execution_limit_error_is_non_retryable(self):
        """ExecutionLimitError should not be retried."""
        assert "ExecutionLimitError" in NON_RETRYABLE_ERRORS

    def test_contains_exactly_five_error_types(self):
        """The list should contain exactly the 5 known non-retryable types."""
        assert len(NON_RETRYABLE_ERRORS) == 5

    def test_all_entries_are_strings(self):
        """All entries should be string names of exception types."""
        for entry in NON_RETRYABLE_ERRORS:
            assert isinstance(entry, str)

    def test_connection_error_is_retryable(self):
        """ConnectionError should NOT be in the non-retryable list."""
        assert "ConnectionError" not in NON_RETRYABLE_ERRORS

    def test_timeout_error_is_retryable(self):
        """TimeoutError should NOT be in the non-retryable list."""
        assert "TimeoutError" not in NON_RETRYABLE_ERRORS


# =========================================================================
# Pipeline phases tests
# =========================================================================


class TestPipelinePhases:
    """Tests for the PIPELINE_PHASES constant."""

    def test_all_six_phases_defined(self):
        """There should be exactly 6 pipeline phases."""
        assert len(PIPELINE_PHASES) == 6

    def test_phase_order_is_correct(self):
        """Phases should be in the correct execution order."""
        assert PIPELINE_PHASES == [
            "scanner_orchestration",
            "ai_enrichment",
            "multi_agent_review",
            "sandbox_validation",
            "policy_gates",
            "reporting",
        ]

    def test_scanner_orchestration_is_first(self):
        """Scanner orchestration must run first."""
        assert PIPELINE_PHASES[0] == "scanner_orchestration"

    def test_reporting_is_last(self):
        """Reporting must be the final phase."""
        assert PIPELINE_PHASES[-1] == "reporting"

    def test_all_phases_are_strings(self):
        """All phase names should be strings."""
        for phase in PIPELINE_PHASES:
            assert isinstance(phase, str)

    def test_no_duplicate_phases(self):
        """There should be no duplicate phase names."""
        assert len(set(PIPELINE_PHASES)) == len(PIPELINE_PHASES)

    def test_phases_use_snake_case(self):
        """Phase names should follow snake_case convention."""
        import re

        for phase in PIPELINE_PHASES:
            assert re.match(r"^[a-z][a-z0-9_]*$", phase), (
                f"Phase name '{phase}' is not snake_case"
            )


# =========================================================================
# Temporal availability tests
# =========================================================================


class TestTemporalAvailability:
    """Tests for the TEMPORAL_AVAILABLE flag and conditional imports."""

    def test_temporal_available_is_boolean(self):
        """TEMPORAL_AVAILABLE should be a boolean."""
        assert isinstance(TEMPORAL_AVAILABLE, bool)

    def test_create_temporal_client_without_temporal(self):
        """create_temporal_client should raise if temporalio is not available."""
        import asyncio

        async def _test():
            with patch("temporal_orchestrator.TEMPORAL_AVAILABLE", False), \
                 pytest.raises(RuntimeError, match="temporalio package not installed"):
                await create_temporal_client()

        asyncio.run(_test())


# =========================================================================
# Config integration tests
# =========================================================================


class TestConfigIntegration:
    """Tests that the config_loader includes Temporal config keys."""

    def test_default_config_has_temporal_keys(self):
        """The default config should include Temporal-related keys."""
        from config_loader import get_default_config

        defaults = get_default_config()
        assert "enable_temporal" in defaults
        assert "temporal_server" in defaults
        assert "temporal_namespace" in defaults
        assert "temporal_retry_mode" in defaults

    def test_temporal_defaults_are_correct(self):
        """Temporal defaults should be conservative (disabled)."""
        from config_loader import get_default_config

        defaults = get_default_config()
        assert defaults["enable_temporal"] is False
        assert defaults["temporal_server"] == "localhost:7233"
        assert defaults["temporal_namespace"] == "argus"
        assert defaults["temporal_retry_mode"] == "production"
