"""Tests for audit_trail module: per-agent metrics, prompt archival, audit logging."""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from audit_trail import (
    AGENT_PHASE_MAP,
    AgentAttempt,
    AgentMetricsRecord,
    AuditSession,
)


@pytest.fixture()
def audit_dir(tmp_path):
    """Return a temporary directory for audit output."""
    return str(tmp_path / "audit_output")


@pytest.fixture()
def session(audit_dir):
    """Return an initialized AuditSession."""
    s = AuditSession(
        session_id="test-001",
        repo_path="/tmp/fake-repo",
        output_dir=audit_dir,
    )
    s.initialize()
    return s


def _make_attempt(
    success=True,
    attempt_number=1,
    duration=1.5,
    cost=0.01,
    input_tokens=100,
    output_tokens=50,
    model="claude-sonnet-4",
    error=None,
):
    """Helper to build an AgentAttempt."""
    return AgentAttempt(
        attempt_number=attempt_number,
        duration_seconds=duration,
        cost_usd=cost,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        success=success,
        model=model,
        timestamp="2025-01-01T00:00:00+00:00",
        error=error,
    )


# -----------------------------------------------------------------------
# Initialization
# -----------------------------------------------------------------------


class TestAuditSessionInit:
    def test_creates_directories(self, audit_dir):
        session = AuditSession(
            session_id="init-test",
            repo_path="/tmp/repo",
            output_dir=audit_dir,
        )
        session.initialize()

        assert os.path.isdir(os.path.join(audit_dir, "agents"))
        assert os.path.isdir(os.path.join(audit_dir, "prompts"))
        assert os.path.isfile(os.path.join(audit_dir, "session.json"))

    def test_idempotent(self, audit_dir):
        session = AuditSession(
            session_id="idem-test",
            repo_path="/tmp/repo",
            output_dir=audit_dir,
        )
        session.initialize()
        # Second call should not raise
        session.initialize()

        assert os.path.isdir(os.path.join(audit_dir, "agents"))

    def test_default_output_dir(self, tmp_path):
        repo = str(tmp_path / "myrepo")
        os.makedirs(repo, exist_ok=True)
        session = AuditSession(session_id="abc", repo_path=repo)
        session.initialize()

        expected = os.path.join(repo, ".argus", "audit", "abc")
        assert session.output_dir == expected
        assert os.path.isdir(expected)

    def test_session_id_property(self, session):
        assert session.session_id == "test-001"


# -----------------------------------------------------------------------
# start_agent
# -----------------------------------------------------------------------


class TestStartAgent:
    def test_creates_record(self, session):
        session.start_agent("security", "prompt text", attempt=1)
        summary = session.get_summary()
        assert "security" in summary["metrics"]["agents"]
        assert summary["metrics"]["agents"]["security"]["status"] == "in_progress"

    def test_saves_prompt_on_first_attempt(self, session):
        session.start_agent("security", "my prompt content", attempt=1)
        prompt_path = os.path.join(session.output_dir, "prompts", "security.md")
        assert os.path.isfile(prompt_path)
        content = Path(prompt_path).read_text()
        assert "my prompt content" in content
        assert "Prompt Snapshot: security" in content
        assert session.session_id in content

    def test_skips_prompt_on_retry(self, session):
        # First attempt saves prompt
        session.start_agent("security", "first prompt", attempt=1)
        # Second attempt should NOT overwrite
        session.start_agent("security", "retry prompt", attempt=2)
        prompt_path = os.path.join(session.output_dir, "prompts", "security.md")
        content = Path(prompt_path).read_text()
        assert "first prompt" in content
        assert "retry prompt" not in content

    def test_skips_prompt_when_empty(self, session):
        session.start_agent("security", "", attempt=1)
        prompt_path = os.path.join(session.output_dir, "prompts", "security.md")
        assert not os.path.isfile(prompt_path)

    def test_logs_start_event(self, session):
        session.start_agent("security", "prompt", attempt=1)
        log_path = os.path.join(session.output_dir, "agents", "security.log")
        assert os.path.isfile(log_path)
        with open(log_path) as f:
            events = [json.loads(line) for line in f]
        assert len(events) == 1
        assert events[0]["type"] == "start"
        assert events[0]["data"]["attempt"] == 1


# -----------------------------------------------------------------------
# end_agent
# -----------------------------------------------------------------------


class TestEndAgent:
    def test_records_attempt(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent("security", _make_attempt(success=True))

        summary = session.get_summary()
        agent = summary["metrics"]["agents"]["security"]
        assert len(agent["attempts"]) == 1
        assert agent["attempts"][0]["success"] is True

    def test_updates_session_json(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent("security", _make_attempt(success=True))

        session_path = os.path.join(session.output_dir, "session.json")
        with open(session_path) as f:
            data = json.load(f)
        assert "security" in data["metrics"]["agents"]

    def test_calculates_total_cost(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent("security", _make_attempt(cost=0.05))
        session.end_agent("security", _make_attempt(cost=0.03, attempt_number=2))

        summary = session.get_summary()
        agent = summary["metrics"]["agents"]["security"]
        assert abs(agent["total_cost_usd"] - 0.08) < 0.001

    def test_success_updates_status(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent("security", _make_attempt(success=True))

        summary = session.get_summary()
        assert summary["metrics"]["agents"]["security"]["status"] == "success"

    def test_failure_updates_status(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent(
            "security",
            _make_attempt(success=False, error="timeout"),
        )

        summary = session.get_summary()
        assert summary["metrics"]["agents"]["security"]["status"] == "failed"

    def test_end_without_start_creates_record(self, session):
        """end_agent should work even if start_agent was not called."""
        session.end_agent("security", _make_attempt(success=True))
        summary = session.get_summary()
        assert "security" in summary["metrics"]["agents"]


# -----------------------------------------------------------------------
# get_summary
# -----------------------------------------------------------------------


class TestGetSummary:
    def test_per_phase_metrics(self, session):
        # Security analysis phase: 2 agents
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt(cost=0.10, duration=10.0))
        session.start_agent("exploit-analyst", "p")
        session.end_agent("exploit-analyst", _make_attempt(cost=0.05, duration=5.0))

        # Quality analysis phase: 1 agent
        session.start_agent("performance", "p")
        session.end_agent("performance", _make_attempt(cost=0.08, duration=8.0))

        summary = session.get_summary()
        phases = summary["metrics"]["phases"]

        assert "security_analysis" in phases
        assert phases["security_analysis"]["agent_count"] == 2
        assert abs(phases["security_analysis"]["cost_usd"] - 0.15) < 0.001

        assert "quality_analysis" in phases
        assert phases["quality_analysis"]["agent_count"] == 1
        assert abs(phases["quality_analysis"]["cost_usd"] - 0.08) < 0.001

    def test_duration_percentages(self, session):
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt(duration=10.0))
        session.start_agent("orchestrator", "p")
        session.end_agent("orchestrator", _make_attempt(duration=5.0))

        summary = session.get_summary()
        phases = summary["metrics"]["phases"]

        # Percentages should be present and non-negative
        for phase_data in phases.values():
            assert "duration_percentage" in phase_data
            assert phase_data["duration_percentage"] >= 0

    def test_session_status_completed(self, session):
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt(success=True))

        summary = session.get_summary()
        assert summary["session"]["status"] == "completed"

    def test_session_status_in_progress(self, session):
        session.start_agent("security", "p")
        # Don't call end_agent -- still in progress

        summary = session.get_summary()
        assert summary["session"]["status"] == "in_progress"

    def test_session_status_completed_with_errors(self, session):
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt(success=True))
        session.start_agent("performance", "p")
        session.end_agent("performance", _make_attempt(success=False, error="fail"))

        summary = session.get_summary()
        assert summary["session"]["status"] == "completed_with_errors"

    def test_session_status_pending(self, session):
        summary = session.get_summary()
        assert summary["session"]["status"] == "pending"

    def test_summary_has_session_metadata(self, session):
        summary = session.get_summary()
        assert summary["session"]["id"] == "test-001"
        assert summary["session"]["repo_path"] == "/tmp/fake-repo"
        assert "created_at" in summary["session"]
        assert "total_duration_seconds" in summary["session"]

    def test_summary_total_cost(self, session):
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt(cost=0.10))
        session.start_agent("performance", "p")
        session.end_agent("performance", _make_attempt(cost=0.05))

        summary = session.get_summary()
        assert abs(summary["metrics"]["total_cost_usd"] - 0.15) < 0.001


# -----------------------------------------------------------------------
# Thread safety
# -----------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_end_agent(self, session):
        """Multiple threads calling end_agent should not corrupt state."""
        agent_names = [
            "security",
            "exploit-analyst",
            "security-test-generator",
            "performance",
            "testing",
            "quality",
        ]

        for name in agent_names:
            session.start_agent(name, f"prompt-{name}")

        errors = []

        def end_agent(name):
            try:
                session.end_agent(name, _make_attempt(cost=0.01))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=end_agent, args=(n,)) for n in agent_names]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Errors during concurrent end_agent: {errors}"

        summary = session.get_summary()
        assert len(summary["metrics"]["agents"]) == len(agent_names)
        for name in agent_names:
            assert summary["metrics"]["agents"][name]["status"] == "success"


# -----------------------------------------------------------------------
# Logging (append-only)
# -----------------------------------------------------------------------


class TestAgentLogging:
    def test_append_only(self, session):
        session.start_agent("security", "p", attempt=1)
        session.end_agent("security", _make_attempt(success=True))
        session.start_agent("security", "", attempt=2)
        session.end_agent("security", _make_attempt(success=True, attempt_number=2))

        log_path = os.path.join(session.output_dir, "agents", "security.log")
        with open(log_path) as f:
            events = [json.loads(line) for line in f]

        # start + end + start + end = 4 events
        assert len(events) == 4
        types = [e["type"] for e in events]
        assert types == ["start", "end", "start", "end"]


# -----------------------------------------------------------------------
# Atomic writes
# -----------------------------------------------------------------------


class TestAtomicWrites:
    def test_session_json_no_temp_file_left(self, session):
        session.start_agent("security", "p")
        session.end_agent("security", _make_attempt())

        temp_path = os.path.join(session.output_dir, "session.json.tmp")
        assert not os.path.exists(temp_path)

        session_path = os.path.join(session.output_dir, "session.json")
        assert os.path.isfile(session_path)

        # Verify JSON is valid
        with open(session_path) as f:
            data = json.load(f)
        assert data["session"]["id"] == "test-001"


# -----------------------------------------------------------------------
# Agent phase mapping
# -----------------------------------------------------------------------


class TestAgentPhaseMapping:
    def test_covers_known_agents(self):
        """AGENT_PHASE_MAP should cover all standard pipeline agents."""
        expected_agents = {
            "security",
            "exploit-analyst",
            "security-test-generator",
            "performance",
            "testing",
            "quality",
            "orchestrator",
        }
        assert expected_agents == set(AGENT_PHASE_MAP.keys())

    def test_phase_values(self):
        """All phases should be one of the expected values."""
        valid_phases = {"security_analysis", "quality_analysis", "synthesis"}
        for phase in AGENT_PHASE_MAP.values():
            assert phase in valid_phases

    def test_unknown_agent_maps_to_other(self, session):
        """An agent not in AGENT_PHASE_MAP should appear under 'other' phase."""
        session.start_agent("custom-agent", "p")
        session.end_agent("custom-agent", _make_attempt())

        summary = session.get_summary()
        assert "other" in summary["metrics"]["phases"]
        assert summary["metrics"]["phases"]["other"]["agent_count"] == 1


# -----------------------------------------------------------------------
# Dataclass tests
# -----------------------------------------------------------------------


class TestDataclasses:
    def test_agent_attempt_defaults(self):
        a = AgentAttempt(
            attempt_number=1,
            duration_seconds=1.0,
            cost_usd=0.01,
            input_tokens=100,
            output_tokens=50,
            success=True,
            model="test",
            timestamp="2025-01-01T00:00:00",
        )
        assert a.error is None

    def test_agent_attempt_with_error(self):
        a = AgentAttempt(
            attempt_number=1,
            duration_seconds=1.0,
            cost_usd=0.0,
            input_tokens=0,
            output_tokens=0,
            success=False,
            model="test",
            timestamp="2025-01-01T00:00:00",
            error="connection timeout",
        )
        assert a.error == "connection timeout"
        assert not a.success

    def test_agent_metrics_record_defaults(self):
        r = AgentMetricsRecord(agent_name="test-agent")
        assert r.status == "pending"
        assert r.attempts == []
        assert r.final_duration_seconds == 0.0
        assert r.total_cost_usd == 0.0
