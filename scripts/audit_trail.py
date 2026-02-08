"""
Per-Agent Metrics + Audit Trail for Argus Security Pipeline.

Provides:
- AuditSession: Facade for per-agent metrics tracking
- AgentAttempt: Record of a single agent execution attempt
- AgentMetricsRecord: Aggregate metrics per agent
- Atomic session.json writes (temp+rename)
- Rendered prompt archival
- Append-only per-agent log files
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AgentAttempt:
    """Record of a single agent execution attempt."""

    attempt_number: int
    duration_seconds: float
    cost_usd: float
    input_tokens: int
    output_tokens: int
    success: bool
    model: str
    timestamp: str
    error: str | None = None


@dataclass
class AgentMetricsRecord:
    """Aggregate metrics for a single agent."""

    agent_name: str
    status: str = "pending"  # pending, in_progress, success, failed
    attempts: list[AgentAttempt] = field(default_factory=list)
    final_duration_seconds: float = 0.0
    total_cost_usd: float = 0.0


# Phase mapping for agents
AGENT_PHASE_MAP: dict[str, str] = {
    "security": "security_analysis",
    "exploit-analyst": "security_analysis",
    "security-test-generator": "security_analysis",
    "performance": "quality_analysis",
    "testing": "quality_analysis",
    "quality": "quality_analysis",
    "orchestrator": "synthesis",
}


class AuditSession:
    """Facade for per-agent metrics tracking and audit logging.

    Thread-safe for concurrent agent execution.
    Uses atomic file writes (temp+rename) for crash safety.
    """

    def __init__(
        self,
        session_id: str,
        repo_path: str,
        output_dir: str | None = None,
    ):
        self._session_id = session_id or str(uuid.uuid4())
        self._repo_path = repo_path
        # Default output: .argus/audit/{session_id}/
        self._output_dir = output_dir or os.path.join(repo_path, ".argus", "audit", self._session_id)
        self._agents: dict[str, AgentMetricsRecord] = {}
        self._lock = threading.RLock()
        self._start_time = time.time()
        self._initialized = False

    @property
    def session_id(self) -> str:
        """Return the session identifier."""
        return self._session_id

    @property
    def output_dir(self) -> str:
        """Return the audit output directory path."""
        return self._output_dir

    def initialize(self) -> None:
        """Create audit directory structure.

        Safe to call multiple times (idempotent).
        """
        if self._initialized:
            return
        os.makedirs(os.path.join(self._output_dir, "agents"), exist_ok=True)
        os.makedirs(os.path.join(self._output_dir, "prompts"), exist_ok=True)
        self._save_session()
        self._initialized = True
        logger.info("Audit session initialized: %s", self._output_dir)

    def start_agent(
        self,
        agent_name: str,
        rendered_prompt: str = "",
        attempt: int = 1,
    ) -> None:
        """Record agent start. Save rendered prompt on first attempt."""
        with self._lock:
            if agent_name not in self._agents:
                self._agents[agent_name] = AgentMetricsRecord(agent_name=agent_name)
            self._agents[agent_name].status = "in_progress"

        # Save rendered prompt (first attempt only)
        if attempt == 1 and rendered_prompt:
            self._save_prompt(agent_name, rendered_prompt)

        # Append to agent log
        self._log_agent_event(agent_name, "start", {"attempt": attempt})
        logger.info("Audit: Agent %s started (attempt %d)", agent_name, attempt)

    def end_agent(self, agent_name: str, result: AgentAttempt) -> None:
        """Record agent completion. Update session.json atomically."""
        with self._lock:
            record = self._agents.get(agent_name)
            if not record:
                record = AgentMetricsRecord(agent_name=agent_name)
                self._agents[agent_name] = record

            record.attempts.append(result)
            record.total_cost_usd = sum(a.cost_usd for a in record.attempts)

            if result.success:
                record.status = "success"
                record.final_duration_seconds = result.duration_seconds
            else:
                record.status = "failed"

            self._save_session()

        self._log_agent_event(
            agent_name,
            "end",
            {
                "attempt": result.attempt_number,
                "success": result.success,
                "duration_seconds": result.duration_seconds,
                "cost_usd": result.cost_usd,
                **({"error": result.error} if result.error else {}),
            },
        )
        logger.info(
            "Audit: Agent %s ended (success=%s, cost=$%.4f)",
            agent_name,
            result.success,
            result.cost_usd,
        )

    def get_summary(self) -> dict[str, Any]:
        """Return session metrics summary."""
        with self._lock:
            total_duration = time.time() - self._start_time
            total_cost = sum(r.total_cost_usd for r in self._agents.values())

            # Calculate per-phase metrics
            phases: dict[str, dict[str, Any]] = {}
            for agent_name, record in self._agents.items():
                phase = AGENT_PHASE_MAP.get(agent_name, "other")
                if phase not in phases:
                    phases[phase] = {
                        "duration_seconds": 0.0,
                        "cost_usd": 0.0,
                        "agent_count": 0,
                    }
                phases[phase]["duration_seconds"] += record.final_duration_seconds
                phases[phase]["cost_usd"] += record.total_cost_usd
                phases[phase]["agent_count"] += 1

            # Add duration percentages
            for phase_data in phases.values():
                pct = phase_data["duration_seconds"] / total_duration * 100 if total_duration > 0 else 0.0
                phase_data["duration_percentage"] = round(pct, 1)

            return {
                "session": {
                    "id": self._session_id,
                    "repo_path": self._repo_path,
                    "status": self._get_session_status(),
                    "created_at": datetime.fromtimestamp(self._start_time, tz=timezone.utc).isoformat(),
                    "total_duration_seconds": round(total_duration, 2),
                },
                "metrics": {
                    "total_duration_seconds": round(total_duration, 2),
                    "total_cost_usd": round(total_cost, 4),
                    "phases": phases,
                    "agents": {name: asdict(record) for name, record in self._agents.items()},
                },
            }

    def _get_session_status(self) -> str:
        """Derive overall session status from agent statuses."""
        if any(r.status == "in_progress" for r in self._agents.values()):
            return "in_progress"
        if any(r.status == "failed" for r in self._agents.values()):
            return "completed_with_errors"
        if all(r.status == "success" for r in self._agents.values()) and self._agents:
            return "completed"
        return "pending"

    def _save_session(self) -> None:
        """Atomic write session.json using temp+rename pattern."""
        session_path = os.path.join(self._output_dir, "session.json")
        temp_path = session_path + ".tmp"
        data = self.get_summary()
        try:
            with open(temp_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(temp_path, session_path)  # Atomic on POSIX
        except Exception:
            # Clean up temp file on failure
            with contextlib.suppress(OSError):
                os.unlink(temp_path)
            raise

    def _save_prompt(self, agent_name: str, rendered_prompt: str) -> None:
        """Save rendered prompt snapshot for reproducibility."""
        prompt_path = os.path.join(self._output_dir, "prompts", f"{agent_name}.md")
        header = (
            f"# Prompt Snapshot: {agent_name}\n\n"
            f"**Session:** {self._session_id}\n"
            f"**Saved:** {datetime.now(tz=timezone.utc).isoformat()}\n\n"
            f"---\n\n"
        )
        try:
            with open(prompt_path, "w") as f:
                f.write(header + rendered_prompt)
        except Exception as e:
            logger.warning("Failed to save prompt for %s: %s", agent_name, e)

    def _log_agent_event(self, agent_name: str, event_type: str, data: dict[str, Any]) -> None:
        """Append event to agent-specific log file (append-only)."""
        log_path = os.path.join(self._output_dir, "agents", f"{agent_name}.log")
        event = {
            "type": event_type,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "data": data,
        }
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.warning("Failed to log event for %s: %s", agent_name, e)
