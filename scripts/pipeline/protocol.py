"""
Pipeline Protocol - Defines the stage interface and shared context.

Every pipeline stage implements the ``PipelineStage`` protocol. Stages are
composed into an ordered pipeline by ``PipelineOrchestrator``.

The ``PipelineContext`` dataclass holds all mutable state that flows through
the pipeline.  Stages read what they need and write their contributions.

The ``StageResult`` dataclass captures the outcome of a single stage
execution for logging, metrics, and error reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class PipelineContext:
    """Shared mutable state flowing through the pipeline.

    Each stage reads what it needs and writes its contributions.  This
    replaces the scattered local variables, class attributes, and ad-hoc
    dicts that previously connected phases.

    Attributes
    ----------
    config : dict
        Flat configuration dict produced by ``config_loader.build_unified_config``.
    target_path : str
        Filesystem path to the codebase being analyzed.
    ai_client : Any
        The LLM client (``LLMManager``, Anthropic client, etc.).  Set by the
        provider-initialization stage.
    provider : str
        Active AI provider name (``anthropic``, ``openai``, ``ollama``).
    model : str
        Active model identifier.
    cost_tracker : Any
        ``CostCircuitBreaker`` instance for enforcing cost limits.
    metrics : Any
        ``ReviewMetrics`` instance for observability.
    findings : list
        The primary mutable data.  Starts empty; scanners append findings;
        later stages enrich, filter, and validate them.
    phase_timings : dict
        Wall-clock seconds per stage, keyed by ``stage.name``.
    threat_model : dict | None
        Threat model dict (STRIDE analysis), populated by the threat-modeling
        stage if enabled.
    project_context : Any
        Detected ``ProjectContext`` for context-aware triage.
    policy_gate_result : dict | None
        Pass/fail result from Rego/OPA policy evaluation.
    vulnerability_chains : dict | None
        Attack-chain data from the vulnerability-chaining engine.
    reports : dict
        Generated report content keyed by format (``sarif``, ``json``, ``md``).
    report_paths : dict
        Filesystem paths to saved reports.
    agent_reports : dict
        Raw agent output keyed by agent name (multi-agent mode).
    consensus_results : list
        Findings after consensus building.
    errors : list
        Non-fatal errors collected during the run.
    """

    # -- Immutable configuration --
    config: Dict[str, Any] = field(default_factory=dict)
    target_path: str = ""

    # -- AI client state (set during initialization) --
    ai_client: Any = None
    provider: str = ""
    model: str = ""

    # -- Cost tracking --
    cost_tracker: Any = None

    # -- Metrics --
    metrics: Any = None

    # -- Primary pipeline data --
    findings: List[Any] = field(default_factory=list)

    # -- Phase timings --
    phase_timings: Dict[str, float] = field(default_factory=dict)

    # -- Supplementary stage outputs --
    threat_model: Optional[Dict[str, Any]] = None
    project_context: Any = None
    policy_gate_result: Optional[Dict[str, Any]] = None
    vulnerability_chains: Optional[Dict[str, Any]] = None

    # -- Reports --
    reports: Dict[str, str] = field(default_factory=dict)
    report_paths: Dict[str, str] = field(default_factory=dict)

    # -- Multi-agent data --
    agent_reports: Dict[str, str] = field(default_factory=dict)
    consensus_results: List[Any] = field(default_factory=list)

    # -- Incremental scanning (Feature 4) --
    changed_files: Optional[List[Any]] = None

    # -- Error collection --
    errors: List[str] = field(default_factory=list)


@dataclass
class StageResult:
    """Outcome returned by each pipeline stage.

    Attributes
    ----------
    success : bool
        Whether the stage completed without fatal errors.
    stage_name : str
        Identifier matching ``PipelineStage.name``.
    duration_seconds : float
        Wall-clock execution time.
    findings_before : int
        Number of findings in context before execution.
    findings_after : int
        Number of findings in context after execution.
    error : str | None
        Human-readable error message if the stage failed.
    skipped : bool
        ``True`` if the stage was intentionally skipped (preconditions not met).
    skip_reason : str
        Why the stage was skipped.
    metadata : dict
        Arbitrary stage-specific metadata (e.g., scanner counts, costs).
    """

    success: bool
    stage_name: str
    duration_seconds: float = 0.0
    findings_before: int = 0
    findings_after: int = 0
    error: Optional[str] = None
    skipped: bool = False
    skip_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class PipelineStage(Protocol):
    """Protocol that every pipeline stage must implement.

    Stages are composable, independently testable units that:
    1. Declare their name and dependencies
    2. Check whether they should run (preconditions)
    3. Execute their logic, mutating ``PipelineContext``
    4. Return a ``StageResult`` with outcome metadata

    The use of ``Protocol`` (structural subtyping) means stages do not
    need to inherit from a common base class.  Any object with the right
    attributes and methods satisfies the protocol.

    Example
    -------
    ::

        class MyStage:
            name = "my_stage"
            display_name = "My Custom Stage"
            phase_number = 2.5
            required_stages: list[str] = []

            def should_run(self, ctx: PipelineContext) -> bool:
                return True

            def execute(self, ctx: PipelineContext) -> StageResult:
                # do work, mutate ctx
                return StageResult(success=True, stage_name=self.name)

            def rollback(self, ctx: PipelineContext) -> None:
                pass
    """

    @property
    def name(self) -> str:
        """Unique stage identifier, e.g. ``phase1_scanner_orchestration``."""
        ...

    @property
    def display_name(self) -> str:
        """Human-readable name, e.g. ``Phase 1: Scanner Orchestration``."""
        ...

    @property
    def phase_number(self) -> float:
        """Numeric phase for ordering.

        Uses float to accommodate sub-phases (2.3, 2.5, 5.5, etc.).
        """
        ...

    @property
    def required_stages(self) -> List[str]:
        """Names of stages that must complete before this one.

        Empty list means no dependencies.
        """
        ...

    def should_run(self, ctx: PipelineContext) -> bool:
        """Check preconditions.  Return ``False`` to skip this stage.

        Examples: Phase 2 skips if no findings exist from Phase 1;
        Phase 4 skips if sandbox validation is disabled.
        """
        ...

    def execute(self, ctx: PipelineContext) -> StageResult:
        """Execute the stage logic.

        Must mutate ``ctx`` (findings, phase_timings, metrics, etc.).
        Must handle its own errors gracefully (log and continue).
        """
        ...

    def rollback(self, ctx: PipelineContext) -> None:
        """Optional cleanup if the stage fails.

        Default implementations should be no-ops.
        """
        ...
