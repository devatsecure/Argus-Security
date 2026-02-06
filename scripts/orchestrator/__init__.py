"""Orchestrator Module

Main orchestration package that coordinates all audit components.

This module provides a unified interface for:
- File selection and prioritization (FileSelector)
- Cost tracking and enforcement (CostCircuitBreaker)
- LLM provider management (LLMManager)
- Report generation (ReportGenerator)
- Metrics collection and observability (ReviewMetrics)
- Audit orchestration (AuditOrchestrator)

Usage:
------
    from orchestrator import AuditOrchestrator, CostCircuitBreaker, ReviewMetrics

    orchestrator = AuditOrchestrator(repo_path, config)
    blockers, suggestions, metrics = orchestrator.run_audit()

Components:
-----------
- main.py: AuditOrchestrator - Central coordinator for entire audit workflow
- file_selector.py: FileSelector - File discovery and prioritization
- cost_tracker.py: CostCircuitBreaker - Runtime cost enforcement with guardrails
- llm_manager.py: LLMManager - LLM provider detection and client management
- report_generator.py: ReportGenerator - Multi-format report generation (Markdown, SARIF, JSON)
- metrics_collector.py: ReviewMetrics - Audit metrics tracking and persistence
"""

from .cost_tracker import CostCircuitBreaker, CostLimitExceededError
from .file_selector import FileSelector
from .llm_manager import (
    LLMManager,
    ConsensusBuilder,
    call_llm_api,
    detect_ai_provider,
    get_ai_client,
    get_model_name,
    get_working_model_with_fallback,
    estimate_call_cost,
    calculate_actual_cost,
)
from .main import AuditOrchestrator, run_audit
from .metrics_collector import ReviewMetrics
from .report_generator import ReportGenerator

__all__ = [
    "AuditOrchestrator",
    "calculate_actual_cost",
    "call_llm_api",
    "ConsensusBuilder",
    "CostCircuitBreaker",
    "CostLimitExceededError",
    "detect_ai_provider",
    "estimate_call_cost",
    "FileSelector",
    "get_ai_client",
    "get_model_name",
    "get_working_model_with_fallback",
    "LLMManager",
    "ReportGenerator",
    "ReviewMetrics",
    "run_audit",
]

__version__ = "1.0.0"
