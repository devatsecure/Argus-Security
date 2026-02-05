"""
Pipeline Stage Interface for Argus Security.

Provides the composable pipeline architecture that replaces the monolithic
orchestrators in ``run_ai_audit.py`` and ``hybrid_analyzer.py``.

Key components:
- ``PipelineStage`` -- Protocol every stage implements
- ``PipelineContext`` -- Shared mutable state flowing through stages
- ``StageResult`` -- Outcome returned by each stage
- ``PipelineOrchestrator`` -- Composes and runs stages in order
- ``BaseStage`` -- Convenience ABC for implementing stages
- ``build_default_stages`` -- Factory for the standard 6-phase pipeline
"""

from .protocol import PipelineStage, PipelineContext, StageResult
from .orchestrator import PipelineOrchestrator
from .base_stage import BaseStage
from .stages import (
    ProjectContextStage,
    ScannerOrchestrationStage,
    AIEnrichmentStage,
    RemediationStage,
    SpontaneousDiscoveryStage,
    MultiAgentReviewStage,
    SandboxValidationStage,
    PolicyGateStage,
    ReportingStage,
    build_default_stages,
)

__all__ = [
    # Core protocol
    "PipelineStage",
    "PipelineContext",
    "StageResult",
    # Orchestrator
    "PipelineOrchestrator",
    # Base class
    "BaseStage",
    # Concrete stages
    "ProjectContextStage",
    "ScannerOrchestrationStage",
    "AIEnrichmentStage",
    "RemediationStage",
    "SpontaneousDiscoveryStage",
    "MultiAgentReviewStage",
    "SandboxValidationStage",
    "PolicyGateStage",
    "ReportingStage",
    # Factory
    "build_default_stages",
]

# Feature 4-6 stages (optional imports — don't break if missing)
try:
    from diff_scanner import IncrementalScanFilter, DiffFindingFilter
    __all__.extend(["IncrementalScanFilter", "DiffFindingFilter"])
except ImportError:
    pass

try:
    from fix_verifier import FixVerificationStage
    __all__.append("FixVerificationStage")
except ImportError:
    pass

try:
    from agent_confidence import AgentConfidenceStage
    __all__.append("AgentConfidenceStage")
except ImportError:
    pass
