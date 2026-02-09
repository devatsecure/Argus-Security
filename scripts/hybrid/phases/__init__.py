"""
Phase modules for the Hybrid Security Analysis pipeline.

Each module contains a standalone function that executes one phase of the
6-phase security analysis pipeline. These were extracted from the monolithic
``hybrid_analyzer.py`` to improve modularity and testability.

Modules:
    phase1_scanning    -- Scanner orchestration (Semgrep, Trivy, Checkov, etc.)
    phase2_enrichment  -- AI enrichment, IRIS analysis, remediation, spontaneous discovery
    phase3_review      -- Multi-agent persona review
    phase4_sandbox     -- Docker-based sandbox validation
    phase5_policy      -- Policy gate evaluation and vulnerability chaining
    phase6_reporting   -- Disclosure reports, v2.0 enrichment, result assembly
"""

from hybrid.phases.phase1_scanning import run_phase1_scanning
from hybrid.phases.phase2_enrichment import run_phase2_enrichment
from hybrid.phases.phase3_review import run_phase3_review
from hybrid.phases.phase4_sandbox import run_phase4_sandbox
from hybrid.phases.phase5_policy import run_phase5_policy
from hybrid.phases.phase6_reporting import run_phase6_reporting

__all__ = [
    "run_phase1_scanning",
    "run_phase2_enrichment",
    "run_phase3_review",
    "run_phase4_sandbox",
    "run_phase5_policy",
    "run_phase6_reporting",
]
