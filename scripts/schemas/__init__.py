"""
Pydantic schemas for Argus pipeline validation

This package contains strict Pydantic schemas for all data flowing through
the security analysis pipeline. Schemas enforce data consistency and catch
format errors at pipeline boundaries.
"""

from .unified_finding import UnifiedFinding, Severity, Category, AssetType
from .scanner_outputs import (
    SemgrepOutput,
    TrivyOutput,
    TruffleHogOutput,
    GitleaksOutput,
    CheckovOutput,
    NucleiOutput,
    FalcoOutput,
)
from .correlation import CorrelationInput, CorrelationOutput, CorrelationStatus
from .enrichment import EnrichmentInput, EnrichmentOutput, ThreatContext

__all__ = [
    # Core finding schema
    "UnifiedFinding",
    "Severity",
    "Category",
    "AssetType",
    # Scanner outputs
    "SemgrepOutput",
    "TrivyOutput",
    "TruffleHogOutput",
    "GitleaksOutput",
    "CheckovOutput",
    "NucleiOutput",
    "FalcoOutput",
    # Pipeline schemas
    "CorrelationInput",
    "CorrelationOutput",
    "CorrelationStatus",
    "EnrichmentInput",
    "EnrichmentOutput",
    "ThreatContext",
]
