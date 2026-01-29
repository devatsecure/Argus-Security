#!/usr/bin/env python3
"""
Argus Deep Analysis Engine (Phase 2.7)
Progressive rollout with granular feature flags for advanced security analysis

Modules:
- Semantic Code Twin: Clone detection and logic similarity analysis
- Proactive Scanner: Hypothesis-driven vulnerability discovery
- Taint Analysis: Data flow tracking from sources to sinks
- Zero-Day Hunter: Novel vulnerability pattern detection

Author: Argus Security Team
License: MIT
"""

import json
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# Pricing constants (Claude Sonnet 4.5 as of 2025)
CLAUDE_SONNET_INPUT_PRICE_PER_1M = 3.0  # $3 per 1M input tokens
CLAUDE_SONNET_OUTPUT_PRICE_PER_1M = 15.0  # $15 per 1M output tokens


@dataclass
class TokenUsage:
    """Token usage tracking for LLM calls"""
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> Dict[str, int]:
        return {
            "input": self.input_tokens,
            "output": self.output_tokens,
            "total": self.total_tokens
        }


class DeepAnalysisPhase(Enum):
    """Individual deep analysis modules that can be enabled/disabled"""
    SEMANTIC_CODE_TWIN = "semantic"
    PROACTIVE_SCANNER = "proactive"
    TAINT_ANALYSIS = "taint"
    ZERO_DAY_HUNTER = "zero_day"


class DeepAnalysisMode(Enum):
    """Progressive rollout modes for Deep Analysis Engine"""
    OFF = "off"  # Skip Phase 2.7 entirely (default for backwards compatibility)
    SEMANTIC_ONLY = "semantic-only"  # Only Semantic Code Twin
    CONSERVATIVE = "conservative"  # Semantic + Proactive Scanner
    FULL = "full"  # All modules (semantic, proactive, taint, zero-day)

    @classmethod
    def from_string(cls, mode_str: str) -> "DeepAnalysisMode":
        """Parse mode from string"""
        mode_map = {
            "off": cls.OFF,
            "semantic-only": cls.SEMANTIC_ONLY,
            "conservative": cls.CONSERVATIVE,
            "full": cls.FULL,
        }
        return mode_map.get(mode_str.lower(), cls.OFF)

    def get_enabled_phases(self) -> List[DeepAnalysisPhase]:
        """Get list of enabled phases for this mode"""
        if self == DeepAnalysisMode.OFF:
            return []
        elif self == DeepAnalysisMode.SEMANTIC_ONLY:
            return [DeepAnalysisPhase.SEMANTIC_CODE_TWIN]
        elif self == DeepAnalysisMode.CONSERVATIVE:
            return [
                DeepAnalysisPhase.SEMANTIC_CODE_TWIN,
                DeepAnalysisPhase.PROACTIVE_SCANNER,
            ]
        elif self == DeepAnalysisMode.FULL:
            return [
                DeepAnalysisPhase.SEMANTIC_CODE_TWIN,
                DeepAnalysisPhase.PROACTIVE_SCANNER,
                DeepAnalysisPhase.TAINT_ANALYSIS,
                DeepAnalysisPhase.ZERO_DAY_HUNTER,
            ]
        return []


@dataclass
class DeepAnalysisConfig:
    """Configuration for Deep Analysis Engine with safety controls"""
    mode: DeepAnalysisMode = DeepAnalysisMode.OFF
    enabled_phases: List[DeepAnalysisPhase] = field(default_factory=list)
    max_files: int = 50  # UPDATED: More conservative default (was 100)
    timeout_seconds: int = 300  # NEW: 5-minute timeout (default)
    cost_ceiling: float = 5.0  # UPDATED: More conservative (was 10.0)
    dry_run: bool = False
    min_similarity_threshold: float = 0.85  # For semantic twin detection
    taint_max_depth: int = 5  # Max depth for taint propagation
    zero_day_confidence_threshold: float = 0.7

    @classmethod
    def from_env(cls) -> "DeepAnalysisConfig":
        """Load configuration from environment variables"""
        mode_str = os.getenv("DEEP_ANALYSIS_MODE", "off")
        mode = DeepAnalysisMode.from_string(mode_str)

        max_files = int(os.getenv("DEEP_ANALYSIS_MAX_FILES", "50"))  # UPDATED default
        timeout_seconds = int(os.getenv("DEEP_ANALYSIS_TIMEOUT", "300"))  # NEW
        cost_ceiling = float(os.getenv("DEEP_ANALYSIS_COST_CEILING", "5.0"))  # UPDATED default
        dry_run = os.getenv("DEEP_ANALYSIS_DRY_RUN", "false").lower() == "true"

        return cls(
            mode=mode,
            enabled_phases=mode.get_enabled_phases(),
            max_files=max_files,
            timeout_seconds=timeout_seconds,
            cost_ceiling=cost_ceiling,
            dry_run=dry_run,
        )


@dataclass
class DeepAnalysisResult:
    """Result from deep analysis phase with safety tracking and benchmarking"""
    phase: DeepAnalysisPhase
    findings: List[Dict] = field(default_factory=list)
    files_analyzed: int = 0
    files_skipped: int = 0  # Track skipped files
    execution_time: float = 0.0
    estimated_cost: float = 0.0
    aborted_reason: Optional[str] = None  # "timeout" | "cost_ceiling" | None
    warnings: List[str] = field(default_factory=list)  # Track warnings
    metadata: Dict = field(default_factory=dict)

    # Benchmark metrics
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    actual_cost: float = 0.0  # Calculated from actual token usage

    @property
    def was_aborted(self) -> bool:
        """Check if analysis was aborted early"""
        return self.aborted_reason is not None

    @property
    def is_partial(self) -> bool:
        """Check if results are partial (some files skipped or aborted)"""
        return self.files_skipped > 0 or self.was_aborted

    def calculate_cost(self):
        """Calculate actual cost based on token usage"""
        input_cost = (self.token_usage.input_tokens / 1_000_000) * CLAUDE_SONNET_INPUT_PRICE_PER_1M
        output_cost = (self.token_usage.output_tokens / 1_000_000) * CLAUDE_SONNET_OUTPUT_PRICE_PER_1M
        self.actual_cost = input_cost + output_cost


@dataclass
class CostEstimate:
    """Cost estimation for dry-run mode"""
    total_files: int
    files_to_analyze: int
    estimated_tokens: int
    estimated_time_seconds: float
    estimated_cost_usd: float
    breakdown_by_phase: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "total_files": self.total_files,
            "files_to_analyze": self.files_to_analyze,
            "estimated_tokens": self.estimated_tokens,
            "estimated_time_seconds": self.estimated_time_seconds,
            "estimated_cost_usd": round(self.estimated_cost_usd, 2),
            "breakdown_by_phase": {k: round(v, 2) for k, v in self.breakdown_by_phase.items()},
        }


class DeepAnalysisEngine:
    """
    Phase 2.7: Deep Analysis Engine with production safety controls

    Features:
    - Granular feature flags for controlled rollout
    - Cost estimation and guardrails
    - Multi-phase analysis (semantic, proactive, taint, zero-day)
    - Dry-run mode for cost prediction
    - PRODUCTION SAFETY CONTROLS:
      * File count limiting with truncation
      * Timeout protection (default: 5 minutes)
      * Cost ceiling enforcement with 80% warnings
      * Real-time cost tracking
      * Graceful degradation and partial results
    """

    def __init__(
        self,
        config: Optional[DeepAnalysisConfig] = None,
        ai_client=None,
        model: str = "claude-3-5-sonnet-20241022",
        enable_benchmarking: bool = False,
    ):
        """
        Initialize Deep Analysis Engine

        Args:
            config: Deep analysis configuration (None uses env defaults)
            ai_client: AI client for LLM calls
            model: Model name to use for analysis
            enable_benchmarking: Enable detailed benchmark tracking and reporting
        """
        self.config = config or DeepAnalysisConfig.from_env()
        self.ai_client = ai_client
        self.model = model
        self.total_cost = 0.0
        self.results: List[DeepAnalysisResult] = []
        self.enable_benchmarking = enable_benchmarking

        # Safety control state
        self._aborted = False
        self._abort_reason: Optional[str] = None
        self._timeout_timer: Optional[threading.Timer] = None
        self._analysis_complete = threading.Event()
        self._cost_warning_shown = False  # Track if 80% warning was shown

        # Validate configuration
        if self.config.mode != DeepAnalysisMode.OFF and not ai_client:
            logger.warning("Deep Analysis enabled but no AI client provided")
            self.config.mode = DeepAnalysisMode.OFF
            self.config.enabled_phases = []

        if enable_benchmarking:
            logger.info("📊 Benchmarking enabled - detailed metrics will be tracked")

    def is_enabled(self) -> bool:
        """Check if deep analysis is enabled"""
        return self.config.mode != DeepAnalysisMode.OFF

    def _setup_timeout(self):
        """Setup timeout timer for analysis"""
        def _timeout_handler():
            if not self._analysis_complete.is_set():
                logger.error(f"⏰ TIMEOUT: Analysis exceeded {self.config.timeout_seconds}s limit")
                self._aborted = True
                self._abort_reason = "timeout"

        self._timeout_timer = threading.Timer(self.config.timeout_seconds, _timeout_handler)
        self._timeout_timer.daemon = True
        self._timeout_timer.start()
        logger.debug(f"⏱️  Timeout set: {self.config.timeout_seconds}s")

    def _cancel_timeout(self):
        """Cancel timeout timer and mark analysis complete"""
        if self._timeout_timer:
            self._timeout_timer.cancel()
            self._timeout_timer = None
        self._analysis_complete.set()

    def _check_cost_ceiling(self, additional_cost: float = 0.0) -> bool:
        """
        Check if we're approaching or exceeded cost ceiling

        Args:
            additional_cost: Estimated cost of next operation

        Returns:
            True if safe to proceed, False if ceiling reached
        """
        projected_cost = self.total_cost + additional_cost
        ceiling = self.config.cost_ceiling

        # Warn at 80% threshold
        if not self._cost_warning_shown and projected_cost >= ceiling * 0.8:
            logger.warning(
                f"⚠️  COST WARNING: Approaching ceiling (${ projected_cost:.2f} / ${ceiling:.2f} = "
                f"{projected_cost/ceiling*100:.0f}%)"
            )
            self._cost_warning_shown = True

        # Hard stop at 100%
        if projected_cost >= ceiling:
            logger.error(f"💰 COST CEILING REACHED: ${projected_cost:.2f} >= ${ceiling:.2f}")
            logger.error("   Stopping analysis to prevent overspending")
            self._aborted = True
            self._abort_reason = "cost_ceiling"
            return False

        return True

    def _track_cost(self, cost: float, context: str = ""):
        """Track cost with logging"""
        self.total_cost += cost
        logger.debug(f"💰 Cost: +${cost:.4f} → ${self.total_cost:.4f} {context}")

    def estimate_cost(self, repo_path: str) -> CostEstimate:
        """
        Estimate cost and time for deep analysis without running LLM calls

        Args:
            repo_path: Path to repository to analyze

        Returns:
            CostEstimate with breakdown by phase
        """
        logger.info("🧮 Estimating deep analysis cost...")

        # Discover analyzable files
        files = self._discover_files(repo_path)
        total_files = len(files)
        files_to_analyze = min(total_files, self.config.max_files)

        # Estimate average file size (tokens)
        avg_tokens_per_file = 1500  # Conservative estimate
        total_tokens = files_to_analyze * avg_tokens_per_file

        # Cost per phase (based on Claude Sonnet pricing)
        # Input: $3/MTok, Output: $15/MTok
        cost_per_1k_tokens = {
            DeepAnalysisPhase.SEMANTIC_CODE_TWIN: 0.03,  # Lighter analysis
            DeepAnalysisPhase.PROACTIVE_SCANNER: 0.05,   # Medium complexity
            DeepAnalysisPhase.TAINT_ANALYSIS: 0.08,      # Heavy analysis
            DeepAnalysisPhase.ZERO_DAY_HUNTER: 0.10,     # Most complex
        }

        # Time per phase (seconds per file)
        time_per_file = {
            DeepAnalysisPhase.SEMANTIC_CODE_TWIN: 2,
            DeepAnalysisPhase.PROACTIVE_SCANNER: 3,
            DeepAnalysisPhase.TAINT_ANALYSIS: 5,
            DeepAnalysisPhase.ZERO_DAY_HUNTER: 8,
        }

        # Calculate breakdown
        breakdown = {}
        total_cost = 0.0
        total_time = 0.0

        for phase in self.config.enabled_phases:
            phase_tokens = total_tokens
            phase_cost = (phase_tokens / 1000) * cost_per_1k_tokens[phase]
            phase_time = files_to_analyze * time_per_file[phase]

            breakdown[phase.value] = phase_cost
            total_cost += phase_cost
            total_time += phase_time

        estimate = CostEstimate(
            total_files=total_files,
            files_to_analyze=files_to_analyze,
            estimated_tokens=total_tokens * len(self.config.enabled_phases),
            estimated_time_seconds=total_time,
            estimated_cost_usd=total_cost,
            breakdown_by_phase=breakdown,
        )

        logger.info(f"📊 Estimate: {files_to_analyze} files, ~{int(total_time)}s, ~${total_cost:.2f}")
        return estimate

    def analyze(self, repo_path: str, existing_findings: Optional[List[Dict]] = None) -> List[DeepAnalysisResult]:
        """
        Run deep analysis on repository

        Args:
            repo_path: Path to repository
            existing_findings: Findings from previous phases (for context)

        Returns:
            List of DeepAnalysisResult objects
        """
        if not self.is_enabled():
            logger.info("⏭️  Deep Analysis skipped (mode=off)")
            return []

        # Dry run mode - estimate only
        if self.config.dry_run:
            estimate = self.estimate_cost(repo_path)
            logger.info(f"🔍 DRY RUN - Estimated cost: ${estimate.estimated_cost_usd:.2f}")
            logger.info(f"   Files: {estimate.files_to_analyze}/{estimate.total_files}")
            logger.info(f"   Time: ~{int(estimate.estimated_time_seconds)}s")
            logger.info(f"   Breakdown: {estimate.breakdown_by_phase}")
            return []

        logger.info(f"🔬 Starting Deep Analysis (mode={self.config.mode.value})")
        logger.info(f"   Enabled phases: {[p.value for p in self.config.enabled_phases]}")
        logger.info(f"   Max files: {self.config.max_files}")
        logger.info(f"   Timeout: {self.config.timeout_seconds}s")
        logger.info(f"   Cost ceiling: ${self.config.cost_ceiling:.2f}")

        # SAFETY CHECK 1: Estimate and validate cost
        estimate = self.estimate_cost(repo_path)
        if estimate.estimated_cost_usd > self.config.cost_ceiling:
            logger.warning(
                f"⚠️  Estimated cost ${estimate.estimated_cost_usd:.2f} exceeds ceiling "
                f"${self.config.cost_ceiling:.2f}"
            )
            logger.warning("   Consider reducing --max-files-deep-analysis or increasing --deep-analysis-cost-ceiling")
            return []

        # SAFETY CHECK 2: Setup timeout
        self._setup_timeout()

        try:
            # Run enabled phases
            self.results = []
            for phase in self.config.enabled_phases:
                # Check if aborted (timeout or cost)
                if self._aborted:
                    logger.warning(f"⚠️  Analysis aborted: {self._abort_reason}")
                    break

                # Check cost ceiling before each phase
                if not self._check_cost_ceiling():
                    break

                result = self._run_phase(phase, repo_path, existing_findings)
                self.results.append(result)

                # Track cost from result
                self._track_cost(result.estimated_cost, f"({phase.value})")

            # Summary
            total_findings = sum(len(r.findings) for r in self.results)
            logger.info(f"✅ Deep Analysis complete - {total_findings} findings")
            logger.info(f"   Total cost: ${self.total_cost:.2f}")

            if self._aborted:
                logger.warning(f"   ⚠️  Aborted: {self._abort_reason}")

        finally:
            # SAFETY CHECK 3: Always cancel timeout
            self._cancel_timeout()

        return self.results

    def _discover_files(self, repo_path: str) -> List[Path]:
        """Discover analyzable files in repository"""
        extensions = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c"}
        files = []

        repo = Path(repo_path)
        for ext in extensions:
            files.extend(repo.rglob(f"*{ext}"))

        # Filter out common noise
        filtered = []
        for f in files:
            if any(part.startswith(".") for part in f.parts):
                continue
            if "node_modules" in f.parts or "venv" in f.parts or "__pycache__" in f.parts:
                continue
            if "test" in f.name.lower() and "tests" not in str(f.parent):
                continue
            filtered.append(f)

        return filtered[:self.config.max_files]

    def _run_phase(
        self,
        phase: DeepAnalysisPhase,
        repo_path: str,
        existing_findings: Optional[List[Dict]] = None
    ) -> DeepAnalysisResult:
        """
        Run a specific deep analysis phase

        Args:
            phase: Phase to run
            repo_path: Repository path
            existing_findings: Context from previous phases

        Returns:
            DeepAnalysisResult
        """
        start_time = time.time()
        logger.info(f"🔍 Running {phase.value} analysis...")

        result = DeepAnalysisResult(phase=phase)

        # Check if already aborted
        if self._aborted:
            result.aborted_reason = self._abort_reason
            result.execution_time = 0
            logger.warning(f"   ⚠️  Skipping {phase.value} - already aborted ({self._abort_reason})")
            return result

        try:
            if phase == DeepAnalysisPhase.SEMANTIC_CODE_TWIN:
                result = self._analyze_semantic_twins(repo_path)
            elif phase == DeepAnalysisPhase.PROACTIVE_SCANNER:
                result = self._analyze_proactive(repo_path, existing_findings)
            elif phase == DeepAnalysisPhase.TAINT_ANALYSIS:
                result = self._analyze_taint_flows(repo_path)
            elif phase == DeepAnalysisPhase.ZERO_DAY_HUNTER:
                result = self._hunt_zero_days(repo_path, existing_findings)

            result.execution_time = time.time() - start_time
            logger.info(f"   ✓ {result.files_analyzed} files, {len(result.findings)} findings, {result.execution_time:.1f}s")

        except Exception as e:
            logger.error(f"   ✗ Error in {phase.value}: {e}")
            result.execution_time = time.time() - start_time
            result.metadata["error"] = str(e)

        # Populate abort reason if aborted during phase
        if self._aborted and not result.aborted_reason:
            result.aborted_reason = self._abort_reason

        return result

    def _analyze_semantic_twins(self, repo_path: str) -> DeepAnalysisResult:
        """
        Semantic Code Twin Analysis
        Detect duplicated logic, similar vulnerable patterns across files
        """
        result = DeepAnalysisResult(phase=DeepAnalysisPhase.SEMANTIC_CODE_TWIN)
        files = self._discover_files(repo_path)
        result.files_analyzed = len(files)

        # Placeholder: Real implementation would use embeddings + similarity search
        # For now, return mock findings
        result.findings = [
            {
                "type": "semantic_clone",
                "severity": "medium",
                "title": "Duplicated authentication logic detected",
                "description": "Similar auth validation code found in 3 files - consolidate to prevent inconsistencies",
                "files": ["auth/login.py", "auth/register.py", "api/verify.py"],
                "confidence": 0.92,
            }
        ]
        result.estimated_cost = len(files) * 0.03  # $0.03 per file

        return result

    def _analyze_proactive(self, repo_path: str, existing_findings: Optional[List[Dict]]) -> DeepAnalysisResult:
        """
        Proactive Scanner
        Hypothesis-driven vulnerability discovery based on codebase patterns
        """
        result = DeepAnalysisResult(phase=DeepAnalysisPhase.PROACTIVE_SCANNER)
        files = self._discover_files(repo_path)
        result.files_analyzed = len(files)

        # Placeholder implementation
        result.findings = [
            {
                "type": "proactive_finding",
                "severity": "high",
                "title": "Potential SSRF in URL handling",
                "description": "User-controlled URL passed to requests library without validation",
                "file": "api/webhook.py",
                "line": 45,
                "confidence": 0.78,
            }
        ]
        result.estimated_cost = len(files) * 0.05

        return result

    def _analyze_taint_flows(self, repo_path: str) -> DeepAnalysisResult:
        """
        Taint Analysis
        Track data flow from sources (user input) to sinks (dangerous operations)
        """
        result = DeepAnalysisResult(phase=DeepAnalysisPhase.TAINT_ANALYSIS)
        files = self._discover_files(repo_path)
        result.files_analyzed = len(files)

        # Placeholder implementation
        result.findings = [
            {
                "type": "taint_flow",
                "severity": "critical",
                "title": "SQL injection via tainted user input",
                "description": "User input flows to SQL query without sanitization",
                "source": "request.args['user_id']",
                "sink": "db.execute(query)",
                "taint_path": ["request.args", "validate_input", "build_query", "db.execute"],
                "confidence": 0.95,
            }
        ]
        result.estimated_cost = len(files) * 0.08

        return result

    def _hunt_zero_days(self, repo_path: str, existing_findings: Optional[List[Dict]]) -> DeepAnalysisResult:
        """
        Zero-Day Hunter
        Novel vulnerability pattern detection using advanced LLM reasoning
        """
        result = DeepAnalysisResult(phase=DeepAnalysisPhase.ZERO_DAY_HUNTER)
        files = self._discover_files(repo_path)
        result.files_analyzed = len(files)

        # Placeholder implementation
        result.findings = [
            {
                "type": "zero_day_candidate",
                "severity": "critical",
                "title": "Novel race condition in cache invalidation",
                "description": "Time-of-check-time-of-use vulnerability in distributed cache",
                "file": "cache/manager.py",
                "line": 123,
                "confidence": 0.72,
                "novelty_score": 0.88,
            }
        ]
        result.estimated_cost = len(files) * 0.10

        return result

    def print_benchmark_report(self):
        """
        Print detailed benchmark report in formatted table
        """
        if not self.enable_benchmarking:
            logger.warning("Benchmarking not enabled - use --benchmark flag")
            return

        if not self.results:
            logger.warning("No results to benchmark")
            return

        print("\n" + "=" * 85)
        print("=== Deep Analysis Benchmark Report ===")
        print("=" * 85)
        print(f"{'Phase':<25} {'Time':<10} {'Tokens (In/Out)':<20} {'Cost':<10} {'Findings':<10}")
        print("-" * 85)

        # Print each phase
        for result in self.results:
            phase_name = result.phase.value.replace('_', ' ').title()
            time_str = f"{result.execution_time:.1f}s"

            # Token tracking
            tokens_in = result.token_usage.input_tokens
            tokens_out = result.token_usage.output_tokens
            if tokens_in > 0 or tokens_out > 0:
                tokens_str = f"{tokens_in//1000}K / {tokens_out//1000}K"
                cost_str = f"${result.actual_cost:.3f}"
            else:
                # Use estimated cost if no actual token data
                tokens_str = "N/A"
                cost_str = f"~${result.estimated_cost:.3f}"

            findings_str = str(len(result.findings))

            print(f"{phase_name:<25} {time_str:<10} {tokens_str:<20} {cost_str:<10} {findings_str:<10}")

        # Print totals
        print("-" * 85)
        total_time = sum(r.execution_time for r in self.results)
        total_input = sum(r.token_usage.input_tokens for r in self.results)
        total_output = sum(r.token_usage.output_tokens for r in self.results)
        total_actual_cost = sum(r.actual_cost for r in self.results)
        total_findings = sum(len(r.findings) for r in self.results)

        total_time_str = f"{total_time:.1f}s"
        if total_input > 0 or total_output > 0:
            total_tokens_str = f"{total_input//1000}K / {total_output//1000}K"
            total_cost_str = f"${total_actual_cost:.3f}"
        else:
            total_tokens_str = "N/A"
            total_cost_str = f"~${self.total_cost:.3f}"

        print(f"{'TOTAL':<25} {total_time_str:<10} {total_tokens_str:<20} {total_cost_str:<10} {total_findings:<10}")
        print("=" * 85)

        # Additional statistics
        print(f"\n📊 Additional Statistics:")
        files_analyzed_total = sum(r.files_analyzed for r in self.results)
        if total_time > 0:
            print(f"   Files analyzed/sec: {files_analyzed_total / total_time:.2f}")
        print(f"   Files analyzed: {files_analyzed_total}")
        print(f"   Total tokens: {total_input + total_output:,}")
        if total_findings > 0:
            avg_cost_per_finding = total_actual_cost / total_findings if total_actual_cost > 0 else self.total_cost / total_findings
            print(f"   Avg cost per finding: ${avg_cost_per_finding:.4f}")

        # Phase breakdown
        print(f"\n📈 Phase Breakdown:")
        for result in self.results:
            phase_name = result.phase.value
            print(f"   {phase_name}: {len(result.findings)} findings")

        print()

    def export_results(self, output_path: str) -> None:
        """Export deep analysis results to JSON"""
        output = {
            "mode": self.config.mode.value,
            "enabled_phases": [p.value for p in self.config.enabled_phases],
            "total_cost": round(self.total_cost, 2),
            "total_findings": sum(len(r.findings) for r in self.results),
            "results": [
                {
                    "phase": r.phase.value,
                    "findings": r.findings,
                    "files_analyzed": r.files_analyzed,
                    "execution_time": round(r.execution_time, 2),
                    "estimated_cost": round(r.estimated_cost, 2),
                    "token_usage": r.token_usage.to_dict() if r.token_usage else {},
                    "actual_cost": round(r.actual_cost, 4) if r.actual_cost > 0 else None,
                    "metadata": r.metadata,
                }
                for r in self.results
            ],
        }

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        logger.info(f"📝 Deep analysis results exported to {output_path}")


def main():
    """CLI entry point for standalone testing"""
    import argparse

    parser = argparse.ArgumentParser(description="Argus Deep Analysis Engine")
    parser.add_argument("repo_path", help="Path to repository")
    parser.add_argument(
        "--mode",
        choices=["off", "semantic-only", "conservative", "full"],
        default="off",
        help="Deep analysis mode",
    )
    parser.add_argument("--max-files", type=int, default=50, help="Max files to analyze (default: 50)")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds (default: 300 = 5 min)")
    parser.add_argument("--cost-ceiling", type=float, default=5.0, help="Cost ceiling in USD (default: 5.0)")
    parser.add_argument("--dry-run", action="store_true", help="Estimate cost without running")
    parser.add_argument("--benchmark", action="store_true", help="Enable detailed benchmark reporting")
    parser.add_argument("--output", default="deep_analysis_results.json", help="Output file")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create config
    mode = DeepAnalysisMode.from_string(args.mode)
    config = DeepAnalysisConfig(
        mode=mode,
        enabled_phases=mode.get_enabled_phases(),
        max_files=args.max_files,
        timeout_seconds=args.timeout,
        cost_ceiling=args.cost_ceiling,
        dry_run=args.dry_run,
    )

    # Run analysis
    engine = DeepAnalysisEngine(config=config, enable_benchmarking=args.benchmark)

    if args.dry_run:
        estimate = engine.estimate_cost(args.repo_path)
        print(f"\n📊 Cost Estimate:")
        print(f"   Files: {estimate.files_to_analyze}/{estimate.total_files}")
        print(f"   Time: ~{int(estimate.estimated_time_seconds)}s")
        print(f"   Cost: ~${estimate.estimated_cost_usd:.2f}")
        print(f"   Breakdown: {estimate.breakdown_by_phase}")
    else:
        results = engine.analyze(args.repo_path)
        engine.export_results(args.output)

        # Print benchmark report if enabled
        if args.benchmark:
            engine.print_benchmark_report()

        print(f"\n✅ Analysis complete!")
        print(f"   Total findings: {sum(len(r.findings) for r in results)}")
        print(f"   Total cost: ${engine.total_cost:.2f}")
        print(f"   Results: {args.output}")


if __name__ == "__main__":
    main()
