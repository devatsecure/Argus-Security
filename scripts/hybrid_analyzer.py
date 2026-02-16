#!/usr/bin/env python3
"""
Hybrid Security Analyzer for Argus — Facade Module

This module is a thin facade that delegates to the extracted submodules in
scripts/hybrid/. The original god-object (2,502 lines) has been decomposed into:

    hybrid.models           — HybridFinding, HybridScanResult dataclasses
    hybrid.scanner_runners  — All scanner runner functions
    hybrid.ai_enrichment    — AI enrichment and IRIS analysis functions
    hybrid.report           — Report generation (SARIF, JSON, Markdown)
    hybrid.cli              — CLI entry point (main, env helpers)
    hybrid.phases           — Phase execution modules (phase1-6)

This facade preserves the exact public API:
    - HybridFinding and HybridScanResult (re-exported for backward compat)
    - HybridSecurityAnalyzer class with __init__(), analyze(), and all _private methods
    - main() function and __main__ guard

The analyze() method delegates to phase modules in hybrid.phases/:
    phase1_scanning    — Scanner orchestration
    phase2_enrichment  — AI enrichment, IRIS, remediation, discovery
    phase3_review      — Multi-agent persona review
    phase4_sandbox     — Docker sandbox validation
    phase5_policy      — Policy gate evaluation, vulnerability chaining
    phase6_reporting   — Disclosure, enrichment pipeline, result assembly

Architecture:
+---------------------------------------------------------------------+
|  PHASE 1: Fast Deterministic Scanning (30-60 sec)                   |
|  +- Semgrep (SAST)                                                  |
|  +- Trivy (CVE/Dependencies)                                        |
|  +- Checkov (IaC)                                                   |
+---------------------------------------------------------------------+
|  PHASE 2: AI Enrichment (2-5 min)                                   |
|  +- Claude/OpenAI (Security analysis, CWE mapping)                  |
|  +- Existing Argus agents                                           |
+---------------------------------------------------------------------+
|  PHASE 2.5: Automated Remediation (Optional)                        |
|  +- AI-Generated Fix Suggestions                                    |
+---------------------------------------------------------------------+
|  PHASE 2.6: Spontaneous Discovery (Optional)                        |
|  +- Find issues beyond scanner rules (15-20% more findings)         |
+---------------------------------------------------------------------+
|  PHASE 3: Multi-Agent Persona Review (Optional)                     |
|  +- SecretHunter, ArchitectureReviewer, ExploitAssessor, etc.       |
+---------------------------------------------------------------------+
|  PHASE 3.5: Collaborative Reasoning (Opt-in, +cost)                 |
|  +- Multi-agent discussion & consensus (30-40% less FP)             |
+---------------------------------------------------------------------+
|  PHASE 4: Sandbox Validation (Optional)                             |
|  +- Docker-based Exploit Validation                                 |
+---------------------------------------------------------------------+
|  PHASE 5: Policy Gate Evaluation (Optional)                         |
|  +- Rego policy enforcement (PR/release gates)                      |
+---------------------------------------------------------------------+
|  PHASE 6: Report Generation                                         |
|  +- SARIF + JSON + Markdown                                         |
+---------------------------------------------------------------------+

Cost Optimization: Deterministic tools first, AI only when needed
"""

import atexit
import contextlib
import logging
import os
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

# Ensure scripts directory is in path for imports
SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

# Import project context detector for context-aware AI triage
try:
    from project_context_detector import ProjectContext, detect_project_context

    PROJECT_CONTEXT_AVAILABLE = True
except ImportError:
    PROJECT_CONTEXT_AVAILABLE = False
    ProjectContext = None  # type: ignore

# Import IRIS analyzer for semantic vulnerability analysis
try:
    from iris_analyzer import IRISAnalyzer

    IRIS_AVAILABLE = True
except ImportError:
    IRIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Re-export dataclasses from hybrid.models for backward compatibility.
# Any code that does ``from hybrid_analyzer import HybridFinding`` will still
# work.
# ---------------------------------------------------------------------------
from hybrid.models import HybridFinding, HybridScanResult  # noqa: E402

# Scanner registry for plugin discovery and metadata
try:
    from scanner_registry import ScannerRegistry

    _REGISTRY_OK = True
except ImportError:
    _REGISTRY_OK = False

# Vulnerability enrichment modules (v2.0)
# EPSS, fix versions, VEX, dedup, compliance, and suppression are now
# handled by the shared enrichment_pipeline module.  Only license risk
# scoring is still used directly here (operates on SBOM components).
try:
    from license_risk_scorer import LicenseRiskScorer

    _LICENSE_OK = True
except ImportError:
    _LICENSE_OK = False

try:
    from heuristic_scanner import HeuristicScanner

    _HEURISTIC_OK = True
except ImportError:
    _HEURISTIC_OK = False

try:
    from nuclei_template_scanner import NucleiTemplateScanner

    _NUCLEI_TEMPLATE_OK = True
except ImportError:
    _NUCLEI_TEMPLATE_OK = False

try:
    from zap_baseline_scanner import ZAPBaselineScanner

    _ZAP_BASELINE_OK = True
except ImportError:
    _ZAP_BASELINE_OK = False

try:
    from phase_gate import PhaseGate

    _PHASE_GATE_OK = True
except ImportError:
    _PHASE_GATE_OK = False

try:
    from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisEngine, DeepAnalysisMode

    _DEEP_ANALYSIS_OK = True
except ImportError:
    _DEEP_ANALYSIS_OK = False

# MCP server (optional, Phase 0)
try:
    from mcp_server import MCP_AVAILABLE as _MCP_LIB_OK
    from mcp_server import create_argus_mcp_server

    _MCP_IMPORT_OK = True
except ImportError:
    _MCP_IMPORT_OK = False
    _MCP_LIB_OK = False

# Temporal orchestrator (optional execution backend)
try:
    from temporal_orchestrator import (
        AuditWorkflowRunner,
        PipelineActivities,
    )

    _TEMPORAL_IMPORT_OK = True
except ImportError:
    _TEMPORAL_IMPORT_OK = False
    _TEMPORAL_LIB_OK = False


class HybridSecurityAnalyzer:
    """
    Hybrid Security Analyzer

    Combines deterministic tools (Semgrep, Trivy, Checkov) with AI analysis
    (Claude, OpenAI, Argus agents)
    """

    def __init__(
        self,
        enable_semgrep: bool = True,
        enable_trivy: bool = True,
        enable_checkov: bool = True,
        enable_api_security: bool = True,
        enable_dast: bool = True,
        enable_supply_chain: bool = True,
        enable_fuzzing: bool = True,
        enable_threat_intel: bool = True,
        enable_remediation: bool = True,
        enable_runtime_security: bool = False,  # opt-in: requires Falco binary
        enable_regression_testing: bool = True,
        enable_ai_enrichment: bool = True,
        enable_argus: bool = False,  # Use existing argus if needed
        enable_sandbox: bool = True,  # Validate exploits in Docker sandbox
        enable_multi_agent: bool = True,  # Use specialized agent personas
        enable_spontaneous_discovery: bool = True,  # Discover issues beyond scanner rules
        enable_collaborative_reasoning: bool = True,  # Multi-agent discussion
        enable_trufflehog: bool = True,  # TruffleHog verified secret detection
        enable_iris: bool = True,  # IRIS-style semantic analysis (arXiv 2405.17238)
        enable_nuclei_templates: bool = True,  # Nuclei source-aware DAST analysis
        enable_zap_baseline: bool = False,  # opt-in: requires ZAP binary or Docker image
        ai_provider: Optional[str] = None,
        dast_target_url: Optional[str] = None,
        fuzzing_duration: int = 300,  # 5 minutes default
        runtime_monitoring_duration: int = 60,  # 1 minute default
        config: Optional[dict] = None,
    ):
        """
        Initialize hybrid analyzer

        Args:
            enable_semgrep: Run Semgrep SAST
            enable_trivy: Run Trivy CVE scanning
            enable_checkov: Run Checkov IaC scanning
            enable_api_security: Run API Security Scanner
            enable_dast: Run DAST Scanner
            enable_supply_chain: Run Supply Chain Attack Detection
            enable_fuzzing: Run Intelligent Fuzzing Engine
            enable_threat_intel: Run Threat Intelligence Enrichment
            enable_remediation: Run Automated Remediation Engine
            enable_runtime_security: Run Container Runtime Security Monitoring
            enable_regression_testing: Run Security Regression Testing
            enable_ai_enrichment: Use AI (Claude/OpenAI) for enrichment
            enable_argus: Use existing Argus multi-agent system
            enable_sandbox: Validate exploits in Docker sandbox
            enable_multi_agent: Use specialized agent personas (SecretHunter, ArchitectureReviewer, etc.)
            enable_spontaneous_discovery: Discover issues beyond traditional scanner rules
            enable_collaborative_reasoning: Enable multi-agent discussion and debate (opt-in, adds cost)
            enable_iris: Enable IRIS-style semantic analysis (research-proven 2x improvement, arXiv 2405.17238)
            ai_provider: AI provider name (anthropic, openai, etc.)
            dast_target_url: Target URL for DAST scanning
            fuzzing_duration: Fuzzing duration in seconds (default: 300)
            runtime_monitoring_duration: Runtime monitoring duration in seconds (default: 60)
            config: Additional configuration
        """
        self.enable_semgrep = enable_semgrep
        self.enable_trivy = enable_trivy
        self.enable_checkov = enable_checkov
        self.enable_api_security = enable_api_security
        self.enable_dast = enable_dast
        self.enable_supply_chain = enable_supply_chain
        self.enable_fuzzing = enable_fuzzing
        self.enable_threat_intel = enable_threat_intel
        self.enable_remediation = enable_remediation
        self.enable_runtime_security = enable_runtime_security
        self.enable_regression_testing = enable_regression_testing
        self.enable_ai_enrichment = enable_ai_enrichment
        self.enable_argus = enable_argus
        self.enable_sandbox = enable_sandbox
        self.enable_multi_agent = enable_multi_agent
        self.enable_spontaneous_discovery = enable_spontaneous_discovery
        self.enable_collaborative_reasoning = enable_collaborative_reasoning
        self.enable_trufflehog = enable_trufflehog
        self.enable_iris = enable_iris
        self.enable_nuclei_templates = enable_nuclei_templates
        self.enable_zap_baseline = enable_zap_baseline
        self.ai_provider = ai_provider
        self.dast_target_url = dast_target_url
        self.fuzzing_duration = fuzzing_duration
        self.runtime_monitoring_duration = runtime_monitoring_duration
        self.config = config or {}

        # Initialize scanners
        self.semgrep_scanner = None
        self.trivy_scanner = None
        self.checkov_scanner = None
        self.api_security_scanner = None
        self.dast_scanner = None
        self.supply_chain_scanner = None
        self.fuzzing_scanner = None
        self.threat_intel_enricher = None
        self.remediation_engine = None
        self.runtime_security_monitor = None
        self.regression_tester = None
        self.trufflehog_scanner = None
        self.nuclei_template_scanner = None
        self.zap_baseline_scanner = None
        self.sandbox_validator = None
        self.ai_client = None

        # Initialize multi-agent system components
        self.agent_personas = None
        self.spontaneous_discovery = None
        self.collaborative_reasoning = None
        self.iris_analyzer = None  # IRIS semantic analyzer

        # Initialize project context for context-aware AI triage
        self.project_context = None

        # Initialize AI client if enrichment is enabled
        if self.enable_ai_enrichment:
            try:
                from orchestrator.llm_manager import LLMManager

                self.llm_manager = LLMManager(config=self.config)
                if self.llm_manager.initialize(provider=ai_provider):
                    self.ai_client = self.llm_manager
                    logger.info(f"✅ AI enrichment enabled with {self.llm_manager.provider}")
                else:
                    logger.warning("⚠️  Could not initialize AI client")
                    logger.info("   💡 Continuing without AI enrichment")
                    self.enable_ai_enrichment = False
            except Exception as e:
                logger.warning(f"⚠️  Could not load AI client: {e}")
                logger.info("   💡 Continuing without AI enrichment")
                self.enable_ai_enrichment = False

        # Initialize multi-agent system (requires AI client)
        if self.enable_multi_agent and self.enable_ai_enrichment and self.ai_client:
            try:
                # Import agent persona functions (no class needed, just functions)
                import agent_personas

                self.agent_personas = agent_personas  # Module reference for calling functions
                logger.info("✅ Multi-agent personas initialized (5 specialized agents)")
            except (ImportError, Exception) as e:
                logger.warning(f"⚠️  Could not load agent personas: {e}")
                logger.info("   💡 Continuing without multi-agent personas")
                self.enable_multi_agent = False

        if self.enable_spontaneous_discovery and self.enable_ai_enrichment and self.ai_client:
            try:
                from spontaneous_discovery import SpontaneousDiscovery

                self.spontaneous_discovery = SpontaneousDiscovery(llm_manager=self.ai_client)
                logger.info("✅ Spontaneous discovery initialized")
            except (ImportError, Exception) as e:
                logger.warning(f"⚠️  Could not load spontaneous discovery: {e}")
                logger.info("   💡 Continuing without spontaneous discovery")
                self.enable_spontaneous_discovery = False

        # Initialize IRIS semantic analyzer (requires AI client)
        if self.enable_iris and IRIS_AVAILABLE and self.enable_ai_enrichment and self.ai_client:
            try:
                self.iris_analyzer = IRISAnalyzer(ai_provider=self.ai_client, confidence_threshold=0.85)
                logger.info("✅ IRIS semantic analyzer initialized (arXiv 2405.17238 research)")
            except Exception as e:
                logger.warning(f"⚠️  Could not initialize IRIS analyzer: {e}")
                logger.info("   💡 Continuing without IRIS semantic analysis")
                self.enable_iris = False
        elif self.enable_iris and not IRIS_AVAILABLE:
            logger.warning("⚠️  IRIS analyzer module not available")
            logger.info("   💡 Continuing without IRIS semantic analysis")
            self.enable_iris = False

        if self.enable_collaborative_reasoning and self.enable_ai_enrichment and self.ai_client:
            try:
                from collaborative_reasoning import (
                    CollaborativeReasoning,
                    ComplianceAgent,
                    ContextExpertAgent,
                    ExploitAssessorAgent,
                    FalsePositiveFilterAgent,
                    SecretHunterAgent,
                )

                agents = [
                    SecretHunterAgent(self.ai_client),
                    FalsePositiveFilterAgent(self.ai_client),
                    ExploitAssessorAgent(self.ai_client),
                    ComplianceAgent(self.ai_client),
                    ContextExpertAgent(self.ai_client),
                ]
                self.collaborative_reasoning = CollaborativeReasoning(agents)
                logger.info("✅ Collaborative reasoning initialized")
            except (ImportError, Exception) as e:
                logger.warning(f"⚠️  Could not load collaborative reasoning: {e}")
                logger.info("   💡 Continuing without collaborative reasoning")
                self.enable_collaborative_reasoning = False

        if self.enable_semgrep:
            try:
                from semgrep_scanner import SemgrepScanner

                self.semgrep_scanner = SemgrepScanner()
                logger.info("✅ Semgrep scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Semgrep scanner not available: {e}")
                self.enable_semgrep = False

        if self.enable_trufflehog:
            try:
                from trufflehog_scanner import TruffleHogScanner

                self.trufflehog_scanner = TruffleHogScanner()
                logger.info("✅ TruffleHog scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  TruffleHog scanner not available: {e}")
                self.enable_trufflehog = False

        if self.enable_nuclei_templates and _NUCLEI_TEMPLATE_OK:
            try:
                self.nuclei_template_scanner = NucleiTemplateScanner()
                logger.info("✅ Nuclei template scanner initialized (source-aware DAST)")
            except Exception as e:
                logger.warning(f"⚠️  Nuclei template scanner not available: {e}")
                self.enable_nuclei_templates = False
        elif self.enable_nuclei_templates and not _NUCLEI_TEMPLATE_OK:
            logger.warning("⚠️  Nuclei template scanner module not available")
            self.enable_nuclei_templates = False

        if self.enable_zap_baseline and _ZAP_BASELINE_OK:
            try:
                self.zap_baseline_scanner = ZAPBaselineScanner()
                logger.info("✅ ZAP baseline scanner initialized (passive checks)")
            except Exception as e:
                logger.warning(f"⚠️  ZAP baseline scanner not available: {e}")
                self.enable_zap_baseline = False
        elif self.enable_zap_baseline and not _ZAP_BASELINE_OK:
            logger.warning("⚠️  ZAP baseline scanner module not available")
            self.enable_zap_baseline = False

        if self.enable_trivy:
            try:
                from trivy_scanner import TrivyScanner

                self.trivy_scanner = TrivyScanner(foundation_sec_enabled=False, foundation_sec_model=None)
                logger.info("✅ Trivy scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Trivy scanner not available: {e}")
                self.enable_trivy = False

        if self.enable_checkov:
            try:
                from checkov_scanner import CheckovScanner

                self.checkov_scanner = CheckovScanner()
                logger.info("✅ Checkov scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Checkov scanner not available: {e}")
                self.enable_checkov = False

        if self.enable_api_security:
            try:
                from api_security_scanner import APISecurityScanner

                self.api_security_scanner = APISecurityScanner()
                logger.info("✅ API Security scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  API Security scanner not available: {e}")
                self.enable_api_security = False

        if self.enable_dast:
            try:
                from dast_orchestrator import DASTOrchestrator, OrchestratorConfig

                orch_config = OrchestratorConfig(
                    project_path=self.config.get("project_path"),
                    dast_auth_config_path=self.config.get("dast_auth_config_path", ""),
                    enable_nuclei=self.config.get("dast_enable_nuclei", True),
                    enable_zap=self.config.get("dast_enable_zap", True),
                    max_duration=self.config.get("dast_max_duration", 900),
                    parallel_agents=self.config.get("dast_parallel_agents", True),
                )
                self.dast_scanner = DASTOrchestrator(config=orch_config)
                logger.info(
                    "DAST orchestrator initialized (nuclei=%s, zap=%s, parallel=%s, max_duration=%ds)",
                    orch_config.enable_nuclei,
                    orch_config.enable_zap,
                    orch_config.parallel_agents,
                    orch_config.max_duration,
                )
            except (ImportError, RuntimeError) as e:
                logger.warning("DAST orchestrator not available: %s", e)
                self.enable_dast = False

        if self.enable_supply_chain:
            try:
                from supply_chain_analyzer import SupplyChainAnalyzer

                self.supply_chain_scanner = SupplyChainAnalyzer()
                logger.info("✅ Supply Chain scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Supply Chain scanner not available: {e}")
                self.enable_supply_chain = False

        if self.enable_fuzzing:
            try:
                from fuzzing_engine import FuzzingEngine

                self.fuzzing_scanner = FuzzingEngine(llm_manager=self.ai_client)
                logger.info("✅ Fuzzing Engine initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Fuzzing Engine not available: {e}")
                self.enable_fuzzing = False

        if self.enable_threat_intel:
            try:
                from threat_intel_enricher import ThreatIntelEnricher

                self.threat_intel_enricher = ThreatIntelEnricher()
                logger.info("✅ Threat Intelligence Enricher initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Threat Intelligence Enricher not available: {e}")
                self.enable_threat_intel = False

        if self.enable_remediation:
            try:
                from remediation_engine import RemediationEngine

                self.remediation_engine = RemediationEngine(llm_manager=self.ai_client)
                logger.info("✅ Remediation Engine initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Remediation Engine not available: {e}")
                self.enable_remediation = False

        if self.enable_runtime_security:
            try:
                from runtime_security_monitor import RuntimeSecurityMonitor

                self.runtime_security_monitor = RuntimeSecurityMonitor()
                logger.info("✅ Runtime Security Monitor initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Runtime Security Monitor not available: {e}")
                self.enable_runtime_security = False

        if self.enable_regression_testing:
            try:
                from regression_tester import RegressionTester

                self.regression_tester = RegressionTester()
                logger.info("✅ Security Regression Tester initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Security Regression Tester not available: {e}")
                self.enable_regression_testing = False

        # Initialize sandbox validator if enabled
        if self.enable_sandbox:
            try:
                from sandbox_validator import SandboxValidator

                self.sandbox_validator = SandboxValidator()
                logger.info("✅ Sandbox validator initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Sandbox validator not available: {e}")
                self.enable_sandbox = False

        # Initialize scanner registry for plugin discovery and metadata
        self.scanner_registry = None
        if _REGISTRY_OK:
            try:
                plugin_dir = self.config.get("plugin_dir")
                self.scanner_registry = ScannerRegistry(plugin_dir=Path(plugin_dir) if plugin_dir else None)
                builtin = self.scanner_registry.list_scanners()
                logger.info("Scanner registry: %d scanners discovered", len(builtin))
            except Exception as e:
                logger.warning("Scanner registry init failed (non-fatal): %s", e)

        # -- Phase 0: MCP Server (optional background service) --
        self._mcp_server = None
        self._mcp_thread = None
        self._mcp_started = False
        enable_mcp = self.config.get("enable_mcp_server", False)
        if enable_mcp and _MCP_IMPORT_OK and _MCP_LIB_OK:
            try:
                repo_path = self.config.get("repo_path", os.getcwd())
                self._mcp_server = create_argus_mcp_server(repo_path, config=self.config)
                if self._mcp_server is not None:
                    self._mcp_thread = threading.Thread(
                        target=self._run_mcp_server,
                        name="argus-mcp-server",
                        daemon=True,
                    )
                    self._mcp_started = True  # Set before start() to avoid race with finally block
                    self._mcp_thread.start()
                    atexit.register(self.stop_mcp_server)
                    logger.info("Phase 0: MCP server started in background thread")
                else:
                    logger.warning("Phase 0: MCP server creation returned None (MCP library may be missing)")
            except Exception as e:
                logger.warning("Phase 0: MCP server failed to start (non-fatal): %s", e)
                self._mcp_server = None
                self._mcp_thread = None
                self._mcp_started = False
        elif enable_mcp and not _MCP_IMPORT_OK:
            logger.warning("Phase 0: MCP server module not importable — skipping")
        elif enable_mcp and not _MCP_LIB_OK:
            logger.warning("Phase 0: MCP library not installed (pip install 'mcp>=1.0.0') — skipping")

        # Validation: At least one scanner or AI enrichment must be enabled
        active_features = [
            name
            for name in (
                "semgrep",
                "trivy",
                "checkov",
                "api_security",
                "dast",
                "supply_chain",
                "fuzzing",
                "threat_intel",
                "remediation",
                "runtime_security",
                "regression_testing",
                "ai_enrichment",
                "nuclei_templates",
                "zap_baseline",
            )
            if getattr(self, f"enable_{name}", False)
        ]
        if not active_features:
            raise ValueError("At least one tool must be enabled! Use --help to see available scanner flags.")

    def analyze(
        self, target_path: str, output_dir: Optional[str] = None, severity_filter: Optional[list[str]] = None
    ) -> HybridScanResult:
        """
        Run complete hybrid security analysis.

        Delegates each phase to its own module under ``hybrid.phases``.

        Args:
            target_path: Path to analyze (repo, directory, or file)
            output_dir: Directory to save results (default: .argus/hybrid-results)
            severity_filter: Only report these severities (default: all)

        Returns:
            HybridScanResult with all findings
        """
        from hybrid.phases.phase1_scanning import run_phase1_scanning
        from hybrid.phases.phase2_enrichment import run_phase2_enrichment
        from hybrid.phases.phase3_review import run_phase3_review
        from hybrid.phases.phase4_sandbox import run_phase4_sandbox
        from hybrid.phases.phase5_policy import run_phase5_policy
        from hybrid.phases.phase6_reporting import run_phase6_reporting

        # Validate target path exists
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        logger.info("=" * 80)
        logger.info("HYBRID SECURITY ANALYSIS")
        logger.info("=" * 80)
        logger.info("Target: %s", target_path)
        logger.info("Tools: %s", self._get_enabled_tools())
        logger.info("")

        # -- Temporal execution backend (optional) --
        if self.config.get("enable_temporal", False):
            temporal_result = self._try_temporal_execution(
                target_path=target_path,
                output_dir=output_dir,
                severity_filter=severity_filter,
            )
            if temporal_result is not None:
                return temporal_result
            # Fall-through: Temporal was requested but unavailable/failed.
            # The warning was already logged inside _try_temporal_execution.

        # -- PHASE 0: MCP Server Status --
        if self._mcp_started:
            logger.info(
                "Phase 0: MCP server is running (background thread: %s)",
                self._mcp_thread.name if self._mcp_thread else "unknown",
            )
        elif self.config.get("enable_mcp_server", False):
            logger.info("Phase 0: MCP server enabled but not running (startup may have failed)")

        # Detect project context for context-aware AI triage
        if PROJECT_CONTEXT_AVAILABLE and self.enable_ai_enrichment:
            try:
                logger.info("Detecting project context for context-aware AI triage...")
                self.project_context = detect_project_context(target_path)
                logger.info("   Project: %s (%s)", self.project_context.type, self.project_context.runtime)
                logger.info("   Output: %s", ", ".join(self.project_context.output_destinations))
                if self.project_context.framework:
                    logger.info("   Framework: %s", self.project_context.framework)
            except Exception as e:
                logger.warning("Project context detection failed: %s", e)
                logger.info("   Continuing without project context")

        overall_start = time.time()
        phase_timings: dict[str, float] = {}
        total_cost = 0.0

        # -- PHASE 1: Static Analysis (Fast, Deterministic) --
        all_findings, p1_duration, scanner_health = run_phase1_scanning(
            target_path=target_path,
            analyzer=self,
        )
        phase_timings["phase1_static_analysis"] = p1_duration
        self._validate_phase(
            "phase1", {"findings": [asdict(f) for f in all_findings], "scanner_health": scanner_health}
        )

        # -- PHASE 2: AI Enrichment (+ IRIS, Remediation, Spontaneous) --
        all_findings, p2_timings = run_phase2_enrichment(
            all_findings=all_findings,
            target_path=target_path,
            analyzer=self,
        )
        phase_timings.update(p2_timings)

        # -- Heuristic pre-scan (Phase 2.6a) --
        if _HEURISTIC_OK and self.config.get("enable_heuristics", True):
            try:
                heuristic_start = time.time()
                scanner = HeuristicScanner()
                # scan_codebase expects list of {"path": ..., "content": ...} dicts
                _heuristic_files = []
                _target = Path(target_path)
                _heuristic_exts = {
                    ".py",
                    ".js",
                    ".ts",
                    ".tsx",
                    ".jsx",
                    ".java",
                    ".go",
                    ".rb",
                    ".yml",
                    ".yaml",
                    ".json",
                    ".tf",
                }
                for fp in _target.rglob("*"):
                    if (
                        fp.is_file()
                        and fp.suffix in _heuristic_exts
                        and ".git" not in fp.parts
                        and "node_modules" not in fp.parts
                    ):
                        with contextlib.suppress(Exception):
                            _heuristic_files.append({"path": str(fp), "content": fp.read_text(errors="ignore")})
                        if len(_heuristic_files) >= 500:
                            break
                heuristic_findings = scanner.scan_codebase(_heuristic_files) if _heuristic_files else {}
                if heuristic_findings:
                    # scan_codebase returns {path: [flag_strings, ...]}
                    _hcount = 0
                    for fpath, flags in heuristic_findings.items():
                        for flag in flags:
                            _hcount += 1
                            all_findings.append(
                                HybridFinding(
                                    finding_id=f"heuristic-{_hcount}",
                                    source_tool="heuristic",
                                    severity="medium",
                                    category="security",
                                    title=str(flag),
                                    description=str(flag),
                                    file_path=fpath,
                                )
                            )
                    logger.info("Heuristic scanner: %d findings from pattern matching", _hcount)
                logger.info("   Heuristic scan duration: %.1fs", time.time() - heuristic_start)
            except Exception as e:
                logger.warning("Heuristic scanning failed (non-fatal): %s", e)

        self._validate_phase("phase2", {"findings": [asdict(f) for f in all_findings]})

        # -- PHASE 3: Multi-Agent Persona Review --
        all_findings, p3_duration = run_phase3_review(
            all_findings=all_findings,
            target_path=target_path,
            analyzer=self,
        )
        if p3_duration is not None:
            phase_timings["phase3_multi_agent_personas"] = p3_duration

        # -- Quality filter: remove low-quality findings before downstream phases --
        # Findings that lack evidence AND have very low multi-agent confidence
        # are noise (e.g. Checkov rules with no description, no line number,
        # and <30% agent confidence).  IRIS-verified findings are always kept.
        enable_qf = self.config.get("enable_quality_filter", True)
        qf_threshold = float(self.config.get("quality_filter_min_confidence", 0.30))
        if enable_qf and all_findings:
            before = len(all_findings)
            all_findings = [f for f in all_findings if not self._is_low_quality_finding(f, qf_threshold)]
            filtered = before - len(all_findings)
            if filtered:
                logger.info(
                    "   Quality filter: removed %d low-quality finding(s) (confidence < %.0f%% with missing evidence)",
                    filtered,
                    qf_threshold * 100,
                )

        self._validate_phase("phase3", {"findings": [asdict(f) for f in all_findings]})

        # -- PHASE 2.7: Deep Analysis (AISLE) --
        deep_mode = self.config.get("deep_analysis_mode", "off")
        if _DEEP_ANALYSIS_OK and deep_mode != "off" and all_findings:
            try:
                deep_start = time.time()
                mode_map = {
                    "semantic-only": DeepAnalysisMode.SEMANTIC_ONLY,
                    "conservative": DeepAnalysisMode.CONSERVATIVE,
                    "full": DeepAnalysisMode.FULL,
                }
                da_config = DeepAnalysisConfig(
                    mode=mode_map.get(deep_mode, DeepAnalysisMode.CONSERVATIVE),
                    max_files=self.config.get("deep_analysis_max_files", 50),
                    timeout_seconds=self.config.get("deep_analysis_timeout", 300),
                    cost_ceiling=self.config.get("deep_analysis_cost_ceiling", 5.0),
                )
                engine = DeepAnalysisEngine(config=da_config)
                finding_dicts = [asdict(f) for f in all_findings]
                deep_results = engine.analyze(finding_dicts, target_path=target_path)
                if deep_results:
                    # Merge deep analysis results back into findings
                    for f in all_findings:
                        fid = f.finding_id
                        if fid in deep_results:
                            f.description = (
                                (f.description or "")
                                + "\n\n**Deep Analysis:** "
                                + deep_results[fid].get("analysis", "")
                            )
                deep_duration = time.time() - deep_start
                phase_timings["phase2_7_deep_analysis"] = deep_duration
                logger.info("   Phase 2.7 Deep Analysis: %.1fs", deep_duration)
            except Exception as e:
                logger.warning("Deep Analysis failed (non-fatal): %s", e)

        # -- PHASE 4: Sandbox Validation --
        all_findings, p4_duration = run_phase4_sandbox(
            all_findings=all_findings,
            target_path=target_path,
            analyzer=self,
        )
        if p4_duration is not None:
            phase_timings["phase4_sandbox_validation"] = p4_duration

        # -- PHASE 5: Policy Gate + Vulnerability Chaining --
        policy_gate_result, vulnerability_chains, p5_timings = run_phase5_policy(
            all_findings=all_findings,
            analyzer=self,
            output_dir=output_dir,
        )
        phase_timings.update(p5_timings)

        # -- PHASE 6: Reporting + Result Assembly --
        result = run_phase6_reporting(
            all_findings=all_findings,
            target_path=target_path,
            analyzer=self,
            output_dir=output_dir,
            severity_filter=severity_filter,
            overall_start=overall_start,
            phase_timings=phase_timings,
            total_cost=total_cost,
            policy_gate_result=policy_gate_result,
            vulnerability_chains=vulnerability_chains,
        )

        # Attach scanner health so reports can distinguish "0 findings" vs "scanner failed"
        result.__dict__["scanner_health"] = scanner_health

        # -- Phase 0 cleanup: stop MCP server --
        if self._mcp_started:
            self.stop_mcp_server()

        return result

    # ------------------------------------------------------------------
    # Temporal execution backend
    # ------------------------------------------------------------------

    def _try_temporal_execution(
        self,
        target_path: str,
        output_dir: Optional[str],
        severity_filter: Optional[list[str]],
    ) -> Optional[HybridScanResult]:
        """Attempt to run the pipeline via the Temporal orchestrator.

        Returns a ``HybridScanResult`` if Temporal execution succeeds, or
        ``None`` if Temporal is unavailable / fails so the caller should
        fall back to direct execution.

        Graceful degradation hierarchy:
        1. ``temporal_orchestrator`` module not importable -> warn, return None
        2. ``temporalio`` library not installed -> warn, return None
        3. Workflow execution raises any exception -> warn, return None
        """
        if not _TEMPORAL_IMPORT_OK:
            logger.warning(
                "Temporal enabled in config but temporal_orchestrator module "
                "could not be imported. Falling back to direct execution."
            )
            return None

        retry_mode = self.config.get("temporal_retry_mode", "production")

        try:
            runner = AuditWorkflowRunner(
                activities=PipelineActivities(config=self.config),
                retry_mode=retry_mode,
            )
            logger.info("Running pipeline via Temporal orchestrator (mode=%s)", retry_mode)
            runner.run(repo_path=target_path, config=self.config)

            # Log summary from Temporal execution
            summary = runner.get_summary()
            logger.info(
                "Temporal workflow completed: %d/%d phases succeeded",
                summary.get("completed_phases", 0),
                summary.get("total_phases", 0),
            )
            for pname, pdetail in summary.get("phases", {}).items():
                status = pdetail.get("status", "unknown")
                duration = pdetail.get("duration_seconds", 0.0)
                if status == "failed":
                    logger.warning(
                        "  Phase %s: %s (%.1fs) — %s",
                        pname,
                        status,
                        duration,
                        pdetail.get("error", ""),
                    )
                else:
                    logger.info("  Phase %s: %s (%.1fs)", pname, status, duration)

            # After Temporal execution, run the normal analyze() path for the
            # full result assembly.  Temporal adds crash-recovery and retry
            # semantics around the same phase logic; the final reporting still
            # goes through the standard code path.
            #
            # Re-invoke analyze() with Temporal disabled to avoid recursion
            # and get the full HybridScanResult with SARIF/JSON/Markdown.
            original_toggle = self.config.get("enable_temporal", False)
            self.config["enable_temporal"] = False
            try:
                result = self.analyze(
                    target_path=target_path,
                    output_dir=output_dir,
                    severity_filter=severity_filter,
                )
            finally:
                self.config["enable_temporal"] = original_toggle

            # Attach Temporal workflow metadata to the result
            result.__dict__["temporal_summary"] = summary

            return result

        except Exception as exc:
            logger.warning(
                "Temporal execution failed: %s. Falling back to direct execution.",
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Vulnerability enrichment pipeline (v2.0)
    # ------------------------------------------------------------------

    def _enrich_findings(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """Enrich findings with EPSS scores, fix versions, VEX, dedup, etc.

        Delegates the 6-step enrichment pipeline to the shared
        ``enrichment_pipeline`` module, then handles license risk scoring
        (which operates on SBOM components extracted from findings, not on
        findings directly) and reconstructs HybridFinding dataclasses.
        """
        if not findings:
            return findings

        # Convert dataclasses to dicts for the shared enrichment pipeline
        finding_dicts = [asdict(f) for f in findings]

        # -- Shared 6-step enrichment pipeline --
        from enrichment_pipeline import run_enrichment_pipeline

        finding_dicts, _enrichment_meta = run_enrichment_pipeline(
            finding_dicts,
            self.config,
            target_path,
        )

        # -- License risk scoring (hybrid_analyzer-specific, SBOM-based) --
        if _LICENSE_OK and self.config.get("enable_license_risk_scoring", True):
            try:
                license_scorer = LicenseRiskScorer()
                components = []
                for fd in finding_dicts:
                    pkg = fd.get("cve_id") and fd.get("title", "")
                    if pkg and " in " in pkg:
                        pkg_name = pkg.split(" in ")[-1].strip()
                        components.append(
                            {
                                "name": pkg_name,
                                "version": fd.get("installed_version", "unknown"),
                            }
                        )
                if components:
                    risks = license_scorer.score_components(components)
                    if risks:
                        logger.info("License risk: %d components scored", len(risks))
                else:
                    logger.info("License risk: no SBOM components to score")
            except Exception as e:
                logger.warning("License risk scoring failed (non-fatal): %s", e)

        # Reconstruct HybridFinding objects from enriched dicts
        enriched = []
        known_fields = {f.name for f in HybridFinding.__dataclass_fields__.values()}
        for fd in finding_dicts:
            # Only pass fields that HybridFinding knows about
            filtered = {k: v for k, v in fd.items() if k in known_fields}
            try:
                enriched.append(HybridFinding(**filtered))
            except TypeError:
                # If reconstruction fails, keep original finding
                logger.warning("Failed to reconstruct finding: %s", fd.get("finding_id", "unknown"))

        return enriched if enriched else findings

    # ------------------------------------------------------------------
    # Quality filter helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_low_quality_finding(finding: HybridFinding, min_confidence: float) -> bool:
        """Return True if a finding is low-quality noise that should be filtered.

        A finding is considered low-quality when ALL of these hold:
        - Multi-agent confidence is below *min_confidence*
        - Description is missing or empty
        - Not verified by IRIS (which does its own deep analysis)
        - Has no CVE (CVE findings have external evidence even without description)
        """
        if finding.iris_verified:
            return False
        if finding.cve_id:
            return False
        has_description = bool(
            finding.description
            and finding.description.strip()
            and finding.description.strip().lower() not in ("none", "unknown", "n/a")
        )
        if has_description:
            return False
        return finding.confidence < min_confidence

    # ------------------------------------------------------------------
    # Phase gating helper
    # ------------------------------------------------------------------

    def _validate_phase(self, phase_name: str, phase_output: dict) -> None:
        """Validate phase output using PhaseGate if enabled."""
        if not _PHASE_GATE_OK or not self.config.get("enable_phase_gating", True):
            return
        try:
            gate = PhaseGate(strict=self.config.get("phase_gate_strict", False))
            gate.validate(phase_name, phase_output)
        except Exception as e:
            logger.warning("Phase gate validation failed for %s (non-fatal): %s", phase_name, e)

    # ------------------------------------------------------------------
    # MCP server lifecycle
    # ------------------------------------------------------------------

    def _run_mcp_server(self) -> None:
        """Run MCP server in background thread (blocking call wrapped).

        Creates a new asyncio event loop for the thread since server.run()
        is a blocking call that drives an async event loop internally.
        The finally block ensures _mcp_started is reset on any exit.
        """
        import asyncio

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            if self._mcp_server is not None:
                self._mcp_server.run()
        except Exception as e:
            logger.warning("MCP server thread exited with error: %s", e)
        finally:
            self._mcp_started = False

    def stop_mcp_server(self) -> None:
        """Stop the MCP server if running. Safe to call multiple times."""
        if not self._mcp_started:
            return
        self._mcp_started = False
        logger.info("Phase 0: Stopping MCP server")
        # The MCP server runs as a daemon thread, so it will be terminated
        # when the main process exits. We clear references for clean state.
        self._mcp_server = None
        self._mcp_thread = None

    # ------------------------------------------------------------------
    # Delegations to phase modules (kept for backward compat with callers
    # that invoke these methods directly on the analyzer instance)
    # ------------------------------------------------------------------

    def _run_argus_review(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """Delegate to phase3_review module."""
        from hybrid.phases.phase3_review import _run_argus_review

        return _run_argus_review(
            findings=findings,
            target_path=target_path,
            agent_personas=self.agent_personas,
            ai_client=self.ai_client,
            collaborative_reasoning=self.collaborative_reasoning,
            enable_collaborative_reasoning=self.enable_collaborative_reasoning,
        )

    def _run_sandbox_validation(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """Delegate to phase4_sandbox module."""
        from hybrid.phases.phase4_sandbox import _run_sandbox_validation

        return _run_sandbox_validation(
            findings=findings,
            target_path=target_path,
            sandbox_validator=self.sandbox_validator,
        )

    # ------------------------------------------------------------------
    # Thin delegation methods — scanner runners
    # ------------------------------------------------------------------

    def _run_semgrep(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_semgrep

        return run_semgrep(self.semgrep_scanner, target_path, logger)

    def _run_trivy(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_trivy

        return run_trivy(self.trivy_scanner, target_path, logger)

    def _run_checkov(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_checkov

        return run_checkov(self.checkov_scanner, target_path, logger)

    def _run_api_security(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_api_security

        return run_api_security(self.api_security_scanner, target_path, logger)

    def _run_dast(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_dast

        return run_dast(self.dast_scanner, target_path, logger, self.config, self.dast_target_url)

    def _run_supply_chain(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_supply_chain

        return run_supply_chain(self.supply_chain_scanner, target_path, logger)

    def _run_fuzzing(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_fuzzing

        return run_fuzzing(self.fuzzing_scanner, target_path, logger)

    def _run_threat_intel(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_threat_intel

        return run_threat_intel(self.threat_intel_enricher, findings, logger)

    def _run_remediation(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_remediation

        return run_remediation(self.remediation_engine, findings, logger)

    def _run_runtime_security(self, target_path: str) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_runtime_security

        return run_runtime_security(
            self.runtime_security_monitor, target_path, logger, self.runtime_monitoring_duration
        )

    def _run_regression_testing(self, target_path: str, current_findings: list[HybridFinding]) -> list[HybridFinding]:
        from hybrid.scanner_runners import run_regression_testing

        return run_regression_testing(self.regression_tester, target_path, current_findings, logger)

    # ------------------------------------------------------------------
    # Thin delegation methods — AI enrichment
    # ------------------------------------------------------------------

    def _enrich_with_ai(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        from hybrid.ai_enrichment import enrich_with_ai

        return enrich_with_ai(self.ai_client, findings, self.project_context, logger)

    def _enrich_with_iris(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        from hybrid.ai_enrichment import enrich_with_iris

        return enrich_with_iris(self.iris_analyzer, findings, target_path, self.project_context, logger)

    def _analyze_xss_output_destination(self, finding: HybridFinding) -> Optional[str]:
        from hybrid.ai_enrichment import analyze_xss_output_destination

        return analyze_xss_output_destination(finding, "", logger)

    def _build_enrichment_prompt(self, finding: HybridFinding) -> str:
        from hybrid.ai_enrichment import build_enrichment_prompt

        return build_enrichment_prompt(finding, self.project_context, finding.file_path, logger)

    def _parse_ai_response(self, response: str) -> Optional[dict[str, Any]]:
        from hybrid.ai_enrichment import parse_ai_response

        return parse_ai_response(response, logger)

    # ------------------------------------------------------------------
    # Thin delegation methods — utility / reporting
    # ------------------------------------------------------------------

    def _normalize_severity(self, severity: str) -> str:
        from hybrid.scanner_runners import normalize_severity

        return normalize_severity(severity)

    def _count_by_severity(self, findings: list[HybridFinding]) -> dict[str, int]:
        from hybrid.scanner_runners import count_by_severity

        return count_by_severity(findings)

    def _count_by_source(self, findings: list[HybridFinding]) -> dict[str, int]:
        from hybrid.scanner_runners import count_by_source

        return count_by_source(findings)

    def _get_enabled_tools(self) -> list[str]:
        from hybrid.report import get_enabled_tools

        return get_enabled_tools(
            {
                "enable_semgrep": self.enable_semgrep,
                "enable_trivy": self.enable_trivy,
                "enable_checkov": self.enable_checkov,
                "enable_api_security": self.enable_api_security,
                "enable_dast": self.enable_dast,
                "enable_supply_chain": self.enable_supply_chain,
                "enable_fuzzing": self.enable_fuzzing,
                "enable_threat_intel": self.enable_threat_intel,
                "enable_remediation": self.enable_remediation,
                "enable_runtime_security": self.enable_runtime_security,
                "enable_regression_testing": self.enable_regression_testing,
                "enable_ai_enrichment": self.enable_ai_enrichment,
                "enable_nuclei_templates": self.enable_nuclei_templates,
                "enable_zap_baseline": self.enable_zap_baseline,
                "ai_client": self.ai_client,
                "enable_argus": self.enable_argus,
                "enable_sandbox": self.enable_sandbox,
            }
        )

    def _save_results(self, result: HybridScanResult, output_dir: str) -> None:
        from hybrid.report import save_results

        save_results(result, output_dir, result.target_path)

    def _convert_to_sarif(self, result: HybridScanResult) -> dict:
        from hybrid.report import convert_to_sarif

        return convert_to_sarif(result, result.target_path)

    def _severity_to_sarif_level(self, severity: str) -> str:
        from hybrid.report import severity_to_sarif_level

        return severity_to_sarif_level(severity)

    def _generate_markdown_report(self, result: HybridScanResult) -> str:
        from hybrid.report import generate_markdown_report

        return generate_markdown_report(result)

    def _print_summary(self, result: HybridScanResult) -> None:
        from hybrid.report import print_summary

        print_summary(result)


def main():
    """CLI entry point for hybrid analyzer — delegates to hybrid.cli.main()"""
    from hybrid.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
