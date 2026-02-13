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

import logging
import os
import sys
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
    from project_context_detector import detect_project_context, ProjectContext

    PROJECT_CONTEXT_AVAILABLE = True
except ImportError:
    PROJECT_CONTEXT_AVAILABLE = False
    ProjectContext = None  # type: ignore

# Import IRIS analyzer for semantic vulnerability analysis
try:
    from iris_analyzer import IRISAnalyzer, IRISFinding, load_code_context

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
try:
    from epss_scorer import EPSSScorer

    _EPSS_OK = True
except ImportError:
    _EPSS_OK = False

try:
    from fix_version_tracker import FixVersionTracker

    _FIX_OK = True
except ImportError:
    _FIX_OK = False

try:
    from vex_processor import VEXProcessor

    _VEX_OK = True
except ImportError:
    _VEX_OK = False

try:
    from vuln_deduplicator import VulnDeduplicator

    _DEDUP_OK = True
except ImportError:
    _DEDUP_OK = False

try:
    from compliance_mapper import ComplianceMapper

    _COMPLIANCE_OK = True
except ImportError:
    _COMPLIANCE_OK = False

try:
    from advanced_suppression import AdvancedSuppressionManager

    _SUPPRESSION_OK = True
except ImportError:
    _SUPPRESSION_OK = False

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
    from argus_deep_analysis import DeepAnalysisEngine, DeepAnalysisConfig, DeepAnalysisMode

    _DEEP_ANALYSIS_OK = True
except ImportError:
    _DEEP_ANALYSIS_OK = False


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
        enable_runtime_security: bool = True,
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
        enable_zap_baseline: bool = True,  # ZAP passive security checks
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
                    SecretHunterAgent,
                    FalsePositiveFilterAgent,
                    ExploitAssessorAgent,
                    ComplianceAgent,
                    ContextExpertAgent,
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
                from dast_scanner import DASTScanner

                self.dast_scanner = DASTScanner(
                    target_url=self.dast_target_url, openapi_spec=self.config.get("openapi_spec")
                )
                logger.info("✅ DAST scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  DAST scanner not available: {e}")
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

        # Validation: At least one scanner or AI enrichment must be enabled
        if (
            not self.enable_semgrep
            and not self.enable_trivy
            and not self.enable_checkov
            and not self.enable_api_security
            and not self.enable_dast
            and not self.enable_supply_chain
            and not self.enable_fuzzing
            and not self.enable_threat_intel
            and not self.enable_remediation
            and not self.enable_runtime_security
            and not self.enable_regression_testing
            and not self.enable_ai_enrichment
        ):
            raise ValueError(
                "❌ ERROR: At least one tool must be enabled!\n"
                "   Enable: --enable-semgrep, --enable-trivy, --enable-checkov, "
                "--enable-api-security, --enable-dast, --enable-supply-chain, "
                "--enable-fuzzing, --enable-threat-intel, --enable-remediation, "
                "--enable-runtime-security, --enable-regression-testing, or --enable-ai-enrichment"
            )

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
                heuristic_findings = scanner.scan_codebase(target_path)
                if heuristic_findings:
                    # Convert to HybridFinding format
                    for hf in heuristic_findings:
                        if isinstance(hf, dict):
                            all_findings.append(
                                HybridFinding(
                                    finding_id=hf.get("finding_id", f"heuristic-{len(all_findings)}"),
                                    source_tool="heuristic",
                                    severity=hf.get("severity", "medium"),
                                    category=hf.get("category", "security"),
                                    title=hf.get("title", "Heuristic finding"),
                                    description=hf.get("description", ""),
                                    file_path=hf.get("file_path", ""),
                                    line_number=hf.get("line_number", 0),
                                )
                            )
                    logger.info("Heuristic scanner: %d findings from pattern matching", len(heuristic_findings))
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

        return result

    # ------------------------------------------------------------------
    # Vulnerability enrichment pipeline (v2.0)
    # ------------------------------------------------------------------

    def _enrich_findings(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """Enrich findings with EPSS scores, fix versions, VEX, dedup."""
        if not findings:
            return findings

        enable_epss = self.config.get("enable_epss_scoring", True)
        enable_fix = self.config.get("enable_fix_version_tracking", True)
        enable_vex = self.config.get("enable_vex", True)
        enable_dedup = self.config.get("enable_vuln_deduplication", True)

        # Convert dataclasses to dicts for enrichment, then write fields back
        finding_dicts = [asdict(f) for f in findings]

        # EPSS scoring
        if _EPSS_OK and enable_epss:
            try:
                scorer = EPSSScorer(
                    cache_dir=str(Path(target_path) / ".argus-cache"),
                )
                finding_dicts = scorer.enrich_findings(finding_dicts)
                logger.info("EPSS: enriched findings with exploit probability scores")
            except Exception as e:
                logger.warning("EPSS scoring failed (non-fatal): %s", e)

        # License risk scoring
        if _LICENSE_OK and self.config.get("enable_license_risk_scoring", True):
            try:
                license_scorer = LicenseRiskScorer()
                finding_dicts = license_scorer.score_findings(finding_dicts, target_path=target_path)
                logger.info("License risk: findings scored for license compliance")
            except Exception as e:
                logger.warning("License risk scoring failed (non-fatal): %s", e)

        # Fix version tracking
        if _FIX_OK and enable_fix:
            try:
                tracker = FixVersionTracker()
                fix_infos = [info for f in finding_dicts if (info := tracker.extract_fix_info(f)) is not None]
                if fix_infos:
                    finding_dicts = tracker.enrich_findings(finding_dicts, fix_infos)
                    logger.info("Fix versions: %d upgrade paths found", len(fix_infos))
            except Exception as e:
                logger.warning("Fix version tracking failed (non-fatal): %s", e)

        # VEX filtering
        if _VEX_OK and enable_vex:
            try:
                processor = VEXProcessor(
                    auto_discover_dir=str(Path(target_path) / ".argus/vex"),
                )
                statements = processor.load_statements()
                if statements:
                    finding_dicts, suppressed = processor.filter_findings(finding_dicts, statements)
                    logger.info("VEX: %d suppressed, %d remaining", len(suppressed), len(finding_dicts))
            except Exception as e:
                logger.warning("VEX processing failed (non-fatal): %s", e)

        # Deduplication
        if _DEDUP_OK and enable_dedup:
            try:
                strategy = self.config.get("deduplication_strategy", "auto")
                deduplicator = VulnDeduplicator(strategy=strategy)
                result = deduplicator.deduplicate(finding_dicts)
                finding_dicts = result.kept_findings
                logger.info("Dedup: %d findings after deduplication", len(finding_dicts))
            except Exception as e:
                logger.warning("Deduplication failed (non-fatal): %s", e)

        # Compliance mapping
        if _COMPLIANCE_OK and self.config.get("enable_compliance_mapping", True):
            try:
                mapper = ComplianceMapper()
                frameworks_str = self.config.get("compliance_frameworks", "")
                frameworks = [f.strip() for f in frameworks_str.split(",") if f.strip()] if frameworks_str else None
                finding_dicts = mapper.map_findings(finding_dicts, frameworks=frameworks)
                logger.info("Compliance mapping: findings mapped to frameworks")
            except Exception as e:
                logger.warning("Compliance mapping failed (non-fatal): %s", e)

        # Advanced suppression (.argus-ignore.yml)
        if _SUPPRESSION_OK and self.config.get("enable_advanced_suppression", True):
            try:
                suppressor = AdvancedSuppressionManager(
                    config_dir=str(Path(target_path)),
                    auto_expire_days=self.config.get("suppression_auto_expire_days", 90),
                )
                before_count = len(finding_dicts)
                finding_dicts = suppressor.filter_findings(finding_dicts)
                suppressed = before_count - len(finding_dicts)
                if suppressed:
                    logger.info("Suppression: %d findings suppressed via .argus-ignore.yml", suppressed)
            except Exception as e:
                logger.warning("Advanced suppression failed (non-fatal): %s", e)

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
