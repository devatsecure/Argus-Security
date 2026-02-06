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

This facade preserves the exact public API:
    - HybridFinding and HybridScanResult (re-exported for backward compat)
    - HybridSecurityAnalyzer class with __init__(), analyze(), and all _private methods
    - main() function and __main__ guard

Orchestration logic (__init__, analyze, _run_argus_review, _run_sandbox_validation)
remains inline. All other methods are thin 2-3 line delegations.

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

import glob as glob_module
import logging
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime
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
        enable_dast: bool = False,
        enable_supply_chain: bool = True,
        enable_fuzzing: bool = False,
        enable_threat_intel: bool = True,
        enable_remediation: bool = True,
        enable_runtime_security: bool = False,
        enable_regression_testing: bool = True,
        enable_ai_enrichment: bool = True,
        enable_argus: bool = False,  # Use existing argus if needed
        enable_sandbox: bool = True,  # Validate exploits in Docker sandbox
        enable_multi_agent: bool = True,  # Use specialized agent personas
        enable_spontaneous_discovery: bool = True,  # Discover issues beyond scanner rules
        enable_collaborative_reasoning: bool = False,  # Multi-agent discussion (opt-in, more expensive)
        enable_iris: bool = True,  # IRIS-style semantic analysis (arXiv 2405.17238)
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
        self.enable_iris = enable_iris
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
                from collaborative_reasoning import CollaborativeReasoning
                self.collaborative_reasoning = CollaborativeReasoning(llm_manager=self.ai_client)
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

        if self.enable_trivy:
            try:
                from trivy_scanner import TrivyScanner

                self.trivy_scanner = TrivyScanner(
                    foundation_sec_enabled=False, foundation_sec_model=None
                )
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
                    target_url=self.dast_target_url,
                    openapi_spec=self.config.get("openapi_spec")
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

                self.fuzzing_scanner = FuzzingEngine(ai_provider=self.ai_provider)
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

                self.runtime_security_monitor = RuntimeSecurityMonitor(
                    duration_seconds=self.runtime_monitoring_duration
                )
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

        # Validation: At least one scanner or AI enrichment must be enabled
        if (not self.enable_semgrep and not self.enable_trivy and not self.enable_checkov
            and not self.enable_api_security and not self.enable_dast and not self.enable_supply_chain
            and not self.enable_fuzzing and not self.enable_threat_intel and not self.enable_remediation
            and not self.enable_runtime_security and not self.enable_regression_testing
            and not self.enable_ai_enrichment):
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
        Run complete hybrid security analysis

        Args:
            target_path: Path to analyze (repo, directory, or file)
            output_dir: Directory to save results (default: .argus/hybrid-results)
            severity_filter: Only report these severities (default: all)

        Returns:
            HybridScanResult with all findings
        """
        # Validate target path exists
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"❌ Target path does not exist: {target_path}")

        logger.info("=" * 80)
        logger.info("🔒 HYBRID SECURITY ANALYSIS")
        logger.info("=" * 80)
        logger.info(f"📁 Target: {target_path}")
        logger.info(f"🛠️  Tools: {self._get_enabled_tools()}")
        logger.info("")

        # Detect project context for context-aware AI triage
        if PROJECT_CONTEXT_AVAILABLE and self.enable_ai_enrichment:
            try:
                logger.info("🔍 Detecting project context for context-aware AI triage...")
                self.project_context = detect_project_context(target_path)
                logger.info(f"   ✅ Project: {self.project_context.type} ({self.project_context.runtime})")
                logger.info(f"   📤 Output: {', '.join(self.project_context.output_destinations)}")
                if self.project_context.framework:
                    logger.info(f"   🔧 Framework: {self.project_context.framework}")
            except Exception as e:
                logger.warning(f"⚠️  Project context detection failed: {e}")
                logger.info("   💡 Continuing without project context")

        overall_start = time.time()
        phase_timings = {}
        all_findings = []
        total_cost = 0.0

        # PHASE 1: Static Analysis (Fast, Deterministic)
        logger.info("─" * 80)
        logger.info("📊 PHASE 1: Static Analysis (Deterministic)")
        logger.info("─" * 80)

        phase1_start = time.time()

        # Run Semgrep
        if self.enable_semgrep and self.semgrep_scanner:
            try:
                logger.info("   🔍 Running Semgrep SAST...")
                semgrep_findings = self._run_semgrep(target_path)
                all_findings.extend(semgrep_findings)
                logger.info(f"   ✅ Semgrep: {len(semgrep_findings)} findings")
            except Exception as e:
                logger.error(f"   ❌ Semgrep scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Trivy
        if self.enable_trivy and self.trivy_scanner:
            try:
                logger.info("   🔍 Running Trivy CVE scanner...")
                trivy_findings = self._run_trivy(target_path)
                all_findings.extend(trivy_findings)
                logger.info(f"   ✅ Trivy: {len(trivy_findings)} CVEs")
            except Exception as e:
                logger.error(f"   ❌ Trivy scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Checkov
        if self.enable_checkov and self.checkov_scanner:
            try:
                logger.info("   🔍 Running Checkov IaC scanner...")
                checkov_findings = self._run_checkov(target_path)
                all_findings.extend(checkov_findings)
                logger.info(f"   ✅ Checkov: {len(checkov_findings)} IaC misconfigurations")
            except Exception as e:
                logger.error(f"   ❌ Checkov scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run API Security Scanner
        if self.enable_api_security and self.api_security_scanner:
            try:
                logger.info("   🔍 Running API Security scanner...")
                api_findings = self._run_api_security(target_path)
                all_findings.extend(api_findings)
                logger.info(f"   ✅ API Security: {len(api_findings)} API vulnerabilities")
            except Exception as e:
                logger.error(f"   ❌ API Security scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run DAST Scanner
        if self.enable_dast and self.dast_scanner:
            try:
                logger.info("   🔍 Running DAST scanner...")
                dast_findings = self._run_dast(target_path)
                all_findings.extend(dast_findings)
                logger.info(f"   ✅ DAST: {len(dast_findings)} runtime vulnerabilities")
            except Exception as e:
                logger.error(f"   ❌ DAST scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Supply Chain Scanner
        if self.enable_supply_chain and self.supply_chain_scanner:
            try:
                logger.info("   🔍 Running Supply Chain scanner...")
                supply_chain_findings = self._run_supply_chain(target_path)
                all_findings.extend(supply_chain_findings)
                logger.info(f"   ✅ Supply Chain: {len(supply_chain_findings)} dependency threats")
            except Exception as e:
                logger.error(f"   ❌ Supply Chain scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Fuzzing Engine
        if self.enable_fuzzing and self.fuzzing_scanner:
            try:
                logger.info("   🔍 Running Fuzzing Engine...")
                fuzzing_findings = self._run_fuzzing(target_path)
                all_findings.extend(fuzzing_findings)
                logger.info(f"   ✅ Fuzzing: {len(fuzzing_findings)} crashes discovered")
            except Exception as e:
                logger.error(f"   ❌ Fuzzing failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Threat Intelligence Enrichment
        if self.enable_threat_intel and self.threat_intel_enricher and all_findings:
            try:
                logger.info("   🔍 Running Threat Intelligence Enrichment...")
                enriched_findings = self._run_threat_intel(all_findings)
                all_findings = enriched_findings
                logger.info(f"   ✅ Threat Intel: {len(all_findings)} findings enriched with threat context")
            except Exception as e:
                logger.error(f"   ❌ Threat Intelligence enrichment failed: {e}")
                logger.info("   💡 Continuing with unenriched findings...")

        # Run Runtime Security Monitoring
        if self.enable_runtime_security and self.runtime_security_monitor:
            try:
                logger.info("   🔍 Running Runtime Security Monitoring...")
                runtime_findings = self._run_runtime_security(target_path)
                all_findings.extend(runtime_findings)
                logger.info(f"   ✅ Runtime Security: {len(runtime_findings)} runtime threats detected")
            except Exception as e:
                logger.error(f"   ❌ Runtime Security monitoring failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Security Regression Testing
        if self.enable_regression_testing and self.regression_tester:
            try:
                logger.info("   🔍 Running Security Regression Testing...")
                regression_findings = self._run_regression_testing(target_path, all_findings)
                all_findings.extend(regression_findings)
                logger.info(f"   ✅ Regression Testing: {len(regression_findings)} regressions detected")
            except Exception as e:
                logger.error(f"   ❌ Regression testing failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        phase_timings["phase1_static_analysis"] = time.time() - phase1_start
        logger.info(f"   ⏱️  Phase 1 duration: {phase_timings['phase1_static_analysis']:.1f}s")

        # Check if we have any findings
        if not all_findings:
            logger.info("   ℹ️  No findings from Phase 1 scanners")

        # PHASE 2: AI Enrichment (Optional)
        if self.enable_ai_enrichment and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🤖 PHASE 2: AI Enrichment (Claude/OpenAI)")
            logger.info("─" * 80)

            phase2_start = time.time()

            try:
                # Enrich findings with AI analysis
                enriched_findings = self._enrich_with_ai(all_findings)
                all_findings = enriched_findings
                logger.info("   ✅ AI enrichment complete")
            except Exception as e:
                logger.error(f"   ❌ AI enrichment failed: {e}")
                logger.info("   💡 Continuing with unenriched findings...")

            phase_timings["phase2_ai_enrichment"] = time.time() - phase2_start
            logger.info(f"   ⏱️  Phase 2 duration: {phase_timings['phase2_ai_enrichment']:.1f}s")
        elif self.enable_ai_enrichment and not all_findings:
            logger.info("   ⚠️  Skipping Phase 2: No findings to enrich")

        # PHASE 2.3: IRIS Semantic Analysis (Optional)
        if self.enable_iris and all_findings and self.iris_analyzer:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🔬 PHASE 2.3: IRIS Semantic Analysis (Research-Proven Deep Analysis)")
            logger.info("─" * 80)

            phase2_3_start = time.time()

            try:
                # Run IRIS semantic analysis on high-severity findings
                iris_enriched = self._enrich_with_iris(all_findings, target_path=target_path)
                all_findings = iris_enriched

                # Get IRIS statistics
                iris_stats = self.iris_analyzer.get_statistics()
                logger.info(f"   ✅ IRIS analysis complete")
                logger.info(f"      Findings analyzed: {iris_stats['total_findings_analyzed']}")
                logger.info(f"      True positives: {iris_stats['true_positives']}")
                logger.info(f"      False positives: {iris_stats['false_positives']}")
                logger.info(f"      Cost: ${iris_stats['total_cost_usd']}")
            except Exception as e:
                logger.error(f"   ❌ IRIS semantic analysis failed: {e}")
                logger.info("   💡 Continuing with basic AI enrichment...")

            phase_timings["phase2_3_iris"] = time.time() - phase2_3_start
            logger.info(f"   ⏱️  Phase 2.3 duration: {phase_timings['phase2_3_iris']:.1f}s")
        elif self.enable_iris and not all_findings:
            logger.info("   ⚠️  Skipping Phase 2.3: No findings to analyze with IRIS")

        # PHASE 2.5: Automated Remediation (Optional)
        if self.enable_remediation and all_findings and self.remediation_engine:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🔧 PHASE 2.5: Automated Remediation (AI-Generated Fixes)")
            logger.info("─" * 80)

            phase2_5_start = time.time()

            try:
                # Generate remediation suggestions for findings
                remediated_findings = self._run_remediation(all_findings)
                all_findings = remediated_findings
                logger.info("   ✅ Remediation suggestions generated")
            except Exception as e:
                logger.error(f"   ❌ Remediation generation failed: {e}")
                logger.info("   💡 Continuing without remediation suggestions...")

            phase_timings["phase2_5_remediation"] = time.time() - phase2_5_start
            logger.info(f"   ⏱️  Phase 2.5 duration: {phase_timings['phase2_5_remediation']:.1f}s")
        elif self.enable_remediation and not all_findings:
            logger.info("   ⚠️  Skipping Phase 2.5: No findings to remediate")

        # PHASE 2.6: Spontaneous Discovery (Optional)
        if self.enable_spontaneous_discovery and self.spontaneous_discovery:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🔍 PHASE 2.6: Spontaneous Discovery (Beyond Scanner Rules)")
            logger.info("─" * 80)

            phase2_6_start = time.time()

            try:
                # Get all Python/JS/Java files for analysis
                code_files = []
                for ext in ["**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.java", "**/*.go"]:
                    code_files.extend(glob_module.glob(str(Path(target_path) / ext), recursive=True))

                # Determine architecture from config or infer from files
                architecture = self.config.get("architecture", "backend-api")  # Default to backend-api

                # Run spontaneous discovery
                logger.info(f"   🔎 Analyzing {len(code_files)} code files for hidden issues...")
                discoveries = self.spontaneous_discovery.discover(
                    files=code_files[:100],  # Limit to 100 files to avoid token limits
                    existing_findings=[asdict(f) for f in all_findings],  # Convert to dict for comparison
                    architecture=architecture
                )

                # Convert discoveries to HybridFindings
                for discovery in discoveries:
                    hybrid_finding = HybridFinding(
                        finding_id=f"spontaneous-{len(all_findings) + 1}",
                        source_tool="spontaneous_discovery",
                        severity=discovery.severity,
                        category=discovery.category,
                        title=discovery.title,
                        description=discovery.description,
                        file_path=discovery.evidence[0] if discovery.evidence else str(target_path),
                        line_number=None,
                        cwe_id=discovery.cwe_id,
                        cve_id=None,
                        cvss_score=None,
                        exploitability=None,
                        recommendation=discovery.remediation,
                        references=[],
                        confidence=discovery.confidence,
                        llm_enriched=True,
                        sandbox_validated=False,
                    )
                    all_findings.append(hybrid_finding)

                logger.info(f"   ✅ Spontaneous discovery complete: {len(discoveries)} new issues found")
                logger.info(f"   📊 Total findings after discovery: {len(all_findings)}")

            except Exception as e:
                logger.error(f"   ❌ Spontaneous discovery failed: {e}")
                logger.info("   💡 Continuing with findings from Phase 1 & 2")

            phase_timings["phase2_6_spontaneous_discovery"] = time.time() - phase2_6_start
            logger.info(f"   ⏱️  Phase 2.6 duration: {phase_timings['phase2_6_spontaneous_discovery']:.1f}s")
        elif self.enable_spontaneous_discovery and not self.spontaneous_discovery:
            logger.info("   ⚠️  Skipping Phase 2.6: Spontaneous discovery not initialized")

        # PHASE 3: Multi-Agent Persona Review (Optional)
        if self.enable_multi_agent and self.agent_personas and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🎯 PHASE 3: Multi-Agent Persona Review")
            logger.info("─" * 80)

            phase3_start = time.time()

            # Run multi-agent persona review on findings
            try:
                enriched_findings = self._run_argus_review(all_findings, target_path)
                all_findings = enriched_findings
                logger.info(f"   ✅ Multi-agent persona review complete: {len(all_findings)} findings reviewed")
            except Exception as e:
                logger.error(f"   ❌ Multi-agent persona review failed: {e}")
                logger.info("   💡 Continuing with findings from Phase 1 & 2")

            phase_timings["phase3_multi_agent_personas"] = time.time() - phase3_start
            logger.info(f"   ⏱️  Phase 3 duration: {phase_timings['phase3_multi_agent_personas']:.1f}s")
        elif self.enable_multi_agent and not all_findings:
            logger.info("   ⚠️  Skipping Phase 3: No findings to review")
        elif self.enable_multi_agent and not self.agent_personas:
            logger.info("   ⚠️  Skipping Phase 3: Multi-agent personas not initialized")

        # PHASE 4: Sandbox Validation (Optional)
        if self.enable_sandbox and self.sandbox_validator and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🐳 PHASE 4: Sandbox Validation (Docker)")
            logger.info("─" * 80)

            phase4_start = time.time()

            try:
                validated_findings = self._run_sandbox_validation(all_findings, target_path)
                all_findings = validated_findings
                logger.info(f"   ⚠️  Phase 4 checked {len(all_findings)} findings (validation not yet implemented)")
            except Exception as e:
                logger.error(f"   ❌ Sandbox validation failed: {e}")
                logger.info("   💡 Continuing with unvalidated findings...")

            phase_timings["phase4_sandbox_validation"] = time.time() - phase4_start
            logger.info(f"   ⏱️  Phase 4 duration: {phase_timings['phase4_sandbox_validation']:.1f}s")
        elif self.enable_sandbox and not all_findings:
            logger.info("   ⚠️  Skipping Phase 4: No findings to validate")
        elif self.enable_sandbox and not self.sandbox_validator:
            logger.info("   ⚠️  Skipping Phase 4: Sandbox validator not initialized")

        # PHASE 5: Policy Gate Evaluation (Optional)
        policy_gate_result = None
        if all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("📋 PHASE 5: Policy Gate Evaluation")
            logger.info("─" * 80)

            phase5_start = time.time()

            try:
                from gate import PolicyGate

                # Determine stage from config (default to 'pr')
                stage = self.config.get("policy_stage", "pr")
                policy_dir = self.config.get("policy_dir", "policy/rego")

                # Initialize policy gate
                policy_gate = PolicyGate(policy_dir=policy_dir)

                # Convert HybridFindings to dict format expected by PolicyGate
                findings_dict = []
                for finding in all_findings:
                    finding_dict = {
                        "id": finding.finding_id,
                        "source_tool": finding.source_tool,
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "description": finding.description,
                        "path": finding.file_path,
                        "line": finding.line_number,
                        "cwe_id": finding.cwe_id,
                        "cve_id": finding.cve_id,
                        "cvss_score": finding.cvss_score,
                        "exploitability": finding.exploitability,
                        "confidence": finding.confidence,
                    }
                    findings_dict.append(finding_dict)

                # Evaluate policy gate
                logger.info(f"   🔍 Evaluating {len(findings_dict)} findings against {stage} policy...")
                policy_gate_result = policy_gate.evaluate(
                    stage=stage,
                    findings=findings_dict,
                    metadata=self.config.get("policy_metadata", {})
                )

                # Log policy gate results
                decision = policy_gate_result.get("decision", "pass")
                blocks = policy_gate_result.get("blocks", [])
                warnings = policy_gate_result.get("warnings", [])
                reasons = policy_gate_result.get("reasons", [])

                if decision == "pass":
                    logger.info(f"   ✅ Policy gate PASSED: {len(findings_dict)} findings evaluated")
                    if warnings:
                        logger.info(f"   ⚠️  {len(warnings)} warnings (non-blocking)")
                else:
                    logger.warning(f"   ❌ Policy gate FAILED: {len(blocks)} blocking issues")
                    for reason in reasons[:5]:  # Show first 5 reasons
                        logger.warning(f"      • {reason}")

            except ImportError:
                logger.warning("   ⚠️  PolicyGate not available - skipping policy evaluation")
            except Exception as e:
                logger.error(f"   ❌ Policy gate evaluation failed: {e}")
                logger.info("   💡 Continuing without policy enforcement...")

            phase_timings["phase5_policy_gate"] = time.time() - phase5_start
            logger.info(f"   ⏱️  Phase 5 duration: {phase_timings['phase5_policy_gate']:.1f}s")
        else:
            logger.info("   ⚠️  Skipping Phase 5: No findings to evaluate")

        # PHASE 5.5: Vulnerability Chaining Analysis (Optional)
        vulnerability_chains = None
        enable_chaining = os.environ.get("ENABLE_VULNERABILITY_CHAINING", "false").lower() == "true"

        if enable_chaining and all_findings:
            logger.info("─" * 80)
            logger.info("🔗 PHASE 5.5: Vulnerability Chaining Analysis")
            logger.info("─" * 80)

            phase55_start = time.time()

            try:
                # Import chaining engine
                from vulnerability_chaining_engine import VulnerabilityChainer

                # Convert findings to dict format for chaining
                findings_dict = [asdict(f) for f in all_findings]

                # Run chaining analysis
                logger.info("   🔍 Analyzing attack chains...")
                chainer = VulnerabilityChainer(
                    max_chain_length=int(os.environ.get("CHAIN_MAX_LENGTH", "4")),
                    min_risk_threshold=float(os.environ.get("CHAIN_MIN_RISK", "5.0"))
                )

                vulnerability_chains = chainer.analyze(findings_dict)

                logger.info(f"   ✅ Found {vulnerability_chains['total_chains']} attack chains")

                if vulnerability_chains['total_chains'] > 0:
                    stats = vulnerability_chains['statistics']
                    logger.info(f"      • Critical chains: {stats.get('critical_chains', 0)}")
                    logger.info(f"      • High-risk chains: {stats.get('high_chains', 0)}")
                    logger.info(f"      • Average chain length: {stats.get('avg_chain_length', 0):.1f}")
                    logger.info(f"      • Maximum risk score: {stats.get('max_risk_score', 0):.1f}/10.0")

                    # Save chain report
                    if output_dir:
                        from chain_visualizer import ChainVisualizer

                        visualizer = ChainVisualizer()
                        chain_report_path = Path(output_dir) / "vulnerability-chains.md"
                        chain_json_path = Path(output_dir) / "vulnerability-chains.json"

                        visualizer.generate_markdown_report(vulnerability_chains, str(chain_report_path))
                        visualizer.generate_json_summary(vulnerability_chains, str(chain_json_path))

                        logger.info(f"   📄 Chain report: {chain_report_path}")
                else:
                    logger.info("   ℹ️  No significant attack chains found")

            except ImportError:
                logger.warning("   ⚠️  Vulnerability chaining engine not available")
                logger.info("   💡 Install networkx: pip install networkx")
            except Exception as e:
                logger.error(f"   ❌ Vulnerability chaining failed: {e}")
                logger.info("   💡 Continuing without chain analysis...")

            phase_timings["phase5.5_vulnerability_chaining"] = time.time() - phase55_start
            logger.info(f"   ⏱️  Phase 5.5 duration: {phase_timings['phase5.5_vulnerability_chaining']:.1f}s")

        # PHASE 6.5: Responsible Disclosure Report Generation (Optional)
        disclosure_report = None
        enable_disclosure = os.environ.get("ENABLE_DISCLOSURE_REPORT", "false").lower() == "true"

        if enable_disclosure and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("📋 PHASE 6.5: Responsible Disclosure Report Generation")
            logger.info("─" * 80)

            phase65_start = time.time()

            try:
                from disclosure_generator import DisclosureGenerator

                # Get repo URL from environment or config
                repo_url = os.environ.get("DISCLOSURE_REPO_URL", self.config.get("repo_url", ""))
                reporter_name = os.environ.get("DISCLOSURE_REPORTER", "Security Researcher")

                generator = DisclosureGenerator(repo_url=repo_url)

                # Convert findings to dict format
                findings_dict = [asdict(f) for f in all_findings]

                # Generate disclosure reports
                disclosure_output_dir = None
                if output_dir:
                    disclosure_output_dir = str(Path(output_dir) / "disclosure")

                disclosure_report = generator.generate(
                    findings=findings_dict,
                    output_dir=disclosure_output_dir,
                    reporter_name=reporter_name
                )

                logger.info(f"   ✅ Disclosure reports generated")
                logger.info(f"      • High/Critical findings: {len(disclosure_report.high_findings)}")
                logger.info(f"      • Dependency CVEs: {len(disclosure_report.dependency_findings)}")
                logger.info(f"      • Private report: DISCLOSURE_PRIVATE.md")
                logger.info(f"      • Public-safe report: ISSUE_PUBLIC_SAFE.md")

                if disclosure_report.has_security_policy:
                    logger.info(f"   🔒 Repository has SECURITY.md - use private reporting")
                elif disclosure_report.has_discussions:
                    logger.info(f"   💬 Repository has Discussions - request security contact there")

                # Optionally create GitHub discussion
                create_discussion = os.environ.get("DISCLOSURE_CREATE_DISCUSSION", "false").lower() == "true"
                if create_discussion and disclosure_report.has_discussions:
                    discussion_url = generator.create_github_discussion()
                    if discussion_url:
                        logger.info(f"   📨 Created security contact discussion: {discussion_url}")

            except ImportError:
                logger.warning("   ⚠️  Disclosure generator not available")
            except Exception as e:
                logger.error(f"   ❌ Disclosure report generation failed: {e}")
                logger.info("   💡 Continuing without disclosure reports...")

            phase_timings["phase6.5_disclosure"] = time.time() - phase65_start
            logger.info(f"   ⏱️  Phase 6.5 duration: {phase_timings['phase6.5_disclosure']:.1f}s")

        # Calculate statistics
        overall_duration = time.time() - overall_start

        findings_by_severity = self._count_by_severity(all_findings)
        findings_by_source = self._count_by_source(all_findings)

        # Apply severity filter if specified
        if severity_filter:
            all_findings = [f for f in all_findings if f.severity.lower() in [s.lower() for s in severity_filter]]

        # Create result
        result = HybridScanResult(
            target_path=target_path,
            scan_timestamp=datetime.now().isoformat(),
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            findings_by_source=findings_by_source,
            findings=all_findings,
            scan_duration_seconds=overall_duration,
            cost_usd=total_cost,
            phase_timings=phase_timings,
            tools_used=self._get_enabled_tools(),
            llm_enrichment_enabled=self.enable_ai_enrichment,
        )

        # Attach vulnerability chains to result if available
        if vulnerability_chains:
            result.__dict__['vulnerability_chains'] = vulnerability_chains

        # Save results
        if output_dir:
            self._save_results(result, output_dir)

        # Print summary
        self._print_summary(result)

        return result

    # ------------------------------------------------------------------
    # Methods kept inline (tightly coupled to instance state)
    # ------------------------------------------------------------------

    def _run_argus_review(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """
        Run multi-agent persona review on findings using the new agent_personas system

        This integrates the multi-agent personas to:
        1. SecretHunter - Validates secret/credential findings
        2. ArchitectureReviewer - Assesses architectural security flaws
        3. ExploitAssessor - Evaluates real-world exploitability
        4. FalsePositiveFilter - Eliminates test code and false positives
        5. ThreatModeler - Maps attack chains and escalation paths

        Optionally uses collaborative reasoning for multi-agent consensus.

        Args:
            findings: List of findings from Phase 1 & 2
            target_path: Repository path being analyzed

        Returns:
            Enhanced findings with agent analysis metadata
        """
        if not self.agent_personas:
            logger.warning("⚠️  Agent personas not initialized, skipping multi-agent review")
            return findings

        enhanced_findings = []
        logger.info(f"   🤖 Running multi-agent analysis on {len(findings)} findings...")

        for finding in findings:
            # Convert HybridFinding to format expected by agents
            finding_dict = {
                "id": finding.finding_id,
                "source_tool": finding.source_tool,
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "cwe_id": finding.cwe_id,
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
            }

            # Use collaborative reasoning if enabled (multi-round discussion)
            if self.enable_collaborative_reasoning and self.collaborative_reasoning:
                logger.debug(f"   💬 Running collaborative reasoning on finding {finding.finding_id}")
                verdict = self.collaborative_reasoning.analyze_collaboratively(
                    finding=finding_dict,
                    mode="discussion"  # Multi-round discussion mode
                )

                # Update finding based on collaborative verdict
                if verdict.final_decision == "false_positive":
                    # Skip false positives
                    logger.debug(f"      ❌ FP: {finding.finding_id} - {verdict.reasoning[:80]}...")
                    continue
                elif verdict.final_decision == "confirmed":
                    # Enhance confirmed finding
                    finding.confidence = verdict.confidence
                    finding.description = f"[Multi-Agent Consensus: {verdict.confidence:.0%} confidence] {finding.description}\n\nReasoning: {verdict.reasoning}"
                    enhanced_findings.append(finding)
                else:  # needs_review
                    # Mark for manual review
                    finding.confidence = verdict.confidence
                    finding.description = f"[Needs Review: {verdict.confidence:.0%} confidence] {finding.description}\n\nReasoning: {verdict.reasoning}"
                    enhanced_findings.append(finding)

            else:
                # Use independent agent analysis (faster, no multi-round discussion)
                # Select best agent for this finding type
                agent = self.agent_personas.select_agent_for_finding(finding_dict, self.ai_client)
                analysis = agent.analyze(finding_dict)

                # Update finding based on agent analysis
                if analysis.verdict == "false_positive":
                    # Skip false positives
                    logger.debug(f"      ❌ FP: {finding.finding_id} - {analysis.reasoning[:80]}...")
                    continue
                elif analysis.verdict == "confirmed":
                    # Enhance confirmed finding
                    finding.confidence = analysis.confidence
                    finding.description = (
                        f"[Agent: {analysis.agent_name}, {analysis.confidence:.0%} confidence] {finding.description}\n\n"
                        f"Reasoning: {analysis.reasoning}\n"
                        f"Recommendations: {', '.join(analysis.recommendations)}"
                    )
                    enhanced_findings.append(finding)
                else:  # needs_review
                    # Mark for manual review
                    finding.confidence = analysis.confidence
                    finding.description = (
                        f"[Needs Review by {analysis.agent_name}: {analysis.confidence:.0%} confidence] {finding.description}\n\n"
                        f"Reasoning: {analysis.reasoning}"
                    )
                    enhanced_findings.append(finding)

        reduction_pct = ((len(findings) - len(enhanced_findings)) / len(findings) * 100) if findings else 0
        logger.info(f"   📊 Multi-agent review complete: {len(enhanced_findings)}/{len(findings)} findings validated ({reduction_pct:.1f}% reduction)")

        return enhanced_findings

    def _run_sandbox_validation(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """
        Validate exploitable findings in Docker sandbox

        This runs Docker-based validation for findings that:
        1. Are marked as highly exploitable
        2. Have high CVSS scores (>= 7.0)
        3. Are confirmed CVEs with known exploits

        Args:
            findings: List of findings to validate
            target_path: Repository path being analyzed

        Returns:
            Findings with sandbox_validated flag updated
        """
        if not self.sandbox_validator:
            logger.warning("⚠️  Sandbox validator not available")
            return findings

        validated_findings = []
        validation_count = 0

        # Only validate high-severity exploitable findings
        for finding in findings:
            should_validate = finding.severity in ["critical", "high"] and (
                finding.exploitability in ["trivial", "moderate"] or (finding.cvss_score and finding.cvss_score >= 7.0)
            )

            if not should_validate:
                # Don't validate low-risk findings
                validated_findings.append(finding)
                continue

            try:
                logger.info(f"   🧪 Checking: {finding.finding_id}...")
                validation_count += 1

                # TODO: Implement automatic PoC exploit generation
                # Current limitation: Sandbox validation requires:
                # 1. PoC exploit code generation (not yet implemented)
                # 2. Target environment setup
                # 3. Safe execution in Docker
                #
                # The sandbox_validator infrastructure exists and works,
                # but automatic exploit generation is not yet implemented.
                # For now, mark findings as NOT validated (accurate status)

                finding.sandbox_validated = False
                # Do not modify description - validation didn't actually happen

                validated_findings.append(finding)

            except Exception as e:
                logger.warning(f"   ⚠️  Validation failed for {finding.finding_id}: {e}")
                finding.sandbox_validated = False
                validated_findings.append(finding)

        if validation_count > 0:
            logger.info(f"   ⚠️  Checked {validation_count} high-risk findings (validation not yet implemented)")
        else:
            logger.info("   ℹ️  No findings required sandbox validation")

        return validated_findings

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
        return run_runtime_security(self.runtime_security_monitor, target_path, logger, self.runtime_monitoring_duration)

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
        return get_enabled_tools({
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
        })

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
