#!/usr/bin/env python3
"""
Hybrid Security Analyzer for Argus
Combines multiple security scanning tools for comprehensive analysis:

1. Semgrep - Fast SAST (static analysis)
2. Trivy - CVE/dependency scanning
3. Checkov - IaC security scanning (Terraform, K8s, Dockerfile, etc.)
4. AI-powered security analysis & CWE mapping (Claude/OpenAI)
5. Existing Argus multi-agent system

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Fast Deterministic Scanning (30-60 sec)               │
│  ├─ Semgrep (SAST)                                              │
│  ├─ Trivy (CVE/Dependencies)                                    │
│  └─ Checkov (IaC)                                               │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: AI Enrichment (2-5 min)                               │
│  ├─ Claude/OpenAI (Security analysis, CWE mapping)              │
│  └─ Existing Argus agents                                    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2.5: Automated Remediation (Optional)                    │
│  └─ AI-Generated Fix Suggestions                                │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2.6: Spontaneous Discovery (Optional)                    │
│  └─ Find issues beyond scanner rules (15-20% more findings)     │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: Multi-Agent Persona Review (Optional)                 │
│  ├─ SecretHunter (OAuth, API keys, credentials)                 │
│  ├─ ArchitectureReviewer (Design flaws, auth issues)            │
│  ├─ ExploitAssessor (Real-world exploitability)                 │
│  ├─ FalsePositiveFilter (Test code, mocks)                      │
│  └─ ThreatModeler (Attack chains, STRIDE)                       │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3.5: Collaborative Reasoning (Opt-in, +cost)             │
│  └─ Multi-agent discussion & consensus (30-40% less FP)         │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 4: Sandbox Validation (Optional)                         │
│  └─ Docker-based Exploit Validation                             │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 5: Policy Gate Evaluation (Optional)                     │
│  └─ Rego policy enforcement (PR/release gates)                  │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 6: Report Generation                                     │
│  └─ SARIF + JSON + Markdown                                     │
└─────────────────────────────────────────────────────────────────┘

Cost Optimization: Deterministic tools first, AI only when needed
"""

import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
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
    logger.warning("⚠️  project_context_detector not available - context-aware triage disabled")

# Import IRIS analyzer for semantic vulnerability analysis
try:
    from iris_analyzer import IRISAnalyzer, IRISFinding, load_code_context
    IRIS_AVAILABLE = True
except ImportError:
    IRIS_AVAILABLE = False
    logger.warning("⚠️  IRIS analyzer not available - semantic analysis disabled")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class HybridFinding:
    """Unified finding from multiple security tools"""

    finding_id: str
    source_tool: str  # 'semgrep', 'trivy', 'checkov', 'api-security', 'dast', 'argus'
    severity: str  # 'critical', 'high', 'medium', 'low'
    category: str  # 'security', 'quality', 'performance'
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploitability: Optional[str] = None  # 'trivial', 'moderate', 'complex', 'theoretical'
    recommendation: Optional[str] = None
    references: list[str] = None
    confidence: float = 1.0
    llm_enriched: bool = False
    sandbox_validated: bool = False
    iris_verified: bool = False  # IRIS semantic analysis verification
    iris_confidence: Optional[float] = None  # IRIS confidence score (0.0-1.0)
    iris_verdict: Optional[str] = None  # 'true_positive', 'false_positive', 'uncertain'

    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class HybridScanResult:
    """Results from hybrid security scan"""

    target_path: str
    scan_timestamp: str
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_source: dict[str, int]
    findings: list[HybridFinding]
    scan_duration_seconds: float
    cost_usd: float
    phase_timings: dict[str, float]
    tools_used: list[str]
    llm_enrichment_enabled: bool


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
                import glob
                code_files = []
                for ext in ["**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.java", "**/*.go"]:
                    code_files.extend(glob.glob(str(Path(target_path) / ext), recursive=True))

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
                logger.info(f"   ✅ Sandbox validation complete: {len(all_findings)} findings validated")
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

        # Save results
        if output_dir:
            self._save_results(result, output_dir)

        # Print summary
        self._print_summary(result)

        return result

    def _run_semgrep(self, target_path: str) -> list[HybridFinding]:
        """Run Semgrep SAST and convert to HybridFinding format"""
        findings = []

        try:
            # Call semgrep scanner (user's implementation)
            # This assumes semgrep_scanner.py has a scan() method
            if hasattr(self.semgrep_scanner, "scan"):
                semgrep_results = self.semgrep_scanner.scan(target_path)

                # Convert to HybridFinding format
                # Semgrep scanner returns dict with 'findings' key
                findings_list = []
                if isinstance(semgrep_results, dict):
                    findings_list = semgrep_results.get('findings', [])
                elif isinstance(semgrep_results, list):
                    findings_list = semgrep_results

                for result in findings_list:
                    finding = HybridFinding(
                        finding_id=f"semgrep-{result.get('check_id', 'unknown')}",
                        source_tool="semgrep",
                        severity=self._normalize_severity(result.get("severity", "medium")),
                        category="security",
                        title=result.get("check_id", "Unknown Issue"),
                        description=result.get("message", ""),
                        file_path=result.get("path", ""),
                        line_number=result.get("line", None),
                        recommendation=result.get("fix", ""),
                        references=result.get("references", []),
                        confidence=0.9,  # Semgrep has low false positive rate
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Semgrep scan failed: {e}")

        return findings

    def _run_trivy(self, target_path: str) -> list[HybridFinding]:
        """Run Trivy CVE scan and convert to HybridFinding format"""
        findings = []

        try:
            # Run Trivy scanner
            trivy_result = self.trivy_scanner.scan_filesystem(target_path, severity="CRITICAL,HIGH,MEDIUM,LOW")

            # Convert to HybridFinding format
            for trivy_finding in trivy_result.findings:
                finding = HybridFinding(
                    finding_id=f"trivy-{trivy_finding.cve_id}",
                    source_tool="trivy",
                    severity=self._normalize_severity(trivy_finding.severity),
                    category="security",
                    title=f"{trivy_finding.cve_id} in {trivy_finding.package_name}",
                    description=trivy_finding.description,
                    file_path=trivy_finding.file_path or target_path,
                    cve_id=trivy_finding.cve_id,
                    cwe_id=trivy_finding.cwe_id,
                    cvss_score=trivy_finding.cvss_score,
                    exploitability=trivy_finding.exploitability,
                    recommendation=(
                        f"Upgrade {trivy_finding.package_name} to {trivy_finding.fixed_version}"
                        if trivy_finding.fixed_version
                        else "No fix available yet"
                    ),
                    references=trivy_finding.references,
                    confidence=1.0,  # CVEs are confirmed
                    llm_enriched=False,  # Will be enriched in Phase 2 if AI is enabled
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Trivy scan failed: {e}")

        return findings

    def _run_checkov(self, target_path: str) -> list[HybridFinding]:
        """Run Checkov IaC scan and convert to HybridFinding format"""
        findings = []

        try:
            # Run Checkov scanner
            checkov_result = self.checkov_scanner.scan(target_path)

            # Convert to HybridFinding format
            for checkov_finding in checkov_result.findings:
                # Build line number from line range
                line_number = None
                if checkov_finding.file_line_range and len(checkov_finding.file_line_range) > 0:
                    line_number = checkov_finding.file_line_range[0]

                finding = HybridFinding(
                    finding_id=f"checkov-{checkov_finding.check_id}",
                    source_tool="checkov",
                    severity=self._normalize_severity(checkov_finding.severity),
                    category="security",
                    title=f"{checkov_finding.check_name} ({checkov_finding.framework})",
                    description=checkov_finding.description,
                    file_path=checkov_finding.file_path,
                    line_number=line_number,
                    recommendation=checkov_finding.guideline,
                    references=[checkov_finding.guideline] if checkov_finding.guideline else [],
                    confidence=0.9,  # Checkov has low false positive rate for IaC
                    llm_enriched=False,  # Will be enriched in Phase 2 if AI is enabled
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Checkov scan failed: {e}")

        return findings

    def _run_api_security(self, target_path: str) -> list[HybridFinding]:
        """Run API Security Scanner and convert to HybridFinding format"""
        findings = []

        try:
            # Run API Security scanner
            api_result = self.api_security_scanner.scan(target_path)

            # Convert to HybridFinding format
            # API scanner returns APIScanResult object with findings attribute
            if hasattr(api_result, 'findings'):
                for api_finding in api_result.findings:
                    finding = HybridFinding(
                        finding_id=api_finding.finding_id,
                        source_tool="api-security",
                        severity=self._normalize_severity(api_finding.severity),
                        category="security",
                        title=api_finding.title,
                        description=api_finding.description,
                        file_path=api_finding.file_path,
                        line_number=api_finding.line_number,
                        cwe_id=api_finding.cwe_id,
                        recommendation=api_finding.recommendation,
                        references=api_finding.references,
                        confidence=api_finding.confidence,
                        llm_enriched=False,
                    )
                    findings.append(finding)
            elif isinstance(api_result, list):
                # Fallback for legacy format
                for api_finding in api_result:
                    finding = HybridFinding(
                        finding_id=f"api-security-{api_finding.get('id', 'unknown')}",
                        source_tool="api-security",
                        severity=self._normalize_severity(api_finding.get("severity", "medium")),
                        category="security",
                        title=api_finding.get("title", "API Security Issue"),
                        description=api_finding.get("description", ""),
                        file_path=api_finding.get("file_path", target_path),
                        line_number=api_finding.get("line_number"),
                        cwe_id=api_finding.get("cwe_id"),
                        recommendation=api_finding.get("recommendation", ""),
                        references=api_finding.get("references", []),
                        confidence=api_finding.get("confidence", 0.85),
                        llm_enriched=False,
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ API Security scan failed: {e}")

        return findings

    def _run_dast(self, target_path: str) -> list[HybridFinding]:
        """Run DAST Scanner and convert to HybridFinding format"""
        findings = []

        # DAST requires a target URL
        if not self.dast_target_url:
            logger.info("   ℹ️  DAST: No target URL provided, skipping")
            return findings

        try:
            # Run DAST scanner
            dast_config = {
                "severity": self.config.get("dast_severity", "critical,high,medium"),
                "timeout": self.config.get("dast_timeout", 300),
            }
            dast_result = self.dast_scanner.scan(dast_config)

            # Convert to HybridFinding format
            if isinstance(dast_result, list):
                for dast_finding in dast_result:
                    finding = HybridFinding(
                        finding_id=f"dast-{dast_finding.get('id', 'unknown')}",
                        source_tool="dast",
                        severity=self._normalize_severity(dast_finding.get("severity", "medium")),
                        category="security",
                        title=dast_finding.get("title", "DAST Issue"),
                        description=dast_finding.get("description", ""),
                        file_path=dast_finding.get("file_path", target_path),
                        line_number=dast_finding.get("line_number"),
                        cwe_id=dast_finding.get("cwe_id"),
                        cve_id=dast_finding.get("cve_id"),
                        cvss_score=dast_finding.get("cvss_score"),
                        exploitability=dast_finding.get("exploitability"),
                        recommendation=dast_finding.get("recommendation", ""),
                        references=dast_finding.get("references", []),
                        confidence=dast_finding.get("confidence", 0.9),
                        llm_enriched=False,
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ DAST scan failed: {e}")

        return findings

    def _run_supply_chain(self, target_path: str) -> list[HybridFinding]:
        """Run Supply Chain Attack Detection and convert to HybridFinding format"""
        findings = []

        try:
            # Run Supply Chain scanner
            # Note: SupplyChainAnalyzer.analyze_dependency_diff returns ThreatAssessment objects
            supply_chain_result = self.supply_chain_scanner.analyze_dependency_diff()

            # Convert to HybridFinding format
            # supply_chain_result is a list of ThreatAssessment objects
            if isinstance(supply_chain_result, list):
                for sc_threat in supply_chain_result:
                    # ThreatAssessment has: package_name, ecosystem, threat_level, threat_types, evidence, recommendations
                    finding = HybridFinding(
                        finding_id=f"supply-chain-{sc_threat.package_name}",
                        source_tool="supply-chain",
                        severity=self._normalize_severity(sc_threat.threat_level.value),
                        category="supply-chain",
                        title=f"Supply Chain Threat: {sc_threat.package_name} ({', '.join(sc_threat.threat_types)})",
                        description="\n".join(sc_threat.evidence) if sc_threat.evidence else f"Detected threats: {', '.join(sc_threat.threat_types)}",
                        file_path=sc_threat.change_info.file_path if sc_threat.change_info else target_path,
                        line_number=None,
                        cwe_id=None,
                        recommendation="\n".join(sc_threat.recommendations) if sc_threat.recommendations else "",
                        references=sc_threat.similar_legitimate_packages if sc_threat.similar_legitimate_packages else [],
                        confidence=0.95,  # Supply chain threats are highly confident when detected
                        llm_enriched=False,
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Supply Chain scan failed: {e}")

        return findings

    def _run_fuzzing(self, target_path: str) -> list[HybridFinding]:
        """Run Intelligent Fuzzing Engine and convert to HybridFinding format"""
        findings = []

        try:
            # Run Fuzzing scanner
            fuzzing_result = self.fuzzing_scanner.scan(target_path)

            # Convert to HybridFinding format
            if isinstance(fuzzing_result, list):
                for fuzz_finding in fuzzing_result:
                    finding = HybridFinding(
                        finding_id=fuzz_finding.get("id", "unknown"),
                        source_tool="fuzzing",
                        severity=self._normalize_severity(fuzz_finding.get("severity", "medium")),
                        category="security",
                        title=fuzz_finding.get("title", "Fuzzing Crash"),
                        description=fuzz_finding.get("description", ""),
                        file_path=fuzz_finding.get("file_path", target_path),
                        line_number=fuzz_finding.get("line_number"),
                        cwe_id=fuzz_finding.get("cwe_id"),
                        recommendation=fuzz_finding.get("recommendation", ""),
                        references=fuzz_finding.get("references", []),
                        confidence=fuzz_finding.get("confidence", 1.0),
                        llm_enriched=False,
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Fuzzing failed: {e}")

        return findings

    def _run_threat_intel(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        """Run Threat Intelligence Enrichment to add real-time threat context"""
        enriched = []

        logger.info(f"   🌐 Enriching {len(findings)} findings with threat intelligence...")

        for finding in findings:
            try:
                # Enrich with threat intelligence if CVE is present
                if finding.cve_id:
                    threat_context = self.threat_intel_enricher.enrich_cve(finding.cve_id)

                    # Add threat intelligence metadata to finding
                    if threat_context:
                        # Update exploitability based on threat intel
                        if threat_context.get("in_kev_catalog"):
                            finding.exploitability = "trivial"  # Actively exploited in wild
                            finding.severity = "critical"  # Escalate severity

                        # Add EPSS score to description
                        epss_score = threat_context.get("epss_score", 0.0)
                        if epss_score > 0.5:
                            finding.description = (
                                f"[EPSS: {epss_score:.1%} exploit probability] {finding.description}"
                            )

                        # Add exploit availability info
                        exploit_available = threat_context.get("exploit_available", False)
                        if exploit_available:
                            finding.description = f"[Public exploit available] {finding.description}"

                        # Add references from threat intel
                        if threat_context.get("references"):
                            finding.references.extend(threat_context["references"])

                enriched.append(finding)

            except Exception as e:
                logger.warning(f"⚠️  Threat intel enrichment failed for {finding.finding_id}: {e}")
                enriched.append(finding)

        logger.info(f"   ✅ Threat intelligence enrichment complete")
        return enriched

    def _run_remediation(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        """Generate AI-powered remediation suggestions for findings"""
        remediated = []

        logger.info(f"   🔧 Generating remediation suggestions for {len(findings)} findings...")

        for finding in findings:
            try:
                # Skip if already has good recommendation
                if finding.recommendation and len(finding.recommendation) > 100:
                    remediated.append(finding)
                    continue

                # Generate AI-powered remediation suggestion
                suggestion = self.remediation_engine.suggest_fix(finding)

                if suggestion:
                    # Update finding with remediation suggestion
                    finding.recommendation = suggestion.get("fix_explanation", finding.recommendation)

                    # Add code patch if available
                    if suggestion.get("code_patch"):
                        finding.description = (
                            f"{finding.description}\n\n"
                            f"**Suggested Fix:**\n```\n{suggestion['code_patch']}\n```"
                        )

                    # Add testing recommendations
                    if suggestion.get("testing_recommendations"):
                        finding.references.append(
                            f"Testing: {suggestion['testing_recommendations']}"
                        )

                remediated.append(finding)

            except Exception as e:
                logger.warning(f"⚠️  Remediation generation failed for {finding.finding_id}: {e}")
                remediated.append(finding)

        logger.info(f"   ✅ Remediation suggestions generated")
        return remediated

    def _run_runtime_security(self, target_path: str) -> list[HybridFinding]:
        """Run Container Runtime Security Monitoring"""
        findings = []

        try:
            logger.info(f"   🐳 Monitoring runtime security for {self.runtime_monitoring_duration}s...")

            # Run runtime security monitor
            runtime_result = self.runtime_security_monitor.monitor(target_path)

            # Convert to HybridFinding format
            if isinstance(runtime_result, list):
                for runtime_finding in runtime_result:
                    finding = HybridFinding(
                        finding_id=runtime_finding.get("id", "unknown"),
                        source_tool="runtime-security",
                        severity=self._normalize_severity(runtime_finding.get("severity", "medium")),
                        category="runtime",
                        title=runtime_finding.get("title", "Runtime Security Threat"),
                        description=runtime_finding.get("description", ""),
                        file_path=runtime_finding.get("file_path", target_path),
                        line_number=runtime_finding.get("line_number"),
                        cwe_id=runtime_finding.get("cwe_id"),
                        recommendation=runtime_finding.get("recommendation", ""),
                        references=runtime_finding.get("references", []),
                        confidence=runtime_finding.get("confidence", 0.9),
                        llm_enriched=False,
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Runtime security monitoring failed: {e}")

        return findings

    def _run_regression_testing(self, target_path: str, current_findings: list[HybridFinding]) -> list[HybridFinding]:
        """Run Security Regression Testing to detect reappearance of fixed vulnerabilities"""
        findings = []

        try:
            logger.info("   🧪 Checking for security regressions...")

            # Run all regression tests
            results = self.regression_tester.run_all_tests()

            # Convert failed tests to HybridFinding format (failures indicate regressions)
            for failure in results.get("failures", []):
                finding = HybridFinding(
                    finding_id=failure.get("test_id", "unknown"),
                    source_tool="regression-testing",
                    severity="high",  # Regressions are always high severity
                    category="regression",
                    title=f"Security Regression: {failure.get('vulnerability', 'Fixed vulnerability reappeared')}",
                    description=f"Previously fixed {failure.get('vulnerability', 'vulnerability')} has reappeared. Test output: {failure.get('output', '')}",
                    file_path=failure.get("file", target_path),
                    line_number=None,
                    cwe_id=None,
                    cve_id=None,
                    recommendation="Review and re-apply the security fix for this vulnerability",
                    references=[],
                    confidence=1.0,  # Regressions are confirmed
                    llm_enriched=False,
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Regression testing failed: {e}")

        return findings

    def _enrich_with_ai(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        """
        Enrich findings with AI analysis (Claude/OpenAI)

        For each finding:
        - Map to CWE (if not already mapped)
        - Assess exploitability (trivial/moderate/complex/theoretical)
        - Generate remediation recommendations
        - Adjust severity based on context
        """
        if not self.ai_client:
            logger.warning("⚠️  AI client not available, skipping enrichment")
            return findings

        enriched = []
        enriched_count = 0

        logger.info(f"   🤖 Enriching {len(findings)} findings with AI analysis...")

        for finding in findings:
            # Skip if already enriched
            if finding.llm_enriched:
                enriched.append(finding)
                continue

            try:
                # Build prompt for AI analysis
                prompt = self._build_enrichment_prompt(finding)

                # Call AI model
                response, _input_tokens, _output_tokens = self.ai_client.call_llm_api(
                    prompt=prompt,
                    max_tokens=1000,
                    operation=f"Enrich finding {finding.finding_id}"
                )

                # Parse AI response
                analysis = self._parse_ai_response(response)

                # Update finding with AI insights
                if analysis:
                    if analysis.get("cwe_id") and not finding.cwe_id:
                        finding.cwe_id = analysis["cwe_id"]

                    if analysis.get("exploitability"):
                        finding.exploitability = analysis["exploitability"]

                    if analysis.get("severity_assessment"):
                        # AI can upgrade/downgrade severity based on context
                        original_severity = finding.severity
                        finding.severity = analysis["severity_assessment"]
                        if original_severity != finding.severity:
                            logger.debug(f"   Severity adjusted: {original_severity} → {finding.severity}")

                    if analysis.get("recommendation"):
                        finding.recommendation = analysis["recommendation"]

                    if analysis.get("references"):
                        finding.references.extend(analysis["references"])

                    finding.llm_enriched = True
                    enriched_count += 1
                    logger.debug(
                        f"   ✅ Enriched {finding.finding_id}: CWE={finding.cwe_id}, exploitability={finding.exploitability}"
                    )

                enriched.append(finding)

            except Exception as e:
                logger.warning(f"⚠️  AI enrichment failed for {finding.finding_id}: {e}")
                enriched.append(finding)

        if enriched_count > 0:
            logger.info(f"   ✅ AI enriched {enriched_count}/{len(findings)} findings")
        else:
            logger.info("   ℹ️  No findings were AI-enriched")

        return enriched

    def _enrich_with_iris(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """
        Enrich findings with IRIS semantic analysis

        IRIS (arXiv 2405.17238) provides multi-step LLM reasoning:
        1. Data flow analysis
        2. Vulnerability assessment
        3. Impact analysis
        4. Confidence scoring

        Only analyzes CRITICAL/HIGH severity findings to manage cost.

        Args:
            findings: List of findings to analyze
            target_path: Repository root path for loading code context

        Returns:
            Findings with IRIS analysis results
        """
        if not self.iris_analyzer:
            logger.warning("⚠️  IRIS analyzer not available")
            return findings

        enriched = []
        analyzed_count = 0

        # Focus on high-severity findings
        high_severity_findings = [
            f for f in findings
            if f.severity.lower() in ['critical', 'high']
        ]

        logger.info(f"   🎯 Analyzing {len(high_severity_findings)}/{len(findings)} CRITICAL/HIGH severity findings")

        for finding in findings:
            # Skip findings that aren't high severity
            if finding.severity.lower() not in ['critical', 'high']:
                enriched.append(finding)
                continue

            try:
                # Skip if already IRIS verified
                if finding.iris_verified:
                    enriched.append(finding)
                    continue

                # Build finding dict for IRIS
                finding_dict = {
                    'id': finding.finding_id,
                    'type': finding.title,
                    'severity': finding.severity,
                    'cwe_id': finding.cwe_id,
                    'description': finding.description,
                    'file_path': finding.file_path,
                    'line_number': finding.line_number or 1,
                }

                # Load code context
                code_context = ""
                if finding.file_path and Path(finding.file_path).exists():
                    # Make path absolute if relative to target
                    file_path = finding.file_path
                    if not Path(file_path).is_absolute():
                        file_path = str(Path(target_path) / file_path)

                    code_context = load_code_context(
                        file_path=file_path,
                        line_number=finding.line_number or 1,
                        lines_before=20,
                        lines_after=20
                    )
                else:
                    logger.debug(f"   ⚠️  Skipping IRIS for {finding.finding_id}: file not found")
                    enriched.append(finding)
                    continue

                # Repository context (frameworks, etc.)
                repo_context = {}
                if hasattr(self, 'project_context') and self.project_context:
                    repo_context = {
                        'frameworks': [self.project_context.framework] if self.project_context.framework else [],
                        'type': self.project_context.type,
                        'runtime': self.project_context.runtime,
                    }

                # Run IRIS analysis
                logger.debug(f"   🔬 IRIS analyzing {finding.finding_id}...")
                iris_finding = self.iris_analyzer.analyze_finding(
                    finding=finding_dict,
                    code_context=code_context,
                    repo_context=repo_context
                )

                # Update finding with IRIS results
                if iris_finding.iris_verified:
                    finding.iris_verified = True
                    finding.iris_confidence = iris_finding.iris_analysis.confidence
                    finding.iris_verdict = iris_finding.iris_analysis.verdict.value

                    # Update exploitability if IRIS has higher confidence
                    if iris_finding.iris_analysis.exploitation_complexity != "UNKNOWN":
                        complexity_map = {
                            "LOW": "trivial",
                            "MEDIUM": "moderate",
                            "HIGH": "complex"
                        }
                        finding.exploitability = complexity_map.get(
                            iris_finding.iris_analysis.exploitation_complexity,
                            finding.exploitability
                        )

                    # Add IRIS attack vector to description if available
                    if iris_finding.iris_analysis.attack_vector:
                        finding.description += f"\n\n**IRIS Attack Vector:** {iris_finding.iris_analysis.attack_vector}"

                    analyzed_count += 1
                    logger.debug(
                        f"   ✅ IRIS: {finding.finding_id} - {iris_finding.iris_verdict} "
                        f"(confidence: {iris_finding.iris_confidence:.2f})"
                    )
                else:
                    logger.debug(f"   ℹ️  IRIS: {finding.finding_id} - not verified")

                enriched.append(finding)

            except Exception as e:
                logger.warning(f"⚠️  IRIS analysis failed for {finding.finding_id}: {e}")
                enriched.append(finding)

        if analyzed_count > 0:
            logger.info(f"   ✅ IRIS verified {analyzed_count}/{len(high_severity_findings)} high-severity findings")
        else:
            logger.info("   ℹ️  No findings were IRIS-verified")

        return enriched

    def _analyze_xss_output_destination(self, finding: HybridFinding) -> Optional[str]:
        """
        Analyze XSS finding to determine output destination (browser vs. terminal)

        Args:
            finding: XSS finding to analyze

        Returns:
            Output destination: 'browser', 'terminal', 'console', or None if unclear
        """
        if not finding.file_path or not Path(finding.file_path).exists():
            return None

        try:
            # Read file content around the finding
            with open(finding.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Browser/HTML output patterns
            browser_patterns = [
                ".innerHTML",
                ".appendChild",
                "document.write",
                "render_template",
                "res.send(",
                "res.render(",
                "HttpResponse(",
                "response.write",
                "<script>",
                "dangerouslySetInnerHTML",
            ]

            # Terminal/console output patterns
            terminal_patterns = [
                "console.log(",
                "print(",
                "println(",
                "fmt.Println(",
                "puts ",
                "echo ",
                "logger.",
                "logging.",
                "System.out.println",
            ]

            # Count matches
            browser_matches = sum(1 for pattern in browser_patterns if pattern in content)
            terminal_matches = sum(1 for pattern in terminal_patterns if pattern in content)

            # Determine destination based on patterns
            if browser_matches > terminal_matches:
                return "browser"
            elif terminal_matches > browser_matches:
                return "terminal"
            elif terminal_matches > 0:
                return "console"

            return None

        except Exception as e:
            logger.debug(f"Error analyzing XSS output destination for {finding.file_path}: {e}")
            return None

    def _build_enrichment_prompt(self, finding: HybridFinding) -> str:
        """Build prompt for AI to analyze a finding with project context"""

        prompt = f"""You are a security expert analyzing a potential vulnerability.

**Finding Details:**
- ID: {finding.finding_id}
- Source Tool: {finding.source_tool}
- Current Severity: {finding.severity}
- Category: {finding.category}
- Title: {finding.title}
- Description: {finding.description}
- File: {finding.file_path}
- Line: {finding.line_number or "N/A"}
"""

        if finding.cve_id:
            prompt += f"- CVE: {finding.cve_id}\n"
        if finding.cvss_score:
            prompt += f"- CVSS Score: {finding.cvss_score}\n"

        # Add project context if available
        if self.project_context:
            prompt += f"""
**Project Context:**
- Type: {self.project_context.type}
- Runtime: {self.project_context.runtime}
- Output Destinations: {', '.join(self.project_context.output_destinations)}
- Framework: {self.project_context.framework or 'Unknown'}
"""

        # Add context-aware rules
        if self.project_context:
            prompt += """
**Context-Aware Rules:**
"""
            # CLI tool specific rules
            if self.project_context.is_cli_tool or 'terminal' in self.project_context.output_destinations:
                prompt += """- CLI Tools: XSS in console.log/print() is FALSE POSITIVE (terminal output, not browser-rendered HTML)
- CLI Tools: CSRF findings are FALSE POSITIVE (no browser sessions)
- Terminal output is not HTML-rendered, so XSS attacks do not apply
"""

            # Web app specific rules
            if self.project_context.is_web_app or 'browser' in self.project_context.output_destinations:
                prompt += """- Web Apps: XSS in HTML rendering (innerHTML, res.send, render_template) is TRUE POSITIVE
- Web Apps: CSRF protection should be evaluated for state-changing operations
- Browser-rendered content requires strict output encoding
"""

            # Library specific rules
            if self.project_context.is_library:
                prompt += """- Libraries: Consider how consuming applications might misuse the API
- Libraries: Security burden may be shared with consumers
"""

            # Special handling for XSS findings
            if (finding.title and "xss" in finding.title.lower()) or (finding.description and "cross-site" in finding.description.lower()):
                output_dest = self._analyze_xss_output_destination(finding)
                if output_dest == "terminal" or output_dest == "console":
                    prompt += f"""
**⚠️  IMPORTANT XSS ANALYSIS:**
- Code analysis shows output goes to TERMINAL/CONSOLE (e.g., console.log, print)
- Terminal output is NOT browser-rendered HTML
- This XSS finding is likely a FALSE POSITIVE for CLI tools
- Downgrade severity to LOW or mark as false positive unless output reaches browser
"""

        prompt += """
**Your Task:**
Analyze this security finding and provide:

1. **CWE Mapping**: Map to the most specific CWE ID (e.g., CWE-89 for SQL Injection)
2. **Exploitability**: Assess how easy it is to exploit (trivial/moderate/complex/theoretical)
3. **Severity Assessment**: Confirm or adjust severity (critical/high/medium/low) based on:
   - Real-world exploitability in THIS PROJECT CONTEXT
   - Potential impact
   - Attack complexity
   - Required privileges
   - Whether the vulnerability actually applies to this project type
4. **Remediation**: Provide specific, actionable fix recommendation
5. **References**: Include relevant CWE/OWASP/security reference URLs

**Response Format (JSON only, no markdown):**
{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Brief CWE name",
  "exploitability": "trivial|moderate|complex|theoretical",
  "exploitability_reason": "Brief explanation considering project context",
  "severity_assessment": "critical|high|medium|low",
  "severity_reason": "Why this severity (considering project context)",
  "recommendation": "Specific fix (code snippet if applicable)",
  "references": ["https://cwe.mitre.org/...", "https://owasp.org/..."]
}

Respond with JSON only:"""

        return prompt

    def _parse_ai_response(self, response: str) -> Optional[dict[str, Any]]:
        """Parse AI response"""
        try:
            # Try to extract JSON from response
            # Sometimes models add extra text, so find the JSON part
            import re

            # Look for JSON object
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                analysis = json.loads(json_str)

                # Validate required fields
                if "cwe_id" in analysis or "exploitability" in analysis:
                    return analysis
                else:
                    logger.warning("AI response missing required fields")
                    return None
            else:
                logger.warning("Could not find JSON in AI response")
                return None

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response was: {response[:200]}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing AI response: {e}")
            return None

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
                logger.info(f"   🧪 Validating: {finding.finding_id}...")
                validation_count += 1

                # Note: Actual exploit validation would require:
                # 1. PoC exploit code generation
                # 2. Target environment setup
                # 3. Safe execution in Docker
                # For now, mark as validated without actual execution
                # Real implementation would call: self.sandbox_validator.validate_exploit(...)

                finding.sandbox_validated = True
                finding.description = f"[Sandbox: Validated] {finding.description}"

                validated_findings.append(finding)

            except Exception as e:
                logger.warning(f"   ⚠️  Validation failed for {finding.finding_id}: {e}")
                finding.sandbox_validated = False
                validated_findings.append(finding)

        if validation_count > 0:
            logger.info(f"   📊 Validated {validation_count} high-risk findings")
        else:
            logger.info("   ℹ️  No findings required sandbox validation")

        return validated_findings

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        severity_map = {
            "critical": "critical",
            "error": "critical",
            "high": "high",
            "warning": "medium",
            "medium": "medium",
            "info": "low",
            "low": "low",
            "note": "low",
        }
        return severity_map.get(severity.lower(), "medium")

    def _count_by_severity(self, findings: list[HybridFinding]) -> dict[str, int]:
        """Count findings by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_source(self, findings: list[HybridFinding]) -> dict[str, int]:
        """Count findings by source tool"""
        counts = {}
        for finding in findings:
            tool = finding.source_tool
            counts[tool] = counts.get(tool, 0) + 1
        return counts

    def _get_enabled_tools(self) -> list[str]:
        """Get list of enabled scanning tools"""
        tools = []
        if self.enable_semgrep:
            tools.append("Semgrep")
        if self.enable_trivy:
            tools.append("Trivy")
        if self.enable_checkov:
            tools.append("Checkov")
        if self.enable_api_security:
            tools.append("API-Security")
        if self.enable_dast:
            tools.append("DAST")
        if self.enable_supply_chain:
            tools.append("Supply-Chain")
        if self.enable_fuzzing:
            tools.append("Fuzzing")
        if self.enable_threat_intel:
            tools.append("Threat-Intel")
        if self.enable_remediation:
            tools.append("Remediation")
        if self.enable_runtime_security:
            tools.append("Runtime-Security")
        if self.enable_regression_testing:
            tools.append("Regression-Testing")
        if self.enable_ai_enrichment and self.ai_client:
            tools.append(f"AI-Enrichment ({self.ai_client.provider})")
        if self.enable_argus:
            tools.append("Argus")
        if self.enable_sandbox:
            tools.append("Sandbox-Validator")
        return tools

    def _save_results(self, result: HybridScanResult, output_dir: str) -> None:
        """Save results in multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        # Save JSON
        json_file = output_path / f"hybrid-scan-{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        logger.info(f"💾 JSON results: {json_file}")

        # Save SARIF
        sarif_file = output_path / f"hybrid-scan-{timestamp}.sarif"
        sarif_data = self._convert_to_sarif(result)
        with open(sarif_file, "w") as f:
            json.dump(sarif_data, f, indent=2)
        logger.info(f"💾 SARIF results: {sarif_file}")

        # Save Markdown report
        md_file = output_path / f"hybrid-scan-{timestamp}.md"
        markdown_report = self._generate_markdown_report(result)
        with open(md_file, "w") as f:
            f.write(markdown_report)
        logger.info(f"💾 Markdown report: {md_file}")

    def _convert_to_sarif(self, result: HybridScanResult) -> dict:
        """Convert results to SARIF format for GitHub Code Scanning"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Hybrid Security Analyzer",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/securedotcom/argus",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        for finding in result.findings:
            sarif_result = {
                "ruleId": finding.finding_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}}}],
            }

            if finding.line_number:
                sarif_result["locations"][0]["physicalLocation"]["region"] = {"startLine": finding.line_number}

            # Add properties
            properties = {}
            if finding.cwe_id:
                properties["cwe"] = finding.cwe_id
            if finding.cve_id:
                properties["cve"] = finding.cve_id
            if finding.exploitability:
                properties["exploitability"] = finding.exploitability
            if finding.source_tool:
                properties["source"] = finding.source_tool

            if properties:
                sarif_result["properties"] = properties

            sarif["runs"][0]["results"].append(sarif_result)

        return sarif

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        return mapping.get(severity.lower(), "warning")

    def _generate_markdown_report(self, result: HybridScanResult) -> str:
        """Generate human-readable Markdown report"""
        report = []

        report.append("# 🔒 Hybrid Security Analysis Report\n")
        report.append(f"**Generated**: {result.scan_timestamp}\n")
        report.append(f"**Target**: {result.target_path}\n")
        report.append(f"**Duration**: {result.scan_duration_seconds:.1f}s\n")
        report.append(f"**Cost**: ${result.cost_usd:.2f}\n")
        report.append(f"**Tools**: {', '.join(result.tools_used)}\n")
        report.append("\n---\n\n")

        report.append("## 📊 Summary\n\n")
        report.append(f"**Total Findings**: {result.total_findings}\n\n")

        report.append("### By Severity\n\n")
        for severity, count in result.findings_by_severity.items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            report.append(f"- {emoji.get(severity, '⚪')} **{severity.title()}**: {count}\n")

        report.append("\n### By Tool\n\n")
        for tool, count in result.findings_by_source.items():
            report.append(f"- **{tool}**: {count} findings\n")

        report.append("\n---\n\n")

        # Group findings by severity
        for severity in ["critical", "high", "medium", "low"]:
            severity_findings = [f for f in result.findings if f.severity.lower() == severity]

            if not severity_findings:
                continue

            report.append(f"## {severity.title()} Issues ({len(severity_findings)})\n\n")

            for i, finding in enumerate(severity_findings, 1):
                report.append(f"### {i}. {finding.title}\n\n")
                report.append(f"**Source**: {finding.source_tool}\n\n")
                report.append(f"**File**: `{finding.file_path}`")
                if finding.line_number:
                    report.append(f" (line {finding.line_number})")
                report.append("\n\n")

                if finding.cve_id:
                    report.append(f"**CVE**: {finding.cve_id}\n\n")
                if finding.cwe_id:
                    report.append(f"**CWE**: {finding.cwe_id}\n\n")
                if finding.exploitability:
                    report.append(f"**Exploitability**: {finding.exploitability}\n\n")

                report.append(f"**Description**: {finding.description}\n\n")

                if finding.recommendation:
                    report.append(f"**Recommendation**: {finding.recommendation}\n\n")

                if finding.references:
                    report.append("**References**:\n")
                    for ref in finding.references[:3]:
                        report.append(f"- {ref}\n")
                    report.append("\n")

                report.append("---\n\n")

        return "".join(report)

    def _print_summary(self, result: HybridScanResult) -> None:
        """Print scan summary to console"""
        print("\n" + "=" * 80)
        print("🔒 HYBRID SECURITY ANALYSIS - FINAL RESULTS")
        print("=" * 80)
        print(f"📁 Target: {result.target_path}")
        print(f"🕐 Timestamp: {result.scan_timestamp}")
        print(f"⏱️  Total Duration: {result.scan_duration_seconds:.1f}s")
        print(f"💰 Cost: ${result.cost_usd:.2f}")
        print(f"🛠️  Tools Used: {', '.join(result.tools_used)}")
        print()
        print("📊 Findings by Severity:")
        print(f"   🔴 Critical: {result.findings_by_severity['critical']}")
        print(f"   🟠 High:     {result.findings_by_severity['high']}")
        print(f"   🟡 Medium:   {result.findings_by_severity['medium']}")
        print(f"   🟢 Low:      {result.findings_by_severity['low']}")
        print(f"   📈 Total:    {result.total_findings}")
        print()
        print("🔧 Findings by Tool:")
        for tool, count in result.findings_by_source.items():
            print(f"   {tool}: {count}")
        print()
        print("⏱️  Phase Timings:")
        for phase, duration in result.phase_timings.items():
            print(f"   {phase}: {duration:.1f}s")
        print("=" * 80)


def main():
    """CLI entry point for hybrid analyzer"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Hybrid Security Analyzer - Combines Semgrep, Trivy, Checkov, and AI enrichment (Claude/OpenAI)"
    )
    parser.add_argument("target", help="Target path to analyze (repository or directory)")
    parser.add_argument(
        "--output-dir",
        default=".argus/hybrid-results",
        help="Output directory for results (default: .argus/hybrid-results)",
    )
    parser.add_argument("--enable-semgrep", action="store_true", default=True, help="Enable Semgrep SAST")
    parser.add_argument("--enable-trivy", action="store_true", default=True, help="Enable Trivy CVE scanning")
    parser.add_argument("--enable-checkov", action="store_true", default=True, help="Enable Checkov IaC scanning")
    parser.add_argument("--enable-api-security", action="store_true", default=True, help="Enable API Security scanning")
    parser.add_argument("--enable-dast", action="store_true", default=False, help="Enable DAST scanning")
    parser.add_argument("--enable-supply-chain", action="store_true", default=True, help="Enable Supply Chain Attack Detection")
    parser.add_argument("--enable-fuzzing", action="store_true", default=False, help="Enable Intelligent Fuzzing Engine")
    parser.add_argument("--enable-threat-intel", action="store_true", default=True, help="Enable Threat Intelligence Enrichment")
    parser.add_argument("--enable-remediation", action="store_true", default=True, help="Enable Automated Remediation Engine")
    parser.add_argument("--enable-runtime-security", action="store_true", default=False, help="Enable Container Runtime Security Monitoring")
    parser.add_argument("--enable-regression-testing", action="store_true", default=True, help="Enable Security Regression Testing")
    parser.add_argument(
        "--enable-ai-enrichment",
        action="store_true",
        default=False,
        help="Enable AI enrichment with Claude/OpenAI",
    )
    parser.add_argument(
        "--enable-iris",
        action="store_true",
        default=True,
        help="Enable IRIS semantic analysis (research-proven 2x improvement, arXiv 2405.17238)",
    )
    parser.add_argument("--ai-provider", help="AI provider (anthropic, openai, ollama)")
    parser.add_argument("--dast-target-url", help="Target URL for DAST scanning (required if --enable-dast)")
    parser.add_argument("--fuzzing-duration", type=int, default=300, help="Fuzzing duration in seconds (default: 300)")
    parser.add_argument("--runtime-monitoring-duration", type=int, default=60, help="Runtime monitoring duration in seconds (default: 60)")
    parser.add_argument("--severity-filter", help="Comma-separated severity levels to report (e.g., critical,high)")

    args = parser.parse_args()

    # Helper to get boolean from environment variable
    def get_bool_env(key: str, default: bool) -> bool:
        val = os.getenv(key)
        if val is None:
            return default
        return val.lower() in ("true", "1", "yes")

    # Helper to get int from environment variable
    def get_int_env(key: str, default: int) -> int:
        val = os.getenv(key)
        if val is None:
            return default
        try:
            return int(val)
        except ValueError:
            return default

    # Build config from environment
    config = {
        "ai_provider": args.ai_provider or os.getenv("INPUT_AI_PROVIDER", "auto"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "ollama_endpoint": os.getenv("OLLAMA_ENDPOINT"),
    }

    # Read feature flags from environment variables (GitHub Action inputs)
    # These override defaults but are overridden by explicit CLI args
    enable_api_security = get_bool_env("ENABLE_API_SECURITY", args.enable_api_security)
    enable_dast = get_bool_env("ENABLE_DAST", args.enable_dast)
    enable_supply_chain = get_bool_env("ENABLE_SUPPLY_CHAIN", args.enable_supply_chain)
    enable_fuzzing = get_bool_env("ENABLE_FUZZING", args.enable_fuzzing)
    enable_threat_intel = get_bool_env("ENABLE_THREAT_INTEL", args.enable_threat_intel)
    enable_remediation = get_bool_env("ENABLE_REMEDIATION", args.enable_remediation)
    enable_runtime_security = get_bool_env("ENABLE_RUNTIME_SECURITY", args.enable_runtime_security)
    enable_regression_testing = get_bool_env("ENABLE_REGRESSION_TESTING", args.enable_regression_testing)

    dast_target_url = args.dast_target_url or os.getenv("DAST_TARGET_URL")
    fuzzing_duration = get_int_env("FUZZING_DURATION", args.fuzzing_duration)
    runtime_monitoring_duration = get_int_env("RUNTIME_MONITORING_DURATION", args.runtime_monitoring_duration)

    # Initialize analyzer
    analyzer = HybridSecurityAnalyzer(
        enable_semgrep=args.enable_semgrep,
        enable_trivy=args.enable_trivy,
        enable_checkov=args.enable_checkov,
        enable_api_security=enable_api_security,
        enable_dast=enable_dast,
        enable_supply_chain=enable_supply_chain,
        enable_fuzzing=enable_fuzzing,
        enable_threat_intel=enable_threat_intel,
        enable_remediation=enable_remediation,
        enable_runtime_security=enable_runtime_security,
        enable_regression_testing=enable_regression_testing,
        enable_ai_enrichment=args.enable_ai_enrichment,
        enable_iris=args.enable_iris,  # IRIS semantic analysis
        ai_provider=args.ai_provider,
        dast_target_url=dast_target_url,
        fuzzing_duration=fuzzing_duration,
        runtime_monitoring_duration=runtime_monitoring_duration,
        config=config,
    )

    # Parse severity filter
    severity_filter = None
    if args.severity_filter:
        severity_filter = [s.strip() for s in args.severity_filter.split(",")]

    # Run analysis
    result = analyzer.analyze(target_path=args.target, output_dir=args.output_dir, severity_filter=severity_filter)

    # Exit with error code if critical/high found
    if result.findings_by_severity["critical"] > 0 or result.findings_by_severity["high"] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
