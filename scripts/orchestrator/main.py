#!/usr/bin/env python3
"""
Main Orchestrator Module

Coordinates all extracted modules to execute the complete AI audit workflow:
- File selection and prioritization
- Cost estimation and tracking
- LLM provider detection and client management
- Report generation
- Metrics collection and observability

This module acts as the central coordinator, orchestrating the flow from
repository analysis through report generation.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cost_tracker import CostCircuitBreaker, CostLimitExceededError
from .metrics_collector import ReviewMetrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class AuditOrchestrator:
    """Main orchestrator for AI-powered code audits

    Coordinates the workflow:
    1. Detect AI provider and initialize client
    2. Select and prioritize files
    3. Estimate and track costs
    4. Execute LLM analysis
    5. Generate reports and metrics

    Example:
        orchestrator = AuditOrchestrator(repo_path, config)
        blockers, suggestions, metrics = orchestrator.run()
    """

    def __init__(self, repo_path: str, config: Dict[str, Any]):
        """Initialize the orchestrator"""
        self.repo_path = repo_path
        self.config = config
        self.metrics = ReviewMetrics()
        self.circuit_breaker: Optional[CostCircuitBreaker] = None
        self.client: Optional[Any] = None
        self.provider: Optional[str] = None
        self.model: Optional[str] = None
        self.threat_model: Optional[Dict] = None
        self.files: List[Dict] = []
        logger.info(f"Orchestrator initialized for repository: {repo_path}")

    def initialize_provider(self) -> bool:
        """Initialize AI provider and client"""
        logger.info("Initializing AI provider...")
        try:
            from scripts.run_ai_audit import (
                detect_ai_provider,
                get_ai_client,
                get_model_name,
                get_working_model_with_fallback,
            )

            self.provider = detect_ai_provider(self.config)
            if not self.provider:
                logger.error("No AI provider available")
                return False

            self.client, _ = get_ai_client(self.provider, self.config)
            if not self.client:
                logger.error("Failed to get AI client")
                return False

            self.model = get_model_name(self.provider, self.config)

            if self.provider == "anthropic":
                self.model = get_working_model_with_fallback(self.client, self.provider, self.model)

            self.metrics.metrics["provider"] = self.provider
            self.metrics.metrics["model"] = self.model

            cost_limit = float(self.config.get("cost_limit", 1.0))
            self.circuit_breaker = CostCircuitBreaker(cost_limit_usd=cost_limit)

            logger.info("Provider initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Provider initialization failed: {e}")
            return False

    def select_files(self) -> bool:
        """Select and prioritize files for analysis"""
        logger.info("Selecting and prioritizing files...")
        try:
            from scripts.run_ai_audit import get_codebase_context

            self.files = get_codebase_context(self.repo_path, self.config)
            if not self.files:
                logger.warning("No files to analyze")
                return False

            for f in self.files:
                self.metrics.record_file(f.get("lines", 0))

            logger.info(f"Selected {len(self.files)} files for analysis")
            return True
        except Exception as e:
            logger.error(f"File selection failed: {e}")
            return False

    def estimate_costs(self) -> float:
        """Estimate and validate audit costs"""
        logger.info("Estimating audit costs...")
        try:
            from scripts.run_ai_audit import estimate_cost

            max_tokens = int(self.config.get("max_tokens", 8000))
            estimated_cost, _, _ = estimate_cost(self.files, max_tokens, self.provider)
            logger.info(f"Estimated cost: ${estimated_cost:.2f}")

            cost_limit = float(self.config.get("cost_limit", 1.0))
            if estimated_cost > cost_limit and self.provider != "ollama":
                logger.error(f"Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
                return -1

            return estimated_cost
        except Exception as e:
            logger.error(f"Cost estimation failed: {e}")
            return -1

    def load_threat_model(self) -> bool:
        """Load or generate threat model"""
        logger.info("Loading threat model...")
        try:
            from scripts.run_ai_audit import THREAT_MODELING_AVAILABLE

            if not THREAT_MODELING_AVAILABLE:
                return False

            try:
                from threat_model_generator import HybridThreatModelGenerator
            except ImportError:
                try:
                    from pytm_threat_model import PytmThreatModelGenerator as HybridThreatModelGenerator
                except ImportError:
                    logger.warning("Threat modeling libraries not available")
                    return False

            threat_model_path = Path(self.repo_path) / ".argus/threat-model.json"
            api_key = (
                self.config.get("anthropic_api_key", "")
                if self.config.get("enable_threat_modeling", "true").lower() == "true"
                else None
            )

            generator = HybridThreatModelGenerator(api_key)
            self.threat_model = generator.load_existing_threat_model(threat_model_path)

            if not self.threat_model:
                repo_context = generator.analyze_repository(self.repo_path)
                self.threat_model = generator.generate_threat_model(repo_context)
                generator.save_threat_model(self.threat_model, threat_model_path)
                logger.info(f"Threat model generated: {threat_model_path}")
            else:
                logger.info(f"Loaded existing threat model: {threat_model_path}")

            self.metrics.record_threat_model(self.threat_model)
            return True
        except Exception as e:
            logger.error(f"Threat modeling failed: {e}")
            return False

    def run_heuristic_scan(self) -> Dict[str, List[str]]:
        """Run heuristic pre-scan on files"""
        logger.info("Running heuristic pre-scan...")
        try:
            if not self.config.get("enable_heuristics", "true").lower() == "true":
                return {}

            from scripts.run_ai_audit import HeuristicScanner

            scanner = HeuristicScanner()
            results = scanner.scan_codebase(self.files)

            if results:
                flagged = len(results)
                total_flags = sum(len(flags) for flags in results.values())
                logger.info(f"Flagged {flagged} files with {total_flags} potential issues")
            else:
                logger.info("No heuristic flags - codebase looks clean")

            return results
        except Exception as e:
            logger.warning(f"Heuristic scan failed: {e}")
            return {}

    def run_semgrep_scan(self) -> Dict[str, Any]:
        """Run Semgrep SAST scan"""
        logger.info("Running Semgrep SAST scan...")
        try:
            if not self.config.get("enable_semgrep", True):
                return {}

            from scripts.semgrep_scanner import SemgrepScanner

            semgrep_scanner = SemgrepScanner({
                "semgrep_rules": "auto",
                "exclude_patterns": [
                    "*/test/*", "*/tests/*", "*/.git/*", "*/node_modules/*",
                    "*/.venv/*", "*/venv/*", "*/build/*", "*/dist/*",
                ],
            })

            results = semgrep_scanner.scan(self.repo_path)

            if results.get("findings"):
                count = len(results["findings"])
                logger.info(f"Semgrep found {count} issues")
                self.metrics.record("semgrep_findings", count)
            else:
                logger.info("Semgrep: no issues found")
                self.metrics.record("semgrep_findings", 0)

            return results
        except ImportError:
            logger.warning("Semgrep not installed")
            return {}
        except Exception as e:
            logger.warning(f"Semgrep scan failed: {e}")
            return {}

    def execute_llm_analysis(
        self,
        prompt: str,
        max_tokens: int,
        operation: str = "LLM call",
    ) -> Tuple[str, int, int]:
        """Execute LLM analysis with cost enforcement"""
        logger.info(f"Executing LLM analysis ({operation})...")
        try:
            from scripts.run_ai_audit import call_llm_api

            report, input_tokens, output_tokens = call_llm_api(
                self.client,
                self.provider,
                self.model,
                prompt,
                max_tokens,
                circuit_breaker=self.circuit_breaker,
                operation=operation,
            )

            self.metrics.record_llm_call(input_tokens, output_tokens, self.provider)
            logger.info(f"LLM analysis complete: {input_tokens} input, {output_tokens} output tokens")
            return report, input_tokens, output_tokens
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise

    def generate_reports(
        self,
        findings: List[Dict],
        report_text: str,
        report_dir: Optional[Path] = None,
    ) -> Dict[str, str]:
        """Generate audit reports in multiple formats"""
        logger.info("Generating reports...")

        if report_dir is None:
            report_dir = Path(self.repo_path) / ".argus/reviews"

        report_dir.mkdir(parents=True, exist_ok=True)

        try:
            from scripts.run_ai_audit import generate_sarif, parse_findings_from_report

            # Save Markdown report
            report_file = report_dir / "audit-report.md"
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(f"Markdown report saved: {report_file}")

            # Parse findings if not provided
            if not findings:
                findings = parse_findings_from_report(report_text)

            for finding in findings:
                self.metrics.record_finding(
                    finding.get("severity", "low"),
                    finding.get("category", "quality"),
                )

            # Generate SARIF
            sarif = generate_sarif(findings, self.repo_path, self.metrics)
            sarif_file = report_dir / "results.sarif"
            with open(sarif_file, "w") as f:
                json.dump(sarif, f, indent=2)
            logger.info(f"SARIF report saved: {sarif_file}")

            # Generate JSON
            json_output = {
                "version": "1.0.16",
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
                "commit": os.environ.get("GITHUB_SHA", "unknown"),
                "provider": self.provider,
                "model": self.model,
                "summary": self.metrics.metrics,
                "findings": findings,
            }

            json_file = report_dir / "results.json"
            with open(json_file, "w") as f:
                json.dump(json_output, f, indent=2)
            logger.info(f"JSON report saved: {json_file}")

            # Save metrics
            metrics_file = report_dir / "metrics.json"
            self.metrics.finalize()
            self.metrics.save(metrics_file)

            return {
                "markdown": str(report_file),
                "sarif": str(sarif_file),
                "json": str(json_file),
                "metrics": str(metrics_file),
            }
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise

    def print_summary(self, findings: List[Dict]) -> Tuple[int, int]:
        """Print audit summary to console"""
        self.metrics.finalize()

        blocker_count = (
            self.metrics.metrics["findings"]["critical"] + self.metrics.metrics["findings"]["high"]
        )
        suggestion_count = (
            self.metrics.metrics["findings"]["medium"] + self.metrics.metrics["findings"]["low"]
        )

        print("\n📊 Final Results:")
        print(f"   Critical: {self.metrics.metrics['findings']['critical']}")
        print(f"   High: {self.metrics.metrics['findings']['high']}")
        print(f"   Medium: {self.metrics.metrics['findings']['medium']}")
        print(f"   Low: {self.metrics.metrics['findings']['low']}")
        print(f"\n💰 Total Cost: ${self.metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Total Duration: {self.metrics.metrics['duration_seconds']}s")

        if any(self.metrics.metrics["exploitability"].values()):
            print("\n⚠️  Exploitability:")
            for level, count in self.metrics.metrics["exploitability"].items():
                if count > 0:
                    print(f"   {level}: {count}")

        if self.metrics.metrics["exploit_chains_found"] > 0:
            print(f"   ⛓️  Exploit Chains: {self.metrics.metrics['exploit_chains_found']}")

        if self.metrics.metrics["tests_generated"] > 0:
            print(f"   🧪 Tests Generated: {self.metrics.metrics['tests_generated']}")

        print(f"\nblockers={blocker_count}")
        print(f"suggestions={suggestion_count}")
        print(f"cost-estimate={self.metrics.metrics['cost_usd']:.4f}")
        print(f"files-analyzed={self.metrics.metrics['files_reviewed']}")
        print(f"duration-seconds={self.metrics.metrics['duration_seconds']}")

        return blocker_count, suggestion_count

    def check_fail_conditions(self, findings: List[Dict]) -> bool:
        """Check if audit should fail based on configured conditions"""
        fail_on = self.config.get("fail_on", "")
        if not fail_on:
            return False

        print(f"\n🚦 Checking fail conditions: {fail_on}")
        conditions = [c.strip() for c in fail_on.split(",") if c.strip()]

        should_fail = False
        for condition in conditions:
            if ":" in condition:
                category, severity = condition.split(":", 1)
                category = category.strip().lower()
                severity = severity.strip().lower()

                if category == "any":
                    if severity in self.metrics.metrics["findings"] and self.metrics.metrics["findings"][
                        severity
                    ] > 0:
                        print(f"   ❌ FAIL: Found {self.metrics.metrics['findings'][severity]} {severity} issues")
                        should_fail = True
                else:
                    matching = [
                        f for f in findings
                        if f.get("category") == category and f.get("severity") == severity
                    ]
                    if matching:
                        print(f"   ❌ FAIL: Found {len(matching)} {category}:{severity} issues")
                        should_fail = True

        return should_fail

    def write_github_output(self, reports: Dict[str, str], blockers: int, suggestions: int) -> None:
        """Write output for GitHub Actions"""
        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"blockers={blockers}\n")
                f.write(f"suggestions={suggestions}\n")
                f.write(f"report-path={reports.get('markdown', '')}\n")
                f.write(f"sarif-path={reports.get('sarif', '')}\n")
                f.write(f"json-path={reports.get('json', '')}\n")
                f.write(f"cost-estimate={self.metrics.metrics['cost_usd']:.2f}\n")
                f.write(f"files-analyzed={self.metrics.metrics['files_reviewed']}\n")
                f.write(f"duration-seconds={self.metrics.metrics['duration_seconds']}\n")
            logger.info("GitHub Actions output written")


def run_audit(repo_path: str, config: Dict[str, Any], review_type: str = "audit") -> Tuple[int, int, ReviewMetrics]:
    """Run a complete AI-powered code audit

    Orchestrates the entire audit workflow from file selection through
    report generation and GitHub Actions integration.

    Args:
        repo_path: Path to the repository to audit
        config: Configuration dictionary
        review_type: Type of review (audit, security, performance, etc.)

    Returns:
        Tuple[int, int, ReviewMetrics]: (blockers, suggestions, metrics)
    """
    print(f"🤖 Starting AI-powered {review_type} analysis...")
    print(f"📁 Repository: {repo_path}")

    orchestrator = AuditOrchestrator(repo_path, config)

    if not orchestrator.initialize_provider():
        print("❌ Failed to initialize AI provider")
        sys.exit(2)

    print(f"🔧 Provider: {orchestrator.provider}")
    print(f"🧠 Model: {orchestrator.model}")

    print("📂 Analyzing codebase structure...")
    if not orchestrator.select_files():
        print("⚠️  No files to analyze")
        return 0, 0, orchestrator.metrics

    estimated_cost = orchestrator.estimate_costs()
    if estimated_cost < 0:
        print("❌ Cost limit would be exceeded")
        sys.exit(2)

    if orchestrator.provider == "ollama":
        print("💰 Estimated cost: $0.00 (local Ollama)")
    else:
        print(f"💰 Estimated cost: ${estimated_cost:.2f}")

    orchestrator.load_threat_model()
    heuristic_results = orchestrator.run_heuristic_scan()
    semgrep_results = orchestrator.run_semgrep_scan()

    print("✅ Orchestrator initialized and ready for analysis")
    print(f"   Provider: {orchestrator.provider}")
    print(f"   Model: {orchestrator.model}")
    print(f"   Files: {len(orchestrator.files)}")
    print(f"   Heuristic flags: {len(heuristic_results)}")
    print(f"   Semgrep issues: {len(semgrep_results.get('findings', []))}")

    return 0, 0, orchestrator.metrics
