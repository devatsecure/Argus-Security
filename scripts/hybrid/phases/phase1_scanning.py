"""
Phase 1: Scanner Orchestration.

Runs all enabled deterministic security scanners in sequence and collects
their findings into a unified list of ``HybridFinding`` objects.

Scanners covered:
    Semgrep, TruffleHog, Trivy, Checkov, API-Security, DAST,
    Supply-Chain, Fuzzing, Threat-Intel, Runtime-Security,
    Regression-Testing.

The function is independent of the ``HybridSecurityAnalyzer`` class so that
it can be tested and invoked in isolation.
"""

import logging
import time
from typing import Any, Optional

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase1_scanning(
    *,
    target_path: str,
    analyzer: Any,
) -> tuple[list[HybridFinding], float]:
    """Execute Phase 1 -- deterministic scanner orchestration.

    Args:
        target_path: Filesystem path to scan.
        analyzer: ``HybridSecurityAnalyzer`` instance whose scanner
            instances and ``enable_*`` flags are inspected.

    Returns:
        A tuple of ``(findings, duration_seconds)``.
    """
    logger.info("-" * 80)
    logger.info("Phase 1: Static Analysis (Deterministic)")
    logger.info("-" * 80)

    phase1_start = time.time()
    all_findings: list[HybridFinding] = []

    # --- Semgrep ---
    if analyzer.enable_semgrep and analyzer.semgrep_scanner:
        try:
            logger.info("   Running Semgrep SAST...")
            semgrep_findings = analyzer._run_semgrep(target_path)
            all_findings.extend(semgrep_findings)
            logger.info("   Semgrep: %d findings", len(semgrep_findings))
        except Exception as e:
            logger.error("   Semgrep scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- TruffleHog ---
    if analyzer.enable_trufflehog and analyzer.trufflehog_scanner:
        try:
            logger.info("   Running TruffleHog secret scanner...")
            th_result = analyzer.trufflehog_scanner.scan(str(target_path), scan_type="filesystem")
            th_findings_raw = th_result.get("findings", [])
            trufflehog_findings: list[HybridFinding] = []
            for f in th_findings_raw:
                trufflehog_findings.append(HybridFinding(
                    finding_id=f"trufflehog-{f.get('detector_type', 'unknown')}-{len(trufflehog_findings)}",
                    source_tool="trufflehog",
                    severity="critical" if f.get("verified") else "high",
                    category="secrets",
                    title=f"Secret detected: {f.get('detector_type', 'Unknown')}",
                    description=(
                        f"TruffleHog detected a {'verified' if f.get('verified') else 'potential'} "
                        f"{f.get('detector_name', 'secret')} in {f.get('file_path', 'unknown')}"
                    ),
                    file_path=f.get("file_path", ""),
                    line_number=f.get("line"),
                ))
            all_findings.extend(trufflehog_findings)
            logger.info("   TruffleHog: %d secrets detected", len(trufflehog_findings))
        except Exception as e:
            logger.error("   TruffleHog scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Trivy ---
    if analyzer.enable_trivy and analyzer.trivy_scanner:
        try:
            logger.info("   Running Trivy CVE scanner...")
            trivy_findings = analyzer._run_trivy(target_path)
            all_findings.extend(trivy_findings)
            logger.info("   Trivy: %d CVEs", len(trivy_findings))
        except Exception as e:
            logger.error("   Trivy scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Checkov ---
    if analyzer.enable_checkov and analyzer.checkov_scanner:
        try:
            logger.info("   Running Checkov IaC scanner...")
            checkov_findings = analyzer._run_checkov(target_path)
            all_findings.extend(checkov_findings)
            logger.info("   Checkov: %d IaC misconfigurations", len(checkov_findings))
        except Exception as e:
            logger.error("   Checkov scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- API Security ---
    if analyzer.enable_api_security and analyzer.api_security_scanner:
        try:
            logger.info("   Running API Security scanner...")
            api_findings = analyzer._run_api_security(target_path)
            all_findings.extend(api_findings)
            logger.info("   API Security: %d API vulnerabilities", len(api_findings))
        except Exception as e:
            logger.error("   API Security scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- DAST ---
    if analyzer.enable_dast and analyzer.dast_scanner:
        try:
            logger.info("   Running DAST scanner...")
            dast_findings = analyzer._run_dast(target_path)
            all_findings.extend(dast_findings)
            logger.info("   DAST: %d runtime vulnerabilities", len(dast_findings))
        except Exception as e:
            logger.error("   DAST scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Supply Chain ---
    if analyzer.enable_supply_chain and analyzer.supply_chain_scanner:
        try:
            logger.info("   Running Supply Chain scanner...")
            supply_chain_findings = analyzer._run_supply_chain(target_path)
            all_findings.extend(supply_chain_findings)
            logger.info("   Supply Chain: %d dependency threats", len(supply_chain_findings))
        except Exception as e:
            logger.error("   Supply Chain scan failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Fuzzing ---
    if analyzer.enable_fuzzing and analyzer.fuzzing_scanner:
        try:
            logger.info("   Running Fuzzing Engine...")
            fuzzing_findings = analyzer._run_fuzzing(target_path)
            all_findings.extend(fuzzing_findings)
            logger.info("   Fuzzing: %d crashes discovered", len(fuzzing_findings))
        except Exception as e:
            logger.error("   Fuzzing failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Threat Intelligence Enrichment ---
    if analyzer.enable_threat_intel and analyzer.threat_intel_enricher and all_findings:
        try:
            logger.info("   Running Threat Intelligence Enrichment...")
            enriched_findings = analyzer._run_threat_intel(all_findings)
            all_findings = enriched_findings
            logger.info("   Threat Intel: %d findings enriched with threat context", len(all_findings))
        except Exception as e:
            logger.error("   Threat Intelligence enrichment failed: %s", e)
            logger.info("   Continuing with unenriched findings...")

    # --- Runtime Security ---
    if analyzer.enable_runtime_security and analyzer.runtime_security_monitor:
        try:
            logger.info("   Running Runtime Security Monitoring...")
            runtime_findings = analyzer._run_runtime_security(target_path)
            all_findings.extend(runtime_findings)
            logger.info("   Runtime Security: %d runtime threats detected", len(runtime_findings))
        except Exception as e:
            logger.error("   Runtime Security monitoring failed: %s", e)
            logger.info("   Continuing with other scanners...")

    # --- Regression Testing ---
    if analyzer.enable_regression_testing and analyzer.regression_tester:
        try:
            logger.info("   Running Security Regression Testing...")
            regression_findings = analyzer._run_regression_testing(target_path, all_findings)
            all_findings.extend(regression_findings)
            logger.info("   Regression Testing: %d regressions detected", len(regression_findings))
        except Exception as e:
            logger.error("   Regression testing failed: %s", e)
            logger.info("   Continuing with other scanners...")

    duration = time.time() - phase1_start
    logger.info("   Phase 1 duration: %.1fs", duration)

    if not all_findings:
        logger.info("   No findings from Phase 1 scanners")

    return all_findings, duration
