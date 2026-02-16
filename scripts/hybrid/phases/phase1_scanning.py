"""
Phase 1: Scanner Orchestration.

Runs all enabled deterministic security scanners in sequence and collects
their findings into a unified list of ``HybridFinding`` objects.

Scanners covered:
    Semgrep, TruffleHog, Gitleaks, Trivy, Checkov, API-Security, DAST,
    Supply-Chain, Fuzzing, Threat-Intel, Runtime-Security,
    Regression-Testing, Nuclei-Templates, ZAP-Baseline.

The function is independent of the ``HybridSecurityAnalyzer`` class so that
it can be tested and invoked in isolation.
"""

import logging
import time
from typing import Any

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase1_scanning(
    *,
    target_path: str,
    analyzer: Any,
) -> tuple[list[HybridFinding], float, dict[str, str]]:
    """Execute Phase 1 -- deterministic scanner orchestration.

    Args:
        target_path: Filesystem path to scan.
        analyzer: ``HybridSecurityAnalyzer`` instance whose scanner
            instances and ``enable_*`` flags are inspected.

    Returns:
        A tuple of ``(findings, duration_seconds, scanner_health)``.

        ``scanner_health`` maps each scanner name to one of:

        - ``"ran(N)"`` -- scanner produced *N* findings
        - ``"clean"``  -- scanner ran successfully but found nothing
        - ``"disabled"`` -- scanner was not enabled or not initialised
        - ``"failed"``  -- scanner raised an exception
    """
    logger.info("-" * 80)
    logger.info("Phase 1: Static Analysis (Deterministic)")
    logger.info("-" * 80)

    phase1_start = time.time()
    all_findings: list[HybridFinding] = []

    # Scanner health tracks status for every known scanner.
    # Pre-populate with the scanners and their enable/init flags so that
    # scanners that are skipped get marked "disabled" without extra logic.
    _scanner_flags: list[tuple[str, bool, bool]] = [
        ("Semgrep", getattr(analyzer, "enable_semgrep", False), getattr(analyzer, "semgrep_scanner", None) is not None),
        (
            "TruffleHog",
            getattr(analyzer, "enable_trufflehog", False),
            getattr(analyzer, "trufflehog_scanner", None) is not None,
        ),
        (
            "Gitleaks",
            getattr(analyzer, "enable_gitleaks", False),
            getattr(analyzer, "gitleaks_scanner", None) is not None,
        ),
        ("Trivy", getattr(analyzer, "enable_trivy", False), getattr(analyzer, "trivy_scanner", None) is not None),
        ("Checkov", getattr(analyzer, "enable_checkov", False), getattr(analyzer, "checkov_scanner", None) is not None),
        (
            "API-Security",
            getattr(analyzer, "enable_api_security", False),
            getattr(analyzer, "api_security_scanner", None) is not None,
        ),
        ("DAST", getattr(analyzer, "enable_dast", False), getattr(analyzer, "dast_scanner", None) is not None),
        (
            "Supply-Chain",
            getattr(analyzer, "enable_supply_chain", False),
            getattr(analyzer, "supply_chain_scanner", None) is not None,
        ),
        ("Fuzzing", getattr(analyzer, "enable_fuzzing", False), getattr(analyzer, "fuzzing_scanner", None) is not None),
        (
            "Threat-Intel",
            getattr(analyzer, "enable_threat_intel", False),
            getattr(analyzer, "threat_intel_enricher", None) is not None,
        ),
        (
            "Runtime-Security",
            getattr(analyzer, "enable_runtime_security", False),
            getattr(analyzer, "runtime_security_monitor", None) is not None,
        ),
        (
            "Regression-Testing",
            getattr(analyzer, "enable_regression_testing", False),
            getattr(analyzer, "regression_tester", None) is not None,
        ),
        (
            "Nuclei-Templates",
            getattr(analyzer, "enable_nuclei_templates", False),
            getattr(analyzer, "nuclei_template_scanner", None) is not None,
        ),
        (
            "ZAP-Baseline",
            getattr(analyzer, "enable_zap_baseline", False),
            getattr(analyzer, "zap_baseline_scanner", None) is not None,
        ),
    ]

    scanner_health: dict[str, str] = {}
    for name, enabled, initialised in _scanner_flags:
        if not enabled or not initialised:
            scanner_health[name] = "disabled"

    # --- Semgrep ---
    if analyzer.enable_semgrep and analyzer.semgrep_scanner:
        try:
            logger.info("   Running Semgrep SAST...")
            semgrep_findings = analyzer._run_semgrep(target_path)
            all_findings.extend(semgrep_findings)
            logger.info("   Semgrep: %d findings", len(semgrep_findings))
            scanner_health["Semgrep"] = f"ran({len(semgrep_findings)})" if semgrep_findings else "clean"
        except Exception as e:
            logger.error("   Semgrep scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Semgrep"] = "failed"

    # --- TruffleHog ---
    if analyzer.enable_trufflehog and analyzer.trufflehog_scanner:
        try:
            logger.info("   Running TruffleHog secret scanner...")
            th_result = analyzer.trufflehog_scanner.scan(str(target_path), scan_type="filesystem")
            th_findings_raw = th_result.get("findings", [])
            trufflehog_findings: list[HybridFinding] = []
            for f in th_findings_raw:
                trufflehog_findings.append(
                    HybridFinding(
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
                    )
                )
            all_findings.extend(trufflehog_findings)
            logger.info("   TruffleHog: %d secrets detected", len(trufflehog_findings))
            scanner_health["TruffleHog"] = f"ran({len(trufflehog_findings)})" if trufflehog_findings else "clean"
        except Exception as e:
            logger.error("   TruffleHog scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["TruffleHog"] = "failed"

    # --- Gitleaks ---
    if getattr(analyzer, "enable_gitleaks", False) and getattr(analyzer, "gitleaks_scanner", None):
        try:
            logger.info("   Running Gitleaks secret scanner...")
            from hybrid.scanner_runners import run_gitleaks

            gitleaks_findings = run_gitleaks(
                analyzer.gitleaks_scanner, str(target_path), logger
            )
            all_findings.extend(gitleaks_findings)
            logger.info("   Gitleaks: %d secrets detected", len(gitleaks_findings))
            scanner_health["Gitleaks"] = f"ran({len(gitleaks_findings)})" if gitleaks_findings else "clean"
        except Exception as e:
            logger.error("   Gitleaks scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Gitleaks"] = "failed"

    # --- Trivy ---
    if analyzer.enable_trivy and analyzer.trivy_scanner:
        try:
            logger.info("   Running Trivy CVE scanner...")
            trivy_findings = analyzer._run_trivy(target_path)
            all_findings.extend(trivy_findings)
            logger.info("   Trivy: %d CVEs", len(trivy_findings))
            scanner_health["Trivy"] = f"ran({len(trivy_findings)})" if trivy_findings else "clean"
        except Exception as e:
            logger.error("   Trivy scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Trivy"] = "failed"

    # --- Checkov ---
    if analyzer.enable_checkov and analyzer.checkov_scanner:
        try:
            logger.info("   Running Checkov IaC scanner...")
            checkov_findings = analyzer._run_checkov(target_path)
            all_findings.extend(checkov_findings)
            logger.info("   Checkov: %d IaC misconfigurations", len(checkov_findings))
            scanner_health["Checkov"] = f"ran({len(checkov_findings)})" if checkov_findings else "clean"
        except Exception as e:
            logger.error("   Checkov scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Checkov"] = "failed"

    # --- API Security ---
    if analyzer.enable_api_security and analyzer.api_security_scanner:
        try:
            logger.info("   Running API Security scanner...")
            api_findings = analyzer._run_api_security(target_path)
            all_findings.extend(api_findings)
            logger.info("   API Security: %d API vulnerabilities", len(api_findings))
            scanner_health["API-Security"] = f"ran({len(api_findings)})" if api_findings else "clean"
        except Exception as e:
            logger.error("   API Security scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["API-Security"] = "failed"

    # --- DAST ---
    if analyzer.enable_dast and analyzer.dast_scanner:
        try:
            logger.info("   Running DAST orchestrator (Nuclei + ZAP)...")
            dast_findings = analyzer._run_dast(target_path)
            all_findings.extend(dast_findings)
            logger.info("   DAST: %d runtime vulnerabilities", len(dast_findings))
            scanner_health["DAST"] = f"ran({len(dast_findings)})" if dast_findings else "clean"
        except Exception as e:
            logger.error("   DAST scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["DAST"] = "failed"

    # --- Supply Chain ---
    if analyzer.enable_supply_chain and analyzer.supply_chain_scanner:
        try:
            logger.info("   Running Supply Chain scanner...")
            supply_chain_findings = analyzer._run_supply_chain(target_path)
            all_findings.extend(supply_chain_findings)
            logger.info("   Supply Chain: %d dependency threats", len(supply_chain_findings))
            scanner_health["Supply-Chain"] = f"ran({len(supply_chain_findings)})" if supply_chain_findings else "clean"
        except Exception as e:
            logger.error("   Supply Chain scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Supply-Chain"] = "failed"

    # --- Fuzzing ---
    if analyzer.enable_fuzzing and analyzer.fuzzing_scanner:
        try:
            logger.info("   Running Fuzzing Engine...")
            fuzzing_findings = analyzer._run_fuzzing(target_path)
            all_findings.extend(fuzzing_findings)
            logger.info("   Fuzzing: %d crashes discovered", len(fuzzing_findings))
            scanner_health["Fuzzing"] = f"ran({len(fuzzing_findings)})" if fuzzing_findings else "clean"
        except Exception as e:
            logger.error("   Fuzzing failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Fuzzing"] = "failed"

    # --- Threat Intelligence Enrichment ---
    if analyzer.enable_threat_intel and analyzer.threat_intel_enricher and all_findings:
        try:
            logger.info("   Running Threat Intelligence Enrichment...")
            enriched_findings = analyzer._run_threat_intel(all_findings)
            all_findings = enriched_findings
            logger.info("   Threat Intel: %d findings enriched with threat context", len(all_findings))
            scanner_health["Threat-Intel"] = f"ran({len(all_findings)})"
        except Exception as e:
            logger.error("   Threat Intelligence enrichment failed: %s", e)
            logger.info("   Continuing with unenriched findings...")
            scanner_health["Threat-Intel"] = "failed"
    elif analyzer.enable_threat_intel and analyzer.threat_intel_enricher and not all_findings:
        # Enabled but nothing to enrich -- mark clean rather than disabled
        scanner_health["Threat-Intel"] = "clean"

    # --- Runtime Security ---
    if analyzer.enable_runtime_security and analyzer.runtime_security_monitor:
        try:
            logger.info("   Running Runtime Security Monitoring...")
            runtime_findings = analyzer._run_runtime_security(target_path)
            all_findings.extend(runtime_findings)
            logger.info("   Runtime Security: %d runtime threats detected", len(runtime_findings))
            scanner_health["Runtime-Security"] = f"ran({len(runtime_findings)})" if runtime_findings else "clean"
        except Exception as e:
            logger.error("   Runtime Security monitoring failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Runtime-Security"] = "failed"

    # --- Regression Testing ---
    if analyzer.enable_regression_testing and analyzer.regression_tester:
        try:
            logger.info("   Running Security Regression Testing...")
            regression_findings = analyzer._run_regression_testing(target_path, all_findings)
            all_findings.extend(regression_findings)
            logger.info("   Regression Testing: %d regressions detected", len(regression_findings))
            scanner_health["Regression-Testing"] = (
                f"ran({len(regression_findings)})" if regression_findings else "clean"
            )
        except Exception as e:
            logger.error("   Regression testing failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Regression-Testing"] = "failed"

    # --- Nuclei Template Scanner (source-aware DAST) ---
    if getattr(analyzer, "enable_nuclei_templates", False) and getattr(analyzer, "nuclei_template_scanner", None):
        try:
            logger.info("   Running Nuclei template scanner (source-aware DAST)...")
            nuclei_findings_raw = analyzer.nuclei_template_scanner.scan_source(str(target_path))
            nuclei_findings: list[HybridFinding] = []
            for f in nuclei_findings_raw:
                nuclei_findings.append(
                    HybridFinding(
                        finding_id=f.get("finding_id", f"nuclei-tmpl-{len(nuclei_findings)}"),
                        source_tool=f.get("source_tool", "nuclei-template"),
                        severity=f.get("severity", "medium"),
                        category=f.get("category", "dast"),
                        title=f.get("title", "Nuclei template finding"),
                        description=f.get("description", ""),
                        file_path=f.get("file_path", ""),
                        line_number=f.get("line_number", 0),
                        cwe_id=f.get("cwe_id"),
                    )
                )
            all_findings.extend(nuclei_findings)
            logger.info("   Nuclei templates: %d source-aware DAST findings", len(nuclei_findings))
            scanner_health["Nuclei-Templates"] = f"ran({len(nuclei_findings)})" if nuclei_findings else "clean"
        except Exception as e:
            logger.error("   Nuclei template scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["Nuclei-Templates"] = "failed"

    # --- ZAP Baseline Scanner (passive security checks) ---
    if getattr(analyzer, "enable_zap_baseline", False) and getattr(analyzer, "zap_baseline_scanner", None):
        try:
            logger.info("   Running ZAP baseline scanner (passive checks)...")
            zap_findings_raw = analyzer.zap_baseline_scanner.scan_source(str(target_path))
            zap_findings: list[HybridFinding] = []
            for f in zap_findings_raw:
                zap_findings.append(
                    HybridFinding(
                        finding_id=f.get("finding_id", f"zap-bl-{len(zap_findings)}"),
                        source_tool=f.get("source_tool", "zap-baseline"),
                        severity=f.get("severity", "low"),
                        category=f.get("category", "configuration"),
                        title=f.get("title", "ZAP baseline finding"),
                        description=f.get("description", ""),
                        file_path=f.get("file_path", ""),
                        line_number=f.get("line_number", 0),
                        cwe_id=f.get("cwe_id"),
                    )
                )
            all_findings.extend(zap_findings)
            logger.info("   ZAP baseline: %d passive findings", len(zap_findings))
            scanner_health["ZAP-Baseline"] = f"ran({len(zap_findings)})" if zap_findings else "clean"
        except Exception as e:
            logger.error("   ZAP baseline scan failed: %s", e)
            logger.info("   Continuing with other scanners...")
            scanner_health["ZAP-Baseline"] = "failed"

    duration = time.time() - phase1_start
    logger.info("   Phase 1 duration: %.1fs", duration)

    if not all_findings:
        logger.info("   No findings from Phase 1 scanners")

    # Log scanner health summary
    health_parts = [f"{name}={status}" for name, status in scanner_health.items()]
    logger.info("   Scanner health: %s", ", ".join(health_parts))

    return all_findings, duration, scanner_health
