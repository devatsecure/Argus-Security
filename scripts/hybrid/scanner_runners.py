"""
Scanner Runner Functions for Hybrid Security Analysis.

This module contains standalone runner functions for each security scanner
supported by the hybrid analyzer. Extracted from hybrid_analyzer.py for
better modularity and testability.

Each runner function:
- Takes a scanner instance, target_path, and logger as parameters
- Returns a list of HybridFinding objects
- Handles conversion from scanner-specific formats to HybridFinding
- Includes error handling and logging

Functions:
    normalize_severity: Convert severity strings to standard levels
    count_by_severity: Count findings by severity level
    count_by_source: Count findings by source tool
    run_semgrep: Run Semgrep SAST scanner
    run_trivy: Run Trivy CVE scanner
    run_checkov: Run Checkov IaC scanner
    run_api_security: Run API Security scanner
    run_dast: Run DAST scanner
    run_supply_chain: Run Supply Chain Attack Detection
    run_fuzzing: Run Intelligent Fuzzing Engine
    run_threat_intel: Run Threat Intelligence Enrichment
    run_remediation: Generate AI-powered remediation suggestions
    run_runtime_security: Run Container Runtime Security Monitoring
    run_regression_testing: Run Security Regression Testing
    run_gitleaks: Run Gitleaks pattern-based secret scanner
"""

import logging
import os
from typing import Any, Callable

from hybrid.models import HybridFinding


def run_scanner_guarded(
    name: str,
    get_findings: Callable[[], list[HybridFinding]],
    logger: logging.Logger,
) -> list[HybridFinding]:
    """
    Shared harness: run a scanner callable and return findings, or [] on any exception.
    Use this to avoid duplicating try/except and error logging in each run_*.
    """
    try:
        return get_findings()
    except Exception as e:
        logger.error("❌ %s scan failed: %s", name, e)
        return []


def normalize_severity(severity: str) -> str:
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


def count_by_severity(findings: list[HybridFinding]) -> dict[str, int]:
    """Count findings by severity level"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def count_by_source(findings: list[HybridFinding]) -> dict[str, int]:
    """Count findings by source tool"""
    counts = {}
    for finding in findings:
        tool = finding.source_tool
        counts[tool] = counts.get(tool, 0) + 1
    return counts


def run_semgrep(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Semgrep SAST and convert to HybridFinding format"""

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        if not hasattr(scanner, "scan"):
            return findings
        semgrep_results = scanner.scan(target_path)
        findings_list = (
            semgrep_results.get("findings", [])
            if isinstance(semgrep_results, dict)
            else semgrep_results
            if isinstance(semgrep_results, list)
            else []
        )
        for result in findings_list:
            rule_id = result.get("rule_id", "unknown")
            findings.append(
                HybridFinding(
                    finding_id=f"semgrep-{rule_id}",
                    source_tool="semgrep",
                    severity=normalize_severity(result.get("severity", "medium")),
                    category="security",
                    title=rule_id,
                    description=result.get("message", ""),
                    file_path=result.get("file_path", ""),
                    line_number=result.get("start_line", None),
                    recommendation=result.get("fix", ""),
                    references=result.get("references", []),
                    confidence=0.9,
                    cwe_id=result.get("cwe", None),
                )
            )
        return findings

    return run_scanner_guarded("Semgrep", _scan, logger)


def run_trivy(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Trivy CVE scan and convert to HybridFinding format"""

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        trivy_result = scanner.scan_filesystem(target_path, severity="CRITICAL,HIGH,MEDIUM,LOW")
        for trivy_finding in trivy_result.findings:
            findings.append(
                HybridFinding(
                    finding_id=f"trivy-{trivy_finding.cve_id}",
                    source_tool="trivy",
                    severity=normalize_severity(trivy_finding.severity),
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
                    confidence=1.0,
                    llm_enriched=False,
                )
            )
        return findings

    return run_scanner_guarded("Trivy", _scan, logger)


def run_checkov(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Checkov IaC scan and convert to HybridFinding format"""

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        checkov_result = scanner.scan(target_path)
        for checkov_finding in checkov_result.findings:
            line_number = (
                checkov_finding.file_line_range[0]
                if checkov_finding.file_line_range and len(checkov_finding.file_line_range) > 0
                else None
            )
            findings.append(
                HybridFinding(
                    finding_id=f"checkov-{checkov_finding.check_id}",
                    source_tool="checkov",
                    severity=normalize_severity(checkov_finding.severity),
                    category="security",
                    title=f"{checkov_finding.check_name} ({checkov_finding.framework})",
                    description=checkov_finding.description,
                    file_path=checkov_finding.file_path,
                    line_number=line_number,
                    recommendation=checkov_finding.guideline,
                    references=[checkov_finding.guideline] if checkov_finding.guideline else [],
                    confidence=0.9,
                    llm_enriched=False,
                )
            )
        return findings

    return run_scanner_guarded("Checkov", _scan, logger)


def run_api_security(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run API Security Scanner and convert to HybridFinding format"""

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        api_result = scanner.scan(target_path)
        if hasattr(api_result, "findings"):
            for api_finding in api_result.findings:
                findings.append(
                    HybridFinding(
                        finding_id=api_finding.finding_id,
                        source_tool="api-security",
                        severity=normalize_severity(api_finding.severity),
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
                )
        elif isinstance(api_result, list):
            for api_finding in api_result:
                findings.append(
                    HybridFinding(
                        finding_id=f"api-security-{api_finding.get('id', 'unknown')}",
                        source_tool="api-security",
                        severity=normalize_severity(api_finding.get("severity", "medium")),
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
                )
        return findings

    return run_scanner_guarded("API Security", _scan, logger)


def _discover_openapi_spec(target_path: str, logger: logging.Logger) -> str | None:
    """Auto-discover OpenAPI/Swagger spec files in the target directory."""
    import glob as glob_mod

    spec_patterns = [
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
        "**/openapi.json",
        "**/openapi.yaml",
        "**/openapi.yml",
        "**/swagger.json",
        "**/swagger.yaml",
        "**/swagger.yml",
        "api-spec.*",
        "api-docs.*",
    ]
    for pattern in spec_patterns:
        matches = glob_mod.glob(os.path.join(target_path, pattern), recursive=True)
        if matches:
            logger.info(f"   🔍 DAST: Auto-discovered OpenAPI spec: {matches[0]}")
            return matches[0]
    return None


def run_dast(
    orchestrator: Any,
    target_path: str,
    logger: logging.Logger,
    config: dict,
    dast_target_url: str | None = None,
) -> list[HybridFinding]:
    """Run DAST Orchestrator (Nuclei + ZAP) and convert to HybridFinding format.

    The orchestrator coordinates multiple DAST agents (Nuclei, ZAP) in
    parallel and returns aggregated, deduplicated findings.

    If no ``dast_target_url`` is provided, auto-discovers OpenAPI/Swagger
    spec files in the target directory for endpoint-aware scanning.

    Args:
        orchestrator: A ``DASTOrchestrator`` instance (from ``dast_orchestrator.py``).
        target_path: Filesystem path to the project being scanned.
        logger: Logger for status messages.
        config: Pipeline configuration dict.
        dast_target_url: Target URL for active DAST scanning.

    Returns:
        List of ``HybridFinding`` objects (empty list on error or no findings).
    """

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        openapi_spec = None
        url = dast_target_url
        if not url:
            openapi_spec = _discover_openapi_spec(target_path, logger)
            if not openapi_spec:
                logger.info("   DAST: No target URL or OpenAPI spec found, skipping")
                return findings
            url = config.get("dast_fallback_url", "http://localhost:8080")
            logger.info("   DAST: Using discovered OpenAPI spec with fallback URL %s", url)

        dast_result = orchestrator.scan(
            target_url=url,
            openapi_spec=openapi_spec or config.get("openapi_spec"),
            output_dir=config.get("dast_output_dir"),
        )

        for idx, agg in enumerate(dast_result.aggregated_findings):
            source_agent = agg.get("source", "dast")
            raw = agg.get("raw", {})
            classification = raw.get("info", {}).get("classification", {}) if isinstance(raw, dict) else {}
            cwe_id = classification.get("cwe-id")
            cve_id = classification.get("cve-id")
            findings.append(
                HybridFinding(
                    finding_id=f"dast-{source_agent}-{idx}",
                    source_tool=f"dast-{source_agent}",
                    severity=normalize_severity(agg.get("severity", "medium")),
                    category="dast",
                    title=agg.get("name", "DAST Finding"),
                    description=agg.get("description", ""),
                    file_path=agg.get("url", url),
                    line_number=None,
                    cwe_id=cwe_id if isinstance(cwe_id, str) else None,
                    cve_id=cve_id if isinstance(cve_id, str) else None,
                    recommendation="Review and remediate the runtime vulnerability",
                    references=[],
                    confidence=0.95,
                    llm_enriched=False,
                )
            )
        if dast_result.agents_failed:
            logger.warning("   DAST: Some agents failed: %s", ", ".join(dast_result.agents_failed))
        return findings

    return run_scanner_guarded("DAST", _scan, logger)


def run_supply_chain(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Supply Chain Attack Detection and convert to HybridFinding format"""

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        supply_chain_result = scanner.analyze_dependency_diff()
        if isinstance(supply_chain_result, list):
            for sc_threat in supply_chain_result:
                findings.append(
                    HybridFinding(
                        finding_id=f"supply-chain-{sc_threat.package_name}",
                        source_tool="supply-chain",
                        severity=normalize_severity(sc_threat.threat_level.value),
                        category="supply-chain",
                        title=f"Supply Chain Threat: {sc_threat.package_name} ({', '.join(sc_threat.threat_types)})",
                        description="\n".join(sc_threat.evidence)
                        if sc_threat.evidence
                        else f"Detected threats: {', '.join(sc_threat.threat_types)}",
                        file_path=sc_threat.change_info.file_path if sc_threat.change_info else target_path,
                        line_number=None,
                        cwe_id=None,
                        recommendation="\n".join(sc_threat.recommendations) if sc_threat.recommendations else "",
                        references=sc_threat.similar_legitimate_packages if sc_threat.similar_legitimate_packages else [],
                        confidence=0.95,
                        llm_enriched=False,
                    )
                )
        return findings

    return run_scanner_guarded("Supply Chain", _scan, logger)


def run_fuzzing(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Intelligent Fuzzing Engine and convert to HybridFinding format."""

    def _scan() -> list[HybridFinding]:
        import glob as glob_mod

        findings: list[HybridFinding] = []
        py_files = glob_mod.glob(os.path.join(target_path, "**", "*.py"), recursive=True)
        if not py_files:
            logger.info("   ℹ️  No Python files found for fuzzing")
            return findings

        fuzz_targets = py_files[:5]
        for py_file in fuzz_targets:
            rel_path = os.path.relpath(py_file, target_path)
            try:
                fuzzing_result = scanner.fuzz_function(
                    function_path=py_file,
                    function_name="__main__",
                    duration_minutes=1,
                )
                if hasattr(fuzzing_result, "crashes"):
                    for crash in fuzzing_result.crashes:
                        findings.append(
                            HybridFinding(
                                finding_id=f"fuzz-{crash.crash_id}",
                                source_tool="fuzzing",
                                severity=normalize_severity(getattr(crash, "severity", "medium")),
                                category="security",
                                title=f"Fuzzing crash in {rel_path}: {crash.crash_type}",
                                description=f"Crash type: {crash.crash_type}\nStack trace: {crash.stack_trace[:500]}",
                                file_path=rel_path,
                                cwe_id=getattr(crash, "cwe", None),
                                recommendation="Review and fix the crash-inducing input handling",
                                confidence=1.0 if crash.reproducible else 0.7,
                                llm_enriched=False,
                            )
                        )
            except Exception as e:
                logger.debug("   Fuzzing %s skipped: %s", rel_path, e)
        return findings

    return run_scanner_guarded("Fuzzing", _scan, logger)


def run_threat_intel(enricher: Any, findings: list[HybridFinding], logger: logging.Logger) -> list[HybridFinding]:
    """Run Threat Intelligence Enrichment to add real-time threat context"""
    enriched = []

    logger.info(f"   🌐 Enriching {len(findings)} findings with threat intelligence...")

    for finding in findings:
        try:
            # Enrich with threat intelligence if CVE is present
            if finding.cve_id:
                threat_context = enricher.enrich_cve(finding.cve_id)

                # Add threat intelligence metadata to finding
                if threat_context:
                    # Update exploitability based on threat intel
                    # ThreatContext is a dataclass, use getattr for attribute access
                    in_kev = getattr(threat_context, "in_kev_catalog", False)
                    if in_kev:
                        finding.exploitability = "trivial"  # Actively exploited in wild
                        finding.severity = "critical"  # Escalate severity

                    # Add EPSS score to description
                    epss_score = getattr(threat_context, "epss_score", None) or 0.0
                    if epss_score > 0.5:
                        finding.description = f"[EPSS: {epss_score:.1%} exploit probability] {finding.description}"

                    # Add exploit availability info
                    exploit_available = getattr(threat_context, "exploit_available", False)
                    if exploit_available:
                        finding.description = f"[Public exploit available] {finding.description}"

                    # Add references from threat intel
                    references = getattr(threat_context, "references", None)
                    if references:
                        finding.references.extend(references)

            enriched.append(finding)

        except Exception as e:
            logger.warning(f"⚠️  Threat intel enrichment failed for {finding.finding_id}: {e}")
            enriched.append(finding)

    logger.info("   ✅ Threat intelligence enrichment complete")
    return enriched


def run_remediation(engine: Any, findings: list[HybridFinding], logger: logging.Logger) -> list[HybridFinding]:
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
            suggestion = engine.suggest_fix(finding)

            if suggestion:
                # Update finding with remediation suggestion
                # RemediationSuggestion is a dataclass, use getattr for access
                fix_explanation = getattr(suggestion, "fix_explanation", None)
                if fix_explanation:
                    finding.recommendation = fix_explanation

                # Add code patch if available
                code_patch = getattr(suggestion, "code_patch", None)
                if code_patch:
                    finding.description = f"{finding.description}\n\n**Suggested Fix:**\n```\n{code_patch}\n```"

                # Add testing recommendations
                testing_recs = getattr(suggestion, "testing_recommendations", None)
                if testing_recs:
                    finding.references.append(f"Testing: {testing_recs}")

            remediated.append(finding)

        except Exception as e:
            logger.warning(f"⚠️  Remediation generation failed for {finding.finding_id}: {e}")
            remediated.append(finding)

    logger.info("   ✅ Remediation suggestions generated")
    return remediated


def run_runtime_security(
    monitor: Any, target_path: str, logger: logging.Logger, monitoring_duration: int
) -> list[HybridFinding]:
    """Run Container Runtime Security Monitoring using Falco-based monitor_realtime()."""

    def _scan() -> list[HybridFinding]:
        logger.info("   🐳 Monitoring runtime security for %ds...", monitoring_duration)
        findings: list[HybridFinding] = []
        alerts = monitor.monitor_realtime(duration_seconds=monitoring_duration)
        for alert in alerts or []:
            findings.append(
                HybridFinding(
                    finding_id=f"runtime-{getattr(alert, 'alert_id', 'unknown')}",
                    source_tool="runtime-security",
                    severity=normalize_severity(getattr(alert, "severity", "medium")),
                    category="runtime",
                    title=getattr(alert, "title", "Runtime Security Threat"),
                    description=getattr(alert, "description", str(alert)),
                    file_path=getattr(alert, "container_id", target_path),
                    cwe_id=getattr(alert, "cwe_id", None),
                    recommendation=getattr(alert, "recommendation", "Review runtime security event"),
                    confidence=0.9,
                    llm_enriched=False,
                )
            )
        return findings

    return run_scanner_guarded("Runtime Security", _scan, logger)


def run_regression_testing(
    tester: Any, target_path: str, current_findings: list[HybridFinding], logger: logging.Logger
) -> list[HybridFinding]:
    """Run Security Regression Testing to detect reappearance of fixed vulnerabilities"""

    def _scan() -> list[HybridFinding]:
        logger.info("   🧪 Checking for security regressions...")
        findings: list[HybridFinding] = []
        results = tester.run_all_tests()
        for failure in results.get("failures", []):
            findings.append(
                HybridFinding(
                    finding_id=failure.get("test_id", "unknown"),
                    source_tool="regression-testing",
                    severity="high",
                    category="regression",
                    title=f"Security Regression: {failure.get('vulnerability', 'Fixed vulnerability reappeared')}",
                    description=f"Previously fixed {failure.get('vulnerability', 'vulnerability')} has reappeared. Test output: {failure.get('output', '')}",
                    file_path=failure.get("file", target_path),
                    line_number=None,
                    cwe_id=None,
                    cve_id=None,
                    recommendation="Review and re-apply the security fix for this vulnerability",
                    references=[],
                    confidence=1.0,
                    llm_enriched=False,
                )
            )
        return findings

    return run_scanner_guarded("Regression Testing", _scan, logger)


def run_gitleaks(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Gitleaks secret scanner and convert to HybridFinding format.

    Gitleaks performs pattern-based secret detection, complementing TruffleHog's
    verified-secret approach.  The scanner wraps the ``gitleaks`` CLI binary and
    returns results as ``HybridFinding`` objects with ``source_tool="gitleaks"``
    and ``category="secrets"``.

    Args:
        scanner: A ``GitleaksScanner`` instance with a ``.scan()`` method.
        target_path: Filesystem path to scan.
        logger: Logger for status messages.

    Returns:
        List of ``HybridFinding`` objects (empty list on error or no findings).
    """

    def _scan() -> list[HybridFinding]:
        findings: list[HybridFinding] = []
        gitleaks_result = scanner.scan(str(target_path), scan_type="filesystem")
        if gitleaks_result.get("error"):
            error_msg = gitleaks_result.get("error", "unknown")
            if error_msg == "gitleaks_not_installed":
                logger.warning("⚠️  Gitleaks binary not installed -- skipping")
            else:
                logger.warning("⚠️  Gitleaks returned error: %s", error_msg)
            return findings

        for idx, f in enumerate(gitleaks_result.get("findings", [])):
            file_path = f.get("file_path", "")
            if not file_path or file_path.strip() in ("", "."):
                continue
            rule_id = f.get("rule_id", "unknown")
            description = f.get("description", "Secret detected")
            findings.append(
                HybridFinding(
                    finding_id=f"gitleaks-{rule_id}-{idx}",
                    source_tool="gitleaks",
                    severity="high",
                    category="secrets",
                    title=f"Secret detected: {description}",
                    description=(
                        f"Gitleaks detected a potential {description} secret in {file_path}"
                        + (f" (commit {f.get('commit', '')[:8]})" if f.get("commit") else "")
                    ),
                    file_path=file_path,
                    line_number=f.get("start_line"),
                    confidence=0.7,
                )
            )
        return findings

    return run_scanner_guarded("Gitleaks", _scan, logger)


__all__ = [
    "normalize_severity",
    "count_by_severity",
    "count_by_source",
    "run_semgrep",
    "run_trivy",
    "run_checkov",
    "run_api_security",
    "run_dast",
    "run_supply_chain",
    "run_fuzzing",
    "run_threat_intel",
    "run_remediation",
    "run_runtime_security",
    "run_regression_testing",
    "run_gitleaks",
]
