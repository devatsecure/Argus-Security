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
"""

import logging
from typing import Any

from hybrid.models import HybridFinding


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
    findings = []

    try:
        # Call semgrep scanner (user's implementation)
        # This assumes semgrep_scanner.py has a scan() method
        if hasattr(scanner, "scan"):
            semgrep_results = scanner.scan(target_path)

            # Convert to HybridFinding format
            # Semgrep scanner returns dict with 'findings' key
            findings_list = []
            if isinstance(semgrep_results, dict):
                findings_list = semgrep_results.get('findings', [])
            elif isinstance(semgrep_results, list):
                findings_list = semgrep_results

            for result in findings_list:
                # SemgrepScanner returns: rule_id, file_path, start_line, message
                rule_id = result.get('rule_id', 'unknown')
                finding = HybridFinding(
                    finding_id=f"semgrep-{rule_id}",
                    source_tool="semgrep",
                    severity=normalize_severity(result.get("severity", "medium")),
                    category="security",
                    title=rule_id,  # Use rule_id as title
                    description=result.get("message", ""),
                    file_path=result.get("file_path", ""),  # Changed from 'path'
                    line_number=result.get("start_line", None),  # Changed from 'line'
                    recommendation=result.get("fix", ""),
                    references=result.get("references", []),
                    confidence=0.9,  # Semgrep has low false positive rate
                    cwe_id=result.get("cwe", None),  # Add CWE if available
                )
                findings.append(finding)

    except Exception as e:
        logger.error(f"❌ Semgrep scan failed: {e}")

    return findings


def run_trivy(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Trivy CVE scan and convert to HybridFinding format"""
    findings = []

    try:
        # Run Trivy scanner
        trivy_result = scanner.scan_filesystem(target_path, severity="CRITICAL,HIGH,MEDIUM,LOW")

        # Convert to HybridFinding format
        for trivy_finding in trivy_result.findings:
            finding = HybridFinding(
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
                confidence=1.0,  # CVEs are confirmed
                llm_enriched=False,  # Will be enriched in Phase 2 if AI is enabled
            )
            findings.append(finding)

    except Exception as e:
        logger.error(f"❌ Trivy scan failed: {e}")

    return findings


def run_checkov(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Checkov IaC scan and convert to HybridFinding format"""
    findings = []

    try:
        # Run Checkov scanner
        checkov_result = scanner.scan(target_path)

        # Convert to HybridFinding format
        for checkov_finding in checkov_result.findings:
            # Build line number from line range
            line_number = None
            if checkov_finding.file_line_range and len(checkov_finding.file_line_range) > 0:
                line_number = checkov_finding.file_line_range[0]

            finding = HybridFinding(
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
                confidence=0.9,  # Checkov has low false positive rate for IaC
                llm_enriched=False,  # Will be enriched in Phase 2 if AI is enabled
            )
            findings.append(finding)

    except Exception as e:
        logger.error(f"❌ Checkov scan failed: {e}")

    return findings


def run_api_security(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run API Security Scanner and convert to HybridFinding format"""
    findings = []

    try:
        # Run API Security scanner
        api_result = scanner.scan(target_path)

        # Convert to HybridFinding format
        # API scanner returns APIScanResult object with findings attribute
        if hasattr(api_result, 'findings'):
            for api_finding in api_result.findings:
                finding = HybridFinding(
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
                findings.append(finding)
        elif isinstance(api_result, list):
            # Fallback for legacy format
            for api_finding in api_result:
                finding = HybridFinding(
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
                findings.append(finding)

    except Exception as e:
        logger.error(f"❌ API Security scan failed: {e}")

    return findings


def run_dast(scanner: Any, target_path: str, logger: logging.Logger, config: dict, dast_target_url: str | None = None) -> list[HybridFinding]:
    """Run DAST Scanner and convert to HybridFinding format"""
    findings = []

    # DAST requires a target URL
    if not dast_target_url:
        logger.info("   ℹ️  DAST: No target URL provided, skipping")
        return findings

    try:
        # Run DAST scanner
        dast_config = {
            "severity": config.get("dast_severity", "critical,high,medium"),
            "timeout": config.get("dast_timeout", 300),
        }
        dast_result = scanner.scan(dast_config)

        # Convert to HybridFinding format
        if isinstance(dast_result, list):
            for dast_finding in dast_result:
                finding = HybridFinding(
                    finding_id=f"dast-{dast_finding.get('id', 'unknown')}",
                    source_tool="dast",
                    severity=normalize_severity(dast_finding.get("severity", "medium")),
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


def run_supply_chain(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Supply Chain Attack Detection and convert to HybridFinding format"""
    findings = []

    try:
        # Run Supply Chain scanner
        # Note: SupplyChainAnalyzer.analyze_dependency_diff returns ThreatAssessment objects
        supply_chain_result = scanner.analyze_dependency_diff()

        # Convert to HybridFinding format
        # supply_chain_result is a list of ThreatAssessment objects
        if isinstance(supply_chain_result, list):
            for sc_threat in supply_chain_result:
                # ThreatAssessment has: package_name, ecosystem, threat_level, threat_types, evidence, recommendations
                finding = HybridFinding(
                    finding_id=f"supply-chain-{sc_threat.package_name}",
                    source_tool="supply-chain",
                    severity=normalize_severity(sc_threat.threat_level.value),
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


def run_fuzzing(scanner: Any, target_path: str, logger: logging.Logger) -> list[HybridFinding]:
    """Run Intelligent Fuzzing Engine and convert to HybridFinding format"""
    findings = []

    try:
        # Run Fuzzing scanner
        fuzzing_result = scanner.scan(target_path)

        # Convert to HybridFinding format
        if isinstance(fuzzing_result, list):
            for fuzz_finding in fuzzing_result:
                finding = HybridFinding(
                    finding_id=fuzz_finding.get("id", "unknown"),
                    source_tool="fuzzing",
                    severity=normalize_severity(fuzz_finding.get("severity", "medium")),
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
                        finding.description = (
                            f"[EPSS: {epss_score:.1%} exploit probability] {finding.description}"
                        )

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

    logger.info(f"   ✅ Threat intelligence enrichment complete")
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
                    finding.description = (
                        f"{finding.description}\n\n"
                        f"**Suggested Fix:**\n```\n{code_patch}\n```"
                    )

                # Add testing recommendations
                testing_recs = getattr(suggestion, "testing_recommendations", None)
                if testing_recs:
                    finding.references.append(
                        f"Testing: {testing_recs}"
                    )

            remediated.append(finding)

        except Exception as e:
            logger.warning(f"⚠️  Remediation generation failed for {finding.finding_id}: {e}")
            remediated.append(finding)

    logger.info(f"   ✅ Remediation suggestions generated")
    return remediated


def run_runtime_security(monitor: Any, target_path: str, logger: logging.Logger, monitoring_duration: int) -> list[HybridFinding]:
    """Run Container Runtime Security Monitoring"""
    findings = []

    try:
        logger.info(f"   🐳 Monitoring runtime security for {monitoring_duration}s...")

        # Run runtime security monitor
        runtime_result = monitor.monitor(target_path)

        # Convert to HybridFinding format
        if isinstance(runtime_result, list):
            for runtime_finding in runtime_result:
                finding = HybridFinding(
                    finding_id=runtime_finding.get("id", "unknown"),
                    source_tool="runtime-security",
                    severity=normalize_severity(runtime_finding.get("severity", "medium")),
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


def run_regression_testing(tester: Any, target_path: str, current_findings: list[HybridFinding], logger: logging.Logger) -> list[HybridFinding]:
    """Run Security Regression Testing to detect reappearance of fixed vulnerabilities"""
    findings = []

    try:
        logger.info("   🧪 Checking for security regressions...")

        # Run all regression tests
        results = tester.run_all_tests()

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
]
