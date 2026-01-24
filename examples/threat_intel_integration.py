#!/usr/bin/env python3
"""
Example: Integrating Threat Intelligence Enrichment with Argus Scanners

This example demonstrates how to:
1. Run security scanners (Trivy, Semgrep)
2. Enrich findings with threat intelligence
3. Apply intelligent prioritization
4. Generate actionable reports
"""

import json
import logging
from pathlib import Path
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_scanner_results(trivy_file: Path, semgrep_file: Path) -> List[Dict]:
    """Load and normalize findings from multiple scanners"""
    findings = []

    # Load Trivy results (CVE findings)
    if trivy_file.exists():
        with open(trivy_file) as f:
            trivy_data = json.load(f)

        # Extract CVE findings from Trivy format
        for result in trivy_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "id": f"trivy-{vuln.get('VulnerabilityID')}",
                    "cve": vuln.get("VulnerabilityID"),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "scanner": "trivy",
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "file": result.get("Target", ""),
                })

    # Load Semgrep results (code findings)
    if semgrep_file.exists():
        with open(semgrep_file) as f:
            semgrep_data = json.load(f)

        # Extract findings from Semgrep format
        for result in semgrep_data.get("results", []):
            # Check if finding mentions a CVE
            cve_match = None
            message = result.get("extra", {}).get("message", "")
            if "CVE-" in message:
                import re
                cve_match = re.search(r"CVE-\d{4}-\d{4,}", message)

            findings.append({
                "id": result.get("check_id", ""),
                "cve": cve_match.group(0) if cve_match else None,
                "title": result.get("check_id", "").split(".")[-1],
                "description": message,
                "severity": result.get("extra", {}).get("severity", "UNKNOWN"),
                "scanner": "semgrep",
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
            })

    logger.info(f"Loaded {len(findings)} findings from scanners")
    return findings


def enrich_with_threat_intel(findings: List[Dict]) -> List[Dict]:
    """Enrich findings with threat intelligence"""
    try:
        # Import enricher
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from threat_intel_enricher import ThreatIntelEnricher

        # Initialize enricher
        enricher = ThreatIntelEnricher(use_progress=True)

        # Enrich findings
        enriched = enricher.enrich_findings(findings)

        logger.info(f"Successfully enriched {len(enriched)} findings")
        return enriched

    except ImportError as e:
        logger.error(f"Failed to import threat_intel_enricher: {e}")
        logger.info("Skipping threat intelligence enrichment")
        return []


def generate_priority_report(enriched_findings: List) -> None:
    """Generate a prioritized report of findings"""

    # Group by adjusted priority
    by_priority = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": []
    }

    for finding in enriched_findings:
        priority = finding.adjusted_priority
        by_priority[priority].append(finding)

    # Print report
    print("\n" + "=" * 80)
    print("🛡️  THREAT INTELLIGENCE ENRICHED SECURITY REPORT")
    print("=" * 80)

    total_findings = len(enriched_findings)
    critical_count = len(by_priority["CRITICAL"])
    high_count = len(by_priority["HIGH"])

    print(f"\n📊 Summary:")
    print(f"   Total Findings: {total_findings}")
    print(f"   CRITICAL: {critical_count}")
    print(f"   HIGH: {high_count}")
    print(f"   MEDIUM: {len(by_priority['MEDIUM'])}")
    print(f"   LOW: {len(by_priority['LOW'])}")

    # Report critical findings in detail
    if by_priority["CRITICAL"]:
        print("\n" + "=" * 80)
        print("🚨 CRITICAL PRIORITY FINDINGS (IMMEDIATE ACTION REQUIRED)")
        print("=" * 80)

        for i, finding in enumerate(by_priority["CRITICAL"], 1):
            ctx = finding.threat_context
            print(f"\n{i}. {ctx.cve_id} - Risk Score: {finding.risk_score:.1f}/10.0")
            print(f"   Package: {finding.original_finding.get('package', 'N/A')}")
            print(f"   File: {finding.original_finding.get('file', 'N/A')}")

            if ctx.cvss_score:
                print(f"   CVSS: {ctx.cvss_score} ({ctx.cvss_severity})")

            if ctx.epss_score:
                print(f"   EPSS: {ctx.epss_score:.1%} exploitation probability")

            if ctx.in_kev_catalog:
                print(f"   ⚠️  ACTIVELY EXPLOITED IN THE WILD (KEV catalog)")
                print(f"   Due Date: {ctx.kev_due_date}")

            if ctx.public_exploit_available:
                print(f"   🔴 {ctx.exploit_count} public exploit(s) available")

            print(f"   Action: {finding.recommended_action}")

            if finding.priority_boost_reasons:
                print(f"   Boost Reasons:")
                for reason in finding.priority_boost_reasons:
                    print(f"     • {reason}")

    # Report high priority findings (summary)
    if by_priority["HIGH"]:
        print("\n" + "=" * 80)
        print("🔴 HIGH PRIORITY FINDINGS (PATCH WITHIN 7 DAYS)")
        print("=" * 80)

        for i, finding in enumerate(by_priority["HIGH"][:10], 1):  # Top 10
            ctx = finding.threat_context
            print(f"\n{i}. {ctx.cve_id} - Risk Score: {finding.risk_score:.1f}/10.0")

            if ctx.cvss_score:
                print(f"   CVSS: {ctx.cvss_score}")

            if ctx.epss_score:
                print(f"   EPSS: {ctx.epss_score:.1%}")

            if finding.priority_boost_reasons:
                print(f"   Reason: {finding.priority_boost_reasons[0]}")

        if len(by_priority["HIGH"]) > 10:
            print(f"\n   ... and {len(by_priority['HIGH']) - 10} more HIGH priority findings")

    print("\n" + "=" * 80 + "\n")


def generate_kev_alert(enriched_findings: List) -> None:
    """Generate alert for findings in CISA KEV catalog"""

    kev_findings = [
        f for f in enriched_findings
        if f.threat_context and f.threat_context.in_kev_catalog
    ]

    if not kev_findings:
        return

    print("\n" + "!" * 80)
    print("⚠️  CISA KEV CATALOG ALERT - ACTIVELY EXPLOITED VULNERABILITIES DETECTED")
    print("!" * 80)

    for finding in kev_findings:
        ctx = finding.threat_context
        print(f"\n🚨 {ctx.cve_id}")
        print(f"   Added to KEV: {ctx.kev_date_added}")
        print(f"   Remediation Due: {ctx.kev_due_date}")
        print(f"   Required Action: {ctx.kev_action_required}")
        print(f"   Package: {finding.original_finding.get('package', 'N/A')}")
        print(f"   File: {finding.original_finding.get('file', 'N/A')}")

    print("\n" + "!" * 80)
    print(f"IMMEDIATE ACTION REQUIRED: {len(kev_findings)} vulnerability(ies) actively exploited!")
    print("!" * 80 + "\n")


def main():
    """Main execution"""

    # Paths (adjust as needed)
    trivy_results = Path("trivy-results.json")
    semgrep_results = Path("semgrep-results.json")
    output_file = Path("enriched-findings.json")

    # Check if scanner results exist
    if not trivy_results.exists() and not semgrep_results.exists():
        logger.warning("No scanner results found!")
        logger.info("Run scanners first:")
        logger.info("  trivy fs --format json --output trivy-results.json .")
        logger.info("  semgrep --config auto --json --output semgrep-results.json .")
        return 1

    # Step 1: Load scanner results
    logger.info("Step 1: Loading scanner results...")
    findings = load_scanner_results(trivy_results, semgrep_results)

    if not findings:
        logger.warning("No findings to enrich")
        return 0

    # Step 2: Enrich with threat intelligence
    logger.info("Step 2: Enriching with threat intelligence...")
    enriched = enrich_with_threat_intel(findings)

    if not enriched:
        logger.warning("No findings were enriched (no CVEs found)")
        return 0

    # Step 3: Generate reports
    logger.info("Step 3: Generating reports...")
    generate_kev_alert(enriched)
    generate_priority_report(enriched)

    # Step 4: Export enriched findings
    logger.info(f"Step 4: Exporting to {output_file}...")
    try:
        from threat_intel_enricher import ThreatIntelEnricher
        enricher = ThreatIntelEnricher()
        enricher.export_enriched_findings(enriched, output_file)
    except Exception as e:
        logger.error(f"Failed to export: {e}")
        return 1

    # Return exit code based on findings
    critical_count = sum(1 for f in enriched if f.adjusted_priority == "CRITICAL")

    if critical_count > 0:
        logger.warning(f"❌ {critical_count} CRITICAL findings detected")
        return 1

    logger.info("✅ No critical findings detected")
    return 0


if __name__ == "__main__":
    exit(main())
