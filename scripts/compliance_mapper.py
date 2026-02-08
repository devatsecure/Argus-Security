#!/usr/bin/env python3
"""
Compliance Framework Mapping for Argus Security Pipeline.

Maps security findings to compliance framework controls via CWE-to-control
static mapping tables.  Supports NIST 800-53, PCI DSS 4.0, OWASP Top 10
2021, SOC 2, CIS Kubernetes, and ISO 27001.

Usage:
    mapper = ComplianceMapper(frameworks=["nist_800_53", "pci_dss_4"])
    mappings = mapper.map_findings(findings)
    reports = mapper.generate_all_reports(findings)
    markdown = mapper.render_all_markdown(reports)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ComplianceMapping:
    """A single mapping from a finding to a compliance control."""

    finding_id: str
    cwe_id: str
    framework: str
    control_id: str
    control_title: str
    severity: str = ""
    status: str = "fail"


@dataclass
class ComplianceReport:
    """Aggregated compliance posture for one framework."""

    framework: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    coverage_percentage: float
    mappings: list[ComplianceMapping] = field(default_factory=list)
    generated_at: str = ""


# ---------------------------------------------------------------------------
# Control entry helper
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ControlEntry:
    """Internal representation of a single compliance control."""

    control_id: str
    control_title: str
    framework: str


# ---------------------------------------------------------------------------
# ComplianceMapper
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """Maps security findings to compliance framework controls.

    The mapper uses a three-tier resolution strategy:
      1. **CWE lookup** - direct CWE-to-control mapping (highest fidelity).
      2. **Category fallback** - maps scanner categories (``secrets``,
         ``sast``, ``dependency``, ``iac``, ``container``) to relevant
         controls when no CWE is available.
      3. **Severity defaults** - minimal catch-all for critical/high
         findings that escape the first two tiers.
    """

    # Frameworks supported by this mapper.
    SUPPORTED_FRAMEWORKS: list[str] = [
        "nist_800_53",
        "pci_dss_4",
        "owasp_top10_2021",
        "soc2",
        "cis_kubernetes",
        "iso_27001",
    ]

    # ------------------------------------------------------------------
    # CWE -> controls mapping
    # ------------------------------------------------------------------

    CWE_TO_CONTROLS: dict[str, list[dict[str, str]]] = {
        # CWE-79: Cross-site Scripting (XSS)
        "CWE-79": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "6.2.4", "control_title": "Software Engineering Techniques", "framework": "pci_dss_4"},
            {"control_id": "A03:2021", "control_title": "Injection", "framework": "owasp_top10_2021"},
            {"control_id": "CC6.1", "control_title": "Logical and Physical Access Controls", "framework": "soc2"},
        ],
        # CWE-89: SQL Injection
        "CWE-89": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "6.2.4", "control_title": "Software Engineering Techniques", "framework": "pci_dss_4"},
            {"control_id": "A03:2021", "control_title": "Injection", "framework": "owasp_top10_2021"},
            {"control_id": "CC6.1", "control_title": "Logical and Physical Access Controls", "framework": "soc2"},
        ],
        # CWE-78: OS Command Injection
        "CWE-78": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "6.2.4", "control_title": "Software Engineering Techniques", "framework": "pci_dss_4"},
            {"control_id": "A03:2021", "control_title": "Injection", "framework": "owasp_top10_2021"},
        ],
        # CWE-287: Improper Authentication
        "CWE-287": [
            {"control_id": "IA-2", "control_title": "Identification and Authentication", "framework": "nist_800_53"},
            {"control_id": "8.3", "control_title": "Strong Authentication for Users and Admins", "framework": "pci_dss_4"},
            {"control_id": "A07:2021", "control_title": "Identification and Authentication Failures", "framework": "owasp_top10_2021"},
            {"control_id": "CC6.1", "control_title": "Logical and Physical Access Controls", "framework": "soc2"},
        ],
        # CWE-798: Hard-coded Credentials
        "CWE-798": [
            {"control_id": "IA-5", "control_title": "Authenticator Management", "framework": "nist_800_53"},
            {"control_id": "8.6", "control_title": "Authentication Mechanism Management", "framework": "pci_dss_4"},
            {"control_id": "A07:2021", "control_title": "Identification and Authentication Failures", "framework": "owasp_top10_2021"},
            {"control_id": "CC6.1", "control_title": "Logical and Physical Access Controls", "framework": "soc2"},
        ],
        # CWE-200: Information Exposure
        "CWE-200": [
            {"control_id": "SC-28", "control_title": "Protection of Information at Rest", "framework": "nist_800_53"},
            {"control_id": "3.4", "control_title": "Render PAN Unreadable", "framework": "pci_dss_4"},
            {"control_id": "A01:2021", "control_title": "Broken Access Control", "framework": "owasp_top10_2021"},
        ],
        # CWE-22: Path Traversal
        "CWE-22": [
            {"control_id": "AC-6", "control_title": "Least Privilege", "framework": "nist_800_53"},
            {"control_id": "6.2.4", "control_title": "Software Engineering Techniques", "framework": "pci_dss_4"},
            {"control_id": "A01:2021", "control_title": "Broken Access Control", "framework": "owasp_top10_2021"},
        ],
        # CWE-502: Deserialization of Untrusted Data
        "CWE-502": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "A08:2021", "control_title": "Software and Data Integrity Failures", "framework": "owasp_top10_2021"},
        ],
        # CWE-918: Server-Side Request Forgery (SSRF)
        "CWE-918": [
            {"control_id": "SC-7", "control_title": "Boundary Protection", "framework": "nist_800_53"},
            {"control_id": "A10:2021", "control_title": "Server-Side Request Forgery", "framework": "owasp_top10_2021"},
        ],
        # CWE-611: XML External Entity (XXE)
        "CWE-611": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "A05:2021", "control_title": "Security Misconfiguration", "framework": "owasp_top10_2021"},
        ],
        # CWE-327: Broken Cryptography
        "CWE-327": [
            {"control_id": "SC-13", "control_title": "Cryptographic Protection", "framework": "nist_800_53"},
            {"control_id": "4.2", "control_title": "Protect Cardholder Data with Strong Cryptography", "framework": "pci_dss_4"},
            {"control_id": "A02:2021", "control_title": "Cryptographic Failures", "framework": "owasp_top10_2021"},
        ],
        # CWE-306: Missing Authentication for Critical Function
        "CWE-306": [
            {"control_id": "AC-3", "control_title": "Access Enforcement", "framework": "nist_800_53"},
            {"control_id": "7.2", "control_title": "Access Controls for System Components", "framework": "pci_dss_4"},
            {"control_id": "A07:2021", "control_title": "Identification and Authentication Failures", "framework": "owasp_top10_2021"},
        ],
        # CWE-862: Missing Authorization
        "CWE-862": [
            {"control_id": "AC-3", "control_title": "Access Enforcement", "framework": "nist_800_53"},
            {"control_id": "7.2", "control_title": "Access Controls for System Components", "framework": "pci_dss_4"},
            {"control_id": "A01:2021", "control_title": "Broken Access Control", "framework": "owasp_top10_2021"},
        ],
        # CWE-434: Unrestricted File Upload
        "CWE-434": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "A04:2021", "control_title": "Insecure Design", "framework": "owasp_top10_2021"},
        ],
        # CWE-1035: Vulnerable Third-Party Dependency
        "CWE-1035": [
            {"control_id": "SI-2", "control_title": "Flaw Remediation", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
            {"control_id": "A06:2021", "control_title": "Vulnerable and Outdated Components", "framework": "owasp_top10_2021"},
            {"control_id": "5.3.1", "control_title": "Minimize Container Image Vulnerabilities", "framework": "cis_kubernetes"},
            {"control_id": "A.12.6.1", "control_title": "Management of Technical Vulnerabilities", "framework": "iso_27001"},
        ],
        # CWE-937: Known Vulnerable Component
        "CWE-937": [
            {"control_id": "SI-2", "control_title": "Flaw Remediation", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
            {"control_id": "A06:2021", "control_title": "Vulnerable and Outdated Components", "framework": "owasp_top10_2021"},
        ],
    }

    # ------------------------------------------------------------------
    # Category -> controls fallback mapping
    # ------------------------------------------------------------------

    CATEGORY_TO_CONTROLS: dict[str, list[dict[str, str]]] = {
        "secrets": [
            {"control_id": "IA-5", "control_title": "Authenticator Management", "framework": "nist_800_53"},
            {"control_id": "8.6", "control_title": "Authentication Mechanism Management", "framework": "pci_dss_4"},
            {"control_id": "A07:2021", "control_title": "Identification and Authentication Failures", "framework": "owasp_top10_2021"},
            {"control_id": "CC6.1", "control_title": "Logical and Physical Access Controls", "framework": "soc2"},
            {"control_id": "A.9.4.3", "control_title": "Password Management System", "framework": "iso_27001"},
        ],
        "sast": [
            {"control_id": "SI-10", "control_title": "Information Input Validation", "framework": "nist_800_53"},
            {"control_id": "6.2.4", "control_title": "Software Engineering Techniques", "framework": "pci_dss_4"},
            {"control_id": "A03:2021", "control_title": "Injection", "framework": "owasp_top10_2021"},
            {"control_id": "CC7.1", "control_title": "System Change Management", "framework": "soc2"},
        ],
        "dependency": [
            {"control_id": "SI-2", "control_title": "Flaw Remediation", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
            {"control_id": "A06:2021", "control_title": "Vulnerable and Outdated Components", "framework": "owasp_top10_2021"},
            {"control_id": "5.3.1", "control_title": "Minimize Container Image Vulnerabilities", "framework": "cis_kubernetes"},
            {"control_id": "A.12.6.1", "control_title": "Management of Technical Vulnerabilities", "framework": "iso_27001"},
        ],
        "iac": [
            {"control_id": "CM-6", "control_title": "Configuration Settings", "framework": "nist_800_53"},
            {"control_id": "2.2", "control_title": "System Components Are Configured Securely", "framework": "pci_dss_4"},
            {"control_id": "A05:2021", "control_title": "Security Misconfiguration", "framework": "owasp_top10_2021"},
            {"control_id": "5.1.1", "control_title": "RBAC and Least Privilege", "framework": "cis_kubernetes"},
            {"control_id": "A.14.2.5", "control_title": "Secure System Engineering Principles", "framework": "iso_27001"},
        ],
        "container": [
            {"control_id": "CM-7", "control_title": "Least Functionality", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
            {"control_id": "A05:2021", "control_title": "Security Misconfiguration", "framework": "owasp_top10_2021"},
            {"control_id": "5.3.1", "control_title": "Minimize Container Image Vulnerabilities", "framework": "cis_kubernetes"},
            {"control_id": "A.12.6.1", "control_title": "Management of Technical Vulnerabilities", "framework": "iso_27001"},
        ],
    }

    # ------------------------------------------------------------------
    # Severity-based fallback controls (catch-all for critical/high)
    # ------------------------------------------------------------------

    _SEVERITY_DEFAULTS: dict[str, list[dict[str, str]]] = {
        "critical": [
            {"control_id": "SI-2", "control_title": "Flaw Remediation", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
            {"control_id": "CC7.2", "control_title": "Monitoring and Detection", "framework": "soc2"},
        ],
        "high": [
            {"control_id": "SI-2", "control_title": "Flaw Remediation", "framework": "nist_800_53"},
            {"control_id": "6.3", "control_title": "Security Vulnerabilities Are Identified and Addressed", "framework": "pci_dss_4"},
        ],
    }

    # ------------------------------------------------------------------
    # Framework display names
    # ------------------------------------------------------------------

    _FRAMEWORK_DISPLAY_NAMES: dict[str, str] = {
        "nist_800_53": "NIST 800-53 Rev 5",
        "pci_dss_4": "PCI DSS v4.0",
        "owasp_top10_2021": "OWASP Top 10 (2021)",
        "soc2": "SOC 2 Type II",
        "cis_kubernetes": "CIS Kubernetes Benchmark",
        "iso_27001": "ISO 27001:2022",
    }

    # ------------------------------------------------------------------
    # Total unique controls per framework (for coverage calculation)
    # ------------------------------------------------------------------

    _FRAMEWORK_TOTAL_CONTROLS: dict[str, int] = {
        "nist_800_53": 20,
        "pci_dss_4": 12,
        "owasp_top10_2021": 10,
        "soc2": 5,
        "cis_kubernetes": 6,
        "iso_27001": 10,
    }

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(self, frameworks: list[str] | None = None) -> None:
        """Initialize the mapper with the desired frameworks.

        Args:
            frameworks: list of framework identifiers to assess against.
                If ``None``, all :pyattr:`SUPPORTED_FRAMEWORKS` are used.
        """
        if frameworks is None:
            self.frameworks = list(self.SUPPORTED_FRAMEWORKS)
        else:
            self.frameworks = [
                f for f in frameworks if f in self.SUPPORTED_FRAMEWORKS
            ]
            unsupported = set(frameworks) - set(self.SUPPORTED_FRAMEWORKS)
            if unsupported:
                logger.warning(
                    "Ignoring unsupported frameworks: %s", sorted(unsupported)
                )

        logger.info(
            "ComplianceMapper initialized with frameworks: %s",
            self.frameworks,
        )

    # ------------------------------------------------------------------
    # Single-finding mapping
    # ------------------------------------------------------------------

    def map_finding(self, finding: dict) -> list[ComplianceMapping]:
        """Map a single finding to compliance controls.

        Resolution order:
            1. CWE ID lookup via :pyattr:`CWE_TO_CONTROLS`.
            2. Category fallback via :pyattr:`CATEGORY_TO_CONTROLS`.
            3. Severity defaults for critical/high findings.

        Args:
            finding: dictionary with optional keys ``cwe_id`` or ``cwe_ids``,
                ``category``, ``severity``, and ``id`` / ``finding_id``.

        Returns:
            A list of :class:`ComplianceMapping` instances (may be empty).
        """
        finding_id = finding.get("finding_id") or finding.get("id") or "unknown"
        severity = (finding.get("severity") or "").lower()

        # Collect all CWE identifiers attached to the finding.
        cwe_ids = self._extract_cwe_ids(finding)

        mappings: list[ComplianceMapping] = []
        seen: set[tuple[str, str]] = set()  # (framework, control_id)

        # -- Tier 1: CWE-based lookup --
        for cwe_id in cwe_ids:
            controls = self.CWE_TO_CONTROLS.get(cwe_id, [])
            for ctrl in controls:
                fw = ctrl["framework"]
                cid = ctrl["control_id"]
                if fw not in self.frameworks:
                    continue
                if (fw, cid) in seen:
                    continue
                seen.add((fw, cid))
                mappings.append(
                    ComplianceMapping(
                        finding_id=str(finding_id),
                        cwe_id=cwe_id,
                        framework=fw,
                        control_id=cid,
                        control_title=ctrl["control_title"],
                        severity=severity,
                        status="fail",
                    )
                )

        # -- Tier 2: Category fallback (only if CWE produced nothing) --
        if not mappings:
            category = (finding.get("category") or "").lower()
            controls = self.CATEGORY_TO_CONTROLS.get(category, [])
            for ctrl in controls:
                fw = ctrl["framework"]
                cid = ctrl["control_id"]
                if fw not in self.frameworks:
                    continue
                if (fw, cid) in seen:
                    continue
                seen.add((fw, cid))
                cwe_label = cwe_ids[0] if cwe_ids else ""
                mappings.append(
                    ComplianceMapping(
                        finding_id=str(finding_id),
                        cwe_id=cwe_label,
                        framework=fw,
                        control_id=cid,
                        control_title=ctrl["control_title"],
                        severity=severity,
                        status="fail",
                    )
                )

        # -- Tier 3: Severity-based defaults (only if still empty) --
        if not mappings and severity in self._SEVERITY_DEFAULTS:
            controls = self._SEVERITY_DEFAULTS[severity]
            for ctrl in controls:
                fw = ctrl["framework"]
                cid = ctrl["control_id"]
                if fw not in self.frameworks:
                    continue
                if (fw, cid) in seen:
                    continue
                seen.add((fw, cid))
                cwe_label = cwe_ids[0] if cwe_ids else ""
                mappings.append(
                    ComplianceMapping(
                        finding_id=str(finding_id),
                        cwe_id=cwe_label,
                        framework=fw,
                        control_id=cid,
                        control_title=ctrl["control_title"],
                        severity=severity,
                        status="fail",
                    )
                )

        if mappings:
            logger.debug(
                "Finding %s mapped to %d controls", finding_id, len(mappings)
            )
        else:
            logger.debug(
                "Finding %s produced no compliance mappings", finding_id
            )

        return mappings

    # ------------------------------------------------------------------
    # Batch mapping
    # ------------------------------------------------------------------

    def map_findings(self, findings: list[dict]) -> list[ComplianceMapping]:
        """Map a list of findings to compliance controls.

        Args:
            findings: list of finding dictionaries.

        Returns:
            A flat list of all :class:`ComplianceMapping` instances.
        """
        all_mappings: list[ComplianceMapping] = []
        for finding in findings:
            all_mappings.extend(self.map_finding(finding))
        logger.info(
            "Mapped %d findings to %d compliance controls",
            len(findings),
            len(all_mappings),
        )
        return all_mappings

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self, findings: list[dict], framework: str
    ) -> ComplianceReport:
        """Generate a compliance report for a single framework.

        Args:
            findings: list of finding dictionaries.
            framework: one of :pyattr:`SUPPORTED_FRAMEWORKS`.

        Returns:
            A :class:`ComplianceReport` with coverage statistics.
        """
        if framework not in self.frameworks:
            logger.warning(
                "Framework %s is not in configured frameworks", framework
            )
            return ComplianceReport(
                framework=framework,
                total_controls=0,
                passing_controls=0,
                failing_controls=0,
                coverage_percentage=0.0,
                mappings=[],
                generated_at=self._now_iso(),
            )

        all_mappings = self.map_findings(findings)
        return self._build_report(framework, all_mappings)

    def _build_report(
        self, framework: str, all_mappings: list[ComplianceMapping]
    ) -> ComplianceReport:
        """Build a report for *framework* from pre-computed mappings."""
        # Filter mappings for the requested framework.
        framework_mappings = [
            m for m in all_mappings if m.framework == framework
        ]

        # Unique failing control IDs in this framework.
        failing_control_ids: set[str] = {
            m.control_id for m in framework_mappings if m.status == "fail"
        }

        total_controls = self._FRAMEWORK_TOTAL_CONTROLS.get(framework, 10)
        failing_count = len(failing_control_ids)
        passing_count = max(0, total_controls - failing_count)
        coverage = (
            (passing_count / total_controls * 100.0) if total_controls > 0 else 0.0
        )

        return ComplianceReport(
            framework=framework,
            total_controls=total_controls,
            passing_controls=passing_count,
            failing_controls=failing_count,
            coverage_percentage=round(coverage, 1),
            mappings=framework_mappings,
            generated_at=self._now_iso(),
        )

    def generate_all_reports(
        self, findings: list[dict]
    ) -> list[ComplianceReport]:
        """Generate compliance reports for every configured framework.

        Computes mappings once and reuses across all frameworks.

        Args:
            findings: list of finding dictionaries.

        Returns:
            A list of :class:`ComplianceReport` instances, one per framework.
        """
        all_mappings = self.map_findings(findings)
        reports = [
            self._build_report(framework, all_mappings)
            for framework in self.frameworks
        ]
        logger.info("Generated %d compliance reports", len(reports))
        return reports

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def render_markdown(self, report: ComplianceReport) -> str:
        """Render a single compliance report as Markdown.

        Includes a header, summary statistics, a visual coverage bar,
        a failing controls table, and recommendations.

        Args:
            report: the :class:`ComplianceReport` to render.

        Returns:
            A Markdown string.
        """
        display_name = self._FRAMEWORK_DISPLAY_NAMES.get(
            report.framework, report.framework
        )

        lines: list[str] = []
        lines.append(f"## {display_name} Compliance Report")
        lines.append("")
        lines.append(f"**Generated:** {report.generated_at}")
        lines.append("")

        # -- Summary --
        lines.append("### Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Controls | {report.total_controls} |")
        lines.append(f"| Passing Controls | {report.passing_controls} |")
        lines.append(f"| Failing Controls | {report.failing_controls} |")
        lines.append(f"| Coverage | {report.coverage_percentage}% |")
        lines.append("")

        # -- Coverage bar --
        bar_length = 20
        filled = int(bar_length * report.coverage_percentage / 100)
        empty = bar_length - filled
        bar = "[" + "#" * filled + "-" * empty + "]"
        lines.append(f"**Coverage:** {bar} {report.coverage_percentage}%")
        lines.append("")

        # -- Failing controls table --
        if report.mappings:
            # Deduplicate by control_id for display.
            seen_controls: dict[str, ComplianceMapping] = {}
            for m in report.mappings:
                if m.status == "fail" and m.control_id not in seen_controls:
                    seen_controls[m.control_id] = m

            if seen_controls:
                lines.append("### Failing Controls")
                lines.append("")
                lines.append("| Control ID | Control Title | CWE | Severity | Finding |")
                lines.append("|------------|---------------|-----|----------|---------|")
                for cid, m in sorted(seen_controls.items()):
                    lines.append(
                        f"| {m.control_id} | {m.control_title} "
                        f"| {m.cwe_id} | {m.severity} | {m.finding_id} |"
                    )
                lines.append("")

        # -- Recommendations --
        lines.append("### Recommendations")
        lines.append("")
        if report.failing_controls == 0:
            lines.append(
                "No failing controls detected. Maintain current security posture."
            )
        elif report.coverage_percentage >= 80:
            lines.append(
                f"- Address the {report.failing_controls} failing "
                f"control(s) to improve coverage beyond "
                f"{report.coverage_percentage}%."
            )
            lines.append("- Prioritize remediation by severity.")
        else:
            lines.append(
                f"- **Significant compliance gaps detected.** "
                f"{report.failing_controls} of {report.total_controls} "
                f"controls are failing."
            )
            lines.append(
                "- Immediate remediation is recommended for critical "
                "and high severity findings."
            )
            lines.append(
                "- Consider conducting a full compliance readiness "
                "assessment."
            )
        lines.append("")

        return "\n".join(lines)

    def render_all_markdown(
        self, reports: list[ComplianceReport]
    ) -> str:
        """Combine all framework reports into a single Markdown document.

        Args:
            reports: list of :class:`ComplianceReport` instances.

        Returns:
            A single Markdown string with all reports.
        """
        sections: list[str] = []
        sections.append("# Argus Security - Compliance Assessment Report")
        sections.append("")
        sections.append(f"**Generated:** {self._now_iso()}")
        sections.append("")

        # Quick overview table.
        sections.append("## Overview")
        sections.append("")
        sections.append("| Framework | Coverage | Passing | Failing |")
        sections.append("|-----------|----------|---------|---------|")
        for r in reports:
            display = self._FRAMEWORK_DISPLAY_NAMES.get(
                r.framework, r.framework
            )
            sections.append(
                f"| {display} | {r.coverage_percentage}% "
                f"| {r.passing_controls} | {r.failing_controls} |"
            )
        sections.append("")
        sections.append("---")
        sections.append("")

        # Individual framework sections.
        for r in reports:
            sections.append(self.render_markdown(r))
            sections.append("---")
            sections.append("")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Summary / dashboard data
    # ------------------------------------------------------------------

    def get_summary(
        self, reports: list[ComplianceReport]
    ) -> dict:
        """Return a concise summary dict suitable for dashboards.

        Args:
            reports: list of :class:`ComplianceReport` instances.

        Returns:
            A dictionary with keys:
            - ``frameworks_assessed`` (int)
            - ``overall_coverage`` (float, average across frameworks)
            - ``by_framework`` (dict mapping framework name to coverage/gaps)
            - ``critical_gaps`` (list of control IDs with critical severity)
        """
        if not reports:
            return {
                "frameworks_assessed": 0,
                "overall_coverage": 0.0,
                "by_framework": {},
                "critical_gaps": [],
            }

        by_framework: dict[str, dict] = {}
        total_coverage = 0.0
        critical_gaps: list[str] = []

        for r in reports:
            by_framework[r.framework] = {
                "coverage": r.coverage_percentage,
                "failing_controls": r.failing_controls,
            }
            total_coverage += r.coverage_percentage

            # Identify critical gaps.
            for m in r.mappings:
                if m.status == "fail" and m.severity in ("critical", "high"):
                    gap_label = f"{r.framework}:{m.control_id}"
                    if gap_label not in critical_gaps:
                        critical_gaps.append(gap_label)

        overall_coverage = round(total_coverage / len(reports), 1)

        return {
            "frameworks_assessed": len(reports),
            "overall_coverage": overall_coverage,
            "by_framework": by_framework,
            "critical_gaps": critical_gaps,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cwe_ids(finding: dict) -> list[str]:
        """Extract CWE identifiers from a finding dict.

        Handles both ``cwe_id`` (single string) and ``cwe_ids`` (list).
        Normalises bare numbers to the ``CWE-NNN`` format.
        """
        cwe_ids: list[str] = []

        # Single CWE.
        single = finding.get("cwe_id")
        if single:
            cwe_ids.append(_normalise_cwe(str(single)))

        # List of CWEs.
        multi = finding.get("cwe_ids")
        if isinstance(multi, list):
            for raw in multi:
                normalised = _normalise_cwe(str(raw))
                if normalised not in cwe_ids:
                    cwe_ids.append(normalised)

        return cwe_ids

    @staticmethod
    def _now_iso() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _normalise_cwe(raw: str) -> str:
    """Normalise a CWE identifier to ``CWE-NNN`` format.

    Accepts ``CWE-79``, ``cwe-79``, ``79``, etc.
    """
    raw = raw.strip()
    if raw.upper().startswith("CWE-"):
        return "CWE-" + raw[4:]
    # Bare number.
    try:
        int(raw)
        return f"CWE-{raw}"
    except ValueError:
        return raw
