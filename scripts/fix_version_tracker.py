#!/usr/bin/env python3
"""
Fix Version Tracker

Extracts and surfaces the specific version that fixes each CVE,
along with upgrade path information (patch/minor/major).

Integrates with Trivy scanner output and enriches findings with
actionable upgrade guidance for remediation prioritization.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class UpgradeType(str, Enum):
    """Classification of the upgrade required to fix a vulnerability."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


@dataclass
class FixInfo:
    """Information about a CVE fix version and the upgrade path."""

    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    upgrade_type: UpgradeType
    upgrade_message: str
    is_direct_dependency: bool = True
    source: str = "trivy"


class FixVersionTracker:
    """Extracts fix version data from scanner results and enriches findings.

    Parses CVE fix information from Trivy and other scanner outputs,
    determines upgrade complexity (patch vs minor vs major), and
    provides prioritized remediation guidance.
    """

    def __init__(self) -> None:
        self._version_pattern = re.compile(r"^(\d+(?:\.\d+)*)$")

    def parse_version(self, version_str: str) -> tuple[int, ...] | None:
        """Parse a semver-like version string into a tuple of integers.

        Args:
            version_str: A version string like "1.2.3" or "2.0".

        Returns:
            A tuple of ints, e.g. (1, 2, 3), or None if parsing fails.
        """
        if not version_str or not isinstance(version_str, str):
            return None

        version_str = version_str.strip()
        match = self._version_pattern.match(version_str)
        if not match:
            return None

        try:
            parts = tuple(int(p) for p in version_str.split("."))
            return parts
        except (ValueError, OverflowError):
            return None

    def determine_upgrade_type(self, installed: str, fixed: str) -> UpgradeType:
        """Determine the upgrade type by comparing version components.

        Args:
            installed: Currently installed version string.
            fixed: Version string that contains the fix.

        Returns:
            UpgradeType indicating patch, minor, major, or unknown.
        """
        installed_parts = self.parse_version(installed)
        fixed_parts = self.parse_version(fixed)

        if installed_parts is None or fixed_parts is None:
            logger.debug(
                "Cannot determine upgrade type: unparseable version "
                "(installed=%s, fixed=%s)",
                installed,
                fixed,
            )
            return UpgradeType.UNKNOWN

        # Pad to at least 3 components for consistent comparison
        inst = list(installed_parts) + [0] * (3 - len(installed_parts))
        fix = list(fixed_parts) + [0] * (3 - len(fixed_parts))

        if fix[0] != inst[0]:
            return UpgradeType.MAJOR
        if fix[1] != inst[1]:
            return UpgradeType.MINOR
        return UpgradeType.PATCH

    def generate_upgrade_message(
        self,
        pkg_name: str,
        installed: str,
        fixed: str,
        upgrade_type: UpgradeType,
    ) -> str:
        """Generate a human-readable upgrade recommendation message.

        Args:
            pkg_name: Name of the package.
            installed: Currently installed version.
            fixed: Version containing the fix.
            upgrade_type: The classified upgrade type.

        Returns:
            A formatted upgrade message string.
        """
        type_label = upgrade_type.value
        base_msg = (
            f"Upgrade {pkg_name} from {installed} to {fixed} ({type_label})"
        )

        if upgrade_type == UpgradeType.MAJOR:
            return f"BREAKING: {base_msg}"

        return base_msg

    def extract_fix_info(self, finding: dict) -> FixInfo | None:
        """Extract fix version information from a finding dictionary.

        Handles multiple key naming conventions used across the pipeline:
        - "package_name" or "pkg_name" for the package
        - "installed_version" or "version" for the current version
        - "fixed_version" or "fix_version" for the remediation version

        Args:
            finding: A dictionary representing a security finding.

        Returns:
            A FixInfo object, or None if no fix version is available.
        """
        cve_id = finding.get("cve_id", "")
        if not cve_id:
            cve_id = finding.get("vulnerability_id", "UNKNOWN")

        pkg_name = finding.get("package_name") or finding.get("pkg_name", "")
        if not pkg_name:
            logger.debug("No package name found in finding: %s", cve_id)
            return None

        installed = (
            finding.get("installed_version")
            or finding.get("version")
            or ""
        )

        fixed = (
            finding.get("fixed_version")
            or finding.get("fix_version")
            or ""
        )

        if not fixed:
            logger.debug(
                "No fix version available for %s in %s", cve_id, pkg_name
            )
            return None

        upgrade_type = self.determine_upgrade_type(installed, fixed)
        upgrade_message = self.generate_upgrade_message(
            pkg_name, installed, fixed, upgrade_type
        )

        is_direct = finding.get("is_direct_dependency", True)
        source = finding.get("source", "trivy")

        return FixInfo(
            cve_id=cve_id,
            package_name=pkg_name,
            installed_version=installed,
            fixed_version=fixed,
            upgrade_type=upgrade_type,
            upgrade_message=upgrade_message,
            is_direct_dependency=is_direct,
            source=source,
        )

    def extract_from_trivy_results(self, trivy_output: dict) -> list[FixInfo]:
        """Parse Trivy JSON output and extract fix information for all CVEs.

        Trivy output format:
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-...",
                                "PkgName": "...",
                                "InstalledVersion": "...",
                                "FixedVersion": "..."
                            }
                        ]
                    }
                ]
            }

        Args:
            trivy_output: Parsed Trivy JSON output dictionary.

        Returns:
            List of FixInfo objects for all fixable vulnerabilities.
        """
        fix_infos: list[FixInfo] = []

        results = trivy_output.get("Results", [])
        if not results:
            logger.info("No results found in Trivy output")
            return fix_infos

        for result in results:
            vulnerabilities = result.get("Vulnerabilities") or []
            for vuln in vulnerabilities:
                cve_id = vuln.get("VulnerabilityID", "")
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")

                if not fixed:
                    logger.debug(
                        "No fix available for %s in %s", cve_id, pkg_name
                    )
                    continue

                upgrade_type = self.determine_upgrade_type(installed, fixed)
                upgrade_message = self.generate_upgrade_message(
                    pkg_name, installed, fixed, upgrade_type
                )

                fix_infos.append(
                    FixInfo(
                        cve_id=cve_id,
                        package_name=pkg_name,
                        installed_version=installed,
                        fixed_version=fixed,
                        upgrade_type=upgrade_type,
                        upgrade_message=upgrade_message,
                        is_direct_dependency=True,
                        source="trivy",
                    )
                )

        logger.info(
            "Extracted %d fix versions from Trivy results", len(fix_infos)
        )
        return fix_infos

    def enrich_findings(
        self,
        findings: list[dict],
        fix_infos: list[FixInfo],
    ) -> list[dict]:
        """Add fix version data to matching findings.

        Matches findings to fix information by CVE ID and package name,
        then adds fix_version, upgrade_type, and upgrade_message fields.

        Args:
            findings: List of finding dictionaries to enrich.
            fix_infos: List of FixInfo objects to match against.

        Returns:
            The enriched findings list (modified in place and returned).
        """
        # Build lookup index: (cve_id, package_name) -> FixInfo
        fix_lookup: dict[tuple[str, str], FixInfo] = {}
        for fi in fix_infos:
            key = (fi.cve_id, fi.package_name)
            fix_lookup[key] = fi

        enriched_count = 0
        for finding in findings:
            cve_id = finding.get("cve_id", finding.get("vulnerability_id", ""))
            pkg_name = finding.get("package_name", finding.get("pkg_name", ""))
            key = (cve_id, pkg_name)

            if key in fix_lookup:
                fi = fix_lookup[key]
                finding["fix_version"] = fi.fixed_version
                finding["upgrade_type"] = fi.upgrade_type.value
                finding["upgrade_message"] = fi.upgrade_message
                enriched_count += 1

        logger.info(
            "Enriched %d of %d findings with fix version data",
            enriched_count,
            len(findings),
        )
        return findings

    def get_summary(self, fix_infos: list[FixInfo]) -> dict:
        """Generate a summary of fix version statistics.

        Args:
            fix_infos: List of FixInfo objects to summarize.

        Returns:
            Dictionary with total_fixable, by_upgrade_type counts,
            unfixable_count (always 0 since fix_infos only contains
            fixable items), and packages_needing_major_upgrade.
        """
        by_type: dict[str, int] = {
            "patch": 0,
            "minor": 0,
            "major": 0,
        }

        packages_needing_major: list[str] = []

        for fi in fix_infos:
            type_key = fi.upgrade_type.value
            if type_key in by_type:
                by_type[type_key] += 1
            # UNKNOWN types are not counted in by_type buckets

            if fi.upgrade_type == UpgradeType.MAJOR:
                pkg_label = f"{fi.package_name}@{fi.installed_version}"
                if pkg_label not in packages_needing_major:
                    packages_needing_major.append(pkg_label)

        total_fixable = len(fix_infos)
        unfixable_count = 0

        return {
            "total_fixable": total_fixable,
            "by_upgrade_type": by_type,
            "unfixable_count": unfixable_count,
            "packages_needing_major_upgrade": packages_needing_major,
        }

    def prioritize_fixes(self, fix_infos: list[FixInfo]) -> list[FixInfo]:
        """Sort fix information by upgrade complexity, easiest first.

        Ordering: PATCH < MINOR < MAJOR < UNKNOWN.
        This puts the lowest-risk, easiest upgrades at the top.

        Args:
            fix_infos: List of FixInfo objects to sort.

        Returns:
            A new list sorted by upgrade type priority.
        """
        priority_order = {
            UpgradeType.PATCH: 0,
            UpgradeType.MINOR: 1,
            UpgradeType.MAJOR: 2,
            UpgradeType.UNKNOWN: 3,
        }

        return sorted(
            fix_infos,
            key=lambda fi: priority_order.get(fi.upgrade_type, 99),
        )
