#!/usr/bin/env python3
"""
License Risk Scorer

Classifies SBOM component licenses into severity tiers following Trivy's
license classification model.  Each SPDX license identifier is mapped to a
category (FORBIDDEN, RESTRICTED, RECIPROCAL, NOTICE, UNENCUMBERED) and a
corresponding severity level (critical, high, medium, low, none).  Unknown
or missing licenses are flagged separately so that policy gates can act on
them.

Typical usage:

    scorer = LicenseRiskScorer()
    risks = scorer.score_components(cyclonedx_components)
    summary = scorer.get_summary(risks)
    violations = scorer.generate_policy_violations(risks)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------


class LicenseCategory(str, Enum):
    """License obligation categories ordered from most to least restrictive."""

    FORBIDDEN = "forbidden"
    RESTRICTED = "restricted"
    RECIPROCAL = "reciprocal"
    NOTICE = "notice"
    UNENCUMBERED = "unencumbered"
    UNKNOWN = "unknown"


# Severity ordering used when picking the *highest* severity across multiple
# licenses on a single component.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "none": 1,
    "unknown": 0,
}


@dataclass
class LicenseRisk:
    """Risk assessment result for a single component-license pair."""

    license_id: str
    license_name: str
    category: LicenseCategory
    severity: str  # critical | high | medium | low | none | unknown
    package_name: str
    package_version: str
    source: str = "sbom"


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class LicenseRiskScorer:
    """Classify and score SBOM component licenses.

    The static ``LICENSE_DB`` maps SPDX identifiers to ``(category, severity)``
    tuples.  A case-insensitive lookup index is built at class-load time so
    that callers do not need to worry about casing.
    """

    # -- Static license database -------------------------------------------

    LICENSE_DB: dict[str, tuple[LicenseCategory, str]] = {
        # Forbidden – critical
        "AGPL-3.0-only": (LicenseCategory.FORBIDDEN, "critical"),
        "AGPL-3.0-or-later": (LicenseCategory.FORBIDDEN, "critical"),
        "SSPL-1.0": (LicenseCategory.FORBIDDEN, "critical"),
        "EUPL-1.1": (LicenseCategory.FORBIDDEN, "critical"),
        "EUPL-1.2": (LicenseCategory.FORBIDDEN, "critical"),
        # Restricted – high
        "GPL-2.0-only": (LicenseCategory.RESTRICTED, "high"),
        "GPL-2.0-or-later": (LicenseCategory.RESTRICTED, "high"),
        "GPL-3.0-only": (LicenseCategory.RESTRICTED, "high"),
        "GPL-3.0-or-later": (LicenseCategory.RESTRICTED, "high"),
        "LGPL-2.0-only": (LicenseCategory.RESTRICTED, "high"),
        "LGPL-2.1-only": (LicenseCategory.RESTRICTED, "high"),
        "LGPL-3.0-only": (LicenseCategory.RESTRICTED, "high"),
        "CC-BY-SA-4.0": (LicenseCategory.RESTRICTED, "high"),
        # Reciprocal – medium
        "MPL-2.0": (LicenseCategory.RECIPROCAL, "medium"),
        "EPL-1.0": (LicenseCategory.RECIPROCAL, "medium"),
        "EPL-2.0": (LicenseCategory.RECIPROCAL, "medium"),
        "CDDL-1.0": (LicenseCategory.RECIPROCAL, "medium"),
        "CPL-1.0": (LicenseCategory.RECIPROCAL, "medium"),
        "OSL-3.0": (LicenseCategory.RECIPROCAL, "medium"),
        # Notice – low
        "MIT": (LicenseCategory.NOTICE, "low"),
        "Apache-2.0": (LicenseCategory.NOTICE, "low"),
        "BSD-2-Clause": (LicenseCategory.NOTICE, "low"),
        "BSD-3-Clause": (LicenseCategory.NOTICE, "low"),
        "ISC": (LicenseCategory.NOTICE, "low"),
        "Zlib": (LicenseCategory.NOTICE, "low"),
        "PSF-2.0": (LicenseCategory.NOTICE, "low"),
        "BSL-1.0": (LicenseCategory.NOTICE, "low"),
        "Artistic-2.0": (LicenseCategory.NOTICE, "low"),
        # Unencumbered – none
        "Unlicense": (LicenseCategory.UNENCUMBERED, "none"),
        "CC0-1.0": (LicenseCategory.UNENCUMBERED, "none"),
        "WTFPL": (LicenseCategory.UNENCUMBERED, "none"),
        "0BSD": (LicenseCategory.UNENCUMBERED, "none"),
    }

    # Case-insensitive index built once at class definition time.
    _LICENSE_DB_LOWER: dict[str, tuple[LicenseCategory, str]] = {
        k.lower(): v for k, v in LICENSE_DB.items()
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify_license(self, spdx_id: str) -> tuple[LicenseCategory, str]:
        """Return ``(category, severity)`` for a given SPDX identifier.

        The lookup is case-insensitive.  Unknown identifiers are returned as
        ``(UNKNOWN, "unknown")``.
        """
        if not spdx_id:
            return LicenseCategory.UNKNOWN, "unknown"

        result = self._LICENSE_DB_LOWER.get(spdx_id.lower())
        if result is not None:
            return result

        logger.debug("Unknown license SPDX ID: %s", spdx_id)
        return LicenseCategory.UNKNOWN, "unknown"

    def score_component(self, component: dict) -> LicenseRisk | None:
        """Score a single CycloneDX component dict.

        The *component* dict is expected to follow the CycloneDX schema::

            {
                "name": "some-package",
                "version": "1.2.3",
                "licenses": [
                    {"license": {"id": "MIT"}},
                    {"license": {"id": "GPL-3.0-only"}}
                ]
            }

        If the component carries no ``licenses`` list (or the list is empty)
        the method returns ``None``.

        When multiple licenses are present the **highest severity** is
        selected so that the component inherits the worst-case obligation.
        """
        licenses_list = component.get("licenses")
        if not licenses_list:
            return None

        package_name = component.get("name", "unknown")
        package_version = component.get("version", "unknown")

        best: LicenseRisk | None = None
        best_order = -1

        for entry in licenses_list:
            # CycloneDX wraps each entry in a "license" key.
            license_obj = entry.get("license", entry)
            spdx_id = license_obj.get("id", "")
            license_name = license_obj.get("name", spdx_id)

            category, severity = self.classify_license(spdx_id)
            order = _SEVERITY_ORDER.get(severity, 0)

            if order > best_order:
                best_order = order
                best = LicenseRisk(
                    license_id=spdx_id,
                    license_name=license_name or spdx_id,
                    category=category,
                    severity=severity,
                    package_name=package_name,
                    package_version=package_version,
                )

        return best

    def score_components(self, components: list[dict]) -> list[LicenseRisk]:
        """Batch-score a list of CycloneDX component dicts.

        Components that have no license information are silently skipped.
        """
        risks: list[LicenseRisk] = []
        for comp in components:
            risk = self.score_component(comp)
            if risk is not None:
                risks.append(risk)
        return risks

    # ------------------------------------------------------------------
    # Summarisation & policy
    # ------------------------------------------------------------------

    @staticmethod
    def get_summary(risks: list[LicenseRisk]) -> dict:
        """Aggregate risk data into a summary dict.

        Returns::

            {
                "total_components": <int>,
                "by_severity": {"critical": N, "high": N, ...},
                "by_category": {"forbidden": N, ...},
                "forbidden_licenses": [<LicenseRisk>, ...],
                "restricted_licenses": [<LicenseRisk>, ...]
            }
        """
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        forbidden: list[LicenseRisk] = []
        restricted: list[LicenseRisk] = []

        for risk in risks:
            by_severity[risk.severity] = by_severity.get(risk.severity, 0) + 1
            cat_val = risk.category.value
            by_category[cat_val] = by_category.get(cat_val, 0) + 1

            if risk.category is LicenseCategory.FORBIDDEN:
                forbidden.append(risk)
            elif risk.category is LicenseCategory.RESTRICTED:
                restricted.append(risk)

        return {
            "total_components": len(risks),
            "by_severity": by_severity,
            "by_category": by_category,
            "forbidden_licenses": forbidden,
            "restricted_licenses": restricted,
        }

    @staticmethod
    def generate_policy_violations(
        risks: list[LicenseRisk],
        forbidden_action: str = "block",
        restricted_action: str = "warn",
    ) -> list[dict]:
        """Generate policy violation records for forbidden / restricted licenses.

        Each violation is a dict with keys ``license_id``, ``package``,
        ``action``, and ``message``.
        """
        violations: list[dict] = []

        for risk in risks:
            if risk.category is LicenseCategory.FORBIDDEN:
                violations.append(
                    {
                        "license_id": risk.license_id,
                        "package": f"{risk.package_name}@{risk.package_version}",
                        "action": forbidden_action,
                        "message": (
                            f"Forbidden license {risk.license_id} detected in "
                            f"{risk.package_name}@{risk.package_version}"
                        ),
                    }
                )
            elif risk.category is LicenseCategory.RESTRICTED:
                violations.append(
                    {
                        "license_id": risk.license_id,
                        "package": f"{risk.package_name}@{risk.package_version}",
                        "action": restricted_action,
                        "message": (
                            f"Restricted license {risk.license_id} detected in "
                            f"{risk.package_name}@{risk.package_version}"
                        ),
                    }
                )

        return violations
