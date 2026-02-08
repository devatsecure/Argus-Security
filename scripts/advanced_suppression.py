#!/usr/bin/env python3
"""
Advanced Finding Suppression for Argus Security

Enhanced suppression engine with .argus-ignore.yml file support,
PURL matching, time-based expiration, VEX integration, and EPSS-based
auto-suppression.

Supports 6 match types: CVE, RULE_ID, PURL, PATH_PATTERN, CWE, SEVERITY.
Rules can expire automatically and are auditable.

Usage:
    manager = AdvancedSuppressionManager(config_path=".argus-ignore.yml")
    rules = manager.load_rules()
    remaining, suppressed = manager.filter_findings(findings, rules)
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class MatchType(Enum):
    """Types of matching criteria for suppression rules."""

    CVE = "cve"
    RULE_ID = "rule_id"
    PURL = "purl"
    PATH_PATTERN = "path_pattern"
    CWE = "cwe"
    SEVERITY = "severity"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SuppressionRule:
    """A single suppression rule loaded from config or generated at runtime."""

    id: str
    match_type: MatchType
    match_value: str
    reason: str = ""
    expires_at: str = ""  # ISO-8601 date string, empty means never expires
    approved_by: str = ""
    created_at: str = ""
    source: str = "manual"  # manual | vex | epss_auto
    is_active: bool = True


@dataclass
class SuppressionResult:
    """Outcome of evaluating a single finding against suppression rules."""

    finding: dict
    rule: SuppressionRule | None
    suppressed: bool
    reason: str


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class AdvancedSuppressionManager:
    """
    Manages finding suppression through configurable rules loaded from
    .argus-ignore.yml, VEX documents, or EPSS-based auto-generation.

    Attributes:
        config_path: Default path for the YAML rules file.
        auto_expire_days: Default expiration window for auto-generated rules.
        rules: Currently loaded suppression rules.
    """

    def __init__(
        self,
        config_path: str = ".argus-ignore.yml",
        auto_expire_days: int = 90,
    ) -> None:
        self.config_path = config_path
        self.auto_expire_days = auto_expire_days
        self.rules: list[SuppressionRule] = []

    # ------------------------------------------------------------------
    # Rule loading / saving
    # ------------------------------------------------------------------

    def load_rules(self, path: str | None = None) -> list[SuppressionRule]:
        """Load suppression rules from a YAML file.

        Expected YAML format::

            version: 1
            rules:
              - id: suppress-001
                match_type: cve
                match_value: "CVE-2023-12345"
                reason: "Not exploitable in our config"
                expires_at: "2025-06-01"
                approved_by: "security-team"

        Args:
            path: Path to YAML file. Falls back to ``self.config_path``.

        Returns:
            List of parsed ``SuppressionRule`` objects.
        """
        if yaml is None:
            logger.error(
                "PyYAML is not installed. Install it with: pip install pyyaml"
            )
            return []

        file_path = path or self.config_path

        if not os.path.isfile(file_path):
            logger.warning("Suppression config not found: %s", file_path)
            return []

        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception:
            logger.exception("Failed to parse suppression config: %s", file_path)
            return []

        raw_rules: list[dict[str, Any]] = data.get("rules", [])
        rules: list[SuppressionRule] = []

        for entry in raw_rules:
            try:
                match_type = MatchType(entry["match_type"].lower())
                rule = SuppressionRule(
                    id=str(entry.get("id", "")),
                    match_type=match_type,
                    match_value=str(entry.get("match_value", "")),
                    reason=str(entry.get("reason", "")),
                    expires_at=str(entry.get("expires_at", "")),
                    approved_by=str(entry.get("approved_by", "")),
                    created_at=str(entry.get("created_at", "")),
                    source=str(entry.get("source", "manual")),
                    is_active=bool(entry.get("is_active", True)),
                )
                rules.append(rule)
            except (KeyError, ValueError) as exc:
                logger.warning(
                    "Skipping malformed suppression rule: %s (error: %s)",
                    entry,
                    exc,
                )

        self.rules = rules
        logger.info("Loaded %d suppression rules from %s", len(rules), file_path)
        return rules

    def save_rules(
        self, rules: list[SuppressionRule], path: str | None = None
    ) -> None:
        """Write suppression rules to a YAML file.

        Args:
            rules: Rules to persist.
            path: Destination path. Falls back to ``self.config_path``.
        """
        if yaml is None:
            logger.error(
                "PyYAML is not installed. Install it with: pip install pyyaml"
            )
            return

        file_path = path or self.config_path

        serialized: list[dict[str, Any]] = []
        for rule in rules:
            entry: dict[str, Any] = {
                "id": rule.id,
                "match_type": rule.match_type.value,
                "match_value": rule.match_value,
            }
            if rule.reason:
                entry["reason"] = rule.reason
            if rule.expires_at:
                entry["expires_at"] = rule.expires_at
            if rule.approved_by:
                entry["approved_by"] = rule.approved_by
            if rule.created_at:
                entry["created_at"] = rule.created_at
            if rule.source != "manual":
                entry["source"] = rule.source
            if not rule.is_active:
                entry["is_active"] = rule.is_active
            serialized.append(entry)

        document = {"version": 1, "rules": serialized}

        try:
            with open(file_path, "w", encoding="utf-8") as fh:
                yaml.dump(document, fh, default_flow_style=False, sort_keys=False)
            logger.info("Saved %d suppression rules to %s", len(rules), file_path)
        except Exception:
            logger.exception("Failed to save suppression config: %s", file_path)

    # ------------------------------------------------------------------
    # Expiration logic
    # ------------------------------------------------------------------

    @staticmethod
    def _is_expired(rule: SuppressionRule) -> bool:
        """Check whether a rule has passed its expiration date.

        Args:
            rule: The rule to inspect.

        Returns:
            ``True`` if the rule is expired, ``False`` otherwise.
            Rules with no ``expires_at`` value are never considered expired.
        """
        if not rule.expires_at:
            return False

        try:
            expires = datetime.fromisoformat(str(rule.expires_at))
            # Treat naive datetimes as UTC
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return now > expires
        except (ValueError, TypeError):
            logger.warning(
                "Invalid expires_at format for rule %s: %s",
                rule.id,
                rule.expires_at,
            )
            return False

    # ------------------------------------------------------------------
    # Matching logic
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_finding(rule: SuppressionRule, finding: dict) -> bool:
        """Determine whether a rule matches a given finding.

        Matching strategy depends on ``rule.match_type``:

        - **CVE**: Exact match on ``finding["cve_id"]``
        - **RULE_ID**: Exact match on ``finding["rule_id"]``
        - **PURL**: fnmatch-style wildcard matching of
          ``finding.get("purl", "")`` (e.g. ``"pkg:npm/lodash@*"``)
        - **PATH_PATTERN**: fnmatch matching of ``finding.get("file_path")``
          or ``finding.get("path")`` (e.g. ``"tests/**"``, ``"vendor/*"``)
        - **CWE**: Match on ``finding.get("cwe_id")`` or membership in
          ``finding.get("cwe_ids", [])``
        - **SEVERITY**: Case-insensitive match on ``finding.get("severity")``

        Args:
            rule: Suppression rule to test.
            finding: Security finding dictionary.

        Returns:
            ``True`` if the rule matches the finding.
        """
        match_type = rule.match_type
        value = rule.match_value

        if match_type == MatchType.CVE:
            return finding.get("cve_id", "") == value

        if match_type == MatchType.RULE_ID:
            return finding.get("rule_id", "") == value

        if match_type == MatchType.PURL:
            finding_purl = finding.get("purl", "")
            return fnmatch.fnmatch(finding_purl, value)

        if match_type == MatchType.PATH_PATTERN:
            finding_path = finding.get("file_path", "") or finding.get("path", "")
            return fnmatch.fnmatch(finding_path, value)

        if match_type == MatchType.CWE:
            if finding.get("cwe_id", "") == value:
                return True
            return value in finding.get("cwe_ids", [])

        if match_type == MatchType.SEVERITY:
            return finding.get("severity", "").lower() == value.lower()

        logger.warning("Unknown match type: %s", match_type)
        return False

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_finding(
        self,
        finding: dict,
        rules: list[SuppressionRule] | None = None,
    ) -> SuppressionResult:
        """Evaluate a finding against all active suppression rules.

        Returns the first matching, non-expired rule. Expired rules are
        skipped but a warning is logged for auditing purposes.

        Args:
            finding: Security finding to evaluate.
            rules: Optional rule list. Defaults to ``self.rules``.

        Returns:
            A ``SuppressionResult`` indicating whether the finding was
            suppressed and why.
        """
        effective_rules = rules if rules is not None else self.rules

        for rule in effective_rules:
            if not rule.is_active:
                continue

            if self._is_expired(rule):
                logger.warning(
                    "Suppression rule %s has expired (expires_at=%s) - skipping",
                    rule.id,
                    rule.expires_at,
                )
                continue

            if self._matches_finding(rule, finding):
                reason = rule.reason or f"Matched suppression rule {rule.id}"
                return SuppressionResult(
                    finding=finding,
                    rule=rule,
                    suppressed=True,
                    reason=reason,
                )

        return SuppressionResult(
            finding=finding,
            rule=None,
            suppressed=False,
            reason="No matching suppression rule",
        )

    def filter_findings(
        self,
        findings: list[dict],
        rules: list[SuppressionRule] | None = None,
    ) -> tuple[list[dict], list[dict]]:
        """Partition findings into remaining and suppressed lists.

        Suppressed findings have ``suppression_rule_id`` and
        ``suppression_reason`` metadata injected into their dicts.

        Args:
            findings: List of security findings.
            rules: Optional rule list. Defaults to ``self.rules``.

        Returns:
            A 2-tuple of ``(remaining, suppressed)`` finding lists.
        """
        remaining: list[dict] = []
        suppressed: list[dict] = []

        for finding in findings:
            result = self.evaluate_finding(finding, rules)
            if result.suppressed and result.rule is not None:
                finding_copy = dict(finding)
                finding_copy["suppression_rule_id"] = result.rule.id
                finding_copy["suppression_reason"] = result.reason
                suppressed.append(finding_copy)
            else:
                remaining.append(finding)

        logger.info(
            "Filtered %d findings: %d remaining, %d suppressed",
            len(findings),
            len(remaining),
            len(suppressed),
        )
        return remaining, suppressed

    # ------------------------------------------------------------------
    # VEX integration
    # ------------------------------------------------------------------

    def add_vex_rules(
        self, vex_statements: list[dict]
    ) -> list[SuppressionRule]:
        """Convert VEX ``not_affected`` statements to suppression rules.

        Expected VEX statement format::

            {
                "vulnerability": "CVE-2023-12345",
                "status": "not_affected",
                "justification": "component_not_present",
                "impact_statement": "Library not used in production"
            }

        Only statements with ``status == "not_affected"`` are converted.

        Args:
            vex_statements: List of VEX statement dicts.

        Returns:
            List of newly created ``SuppressionRule`` objects.
        """
        new_rules: list[SuppressionRule] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for stmt in vex_statements:
            status = stmt.get("status", "").lower()
            if status != "not_affected":
                continue

            vuln_id = stmt.get("vulnerability", "")
            if not vuln_id:
                continue

            justification = stmt.get("justification", "")
            impact = stmt.get("impact_statement", "")
            reason_parts = [s for s in [justification, impact] if s]
            reason = " - ".join(reason_parts) if reason_parts else "VEX not_affected"

            rule = SuppressionRule(
                id=f"vex-{vuln_id}",
                match_type=MatchType.CVE,
                match_value=vuln_id,
                reason=reason,
                created_at=now_iso,
                source="vex",
            )
            new_rules.append(rule)
            self.rules.append(rule)

        logger.info(
            "Added %d VEX-derived suppression rules from %d statements",
            len(new_rules),
            len(vex_statements),
        )
        return new_rules

    # ------------------------------------------------------------------
    # EPSS auto-suppression
    # ------------------------------------------------------------------

    def add_epss_auto_suppress(
        self,
        findings: list[dict],
        threshold: float = 0.01,
    ) -> list[SuppressionRule]:
        """Create suppression rules for findings with very low EPSS scores.

        Findings with an ``epss_score`` below ``threshold`` are considered
        unlikely to be exploited and are automatically suppressed.

        Args:
            findings: List of findings, each optionally containing
                ``"epss_score"`` and ``"cve_id"`` keys.
            threshold: EPSS probability below which to suppress (default 0.01).

        Returns:
            List of newly created ``SuppressionRule`` objects.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        expire_date = datetime(
            datetime.now(timezone.utc).year,
            datetime.now(timezone.utc).month,
            datetime.now(timezone.utc).day,
            tzinfo=timezone.utc,
        )
        # Calculate expiry from auto_expire_days
        from datetime import timedelta

        expire_iso = (expire_date + timedelta(days=self.auto_expire_days)).isoformat()

        new_rules: list[SuppressionRule] = []

        for finding in findings:
            epss_score = finding.get("epss_score")
            if epss_score is None:
                continue

            try:
                score = float(epss_score)
            except (ValueError, TypeError):
                continue

            if score >= threshold:
                continue

            cve_id = finding.get("cve_id", "")
            rule_id_value = finding.get("rule_id", "")
            identifier = cve_id or rule_id_value

            if not identifier:
                continue

            # Determine match type based on available identifier
            if cve_id:
                match_type = MatchType.CVE
                match_value = cve_id
            else:
                match_type = MatchType.RULE_ID
                match_value = rule_id_value

            rule = SuppressionRule(
                id=f"epss-auto-{identifier}",
                match_type=match_type,
                match_value=match_value,
                reason=f"EPSS score {score:.4f} below threshold {threshold}",
                expires_at=expire_iso,
                created_at=now_iso,
                source="epss_auto",
            )
            new_rules.append(rule)
            self.rules.append(rule)

        logger.info(
            "Created %d EPSS-based auto-suppression rules (threshold=%.4f)",
            len(new_rules),
            threshold,
        )
        return new_rules

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def get_expired_rules(
        self, rules: list[SuppressionRule] | None = None
    ) -> list[SuppressionRule]:
        """Return all rules that have passed their expiration date.

        Args:
            rules: Optional rule list. Defaults to ``self.rules``.

        Returns:
            List of expired ``SuppressionRule`` objects.
        """
        effective_rules = rules if rules is not None else self.rules
        return [r for r in effective_rules if self._is_expired(r)]

    def get_summary(self, results: list[SuppressionResult]) -> dict:
        """Generate summary statistics from a list of evaluation results.

        Args:
            results: List of ``SuppressionResult`` from ``evaluate_finding``.

        Returns:
            Dict with keys: ``total_evaluated``, ``suppressed_count``,
            ``by_match_type``, ``by_source``, ``expired_rules_used``.
        """
        total = len(results)
        suppressed_count = sum(1 for r in results if r.suppressed)

        by_match_type: dict[str, int] = {}
        by_source: dict[str, int] = {}
        expired_rules_used = 0

        for result in results:
            if result.suppressed and result.rule is not None:
                mt = result.rule.match_type.value
                by_match_type[mt] = by_match_type.get(mt, 0) + 1

                src = result.rule.source
                by_source[src] = by_source.get(src, 0) + 1

                if self._is_expired(result.rule):
                    expired_rules_used += 1

        return {
            "total_evaluated": total,
            "suppressed_count": suppressed_count,
            "by_match_type": by_match_type,
            "by_source": by_source,
            "expired_rules_used": expired_rules_used,
        }
