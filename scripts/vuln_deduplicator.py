#!/usr/bin/env python3
"""
Multi-Level Vulnerability Deduplicator for Argus Security

Deduplicates findings across scanners using a multi-key strategy inspired
by Trivy's deduplication approach.  Supports four strategies:

  - **strict**   : all key fields must match (vuln_id + pkg + version + path + rule)
  - **standard** : vuln_id + package name + version
  - **relaxed**  : vuln_id only
  - **auto**     : picks the best strategy based on finding type

Each duplicate group elects a *canonical* finding (the one with the richest
metadata) and attaches merged evidence from every scanner that reported it.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Scanner priority used to break ties when two findings have the same amount
# of metadata.  Lower index = higher priority.
SCANNER_PRIORITY: list[str] = [
    "trivy",
    "semgrep",
    "checkov",
    "gitleaks",
    "trufflehog",
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DeduplicationKey:
    """Composite key used to identify logically identical findings."""

    vuln_id: str
    pkg_name: str = ""
    pkg_version: str = ""
    pkg_path: str = ""
    file_path: str = ""
    rule_id: str = ""

    def to_hash(self) -> str:
        """Return a deterministic SHA-256 hex digest of the concatenated fields."""
        combined = "|".join(
            [
                self.vuln_id,
                self.pkg_name,
                self.pkg_version,
                self.pkg_path,
                self.file_path,
                self.rule_id,
            ]
        )
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()


@dataclass
class DeduplicationResult:
    """Outcome of a deduplication run."""

    original_count: int
    deduplicated_count: int
    duplicates_removed: int
    merge_groups: list[dict] = field(default_factory=list)
    kept_findings: list[dict] = field(default_factory=list)
    removed_findings: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main deduplicator
# ---------------------------------------------------------------------------


class VulnDeduplicator:
    """Deduplicates vulnerability findings across multiple scanners.

    Parameters
    ----------
    strategy : str
        One of ``"strict"``, ``"standard"``, ``"relaxed"``, or ``"auto"``.
        When ``"auto"`` the strategy is chosen per-finding based on its
        available fields.
    """

    VALID_STRATEGIES = {"strict", "standard", "relaxed", "auto"}

    def __init__(self, strategy: str = "auto") -> None:
        if strategy not in self.VALID_STRATEGIES:
            raise ValueError(
                f"Invalid strategy {strategy!r}. "
                f"Must be one of {sorted(self.VALID_STRATEGIES)}."
            )
        self.strategy = strategy

    # ------------------------------------------------------------------
    # Key extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_key(finding: dict, strategy: str) -> DeduplicationKey:
        """Build a :class:`DeduplicationKey` from *finding*.

        The method normalises several common key-naming conventions so that
        findings from different scanners can still be grouped together.
        """

        # --- vuln_id ---
        vuln_id = (
            finding.get("cve_id")
            or finding.get("vuln_id")
            or finding.get("vulnerability_id")
            or ""
        )

        # --- package name ---
        pkg_name = (
            finding.get("package_name")
            or finding.get("pkg_name")
            or ""
        )

        # --- package version ---
        pkg_version = (
            finding.get("installed_version")
            or finding.get("version")
            or finding.get("pkg_version")
            or ""
        )

        # --- package path ---
        pkg_path = finding.get("pkg_path", "")

        # --- file path ---
        file_path = (
            finding.get("file_path")
            or finding.get("path")
            or finding.get("location")
            or ""
        )

        # --- rule id ---
        rule_id = (
            finding.get("rule_id")
            or finding.get("check_id")
            or ""
        )

        # Build the key respecting the strategy
        if strategy == "relaxed":
            return DeduplicationKey(vuln_id=vuln_id)
        if strategy == "standard":
            return DeduplicationKey(
                vuln_id=vuln_id,
                pkg_name=pkg_name,
                pkg_version=pkg_version,
            )
        # "strict" (or default)
        return DeduplicationKey(
            vuln_id=vuln_id,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            pkg_path=pkg_path,
            file_path=file_path,
            rule_id=rule_id,
        )

    # ------------------------------------------------------------------
    # Strategy auto-detection
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_strategy(finding: dict) -> str:
        """Choose the best deduplication strategy for a single finding.

        * CVE-style identifiers  -> ``"standard"``
        * Static analysis rules  -> ``"strict"``
        * Everything else        -> ``"relaxed"``
        """
        if finding.get("cve_id") or finding.get("vuln_id") or finding.get("vulnerability_id"):
            return "standard"
        if finding.get("rule_id") or finding.get("check_id"):
            return "strict"
        return "relaxed"

    # ------------------------------------------------------------------
    # Canonical selection
    # ------------------------------------------------------------------

    @staticmethod
    def _select_canonical(findings: list[dict]) -> dict:
        """Pick the richest finding from a group of duplicates.

        *Richest* means the finding with the most non-empty values.  Ties
        are broken by scanner priority (trivy > semgrep > checkov > ...).
        """

        def _richness(f: dict) -> int:
            return sum(1 for v in f.values() if v not in (None, "", [], {}))

        def _scanner_rank(f: dict) -> int:
            scanner = str(f.get("scanner", f.get("source", ""))).lower()
            try:
                return SCANNER_PRIORITY.index(scanner)
            except ValueError:
                return len(SCANNER_PRIORITY)

        # Sort: highest richness first, then lowest scanner rank
        ranked = sorted(
            findings,
            key=lambda f: (-_richness(f), _scanner_rank(f)),
        )
        return ranked[0]

    # ------------------------------------------------------------------
    # Evidence merging
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_evidence(findings: list[dict]) -> dict:
        """Create a merged evidence dictionary from a duplicate group."""
        sources: list[str] = []
        summaries: list[str] = []

        for f in findings:
            scanner = f.get("scanner", f.get("source", "unknown"))
            sources.append(str(scanner))
            summary = (
                f.get("message")
                or f.get("title")
                or f.get("description")
                or f.get("vuln_id")
                or f.get("cve_id")
                or str(scanner)
            )
            summaries.append(str(summary))

        return {
            "sources": sources,
            "original_count": len(findings),
            "merged_from": summaries,
        }

    # ------------------------------------------------------------------
    # Core deduplication
    # ------------------------------------------------------------------

    def deduplicate(self, findings: list[dict]) -> DeduplicationResult:
        """Deduplicate *findings* and return a :class:`DeduplicationResult`.

        Each finding is assigned a deduplication key (based on the active
        strategy).  Findings that share the same key hash are grouped
        together; for each group a canonical finding is selected and
        enriched with merged evidence.
        """
        if not findings:
            return DeduplicationResult(
                original_count=0,
                deduplicated_count=0,
                duplicates_removed=0,
                merge_groups=[],
                kept_findings=[],
                removed_findings=[],
            )

        groups: dict[str, list[dict]] = defaultdict(list)

        for finding in findings:
            strategy = (
                self._determine_strategy(finding)
                if self.strategy == "auto"
                else self.strategy
            )
            key = self._extract_key(finding, strategy)
            groups[key.to_hash()].append(finding)

        kept: list[dict] = []
        removed: list[dict] = []
        merge_groups: list[dict] = []

        for key_hash, group in groups.items():
            canonical = self._select_canonical(group)

            if len(group) > 1:
                evidence = self._merge_evidence(group)
                canonical = {**canonical, "merged_evidence": evidence}
                merge_groups.append(
                    {
                        "key_hash": key_hash,
                        "count": len(group),
                        "sources": evidence["sources"],
                    }
                )
                # Everything that is *not* the canonical is considered removed
                for f in group:
                    if f is not canonical and f is not group[0]:
                        removed.append(f)
                    elif f is not canonical:
                        # The original canonical (before copy via {**}) is
                        # the first element that matched; remaining are dupes.
                        removed.append(f)

                # Since we rebuilt canonical via dict spread, the original
                # list items are all potential "removed" entries except one.
                # Re-derive removed properly.
                removed_from_group = [f for f in group if f is not self._select_canonical(group)]
                # Replace the potentially incorrect entries above
                removed = [r for r in removed if r not in group]
                removed.extend(removed_from_group)

            kept.append(canonical)

        duplicates_removed = len(findings) - len(kept)

        logger.info(
            "Deduplication complete: %d -> %d findings (%d removed)",
            len(findings),
            len(kept),
            duplicates_removed,
        )

        return DeduplicationResult(
            original_count=len(findings),
            deduplicated_count=len(kept),
            duplicates_removed=duplicates_removed,
            merge_groups=merge_groups,
            kept_findings=kept,
            removed_findings=removed,
        )

    # ------------------------------------------------------------------
    # Cross-scanner merge
    # ------------------------------------------------------------------

    def cross_scanner_merge(self, findings: list[dict]) -> list[dict]:
        """Merge findings that share the same CVE across different scanners.

        Unlike :meth:`deduplicate` this method explicitly focuses on
        scanner-level merging: when the same CVE is reported by e.g. both
        Trivy and Semgrep the two findings are unified into a single
        record that carries scanner-specific metadata from both.
        """
        if not findings:
            return []

        # Group by CVE / vuln identifier
        by_vuln: dict[str, list[dict]] = defaultdict(list)
        ungrouped: list[dict] = []

        for f in findings:
            vid = (
                f.get("cve_id")
                or f.get("vuln_id")
                or f.get("vulnerability_id")
            )
            if vid:
                by_vuln[vid].append(f)
            else:
                ungrouped.append(f)

        merged: list[dict] = []

        for vid, group in by_vuln.items():
            # Collect distinct scanners
            scanners = list({
                str(f.get("scanner", f.get("source", "unknown")))
                for f in group
            })

            if len(scanners) <= 1 and len(group) <= 1:
                merged.extend(group)
                continue

            canonical = self._select_canonical(group)
            unified = {**canonical}

            # Attach per-scanner details
            scanner_details: dict[str, dict] = {}
            for f in group:
                scanner = str(f.get("scanner", f.get("source", "unknown")))
                scanner_details[scanner] = {
                    k: v
                    for k, v in f.items()
                    if k not in ("scanner", "source") and v not in (None, "", [], {})
                }

            unified["scanners"] = scanners
            unified["scanner_details"] = scanner_details
            unified["merged_evidence"] = self._merge_evidence(group)
            merged.append(unified)

        merged.extend(ungrouped)
        return merged

    # ------------------------------------------------------------------
    # Summary / reporting
    # ------------------------------------------------------------------

    @staticmethod
    def get_summary(result: DeduplicationResult) -> dict:
        """Produce a human-friendly summary dictionary from a result."""
        reduction_pct = 0.0
        if result.original_count > 0:
            reduction_pct = round(
                (result.duplicates_removed / result.original_count) * 100, 2
            )

        # Strategy breakdown (approximate from merge groups)
        by_strategy: dict[str, int] = defaultdict(int)
        for mg in result.merge_groups:
            by_strategy["merged"] += mg.get("count", 0)

        # Top-5 largest merge groups
        sorted_groups = sorted(
            result.merge_groups,
            key=lambda g: g.get("count", 0),
            reverse=True,
        )
        largest = sorted_groups[:5]

        return {
            "original_count": result.original_count,
            "deduplicated_count": result.deduplicated_count,
            "reduction_percentage": reduction_pct,
            "by_strategy": dict(by_strategy),
            "largest_merge_groups": largest,
        }
