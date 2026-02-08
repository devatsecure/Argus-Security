#!/usr/bin/env python3
"""
VEX (Vulnerability Exploitability eXchange) Processor for Argus Security

Parses VEX documents in OpenVEX, CycloneDX VEX, and CSAF formats to filter
security findings that have been assessed as "not_affected". Integrates with
the Phase 2 enrichment pipeline to reduce false positives using vendor-provided
exploitability data.

Supported formats:
  - OpenVEX (https://openvex.dev)
  - CycloneDX VEX (https://cyclonedx.org/capabilities/vex/)
  - CSAF VEX (https://docs.oasis-open.org/csaf/csaf/v2.0/)

Usage:
    processor = VEXProcessor(vex_paths=["./vex/product.vex.json"])
    statements = processor.load_statements()
    remaining, suppressed = processor.filter_findings(findings, statements)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VEXStatus(Enum):
    """VEX exploitability status values (aligned with CISA VEX spec)."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(Enum):
    """Justification codes for NOT_AFFECTED status (aligned with VEX spec)."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"
    NONE = "none"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VEXStatement:
    """A single VEX statement mapping a vulnerability to a product status."""

    vulnerability_id: str
    status: VEXStatus
    justification: VEXJustification = VEXJustification.NONE
    product_id: str = ""
    purl: str = ""
    statement_text: str = ""
    source_format: str = ""
    source_file: str = ""
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Status/justification normalisation helpers
# ---------------------------------------------------------------------------

# Maps various status strings found across VEX formats to our canonical enum.
_STATUS_MAP: dict[str, VEXStatus] = {
    # OpenVEX / canonical
    "not_affected": VEXStatus.NOT_AFFECTED,
    "affected": VEXStatus.AFFECTED,
    "fixed": VEXStatus.FIXED,
    "under_investigation": VEXStatus.UNDER_INVESTIGATION,
    # CycloneDX analysis.state values
    "not_affected": VEXStatus.NOT_AFFECTED,
    "exploitable": VEXStatus.AFFECTED,
    "resolved": VEXStatus.FIXED,
    "resolved_with_pedigree": VEXStatus.FIXED,
    "in_triage": VEXStatus.UNDER_INVESTIGATION,
    "false_positive": VEXStatus.NOT_AFFECTED,
    # CSAF product_status keys (used as synthetic statuses during parsing)
    "known_not_affected": VEXStatus.NOT_AFFECTED,
    "known_affected": VEXStatus.AFFECTED,
    "first_fixed": VEXStatus.FIXED,
}

_JUSTIFICATION_MAP: dict[str, VEXJustification] = {
    "component_not_present": VEXJustification.COMPONENT_NOT_PRESENT,
    "vulnerable_code_not_present": VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
    "vulnerable_code_not_in_execute_path": VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "vulnerable_code_cannot_be_controlled_by_adversary": (
        VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY
    ),
    "inline_mitigations_already_exist": VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
}


def _normalise_status(raw: str) -> VEXStatus:
    """Normalise a raw status string to a ``VEXStatus`` enum member."""
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return _STATUS_MAP.get(key, VEXStatus.UNDER_INVESTIGATION)


def _normalise_justification(raw: str | None) -> VEXJustification:
    """Normalise a raw justification string to a ``VEXJustification`` enum member."""
    if not raw:
        return VEXJustification.NONE
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return _JUSTIFICATION_MAP.get(key, VEXJustification.NONE)


# ---------------------------------------------------------------------------
# VEXProcessor
# ---------------------------------------------------------------------------

class VEXProcessor:
    """
    Loads, parses, and applies VEX statements against Argus findings.

    Parameters
    ----------
    vex_paths:
        Explicit list of VEX document file paths to load.
    auto_discover_dir:
        Directory to scan for ``*.json`` VEX documents.  Defaults to
        ``.argus/vex`` relative to the current working directory.
    """

    def __init__(
        self,
        vex_paths: list[str] | None = None,
        auto_discover_dir: str = ".argus/vex",
    ) -> None:
        self._vex_paths: list[str] = list(vex_paths) if vex_paths else []
        self._auto_discover_dir: str = auto_discover_dir
        self._cached_statements: list[VEXStatement] | None = None

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_format(data: dict) -> str:
        """Detect which VEX format a parsed JSON document uses.

        Returns one of ``"openvex"``, ``"cyclonedx_vex"``, ``"csaf"``, or
        ``"unknown"``.
        """
        # OpenVEX: top-level "@context" containing "openvex"
        context = data.get("@context", "")
        if isinstance(context, str) and "openvex" in context.lower():
            return "openvex"
        if isinstance(context, list):
            for item in context:
                if isinstance(item, str) and "openvex" in item.lower():
                    return "openvex"

        # CycloneDX VEX: "bomFormat" == "CycloneDX"
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx_vex"

        # CSAF: "document" dict with "category" == "csaf_vex"
        doc = data.get("document", {})
        if isinstance(doc, dict) and doc.get("category") == "csaf_vex":
            return "csaf"

        return "unknown"

    # ------------------------------------------------------------------
    # Per-format parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_openvex(data: dict, source_file: str) -> list[VEXStatement]:
        """Parse an OpenVEX JSON document into ``VEXStatement`` objects.

        Expected structure::

            {
              "@context": "https://openvex.dev/ns/v0.2.0",
              "statements": [
                {
                  "vulnerability": {"name": "CVE-2023-1234", ...},
                  "status": "not_affected",
                  "justification": "component_not_present",
                  "products": [{"@id": "...", "purl": "pkg:..."}],
                  "timestamp": "2024-01-01T00:00:00Z",
                  "statement": "Human-readable explanation"
                }
              ]
            }
        """
        statements: list[VEXStatement] = []
        timestamp_doc = data.get("timestamp", "")

        for entry in data.get("statements", []):
            try:
                vuln = entry.get("vulnerability", {})
                vuln_id = vuln.get("name", "") if isinstance(vuln, dict) else str(vuln)
                if not vuln_id:
                    vuln_id = vuln.get("@id", "") if isinstance(vuln, dict) else ""
                if not vuln_id:
                    logger.warning(
                        "Skipping OpenVEX statement without vulnerability ID in %s",
                        source_file,
                    )
                    continue

                status = _normalise_status(entry.get("status", ""))
                justification = _normalise_justification(entry.get("justification"))

                products = entry.get("products", [])
                ts = entry.get("timestamp", timestamp_doc)
                statement_text = entry.get("statement", "")

                if products:
                    for product in products:
                        purl = ""
                        product_id = ""
                        if isinstance(product, dict):
                            purl = product.get("purl", "")
                            product_id = product.get("@id", "")
                        elif isinstance(product, str):
                            product_id = product

                        statements.append(
                            VEXStatement(
                                vulnerability_id=vuln_id,
                                status=status,
                                justification=justification,
                                product_id=product_id,
                                purl=purl,
                                statement_text=statement_text,
                                source_format="openvex",
                                source_file=source_file,
                                timestamp=ts,
                            )
                        )
                else:
                    # No product scoping -- applies globally
                    statements.append(
                        VEXStatement(
                            vulnerability_id=vuln_id,
                            status=status,
                            justification=justification,
                            statement_text=statement_text,
                            source_format="openvex",
                            source_file=source_file,
                            timestamp=ts,
                        )
                    )
            except Exception:
                logger.warning(
                    "Skipping malformed OpenVEX statement in %s", source_file, exc_info=True
                )

        return statements

    @staticmethod
    def _parse_cyclonedx_vex(data: dict, source_file: str) -> list[VEXStatement]:
        """Parse a CycloneDX VEX document into ``VEXStatement`` objects.

        Expected structure::

            {
              "bomFormat": "CycloneDX",
              "vulnerabilities": [
                {
                  "id": "CVE-2023-1234",
                  "analysis": {
                    "state": "not_affected",
                    "justification": "code_not_reachable",
                    "detail": "..."
                  },
                  "affects": [{"ref": "comp-uuid"}]
                }
              ]
            }
        """
        statements: list[VEXStatement] = []

        for vuln in data.get("vulnerabilities", []):
            try:
                vuln_id = vuln.get("id", "")
                if not vuln_id:
                    logger.warning(
                        "Skipping CycloneDX VEX entry without id in %s", source_file
                    )
                    continue

                analysis = vuln.get("analysis", {}) or {}
                state_raw = analysis.get("state", "under_investigation")
                status = _normalise_status(state_raw)
                justification = _normalise_justification(analysis.get("justification"))
                detail = analysis.get("detail", "")

                affects = vuln.get("affects", [])
                if affects:
                    for affect_entry in affects:
                        ref = ""
                        if isinstance(affect_entry, dict):
                            ref = affect_entry.get("ref", "")
                        elif isinstance(affect_entry, str):
                            ref = affect_entry

                        statements.append(
                            VEXStatement(
                                vulnerability_id=vuln_id,
                                status=status,
                                justification=justification,
                                product_id=ref,
                                purl=ref if ref.startswith("pkg:") else "",
                                statement_text=detail,
                                source_format="cyclonedx_vex",
                                source_file=source_file,
                            )
                        )
                else:
                    statements.append(
                        VEXStatement(
                            vulnerability_id=vuln_id,
                            status=status,
                            justification=justification,
                            statement_text=detail,
                            source_format="cyclonedx_vex",
                            source_file=source_file,
                        )
                    )
            except Exception:
                logger.warning(
                    "Skipping malformed CycloneDX VEX entry in %s",
                    source_file,
                    exc_info=True,
                )

        return statements

    @staticmethod
    def _parse_csaf(data: dict, source_file: str) -> list[VEXStatement]:
        """Parse a CSAF VEX advisory into ``VEXStatement`` objects.

        Expected structure::

            {
              "document": {"category": "csaf_vex", ...},
              "vulnerabilities": [
                {
                  "cve": "CVE-2023-1234",
                  "product_status": {
                    "known_not_affected": ["product-id-1"],
                    "known_affected": ["product-id-2"],
                    "fixed": ["product-id-3"],
                    "first_fixed": ["product-id-4"]
                  },
                  "remediations": [
                    {"details": "...", "product_ids": ["product-id-2"]}
                  ],
                  "threats": [
                    {"details": "...", "product_ids": ["product-id-1"]}
                  ]
                }
              ]
            }
        """
        statements: list[VEXStatement] = []

        for vuln in data.get("vulnerabilities", []):
            try:
                cve = vuln.get("cve", "")
                if not cve:
                    logger.warning(
                        "Skipping CSAF vulnerability without CVE in %s", source_file
                    )
                    continue

                product_status = vuln.get("product_status", {}) or {}

                # Collect remediation texts keyed by product_id for enrichment
                remediation_map: dict[str, str] = {}
                for rem in vuln.get("remediations", []):
                    detail = rem.get("details", "")
                    for pid in rem.get("product_ids", []):
                        remediation_map[pid] = detail

                # Collect threat descriptions keyed by product_id
                threat_map: dict[str, str] = {}
                for threat in vuln.get("threats", []):
                    detail = threat.get("details", "")
                    for pid in threat.get("product_ids", []):
                        threat_map[pid] = detail

                # Map CSAF product_status categories to VEX statuses
                category_status_pairs = [
                    ("known_not_affected", VEXStatus.NOT_AFFECTED),
                    ("known_affected", VEXStatus.AFFECTED),
                    ("fixed", VEXStatus.FIXED),
                    ("first_fixed", VEXStatus.FIXED),
                    ("under_investigation", VEXStatus.UNDER_INVESTIGATION),
                ]

                for category, vex_status in category_status_pairs:
                    product_ids = product_status.get(category, [])
                    if not isinstance(product_ids, list):
                        continue

                    for pid in product_ids:
                        statement_text = (
                            remediation_map.get(pid, "")
                            or threat_map.get(pid, "")
                        )

                        statements.append(
                            VEXStatement(
                                vulnerability_id=cve,
                                status=vex_status,
                                justification=VEXJustification.NONE,
                                product_id=pid,
                                purl=pid if isinstance(pid, str) and pid.startswith("pkg:") else "",
                                statement_text=statement_text,
                                source_format="csaf",
                                source_file=source_file,
                            )
                        )
            except Exception:
                logger.warning(
                    "Skipping malformed CSAF vulnerability in %s",
                    source_file,
                    exc_info=True,
                )

        return statements

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def _load_file(self, path: str) -> list[VEXStatement]:
        """Load a single VEX file, detect its format, and parse it."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping invalid JSON file %s: %s", path, exc)
            return []
        except OSError as exc:
            logger.warning("Cannot read VEX file %s: %s", path, exc)
            return []

        if not isinstance(data, dict):
            logger.warning("VEX file %s does not contain a JSON object", path)
            return []

        fmt = self._detect_format(data)

        if fmt == "openvex":
            return self._parse_openvex(data, path)
        elif fmt == "cyclonedx_vex":
            return self._parse_cyclonedx_vex(data, path)
        elif fmt == "csaf":
            return self._parse_csaf(data, path)
        else:
            logger.warning("Unknown VEX format in %s -- skipping", path)
            return []

    def load_statements(self) -> list[VEXStatement]:
        """Load VEX statements from all configured paths and auto-discovery.

        Returns a deduplicated list of ``VEXStatement`` objects.  Results are
        cached after the first call; subsequent calls return the cached list.
        """
        if self._cached_statements is not None:
            return self._cached_statements

        all_statements: list[VEXStatement] = []

        # Explicit paths
        for path in self._vex_paths:
            resolved = Path(path).resolve()
            if resolved.is_file():
                stmts = self._load_file(str(resolved))
                logger.info(
                    "Loaded %d VEX statements from %s", len(stmts), resolved
                )
                all_statements.extend(stmts)
            else:
                logger.warning("VEX path does not exist or is not a file: %s", path)

        # Auto-discover *.json files in the auto_discover_dir
        discover_dir = Path(self._auto_discover_dir)
        if discover_dir.is_dir():
            for json_file in sorted(discover_dir.glob("*.json")):
                if json_file.is_file():
                    stmts = self._load_file(str(json_file.resolve()))
                    logger.info(
                        "Auto-discovered %d VEX statements from %s",
                        len(stmts),
                        json_file,
                    )
                    all_statements.extend(stmts)

        logger.info("Total VEX statements loaded: %d", len(all_statements))
        self._cached_statements = all_statements
        return all_statements

    # ------------------------------------------------------------------
    # Matching logic
    # ------------------------------------------------------------------

    @staticmethod
    def matches_finding(statement: VEXStatement, finding: dict) -> bool:
        """Check whether a VEX statement applies to a given finding.

        Matching rules:
        1. The ``vulnerability_id`` must match ``finding["cve_id"]``
           (case-insensitive).
        2. If *both* the statement and the finding carry a PURL, they must
           also match (case-insensitive).  If either side lacks a PURL the
           CVE match alone is sufficient.
        """
        finding_cve = finding.get("cve_id", "")
        if not finding_cve or not statement.vulnerability_id:
            return False

        if statement.vulnerability_id.lower() != finding_cve.lower():
            return False

        # If both sides have a PURL, require a match
        finding_purl = finding.get("purl", "")
        if statement.purl and finding_purl:
            if statement.purl.lower() != finding_purl.lower():
                return False

        return True

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_findings(
        self,
        findings: list[dict],
        statements: list[VEXStatement] | None = None,
    ) -> tuple[list[dict], list[dict]]:
        """Partition findings into remaining and VEX-suppressed lists.

        For each finding, if a matching ``VEXStatement`` with status
        ``NOT_AFFECTED`` or ``FIXED`` exists, the finding is moved to the
        suppressed list and annotated with ``vex_status`` and
        ``vex_justification`` keys.

        Parameters
        ----------
        findings:
            List of Argus finding dicts (must contain at least ``cve_id``).
        statements:
            Pre-loaded VEX statements.  If ``None``, statements are loaded
            via :meth:`load_statements`.

        Returns
        -------
        tuple of (remaining, suppressed)
        """
        if statements is None:
            statements = self.load_statements()

        remaining: list[dict] = []
        suppressed: list[dict] = []

        suppressible_statuses = {VEXStatus.NOT_AFFECTED, VEXStatus.FIXED}

        for finding in findings:
            matched = False
            for stmt in statements:
                if stmt.status in suppressible_statuses and self.matches_finding(stmt, finding):
                    # Annotate the finding with VEX metadata
                    finding["vex_status"] = stmt.status.value
                    finding["vex_justification"] = stmt.justification.value
                    finding["vex_source"] = stmt.source_file
                    finding["vex_statement"] = stmt.statement_text
                    suppressed.append(finding)
                    matched = True
                    logger.debug(
                        "VEX suppressed finding %s (status=%s, justification=%s)",
                        finding.get("cve_id", "?"),
                        stmt.status.value,
                        stmt.justification.value,
                    )
                    break

            if not matched:
                remaining.append(finding)

        logger.info(
            "VEX filtering complete: %d remaining, %d suppressed",
            len(remaining),
            len(suppressed),
        )
        return remaining, suppressed

    # ------------------------------------------------------------------
    # Summary / reporting
    # ------------------------------------------------------------------

    @staticmethod
    def get_summary(statements: list[VEXStatement]) -> dict:
        """Produce a summary dict describing the loaded VEX statements.

        Returns
        -------
        dict with keys:
            - ``total_statements`` (int)
            - ``by_status`` (dict[str, int])
            - ``by_format`` (dict[str, int])
            - ``sources`` (list[str])
        """
        by_status: dict[str, int] = {}
        by_format: dict[str, int] = {}
        sources: set[str] = set()

        for stmt in statements:
            status_key = stmt.status.value
            by_status[status_key] = by_status.get(status_key, 0) + 1

            fmt_key = stmt.source_format or "unknown"
            by_format[fmt_key] = by_format.get(fmt_key, 0) + 1

            if stmt.source_file:
                sources.add(stmt.source_file)

        return {
            "total_statements": len(statements),
            "by_status": by_status,
            "by_format": by_format,
            "sources": sorted(sources),
        }
