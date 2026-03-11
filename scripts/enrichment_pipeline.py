#!/usr/bin/env python3
"""
Shared Enrichment Pipeline for Argus Security.

Encapsulates the 6-step vulnerability enrichment pipeline used by both
orchestrators (run_ai_audit.py and hybrid_analyzer.py):

    1. EPSS scoring         (exploit probability)
    2. Fix version tracking  (upgrade path info)
    3. VEX filtering         (suppress not_affected findings)
    4. Deduplication          (cross-scanner merge)
    5. Compliance mapping     (framework controls)
    6. Advanced suppression   (rule-based filtering)

License risk scoring is intentionally excluded -- it operates on SBOM
components, not findings, and each orchestrator handles it differently.
"""

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy availability flags -- each enrichment module is optional.
# ---------------------------------------------------------------------------

try:
    from epss_scorer import EPSSScorer

    _EPSS_OK = True
except ImportError:
    _EPSS_OK = False

try:
    from fix_version_tracker import FixVersionTracker

    _FIX_OK = True
except ImportError:
    _FIX_OK = False

try:
    from vex_processor import VEXProcessor

    _VEX_OK = True
except ImportError:
    _VEX_OK = False

try:
    from vuln_deduplicator import VulnDeduplicator

    _DEDUP_OK = True
except ImportError:
    _DEDUP_OK = False

try:
    from compliance_mapper import ComplianceMapper

    _COMPLIANCE_OK = True
except ImportError:
    _COMPLIANCE_OK = False

try:
    from advanced_suppression import AdvancedSuppressionManager

    _SUPPRESSION_OK = True
except ImportError:
    _SUPPRESSION_OK = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_bool(value: Any) -> bool:
    """Parse a config value as boolean."""
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_enrichment_pipeline(
    findings: list[dict[str, Any]],
    config: dict[str, Any],
    target_path: str,
    *,
    as_dicts: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the 6-step enrichment pipeline on findings.

    Args:
        findings: List of finding dicts (or dataclass instances when
            *as_dicts* is ``False``).
        config: Configuration dict with ``enable_*`` flags and tuning knobs.
        target_path: Path to the target repository (used for VEX discovery,
            cache directories, suppression config, and compliance reports).
        as_dicts: If ``True`` (default), the returned list contains plain
            dicts.  If ``False``, the caller is responsible for any
            dataclass reconstruction.

    Returns:
        ``(enriched_findings, metadata)`` where *metadata* is a dict
        keyed by enrichment step name (``epss``, ``fix_versions``, ``vex``,
        ``deduplication``, ``suppression``, ``compliance``).
    """
    if not findings:
        return findings, {}

    metadata: dict[str, Any] = {}
    remaining: list[dict[str, Any]] = list(findings)

    # -- Step 1: EPSS Scoring ------------------------------------------------
    remaining, step_meta = _step_epss(remaining, config, target_path)
    if step_meta:
        metadata["epss"] = step_meta

    # -- Step 2: Fix Version Tracking ----------------------------------------
    remaining, step_meta = _step_fix_versions(remaining, config)
    if step_meta:
        metadata["fix_versions"] = step_meta

    # -- Step 3: VEX Filtering -----------------------------------------------
    remaining, suppressed_by_vex, step_meta = _step_vex(remaining, config, target_path)
    if step_meta:
        metadata["vex"] = step_meta

    # -- Step 4: Vulnerability Deduplication ----------------------------------
    remaining, step_meta = _step_dedup(remaining, config)
    if step_meta:
        metadata["deduplication"] = step_meta

    # -- Step 5: Compliance Mapping -------------------------------------------
    remaining, step_meta = _step_compliance(remaining, config, target_path)
    if step_meta:
        metadata["compliance"] = step_meta

    # -- Step 6: Advanced Suppression -----------------------------------------
    remaining, step_meta = _step_suppression(
        remaining,
        config,
        target_path,
        suppressed_by_vex,
    )
    if step_meta:
        metadata["suppression"] = step_meta

    return remaining, metadata


# ---------------------------------------------------------------------------
# Individual enrichment steps (private)
# ---------------------------------------------------------------------------


def _step_epss(
    findings: list[dict[str, Any]],
    config: dict[str, Any],
    target_path: str,
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Step 1: EPSS scoring."""
    if not _EPSS_OK or not _parse_bool(config.get("enable_epss_scoring", True)):
        return findings, None

    try:
        ttl = int(config.get("epss_cache_ttl_hours", 24))
        scorer = EPSSScorer(
            cache_dir=str(Path(target_path) / ".argus-cache"),
            ttl_hours=ttl,
        )
        findings = scorer.enrich_findings(findings)
        cve_ids = [f.get("cve_id") or f.get("cve", "") for f in findings if f.get("cve_id") or f.get("cve")]
        step_meta: dict[str, Any] = {}
        if cve_ids:
            scores = scorer.fetch_scores(cve_ids)
            step_meta = scorer.get_summary(scores)
        logger.info("EPSS scoring enriched %d findings", len(cve_ids) if cve_ids else 0)
        print(f"   EPSS: enriched {len(cve_ids) if cve_ids else 0} CVE findings")
        return findings, step_meta or None
    except Exception as e:
        logger.warning("EPSS scoring failed (non-fatal): %s", e)
        print(f"   EPSS: skipped ({e})")
        return findings, None


def _step_fix_versions(
    findings: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Step 2: Fix version tracking."""
    if not _FIX_OK or not _parse_bool(config.get("enable_fix_version_tracking", True)):
        return findings, None

    try:
        tracker = FixVersionTracker()
        fix_infos = []
        for finding in findings:
            info = tracker.extract_fix_info(finding)
            if info:
                fix_infos.append(info)
        if fix_infos:
            findings = tracker.enrich_findings(findings, fix_infos)
        step_meta = tracker.get_summary(fix_infos) if fix_infos else None
        logger.info("Fix version tracking: %d fixes found", len(fix_infos))
        print(f"   Fix versions: {len(fix_infos)} upgrade paths identified")
        return findings, step_meta
    except Exception as e:
        logger.warning("Fix version tracking failed (non-fatal): %s", e)
        print(f"   Fix versions: skipped ({e})")
        return findings, None


def _step_vex(
    findings: list[dict[str, Any]],
    config: dict[str, Any],
    target_path: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Step 3: VEX filtering.

    Returns ``(remaining, suppressed_by_vex, metadata)``.
    The *suppressed_by_vex* list is forwarded to Step 6 (suppression)
    so VEX-based auto-suppression rules can be generated.
    """
    suppressed_by_vex: list[dict[str, Any]] = []
    if not _VEX_OK or not _parse_bool(config.get("enable_vex", True)):
        return findings, suppressed_by_vex, None

    try:
        vex_paths_str = config.get("vex_paths", "")
        vex_paths = [p.strip() for p in vex_paths_str.split(",") if p.strip()] if vex_paths_str else None
        auto_dir = config.get("vex_auto_discover_dir", ".argus/vex")
        processor = VEXProcessor(vex_paths=vex_paths, auto_discover_dir=auto_dir)
        statements = processor.load_statements()
        step_meta: dict | None = None
        if statements:
            findings, suppressed_by_vex = processor.filter_findings(findings, statements)
            step_meta = VEXProcessor.get_summary(statements)
            logger.info(
                "VEX: %d suppressed, %d remaining",
                len(suppressed_by_vex),
                len(findings),
            )
        print(f"   VEX: {len(suppressed_by_vex)} suppressed, {len(statements) if statements else 0} statements loaded")
        return findings, suppressed_by_vex, step_meta
    except Exception as e:
        logger.warning("VEX processing failed (non-fatal): %s", e)
        print(f"   VEX: skipped ({e})")
        return findings, suppressed_by_vex, None


def _step_dedup(
    findings: list,
    config: dict,
) -> tuple[list, dict | None]:
    """Step 4: Vulnerability deduplication."""
    if not _DEDUP_OK or not _parse_bool(config.get("enable_vuln_deduplication", True)):
        return findings, None

    try:
        strategy = config.get("deduplication_strategy", "auto")
        deduplicator = VulnDeduplicator(strategy=strategy)
        before_count = len(findings)
        result = deduplicator.deduplicate(findings)
        findings = result.kept_findings
        step_meta = VulnDeduplicator.get_summary(result)
        removed = before_count - len(findings)
        logger.info(
            "Deduplication: %d removed, %d remaining",
            removed,
            len(findings),
        )
        print(f"   Dedup: {removed} duplicates removed ({before_count} -> {len(findings)})")
        return findings, step_meta
    except Exception as e:
        logger.warning("Deduplication failed (non-fatal): %s", e)
        print(f"   Dedup: skipped ({e})")
        return findings, None


def _step_compliance(
    findings: list,
    config: dict,
    target_path: str,
) -> tuple[list, dict | None]:
    """Step 5: Compliance mapping."""
    if not _COMPLIANCE_OK or not _parse_bool(
        config.get("enable_compliance_mapping", True),
    ):
        return findings, None

    try:
        frameworks_str = config.get("compliance_frameworks", "")
        frameworks = [f.strip() for f in frameworks_str.split(",") if f.strip()] if frameworks_str else None
        mapper = ComplianceMapper(frameworks=frameworks)
        reports = mapper.generate_all_reports(findings)
        step_meta: dict | None = None
        if reports:
            step_meta = mapper.get_summary(reports)
            # Save compliance report markdown
            compliance_dir = Path(target_path) / ".argus/reviews"
            compliance_dir.mkdir(parents=True, exist_ok=True)
            compliance_md = mapper.render_all_markdown(reports)
            compliance_file = compliance_dir / "compliance-report.md"
            with open(compliance_file, "w") as fh:
                fh.write(compliance_md)
            logger.info(
                "Compliance mapping: %d reports generated",
                len(reports),
            )
            print(f"   Compliance: {len(reports)} framework reports -> {compliance_file}")
        return findings, step_meta
    except Exception as e:
        logger.warning("Compliance mapping failed (non-fatal): %s", e)
        print(f"   Compliance: skipped ({e})")
        return findings, None


def _step_suppression(
    findings: list,
    config: dict,
    target_path: str,
    suppressed_by_vex: list,
) -> tuple[list, dict | None]:
    """Step 6: Advanced suppression (.argus-ignore.yml + VEX + EPSS rules)."""
    if not _SUPPRESSION_OK or not _parse_bool(
        config.get("enable_advanced_suppression", True),
    ):
        return findings, None

    try:
        expire_days = int(config.get("suppression_auto_expire_days", 90))
        manager = AdvancedSuppressionManager(
            config_path=str(Path(target_path) / ".argus-ignore.yml"),
            auto_expire_days=expire_days,
        )
        rules = manager.load_rules()

        # Add VEX-based suppression rules if VEX data available
        if suppressed_by_vex:
            vex_rules = manager.add_vex_rules(
                [
                    {
                        "cve_id": f.get("cve_id") or f.get("cve", ""),
                        "reason": f.get(
                            "vex_justification",
                            "VEX: not affected",
                        ),
                    }
                    for f in suppressed_by_vex
                    if f.get("cve_id") or f.get("cve")
                ]
            )
            rules.extend(vex_rules)

        # Add EPSS auto-suppress for very low probability findings
        epss_rules = manager.add_epss_auto_suppress(findings, threshold=0.01)
        rules.extend(epss_rules)

        suppressed_by_rules: list = []
        if rules:
            findings, suppressed_by_rules = manager.filter_findings(findings, rules)

        # Warn about expired rules
        expired = manager.get_expired_rules(rules)
        if expired:
            logger.warning("%d suppression rules have expired", len(expired))
            print(f"   Suppression: {len(expired)} expired rules (review recommended)")

        step_meta = {
            "rules_loaded": len(rules),
            "suppressed": len(suppressed_by_rules),
            "expired_rules": len(expired),
        }
        logger.info(
            "Suppression: %d suppressed by rules",
            len(suppressed_by_rules),
        )
        print(f"   Suppression: {len(suppressed_by_rules)} findings suppressed by {len(rules)} rules")
        return findings, step_meta
    except Exception as e:
        logger.warning("Advanced suppression failed (non-fatal): %s", e)
        print(f"   Suppression: skipped ({e})")
        return findings, None
