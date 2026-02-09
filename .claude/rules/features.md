---
description: Advanced feature modules and their configuration toggles
globs: ["scripts/error_classifier.py", "scripts/audit_trail.py", "scripts/phase_gate.py", "scripts/mcp_server.py", "scripts/dast_auth_config.py", "scripts/temporal_orchestrator.py", "scripts/license_risk_scorer.py", "scripts/epss_scorer.py", "scripts/fix_version_tracker.py", "scripts/vex_processor.py", "scripts/vuln_deduplicator.py", "scripts/advanced_suppression.py", "scripts/compliance_mapper.py"]
---

# Advanced Features

## Smart Retry & Error Classification (`scripts/error_classifier.py`)
Classified retry strategies: billing (60s+), rate_limit (30s+), auth/config (fail immediately), transient (exponential backoff), validation (max 3). Toggle: `enable_smart_retry=True`

## Per-Agent Audit Trail (`scripts/audit_trail.py`)
Atomic session.json writes, append-only per-agent logs, phase-level cost/duration aggregation. Toggle: `enable_audit_trail=True`

## Phase Gating (`scripts/phase_gate.py`)
Schema validation for all 6 phases, strict mode (stop) vs lenient (warn). Toggle: `enable_phase_gating=True`, `phase_gate_strict=False`

## MCP Server (`scripts/mcp_server.py`)
Tools: save_finding, get_scan_status, check_policy_gate, trigger_remediation. Toggle: `enable_mcp_server=False`

## Config-Driven DAST Auth (`scripts/dast_auth_config.py`)
Login types: form, SSO, API, basic, bearer. RFC 6238 TOTP, variable substitution, injection blocking.

## Temporal Orchestration (`scripts/temporal_orchestrator.py`)
Crash recovery via activities, env-specific retry policies. Toggle: `enable_temporal=False`

## License Risk Scoring (`scripts/license_risk_scorer.py`)
5-tier SPDX classification (Forbidden→Critical, Restricted→High, Reciprocal→Medium, Notice→Low, Unencumbered→None). 32 identifiers. Toggle: `enable_license_risk_scoring=True`

## EPSS Scoring (`scripts/epss_scorer.py`)
FIRST.org API batch lookups (100/batch), 24h cache, risk categories: critical >0.5, high >0.2, medium >0.05. Toggle: `enable_epss_scoring=True`

## Fix Version Tracking (`scripts/fix_version_tracker.py`)
Semver upgrade detection (PATCH/MINOR/MAJOR), priority by effort. Toggle: `enable_fix_version_tracking=True`

## VEX Support (`scripts/vex_processor.py`)
OpenVEX, CycloneDX VEX, CSAF formats. Auto-discovers in `.argus/vex/`, matches via CVE+PURL. Toggle: `enable_vex=True`

## Vulnerability Deduplication (`scripts/vuln_deduplicator.py`)
Multi-key: {VulnID, PkgName, Version, Path}. Cross-scanner merge. Strategies: auto/strict/standard/relaxed. Toggle: `enable_vuln_deduplication=True`

## Advanced Suppression (`scripts/advanced_suppression.py`)
`.argus-ignore.yml`: CVE, rule_id, PURL (wildcards), path glob, CWE, severity match types. Time-based expiration, VEX+EPSS integration. Toggle: `enable_advanced_suppression=True`

## Compliance Mapping (`scripts/compliance_mapper.py`)
NIST 800-53, PCI DSS 4.0, OWASP Top 10, SOC 2, CIS K8s, ISO 27001. CWE-based mapping + category fallback. Toggle: `enable_compliance_mapping=True`
