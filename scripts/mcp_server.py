"""Custom Argus MCP Server.

Exposes Argus Security pipeline capabilities as MCP tools for Claude Code integration.
Uses factory pattern to capture repo context in closure.

Usage:
    from mcp_server import create_argus_mcp_server
    server = create_argus_mcp_server("/path/to/repo", config)
    server.run()

Requires: mcp>=1.0.0 (optional dependency)
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Conditional MCP import
# ---------------------------------------------------------------------------

try:
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Valid severities
# ---------------------------------------------------------------------------

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

# ---------------------------------------------------------------------------
# CWE -> Remediation mapping (subset, mirrors remediation_engine.py)
# ---------------------------------------------------------------------------

CWE_REMEDIATION_MAP: Dict[str, str] = {
    "CWE-78": (
        "Command Injection: Avoid constructing shell commands from user input. "
        "Use subprocess with a list of arguments instead of shell=True. "
        "Apply strict input validation and allowlisting."
    ),
    "CWE-79": (
        "Cross-Site Scripting (XSS): Encode all user-supplied data before "
        "rendering in HTML. Use framework auto-escaping. Apply Content-Security-Policy headers."
    ),
    "CWE-89": (
        "SQL Injection: Use parameterized queries or prepared statements. "
        "Never concatenate user input into SQL strings. Use an ORM where possible."
    ),
    "CWE-90": (
        "LDAP Injection: Sanitize special characters in LDAP queries. "
        "Use framework-provided LDAP escaping utilities."
    ),
    "CWE-94": (
        "Code Injection: Never pass user input to eval(), exec(), or similar. "
        "Use safe alternatives and strict input validation."
    ),
    "CWE-22": (
        "Path Traversal: Validate and canonicalize file paths. "
        "Use allowlists for permitted directories. Reject paths containing '..'."
    ),
    "CWE-327": (
        "Broken Cryptography: Replace weak algorithms (MD5, SHA1, DES) with "
        "strong ones (SHA-256+, AES-256). Use well-tested crypto libraries."
    ),
    "CWE-352": (
        "CSRF: Implement anti-CSRF tokens on all state-changing requests. "
        "Use SameSite cookie attributes."
    ),
    "CWE-434": (
        "Unrestricted File Upload: Validate file types, enforce size limits, "
        "store uploads outside the web root, and scan for malware."
    ),
    "CWE-502": (
        "Insecure Deserialization: Avoid deserializing untrusted data. "
        "Use safe serialization formats (JSON). Validate and sanitize input."
    ),
    "CWE-601": (
        "Open Redirect: Validate redirect URLs against an allowlist. "
        "Never redirect to user-supplied URLs without validation."
    ),
    "CWE-611": (
        "XXE: Disable external entity processing in XML parsers. "
        "Use defusedxml or equivalent safe parsing libraries."
    ),
    "CWE-798": (
        "Hard-coded Credentials: Remove secrets from source code. "
        "Use environment variables, vaults, or secret managers."
    ),
    "CWE-918": (
        "SSRF: Validate and allowlist target URLs. Block requests to internal "
        "networks and metadata endpoints. Use a proxy for outbound requests."
    ),
}

# ---------------------------------------------------------------------------
# Default policy gate rules per stage
# ---------------------------------------------------------------------------

DEFAULT_GATE_RULES: Dict[str, Dict[str, Any]] = {
    "pr": {
        "block_severities": ["critical"],
        "max_high": 5,
        "require_no_secrets": True,
        "description": "PR gate: blocks on critical findings or verified secrets",
    },
    "release": {
        "block_severities": ["critical", "high"],
        "max_high": 0,
        "require_no_secrets": True,
        "description": "Release gate: blocks on critical or high findings",
    },
    "deploy": {
        "block_severities": ["critical", "high"],
        "max_high": 0,
        "require_no_secrets": True,
        "description": "Deploy gate: blocks on critical or high findings",
    },
}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A security finding to be stored."""

    severity: str  # critical, high, medium, low, info
    title: str
    file_path: str
    line: int
    description: str
    cwe: str = ""
    timestamp: str = ""
    finding_id: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.finding_id:
            self.finding_id = f"ARGUS-{uuid.uuid4().hex[:8].upper()}"


# ---------------------------------------------------------------------------
# Findings store
# ---------------------------------------------------------------------------


class FindingsStore:
    """In-memory findings store with persistence."""

    def __init__(self, output_dir: str) -> None:
        self._findings: List[Finding] = []
        self._output_dir = output_dir

    @property
    def output_dir(self) -> str:
        return self._output_dir

    def add(self, finding: Finding) -> str:
        """Add a finding and return its ID."""
        self._findings.append(finding)
        self.save_to_disk()
        return finding.finding_id

    def get_all(self) -> List[Finding]:
        """Return all findings."""
        return list(self._findings)

    def get_by_severity(self, severity: str) -> List[Finding]:
        """Filter findings by severity."""
        severity_lower = severity.lower()
        return [f for f in self._findings if f.severity.lower() == severity_lower]

    def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Look up a single finding by its ID."""
        for f in self._findings:
            if f.finding_id == finding_id:
                return f
        return None

    def summary(self) -> Dict[str, int]:
        """Return a count of findings by severity."""
        counts: Dict[str, int] = {s: 0 for s in VALID_SEVERITIES}
        for f in self._findings:
            key = f.severity.lower()
            counts[key] = counts.get(key, 0) + 1
        counts["total"] = len(self._findings)
        return counts

    def save_to_disk(self) -> str:
        """Save findings to JSON file, return path."""
        os.makedirs(self._output_dir, exist_ok=True)
        output_path = os.path.join(self._output_dir, "findings.json")
        data = [asdict(f) for f in self._findings]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return output_path

    def clear(self) -> None:
        """Remove all findings from the store."""
        self._findings.clear()


# ---------------------------------------------------------------------------
# Policy gate evaluation (standalone, no OPA dependency)
# ---------------------------------------------------------------------------


def evaluate_policy_gate(
    stage: str,
    findings: List[Dict[str, Any]],
    custom_rules: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate findings against policy gate rules for *stage*.

    Parameters
    ----------
    stage:
        One of "pr", "release", "deploy".
    findings:
        List of finding dicts, each with at least a ``severity`` key.
    custom_rules:
        Optional overrides for the default gate rules.

    Returns
    -------
    dict with keys: passed (bool), stage, reasons (list[str]), summary.
    """
    rules = DEFAULT_GATE_RULES.get(stage)
    if rules is None:
        return {
            "passed": False,
            "stage": stage,
            "reasons": [f"Unknown stage '{stage}'. Valid stages: {', '.join(DEFAULT_GATE_RULES)}"],
            "summary": {},
        }

    if custom_rules:
        rules = {**rules, **custom_rules}

    block_severities = {s.lower() for s in rules.get("block_severities", [])}
    max_high = rules.get("max_high", 5)

    reasons: List[str] = []
    severity_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Check blocking severities
    for sev in block_severities:
        count = severity_counts.get(sev, 0)
        if count > 0:
            reasons.append(f"BLOCKED: {count} {sev} finding(s) present")

    # Check high-severity cap
    high_count = severity_counts.get("high", 0)
    if high_count > max_high:
        reasons.append(
            f"BLOCKED: {high_count} high finding(s) exceed limit of {max_high}"
        )

    passed = len(reasons) == 0
    return {
        "passed": passed,
        "stage": stage,
        "reasons": reasons if reasons else ["All policy checks passed"],
        "summary": severity_counts,
    }


# ---------------------------------------------------------------------------
# Remediation lookup
# ---------------------------------------------------------------------------


def get_remediation(finding: Finding) -> Dict[str, Any]:
    """Generate a remediation suggestion for a finding based on its CWE.

    Returns a dict with remediation details.
    """
    cwe = finding.cwe.strip().upper() if finding.cwe else ""
    advice = CWE_REMEDIATION_MAP.get(cwe, "")

    if not advice and cwe:
        advice = (
            f"No specific remediation template for {cwe}. "
            "Review the finding details and consult the CWE database at "
            f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
        )
    elif not advice:
        advice = (
            "No CWE specified for this finding. Review the description and "
            "apply secure coding practices appropriate to the vulnerability type."
        )

    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity,
        "cwe": cwe,
        "remediation": advice,
        "references": [
            f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
        ]
        if cwe
        else [],
    }


# ---------------------------------------------------------------------------
# Factory: create MCP server with repo context in closure
# ---------------------------------------------------------------------------


def create_argus_mcp_server(
    repo_path: str, config: Optional[Dict[str, Any]] = None
) -> Any:
    """Factory creates MCP server with repo context in closure.

    Returns None if MCP is not available.

    Parameters
    ----------
    repo_path:
        Absolute path to the repository to scan.
    config:
        Optional Argus configuration dict (from config_loader).

    Returns
    -------
    mcp.server.Server or None
        The configured MCP server, or None if MCP is not installed.
    """
    if not MCP_AVAILABLE:
        logger.warning(
            "MCP package not installed. Install with: pip install 'mcp>=1.0.0'"
        )
        return None

    config = config or {}
    findings_dir = os.path.join(repo_path, ".argus", "findings")
    store = FindingsStore(findings_dir)
    server = Server("argus-security")

    # -- Tool: save_finding ------------------------------------------------

    @server.tool("save_finding")
    async def save_finding(
        severity: str,
        title: str,
        file_path: str,
        line: int,
        description: str,
        cwe: str = "",
    ) -> str:
        """Save a security finding to the Argus findings store.

        Parameters:
            severity: One of critical, high, medium, low, info
            title: Short title for the finding
            file_path: Path to the affected file (relative to repo root)
            line: Line number where the issue was found
            description: Detailed description of the finding
            cwe: Optional CWE identifier (e.g. CWE-79)

        Returns:
            Confirmation message with the assigned finding ID.
        """
        sev = severity.lower().strip()
        if sev not in VALID_SEVERITIES:
            return json.dumps(
                {
                    "error": f"Invalid severity '{severity}'. Must be one of: "
                    f"{', '.join(sorted(VALID_SEVERITIES))}"
                }
            )

        finding = Finding(
            severity=sev,
            title=title,
            file_path=file_path,
            line=line,
            description=description,
            cwe=cwe,
        )
        finding_id = store.add(finding)
        return json.dumps(
            {
                "status": "saved",
                "finding_id": finding_id,
                "severity": sev,
                "title": title,
                "message": f"Finding {finding_id} saved successfully.",
            }
        )

    # -- Tool: get_scan_status ---------------------------------------------

    @server.tool("get_scan_status")
    async def get_scan_status() -> str:
        """Get current scan status and metrics.

        Returns:
            JSON with finding counts by severity and total.
        """
        summary = store.summary()
        return json.dumps(
            {
                "status": "ok",
                "repo_path": repo_path,
                "findings": summary,
            }
        )

    # -- Tool: check_policy_gate -------------------------------------------

    @server.tool("check_policy_gate")
    async def check_policy_gate(stage: str, findings_json: str) -> str:
        """Check if findings pass the policy gate for a given stage.

        Parameters:
            stage: Gate stage - one of 'pr', 'release', 'deploy'
            findings_json: JSON array of finding objects with at least a 'severity' key

        Returns:
            JSON with pass/fail result and reasons.
        """
        try:
            findings_list = json.loads(findings_json)
        except (json.JSONDecodeError, TypeError) as exc:
            return json.dumps(
                {"error": f"Invalid findings_json: {exc}"}
            )

        if not isinstance(findings_list, list):
            return json.dumps(
                {"error": "findings_json must be a JSON array"}
            )

        result = evaluate_policy_gate(stage, findings_list)
        return json.dumps(result)

    # -- Tool: trigger_remediation -----------------------------------------

    @server.tool("trigger_remediation")
    async def trigger_remediation(finding_id: str) -> str:
        """Generate remediation suggestion for a specific finding.

        Parameters:
            finding_id: The ID of the finding (e.g. ARGUS-A1B2C3D4)

        Returns:
            JSON with remediation advice, CWE details, and references.
        """
        finding = store.get_by_id(finding_id)
        if finding is None:
            return json.dumps(
                {
                    "error": f"Finding '{finding_id}' not found. "
                    f"Store contains {len(store.get_all())} finding(s)."
                }
            )

        result = get_remediation(finding)
        return json.dumps(result)

    return server
