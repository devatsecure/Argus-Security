#!/usr/bin/env python3
"""
Fix Verification Loop for Argus
Verify that remediation fixes actually resolve vulnerabilities.

After remediation_engine.py generates fix suggestions, this module validates
them by running the fixed code through sandbox validation and static analysis.
Currently fixes are generated but never validated -- this module closes the loop.

Three verification strategies:
1. Sandbox: Apply fix, re-run exploit in Docker container
2. Static analysis: Check if fix addresses the known CWE pattern
3. Pattern match: Verify the fix removes the vulnerable pattern

Usage:
    from fix_verifier import FixVerifier, FixVerificationResult

    verifier = FixVerifier()
    result = verifier.verify_fix(finding, suggestion)

    # Batch verification
    results = verifier.verify_batch(findings, suggestions)

    # Pipeline stage (automatic via PipelineOrchestrator)
    stage = FixVerificationStage()
    stage.execute(ctx)
"""

import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure scripts dir is importable
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from pipeline.base_stage import BaseStage
from pipeline.protocol import PipelineContext

logger = logging.getLogger(__name__)


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class FixVerificationResult:
    """Result of verifying a remediation fix.

    Attributes:
        finding_id: Unique identifier for the finding.
        fix_applied: Was the fix applied successfully?
        original_vulnerable: Was the original code confirmed vulnerable?
        fix_resolves: Does the fix resolve the vulnerability?
        verification_method: "sandbox", "static_analysis", or "pattern_match".
        confidence: 0.0-1.0 confidence score.
        details: Human-readable explanation.
        original_result: Result from testing original code
            (e.g. "exploitable", "not_exploitable").
        fixed_result: Result from testing fixed code
            (e.g. "exploitable", "not_exploitable").
        execution_time_ms: Time taken for verification in milliseconds.
        error: Error message if verification failed.
    """

    finding_id: str
    fix_applied: bool
    original_vulnerable: bool
    fix_resolves: bool
    verification_method: str  # "sandbox", "static_analysis", "pattern_match"
    confidence: float  # 0.0-1.0
    details: str
    original_result: Optional[str] = None  # "exploitable", "not_exploitable", etc.
    fixed_result: Optional[str] = None  # "exploitable", "not_exploitable", etc.
    execution_time_ms: int = 0
    error: Optional[str] = None


# ============================================================================
# FixVerifier
# ============================================================================


class FixVerifier:
    """Verify that remediation fixes actually resolve vulnerabilities.

    Three verification strategies:
    1. Sandbox: Apply fix, re-run exploit in Docker container
    2. Static analysis: Check if fix addresses the known CWE pattern
    3. Pattern match: Verify the fix removes the vulnerable pattern
    """

    # CWE patterns for static analysis verification.
    # Each entry maps a CWE ID to safe patterns (should appear in fixed code)
    # and vulnerable patterns (should be absent from fixed code).
    CWE_PATTERNS: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "name": "SQL Injection",
            "safe_patterns": [
                r"\?",                                  # Parameterized query placeholder
                r"%s",                                  # Format-style placeholder with params
                r":\w+",                                # Named parameter
                r"parameterized",
                r"prepared_statement",
                r"\.execute\([^,]+,\s*[\(\[]",          # execute(query, params)
            ],
            "vuln_patterns": [
                r"f['\"].*SELECT",                      # f-string SQL
                r"\.format\(.*SELECT",                  # .format() SQL
                r"\+\s*['\"].*SELECT",                  # String concatenation SQL
            ],
        },
        "CWE-79": {
            "name": "XSS",
            "safe_patterns": [
                r"escape\(",
                r"html\.escape\(",
                r"markupsafe",
                r"sanitize",
                r"textContent",
                r"bleach\.clean",
                r"DOMPurify",
            ],
            "vuln_patterns": [
                r"innerHTML",
                r"dangerouslySetInnerHTML",
                r"document\.write",
            ],
        },
        "CWE-78": {
            "name": "Command Injection",
            "safe_patterns": [
                r"subprocess\.run\(\s*\[",              # List-form args
                r"subprocess\.call\(\s*\[",
                r"subprocess\.Popen\(\s*\[",
                r"shlex\.quote",
                r"shlex\.split",
            ],
            "vuln_patterns": [
                r"shell\s*=\s*True",
                r"os\.system\(",
                r"os\.popen\(",
            ],
        },
        "CWE-22": {
            "name": "Path Traversal",
            "safe_patterns": [
                r"os\.path\.abspath",
                r"os\.path\.realpath",
                r"Path\.resolve\(\)",
                r"\.resolve\(\)",
                r"os\.path\.basename",
                r"secure_filename",
                r"\.startswith\(",                      # Path prefix validation
            ],
            "vuln_patterns": [
                r"\.\./",
                r"\.\.\\\\",
            ],
        },
        "CWE-798": {
            "name": "Hardcoded Credentials",
            "safe_patterns": [
                r"os\.environ",
                r"os\.getenv",
                r"env\(",
                r"process\.env\.",
                r"vault",
                r"secrets_manager",
                r"keyring",
            ],
            "vuln_patterns": [
                r"(password|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]{8,}['\"]",
            ],
        },
    }

    # Mapping from vulnerability type strings to CWE identifiers.
    _VULN_TYPE_TO_CWE: Dict[str, str] = {
        "sql_injection": "CWE-89",
        "sql-injection": "CWE-89",
        "xss": "CWE-79",
        "cross_site_scripting": "CWE-79",
        "command_injection": "CWE-78",
        "cmd_injection": "CWE-78",
        "path_traversal": "CWE-22",
        "directory_traversal": "CWE-22",
        "hard_coded_secrets": "CWE-798",
        "hardcoded_credentials": "CWE-798",
        "hardcoded_secrets": "CWE-798",
    }

    def __init__(self, sandbox_validator: Any = None):
        """Initialize with optional sandbox validator.

        Args:
            sandbox_validator: Optional ``SandboxValidator`` instance.  If not
                provided, sandbox verification will be attempted by creating
                one on demand (requires Docker).
        """
        self._sandbox_validator = sandbox_validator
        self._sandbox_available: Optional[bool] = None  # Lazy check

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_fix(self, finding: dict, suggestion: Any) -> FixVerificationResult:
        """Verify a single fix suggestion.

        Strategy selection:
        1. If sandbox available and finding has exploit code -> sandbox verification
        2. If CWE is known -> static pattern verification
        3. Fallback -> pattern match verification

        Args:
            finding: Finding dict or dataclass with vulnerability details.
            suggestion: ``RemediationSuggestion`` or similar object with fix
                details (must have ``original_code`` and ``fixed_code``).

        Returns:
            ``FixVerificationResult`` with verification outcome.
        """
        start_time = time.time()
        finding_id = self._get_attr(finding, "id", "finding_id", default="unknown")

        try:
            # Extract fix details
            original_code = self._get_attr(suggestion, "original_code", default="")
            fixed_code = self._get_attr(suggestion, "fixed_code", default="")
            cwe_refs = self._get_attr(suggestion, "cwe_references", default=[])
            vuln_type = self._get_attr(suggestion, "vulnerability_type", default="")

            if not fixed_code:
                return FixVerificationResult(
                    finding_id=finding_id,
                    fix_applied=False,
                    original_vulnerable=False,
                    fix_resolves=False,
                    verification_method="none",
                    confidence=0.0,
                    details="No fixed code provided in suggestion.",
                    execution_time_ms=self._elapsed_ms(start_time),
                    error="missing_fixed_code",
                )

            # Strategy 1: Sandbox verification
            exploit_code = self._get_attr(
                finding, "exploit_code", "poc_code", default=None
            )
            if exploit_code and self._get_sandbox_validator() is not None:
                try:
                    result = self._verify_via_sandbox(finding, suggestion)
                    result.execution_time_ms = self._elapsed_ms(start_time)
                    return result
                except Exception as exc:
                    logger.warning(
                        "Sandbox verification failed for %s, falling back: %s",
                        finding_id,
                        exc,
                    )

            # Strategy 2: Static analysis (CWE-based)
            matched_cwe = self._find_matching_cwe(cwe_refs, vuln_type)
            if matched_cwe:
                result = self._verify_via_static(finding, suggestion, matched_cwe)
                result.execution_time_ms = self._elapsed_ms(start_time)
                return result

            # Strategy 3: Pattern match fallback
            result = self._verify_via_pattern(finding, suggestion)
            result.execution_time_ms = self._elapsed_ms(start_time)
            return result

        except Exception as exc:
            logger.error("Fix verification failed for %s: %s", finding_id, exc)
            return FixVerificationResult(
                finding_id=finding_id,
                fix_applied=False,
                original_vulnerable=False,
                fix_resolves=False,
                verification_method="error",
                confidence=0.0,
                details=f"Verification failed: {exc}",
                execution_time_ms=self._elapsed_ms(start_time),
                error=str(exc),
            )

    def verify_batch(
        self, findings: list, suggestions: list
    ) -> list[FixVerificationResult]:
        """Verify a batch of fixes.

        Pairs findings with suggestions by ``finding_id``.  If a suggestion
        cannot be matched to a finding, it is skipped.

        Args:
            findings: List of finding dicts or dataclass objects.
            suggestions: List of ``RemediationSuggestion`` or similar objects.

        Returns:
            List of ``FixVerificationResult`` objects.
        """
        results: list[FixVerificationResult] = []

        # Build suggestion lookup by finding_id
        suggestion_map: Dict[str, Any] = {}
        for suggestion in suggestions:
            sid = self._get_attr(suggestion, "finding_id", default=None)
            if sid:
                suggestion_map[sid] = suggestion

        for finding in findings:
            fid = self._get_attr(finding, "id", "finding_id", default=None)
            if fid and fid in suggestion_map:
                try:
                    result = self.verify_fix(finding, suggestion_map[fid])
                    results.append(result)
                except Exception as exc:
                    logger.error("Batch verification failed for %s: %s", fid, exc)
                    results.append(
                        FixVerificationResult(
                            finding_id=fid,
                            fix_applied=False,
                            original_vulnerable=False,
                            fix_resolves=False,
                            verification_method="error",
                            confidence=0.0,
                            details=f"Batch verification error: {exc}",
                            error=str(exc),
                        )
                    )

        return results

    # ------------------------------------------------------------------
    # Verification strategies
    # ------------------------------------------------------------------

    def _verify_via_sandbox(
        self, finding: Any, suggestion: Any
    ) -> FixVerificationResult:
        """Apply fix, run exploit against both original and fixed code.

        1. Run exploit against original code -> should be exploitable
        2. Apply fix
        3. Run exploit against fixed code -> should NOT be exploitable
        4. If original=exploitable AND fixed=not_exploitable -> fix verified

        Args:
            finding: Finding with ``exploit_code`` / ``poc_code``.
            suggestion: ``RemediationSuggestion`` with ``original_code``
                and ``fixed_code``.

        Returns:
            ``FixVerificationResult``.
        """
        from sandbox_validator import ExploitConfig, ExploitType

        finding_id = self._get_attr(finding, "id", "finding_id", default="unknown")
        exploit_code = self._get_attr(
            finding, "exploit_code", "poc_code", default=""
        )
        original_code = self._get_attr(suggestion, "original_code", default="")
        fixed_code = self._get_attr(suggestion, "fixed_code", default="")
        language = self._get_attr(finding, "language", default="python")
        vuln_type = self._get_attr(
            suggestion, "vulnerability_type", default="custom"
        )

        # Map vulnerability type to ExploitType enum
        exploit_type = self._map_exploit_type(vuln_type)

        validator = self._get_sandbox_validator()

        # Step 1: Test original code with exploit
        original_config = ExploitConfig(
            name=f"verify-original-{finding_id}",
            exploit_type=exploit_type,
            language=language,
            code=self._build_test_code(original_code, exploit_code),
            expected_indicators=["EXPLOIT_SUCCESS", "VULNERABILITY_CONFIRMED"],
            timeout=30,
            metadata={"phase": "original", "finding_id": finding_id},
        )

        original_metrics = validator.validate_exploit(original_config)
        original_result = original_metrics.result
        original_vulnerable = original_result in ("exploitable", "partial")

        # Step 2: Test fixed code with exploit
        fixed_config = ExploitConfig(
            name=f"verify-fixed-{finding_id}",
            exploit_type=exploit_type,
            language=language,
            code=self._build_test_code(fixed_code, exploit_code),
            expected_indicators=["EXPLOIT_SUCCESS", "VULNERABILITY_CONFIRMED"],
            timeout=30,
            metadata={"phase": "fixed", "finding_id": finding_id},
        )

        fixed_metrics = validator.validate_exploit(fixed_config)
        fixed_result = fixed_metrics.result
        fix_resolves = fixed_result in ("not_exploitable",)

        # Determine confidence
        if original_vulnerable and fix_resolves:
            confidence = 0.95
            details = (
                "Sandbox verified: original code is exploitable and "
                "fixed code is not exploitable."
            )
        elif original_vulnerable and not fix_resolves:
            confidence = 0.3
            details = (
                "Fix does NOT resolve vulnerability: original code is "
                "exploitable and fixed code remains exploitable."
            )
        elif not original_vulnerable and fix_resolves:
            confidence = 0.5
            details = (
                "Original code was not confirmed exploitable in sandbox, "
                "but fixed code passes exploit test."
            )
        else:
            confidence = 0.4
            details = (
                "Inconclusive: neither original nor fixed code produced "
                "clear exploit results in sandbox."
            )

        return FixVerificationResult(
            finding_id=finding_id,
            fix_applied=True,
            original_vulnerable=original_vulnerable,
            fix_resolves=original_vulnerable and fix_resolves,
            verification_method="sandbox",
            confidence=confidence,
            details=details,
            original_result=original_result,
            fixed_result=fixed_result,
        )

    def _verify_via_static(
        self, finding: Any, suggestion: Any, cwe_id: str
    ) -> FixVerificationResult:
        """Verify fix addresses the CWE pattern.

        Known CWE patterns to check:
        - CWE-89 (SQL Injection): Check if parameterized queries are used
        - CWE-79 (XSS): Check if output escaping is present
        - CWE-78 (Command Injection): Check if shell=True is removed
        - CWE-22 (Path Traversal): Check if path validation added
        - CWE-798 (Hardcoded Credentials): Check if env var used instead

        Args:
            finding: Finding dict or dataclass.
            suggestion: ``RemediationSuggestion`` with original/fixed code.
            cwe_id: The CWE identifier to check against (e.g. ``"CWE-89"``).

        Returns:
            ``FixVerificationResult``.
        """
        finding_id = self._get_attr(finding, "id", "finding_id", default="unknown")
        original_code = self._get_attr(suggestion, "original_code", default="")
        fixed_code = self._get_attr(suggestion, "fixed_code", default="")

        cwe_config = self.CWE_PATTERNS.get(cwe_id, {})
        safe_patterns = cwe_config.get("safe_patterns", [])
        vuln_patterns = cwe_config.get("vuln_patterns", [])
        cwe_name = cwe_config.get("name", cwe_id)

        # Check if fixed code contains safe patterns
        safe_found: list[str] = []
        for pattern in safe_patterns:
            if re.search(pattern, fixed_code, re.IGNORECASE):
                safe_found.append(pattern)

        # Check if vulnerable patterns are still present in fixed code
        vuln_remaining: list[str] = []
        for pattern in vuln_patterns:
            if re.search(pattern, fixed_code, re.IGNORECASE):
                vuln_remaining.append(pattern)

        # Check if vulnerable patterns were present in original code
        vuln_in_original: list[str] = []
        for pattern in vuln_patterns:
            if re.search(pattern, original_code, re.IGNORECASE):
                vuln_in_original.append(pattern)

        # Determine result
        has_safe_patterns = len(safe_found) > 0
        no_vuln_remaining = len(vuln_remaining) == 0
        had_vuln_originally = len(vuln_in_original) > 0

        if has_safe_patterns and no_vuln_remaining:
            fix_resolves = True
            confidence = 0.85
            details = (
                f"Static analysis confirms fix for {cwe_name} ({cwe_id}): "
                f"safe patterns found ({', '.join(safe_found[:3])}), "
                f"no vulnerable patterns remain."
            )
        elif has_safe_patterns and not no_vuln_remaining:
            fix_resolves = False
            confidence = 0.6
            details = (
                f"Partial fix for {cwe_name} ({cwe_id}): safe patterns "
                f"added but vulnerable patterns still present "
                f"({', '.join(vuln_remaining[:3])})."
            )
        elif no_vuln_remaining and had_vuln_originally:
            fix_resolves = True
            confidence = 0.7
            details = (
                f"Vulnerable patterns for {cwe_name} ({cwe_id}) removed "
                f"from code, but no recognized safe patterns detected."
            )
        else:
            fix_resolves = False
            confidence = 0.4
            details = (
                f"Unable to confirm fix for {cwe_name} ({cwe_id}): "
                f"no safe patterns found and "
                f"{'vulnerable patterns remain' if vuln_remaining else 'no vulnerable patterns matched'}."
            )

        return FixVerificationResult(
            finding_id=finding_id,
            fix_applied=True,
            original_vulnerable=had_vuln_originally,
            fix_resolves=fix_resolves,
            verification_method="static_analysis",
            confidence=confidence,
            details=details,
            original_result="vulnerable" if had_vuln_originally else "unknown",
            fixed_result="safe" if fix_resolves else "potentially_vulnerable",
        )

    def _verify_via_pattern(
        self, finding: Any, suggestion: Any
    ) -> FixVerificationResult:
        """Fallback: Check if vulnerable pattern is absent in fixed code.

        This is the simplest verification strategy: compare original and fixed
        code to determine if the problematic pattern has been removed or changed.

        Args:
            finding: Finding dict or dataclass.
            suggestion: ``RemediationSuggestion`` with original/fixed code.

        Returns:
            ``FixVerificationResult``.
        """
        finding_id = self._get_attr(finding, "id", "finding_id", default="unknown")
        original_code = self._get_attr(suggestion, "original_code", default="")
        fixed_code = self._get_attr(suggestion, "fixed_code", default="")

        if not original_code or not fixed_code:
            return FixVerificationResult(
                finding_id=finding_id,
                fix_applied=False,
                original_vulnerable=False,
                fix_resolves=False,
                verification_method="pattern_match",
                confidence=0.2,
                details="Insufficient code to perform pattern comparison.",
                error="missing_code",
            )

        # Check if the code actually changed
        if original_code.strip() == fixed_code.strip():
            return FixVerificationResult(
                finding_id=finding_id,
                fix_applied=False,
                original_vulnerable=True,
                fix_resolves=False,
                verification_method="pattern_match",
                confidence=0.3,
                details="Fixed code is identical to original code -- no fix applied.",
            )

        # Compare line-by-line to detect meaningful changes
        original_lines = set(
            line.strip() for line in original_code.splitlines() if line.strip()
        )
        fixed_lines = set(
            line.strip() for line in fixed_code.splitlines() if line.strip()
        )

        removed_lines = original_lines - fixed_lines
        added_lines = fixed_lines - original_lines

        has_changes = len(removed_lines) > 0 or len(added_lines) > 0

        if has_changes and len(added_lines) > 0:
            fix_resolves = True
            confidence = 0.5
            details = (
                f"Pattern match: {len(removed_lines)} line(s) removed, "
                f"{len(added_lines)} line(s) added. Code was modified but "
                f"semantic correctness cannot be confirmed without deeper analysis."
            )
        elif has_changes:
            fix_resolves = True
            confidence = 0.4
            details = (
                f"Pattern match: {len(removed_lines)} line(s) removed. "
                f"Vulnerable code appears to have been changed."
            )
        else:
            fix_resolves = False
            confidence = 0.2
            details = (
                "Pattern match inconclusive: no significant code changes detected."
            )

        return FixVerificationResult(
            finding_id=finding_id,
            fix_applied=has_changes,
            original_vulnerable=True,  # Assumed since a fix was suggested
            fix_resolves=fix_resolves,
            verification_method="pattern_match",
            confidence=confidence,
            details=details,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_attr(self, obj: Any, *attrs: str, default: Any = None) -> Any:
        """Get attribute from dict or dataclass, trying multiple names.

        Args:
            obj: Dict or dataclass to read from.
            *attrs: Attribute names to try in order.
            default: Default value if none found.

        Returns:
            First found attribute value or *default*.
        """
        for attr in attrs:
            if isinstance(obj, dict):
                if attr in obj:
                    return obj[attr]
            else:
                val = getattr(obj, attr, None)
                if val is not None:
                    return val
        return default

    def _elapsed_ms(self, start_time: float) -> int:
        """Calculate elapsed time in milliseconds since *start_time*."""
        return int((time.time() - start_time) * 1000)

    def _find_matching_cwe(
        self, cwe_refs: list, vuln_type: str
    ) -> Optional[str]:
        """Find a CWE ID that we have static analysis patterns for.

        Checks *cwe_refs* first (direct match), then falls back to inferring
        the CWE from *vuln_type*.

        Args:
            cwe_refs: List of CWE identifier strings (e.g. ``["CWE-89"]``).
            vuln_type: Vulnerability type string (e.g. ``"sql_injection"``).

        Returns:
            Matching CWE identifier or ``None``.
        """
        # Direct CWE match
        if cwe_refs:
            for cwe in cwe_refs:
                cwe_upper = cwe.upper() if isinstance(cwe, str) else ""
                if cwe_upper in self.CWE_PATTERNS:
                    return cwe_upper

        # Fallback: infer CWE from vulnerability type
        vuln_type_lower = vuln_type.lower().replace("-", "_")
        return self._VULN_TYPE_TO_CWE.get(vuln_type_lower)

    def _map_exploit_type(self, vuln_type: str) -> Any:
        """Map vulnerability type string to ``ExploitType`` enum value.

        Args:
            vuln_type: Vulnerability type string (e.g. ``"sql_injection"``).

        Returns:
            ``ExploitType`` enum member.
        """
        from sandbox_validator import ExploitType

        mapping = {
            "sql_injection": ExploitType.SQL_INJECTION,
            "sql-injection": ExploitType.SQL_INJECTION,
            "xss": ExploitType.XSS,
            "command_injection": ExploitType.COMMAND_INJECTION,
            "cmd_injection": ExploitType.COMMAND_INJECTION,
            "code_injection": ExploitType.CODE_INJECTION,
            "path_traversal": ExploitType.PATH_TRAVERSAL,
            "ssrf": ExploitType.SSRF,
            "deserialization": ExploitType.DESERIALIZATION,
            "xxe": ExploitType.XXE,
        }

        return mapping.get(
            vuln_type.lower().replace("-", "_"), ExploitType.CUSTOM
        )

    def _build_test_code(self, target_code: str, exploit_code: str) -> str:
        """Combine target code and exploit code for sandbox execution.

        Args:
            target_code: The code under test (original or fixed).
            exploit_code: The exploit/PoC code to run against it.

        Returns:
            Combined code string ready for sandbox execution.
        """
        return (
            "# --- Target Code ---\n"
            f"{target_code}\n\n"
            "# --- Exploit Code ---\n"
            f"{exploit_code}\n"
        )

    def _get_sandbox_validator(self) -> Any:
        """Lazily initialize and return sandbox validator.

        Returns:
            ``SandboxValidator`` instance or ``None`` if unavailable.
        """
        if self._sandbox_validator is not None:
            return self._sandbox_validator

        if self._sandbox_available is False:
            return None

        try:
            from sandbox_validator import SandboxValidator

            self._sandbox_validator = SandboxValidator()
            self._sandbox_available = True
            return self._sandbox_validator
        except Exception as exc:
            logger.debug("Sandbox validator not available: %s", exc)
            self._sandbox_available = False
            return None


# ============================================================================
# Module-level helpers for the pipeline stage
# ============================================================================


def _extract_fix(finding: Any) -> Any:
    """Extract fix suggestion from a finding.

    Looks for ``fix_suggestion`` attribute/key or checks if finding is
    marked as ``auto_fixable`` with remediation data attached.

    Args:
        finding: Finding dict or dataclass.

    Returns:
        Fix suggestion object/dict, or ``None`` if not found.
    """
    # Try direct attribute access
    if hasattr(finding, "fix_suggestion"):
        fix = finding.fix_suggestion
        if fix is not None:
            return fix

    # Try dict access
    if isinstance(finding, dict):
        fix = finding.get("fix_suggestion")
        if fix is not None:
            return fix

    # Check auto_fixable flag with remediation data
    if isinstance(finding, dict):
        auto_fixable = finding.get("auto_fixable", False)
        if auto_fixable and finding.get("remediation"):
            return finding["remediation"]
    elif hasattr(finding, "auto_fixable"):
        auto_fixable = getattr(finding, "auto_fixable", False)
        if auto_fixable and hasattr(finding, "remediation"):
            remediation = getattr(finding, "remediation", None)
            if remediation is not None:
                return remediation

    return None


def _apply_verification(finding: Any, result: FixVerificationResult) -> None:
    """Apply verification result to a finding.

    Sets ``fix_confidence`` on the finding based on the verification result.
    If the fix does not resolve the vulnerability the confidence is halved
    to signal lower trust.

    Args:
        finding: Finding dict or dataclass to update.
        result: ``FixVerificationResult`` with confidence score.
    """
    confidence = result.confidence if result.fix_resolves else result.confidence * 0.5

    try:
        if isinstance(finding, dict):
            finding["fix_confidence"] = confidence
            finding["fix_verified"] = result.fix_resolves
            finding["fix_verification_method"] = result.verification_method
        else:
            # Attempt to set attributes on dataclass/object
            try:
                finding.fix_confidence = confidence
            except AttributeError:
                pass
            try:
                finding.fix_verified = result.fix_resolves
            except AttributeError:
                pass
            try:
                finding.fix_verification_method = result.verification_method
            except AttributeError:
                pass
    except (AttributeError, TypeError) as exc:
        logger.debug(
            "Could not set verification attributes on finding: %s", exc
        )


# ============================================================================
# Pipeline Stage
# ============================================================================


class FixVerificationStage(BaseStage):
    """Phase 2.7: Verify remediation fixes resolve vulnerabilities.

    Runs AFTER remediation (Phase 2.5).  For each finding that has a fix
    suggestion, runs verification and updates the finding's ``fix_confidence``.
    """

    name = "phase2_7_fix_verification"
    display_name = "Phase 2.7: Fix Verification"
    phase_number = 2.7
    required_stages = ["phase2_5_remediation"]

    def should_run(self, ctx: PipelineContext) -> bool:
        """Run if fix verification is enabled (default: True)."""
        return ctx.config.get("enable_fix_verification", True)

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        """Verify all findings that have fix suggestions.

        Returns:
            Dict with ``verified`` and ``resolved`` counts.
        """
        verifier = FixVerifier()
        verified = 0
        resolved = 0

        for finding in ctx.findings:
            fix = _extract_fix(finding)
            if fix:
                try:
                    result = verifier.verify_fix(finding, fix)
                    _apply_verification(finding, result)
                    verified += 1
                    if result.fix_resolves:
                        resolved += 1
                except Exception as exc:
                    fid = verifier._get_attr(
                        finding, "id", "finding_id", default="unknown"
                    )
                    logger.warning(
                        "Fix verification failed for %s: %s", fid, exc
                    )

        logger.info(
            "Fix verification complete: %d verified, %d resolved",
            verified,
            resolved,
        )
        return {"verified": verified, "resolved": resolved}
