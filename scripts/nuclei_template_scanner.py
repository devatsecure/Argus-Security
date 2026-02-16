#!/usr/bin/env python3
"""
Nuclei Template Scanner for Argus Security Pipeline.

Provides two scanning modes:
1. Live DAST mode  -- runs the ``nuclei`` CLI binary against a live URL.
2. Source-aware mode -- statically inspects source code for patterns that
   Nuclei DAST templates would catch at runtime (CSRF, open redirect,
   missing security headers, brute-force susceptibility, weak sessions).

Findings are emitted in a dict format directly compatible with
``HybridFinding`` so that upstream consumers (hybrid_analyzer, reporting)
can ingest them without conversion.

The module degrades gracefully when the ``nuclei`` binary is not
installed: source-aware scanning still works, and ``scan_live`` raises a
clear ``RuntimeError``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
from pathlib import Path

__all__ = ["NucleiTemplateScanner"]

logger = logging.getLogger(__name__)

# File extensions eligible for source-aware scanning.
_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".php", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".rs"}
)

# ---------------------------------------------------------------------------
# CWE / OWASP constants
# ---------------------------------------------------------------------------
_CWE_CSRF = "CWE-352"
_CWE_OPEN_REDIRECT = "CWE-601"
_CWE_MISSING_HEADERS = "CWE-693"
_CWE_BRUTE_FORCE = "CWE-307"
_CWE_WEAK_SESSION = "CWE-384"

_OWASP_CSRF = "A5:2017-Broken Access Control"
_OWASP_OPEN_REDIRECT = "A1:2017-Injection"
_OWASP_MISSING_HEADERS = "A6:2017-Security Misconfiguration"
_OWASP_BRUTE_FORCE = "A2:2017-Broken Authentication"
_OWASP_WEAK_SESSION = "A2:2017-Broken Authentication"

# ---------------------------------------------------------------------------
# Regex helpers compiled once at module load
# ---------------------------------------------------------------------------

# CSRF detection patterns
_RE_HTML_FORM = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_RE_CSRF_TOKEN = re.compile(
    r"csrf|_token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|xsrf",
    re.IGNORECASE,
)
_RE_STATE_CHANGE_GET = re.compile(
    r"""
    (?:                         # PHP / generic
        \$_GET\s*\[.*(?:delete|remove|update|create|modify|edit|drop|destroy|reset|revoke)
    |   (?:app|router)\s*\.\s*get\s*\(\s*['"].*(?:delete|remove|update|create|modify|edit|drop|destroy|reset|revoke)  # Express / Flask
    |   @(?:GetMapping|RequestMapping)\s*\(.*(?:delete|remove|update|create|modify|edit|drop|destroy|reset|revoke)     # Spring
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Open redirect patterns
_RE_REDIRECT_PARAM = re.compile(
    r"""
    (?:
        redirect\s*\(\s*(?:request\.(?:GET|POST|params)|params|req\.(?:query|params|body))  # framework redirect with user input
    |   header\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$_(?:GET|POST|REQUEST)                   # PHP header("Location: " . $_GET[...])
    |   Location\s*[=:]\s*(?:request\.(?:GET|POST|params)|params|req\.(?:query|params|body)) # Response header from user input
    |   res\.redirect\s*\(\s*req\.(?:query|params|body)                                     # Express res.redirect(req.query...)
    |   http\.Redirect\s*\([^,]+,\s*[^,]+,\s*r\.(?:URL|Form)                               # Go http.Redirect with user input
    |   redirect_to\s*\(\s*params                                                           # Rails redirect_to params[...]
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_RE_REDIRECT_WHITELIST = re.compile(
    r"(?:allowed_hosts|whitelist|safelist|valid_redirect|ALLOWED_REDIRECT|is_safe_url|url_has_allowed_host_and_scheme)",
    re.IGNORECASE,
)

# Auth / login endpoint patterns
_RE_AUTH_ENDPOINT = re.compile(
    r"""
    (?:
        (?:app|router)\s*\.\s*post\s*\(\s*['"]/(?:login|signin|sign-in|auth|authenticate|token|session|register|signup|sign-up)  # Express / Flask
    |   @(?:PostMapping|RequestMapping)\s*\(\s*['"].*(?:login|signin|auth|token|session|register)                                 # Spring
    |   def\s+(?:login|signin|authenticate|create_session|sign_in|log_in)\s*\(                                                   # Python function
    |   \$_POST\s*\[.*(?:password|passwd|login|signin)                                                                            # PHP
    |   func\s+(?:Login|SignIn|Authenticate|HandleAuth)\s*\(                                                                      # Go
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_RE_RATE_LIMIT = re.compile(
    r"(?:rate_limit|rateLimit|RateLimiter|throttle|Throttle|slowDown|slow_down|limiter|@rate_limit|@throttle|express-rate-limit|django-ratelimit|rack-attack)",
    re.IGNORECASE,
)

# Security header patterns
_RE_RESPONSE_GENERATION = re.compile(
    r"""
    (?:
        (?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(  # Express / Flask route
    |   @app\.(?:route|before_request|after_request)                       # Flask decorator
    |   def\s+(?:dispatch|get_response|process_response)\s*\(             # Django middleware
    |   http\.Handle(?:Func)?\s*\(                                         # Go HTTP handler
    |   class\s+\w+(?:View|Controller|Handler)\b                          # Class-based views
    |   header\s*\(\s*['"]                                                 # PHP header()
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]
_RE_SECURITY_HEADER_SET = re.compile(
    "|".join(re.escape(h) for h in _SECURITY_HEADERS),
    re.IGNORECASE,
)

# Weak session patterns
_RE_WEAK_SESSION = re.compile(
    r"""
    (?:
        session_id\s*=\s*(?:str\(|int\(|random\.randint|uuid\.uuid1)       # predictable session IDs
    |   \.set_cookie\s*\([^)]*(?:httponly\s*=\s*False|secure\s*=\s*False)   # insecure cookie flags
    |   Set-Cookie[^;]*(?<!Secure)(?<!HttpOnly);\s*$                        # raw Set-Cookie without flags
    |   SESSION_COOKIE_SECURE\s*=\s*False                                   # Django setting
    |   SESSION_COOKIE_HTTPONLY\s*=\s*False                                 # Django setting
    |   cookie\s*\(\s*['"][^'"]+['"]\s*,[^)]*(?:httpOnly\s*:\s*false|secure\s*:\s*false)  # Express cookie
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _make_finding_id(category: str, file_path: str, line_number: int) -> str:
    """Deterministic finding ID from category + location."""
    key = f"nuclei-template:{category}:{file_path}:{line_number}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class NucleiTemplateScanner:
    """Nuclei-based scanner with live DAST and source-aware analysis modes.

    Covers DVWA-style findings:
    - CSRF (missing tokens on state-changing endpoints)
    - Open Redirect (unvalidated redirect URLs)
    - Missing Security Headers (CSP, HSTS, X-Frame-Options, etc.)
    - Brute Force susceptibility (no rate limiting on auth endpoints)
    - Weak Session Management (predictable tokens, missing cookie flags)
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_dir: str | None = None,
    ) -> None:
        """Initialise the scanner.

        Args:
            nuclei_path: Path to the ``nuclei`` CLI binary.  Defaults to
                ``"nuclei"`` (looked up on ``$PATH``).
            templates_dir: Optional path to a custom Nuclei templates
                directory.  When ``None`` the built-in templates are used.
        """
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir
        self._nuclei_available: bool | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_live(
        self,
        target_url: str,
        severity_filter: str = "medium,high,critical",
        tags: list[str] | None = None,
        timeout: int = 300,
    ) -> list[dict]:
        """Run Nuclei against a live URL.

        Args:
            target_url: The target URL to scan (e.g. ``https://example.com``).
            severity_filter: Comma-separated severity levels to include.
            tags: Optional list of Nuclei template tags to filter on.
            timeout: Maximum scan duration in seconds.

        Returns:
            A list of finding dicts compatible with ``HybridFinding``.

        Raises:
            RuntimeError: If the ``nuclei`` binary is not available.
        """
        if not self._is_nuclei_installed():
            raise RuntimeError(
                "Nuclei binary not found. Install Nuclei or provide the correct path via the nuclei_path parameter."
            )

        cmd = self._build_live_command(target_url, severity_filter, tags)
        logger.info("Starting Nuclei live scan against %s", target_url)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise RuntimeError(f"Nuclei binary not found at '{self.nuclei_path}'. Ensure it is installed and on $PATH.")
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out after %d seconds", timeout)
            raise RuntimeError(f"Nuclei scan timed out after {timeout}s")
        except Exception as exc:
            logger.error("Nuclei scan failed: %s", exc)
            raise RuntimeError(f"Nuclei scan failed: {exc}") from exc

        if result.returncode not in (0, 1):
            logger.error(
                "Nuclei exited with code %d: %s",
                result.returncode,
                result.stderr,
            )
            raise RuntimeError(f"Nuclei exited with code {result.returncode}: {result.stderr}")

        output_lines = [line for line in result.stdout.splitlines() if line.strip()]
        findings = self._parse_nuclei_output(output_lines)
        logger.info("Nuclei live scan complete: %d findings", len(findings))
        return findings

    def scan_source(self, target_path: str) -> list[dict]:
        """Source-code-aware analysis.

        Walks the *target_path* directory (or analyses a single file),
        reads eligible source files, and runs pattern detectors for CSRF,
        open redirect, rate-limit gaps, security-header gaps, and weak
        session management.

        Args:
            target_path: Path to a source directory or a single file.

        Returns:
            A list of finding dicts compatible with ``HybridFinding``.
        """
        target = Path(target_path)
        if not target.exists():
            logger.warning("Target path does not exist: %s", target_path)
            return []

        all_findings: list[dict] = []

        if target.is_file():
            files = [target]
        else:
            files = sorted(p for p in target.rglob("*") if p.is_file() and p.suffix in _SOURCE_EXTENSIONS)

        logger.info("Source-aware scan: %d eligible files in %s", len(files), target_path)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except PermissionError:
                logger.debug("Permission denied: %s", file_path)
                continue
            except Exception:
                logger.debug("Could not read file: %s", file_path)
                continue

            fp_str = str(file_path)
            all_findings.extend(self._detect_csrf_issues(fp_str, content))
            all_findings.extend(self._detect_open_redirects(fp_str, content))
            all_findings.extend(self._detect_rate_limit_gaps(fp_str, content))
            all_findings.extend(self._detect_security_header_gaps(fp_str, content))
            all_findings.extend(self._detect_weak_sessions(fp_str, content))

        logger.info(
            "Source-aware scan complete: %d findings across %d files",
            len(all_findings),
            len(files),
        )
        return all_findings

    # ------------------------------------------------------------------
    # Source-aware detectors
    # ------------------------------------------------------------------

    def _detect_csrf_issues(self, file_path: str, content: str) -> list[dict]:
        """Detect CSRF vulnerabilities in source code.

        Looks for:
        - HTML ``<form>`` elements without CSRF tokens.
        - State-changing operations performed via GET requests.
        """
        findings: list[dict] = []
        lines = content.splitlines()

        # --- HTML forms without CSRF tokens ---
        for idx, line in enumerate(lines, start=1):
            if _RE_HTML_FORM.search(line):
                # Grab a window of lines after the form tag to check for a
                # CSRF token hidden input or template variable.
                window = "\n".join(lines[idx - 1 : idx + 15])
                if not _RE_CSRF_TOKEN.search(window):
                    findings.append(
                        self._make_source_finding(
                            file_path=file_path,
                            line_number=idx,
                            severity="high",
                            category="security",
                            title="CSRF: Form without CSRF token",
                            description=(
                                "An HTML form was detected without a CSRF "
                                "token.  An attacker can forge cross-site "
                                "requests on behalf of authenticated users."
                            ),
                            cwe_id=_CWE_CSRF,
                            owasp_category=_OWASP_CSRF,
                        )
                    )

        # --- State-changing operations via GET ---
        for idx, line in enumerate(lines, start=1):
            if _RE_STATE_CHANGE_GET.search(line):
                findings.append(
                    self._make_source_finding(
                        file_path=file_path,
                        line_number=idx,
                        severity="medium",
                        category="security",
                        title="CSRF: State-changing operation via GET",
                        description=(
                            "A state-changing operation (delete, update, "
                            "create, etc.) is handled via a GET request.  "
                            "GET requests should be idempotent; use POST / "
                            "PUT / DELETE instead to mitigate CSRF."
                        ),
                        cwe_id=_CWE_CSRF,
                        owasp_category=_OWASP_CSRF,
                    )
                )

        return findings

    def _detect_open_redirects(self, file_path: str, content: str) -> list[dict]:
        """Detect open redirect patterns in source code.

        Looks for redirects whose destination comes from user-controlled
        input (query parameters, POST body, etc.) without a whitelist
        check.
        """
        findings: list[dict] = []
        lines = content.splitlines()

        # Pre-check: does the file contain any redirect-whitelist pattern?
        has_whitelist = bool(_RE_REDIRECT_WHITELIST.search(content))

        for idx, line in enumerate(lines, start=1):
            if _RE_REDIRECT_PARAM.search(line):
                # If there is a whitelist anywhere in the file we lower the
                # severity but still flag it (the whitelist might not cover
                # this particular redirect call).
                if has_whitelist:
                    severity = "low"
                    desc_suffix = (
                        " A redirect whitelist was detected elsewhere in the file -- verify this redirect is covered."
                    )
                else:
                    severity = "high"
                    desc_suffix = ""

                findings.append(
                    self._make_source_finding(
                        file_path=file_path,
                        line_number=idx,
                        severity=severity,
                        category="security",
                        title="Open Redirect: Unvalidated redirect URL",
                        description=(
                            "A redirect destination is derived from "
                            "user-controlled input without whitelist "
                            "validation.  An attacker can craft a URL "
                            "that redirects victims to a malicious site." + desc_suffix
                        ),
                        cwe_id=_CWE_OPEN_REDIRECT,
                        owasp_category=_OWASP_OPEN_REDIRECT,
                    )
                )

        return findings

    def _detect_rate_limit_gaps(self, file_path: str, content: str) -> list[dict]:
        """Detect missing rate limiting on authentication endpoints.

        Looks for login / auth endpoint definitions that do not appear
        to be protected by a rate-limiter middleware.
        """
        findings: list[dict] = []
        lines = content.splitlines()

        # Quick check -- if the file already imports / configures a rate
        # limiter we assume all routes in the file are covered.
        has_rate_limit = bool(_RE_RATE_LIMIT.search(content))
        if has_rate_limit:
            return findings

        for idx, line in enumerate(lines, start=1):
            if _RE_AUTH_ENDPOINT.search(line):
                findings.append(
                    self._make_source_finding(
                        file_path=file_path,
                        line_number=idx,
                        severity="medium",
                        category="security",
                        title="Brute Force: No rate limiting on auth endpoint",
                        description=(
                            "An authentication endpoint was detected "
                            "without rate-limiting middleware.  This "
                            "enables credential-stuffing and brute-force "
                            "attacks."
                        ),
                        cwe_id=_CWE_BRUTE_FORCE,
                        owasp_category=_OWASP_BRUTE_FORCE,
                    )
                )

        return findings

    def _detect_security_header_gaps(self, file_path: str, content: str) -> list[dict]:
        """Detect missing security headers in response generation code.

        When a file defines HTTP routes or sets response headers, we
        check whether common security headers (CSP, HSTS, X-Frame-Options,
        etc.) are configured.
        """
        findings: list[dict] = []
        lines = content.splitlines()

        # Only flag files that actually handle HTTP responses.
        if not _RE_RESPONSE_GENERATION.search(content):
            return findings

        # Check which security headers are already referenced in the file.
        missing_headers: list[str] = []
        for header in _SECURITY_HEADERS:
            if not re.search(re.escape(header), content, re.IGNORECASE):
                missing_headers.append(header)

        if not missing_headers:
            return findings

        # Find the first route / handler definition to anchor the finding.
        anchor_line = 1
        for idx, line in enumerate(lines, start=1):
            if _RE_RESPONSE_GENERATION.search(line):
                anchor_line = idx
                break

        findings.append(
            self._make_source_finding(
                file_path=file_path,
                line_number=anchor_line,
                severity="medium",
                category="security",
                title="Missing Security Headers: " + ", ".join(missing_headers[:3]),
                description=(
                    "This file defines HTTP response handling but does "
                    "not set the following security headers: "
                    + ", ".join(missing_headers)
                    + ".  Missing headers can expose the application to "
                    "clickjacking, MIME-sniffing, and XSS attacks."
                ),
                cwe_id=_CWE_MISSING_HEADERS,
                owasp_category=_OWASP_MISSING_HEADERS,
            )
        )

        return findings

    def _detect_weak_sessions(self, file_path: str, content: str) -> list[dict]:
        """Detect weak session management patterns.

        Looks for predictable session IDs, missing HttpOnly / Secure
        cookie flags, and insecure Django session settings.
        """
        findings: list[dict] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if _RE_WEAK_SESSION.search(line):
                findings.append(
                    self._make_source_finding(
                        file_path=file_path,
                        line_number=idx,
                        severity="high",
                        category="security",
                        title="Weak Session: Insecure session/cookie configuration",
                        description=(
                            "A weak session management pattern was "
                            "detected (predictable session ID, missing "
                            "HttpOnly/Secure cookie flag, or insecure "
                            "framework setting).  This may allow session "
                            "hijacking or fixation attacks."
                        ),
                        cwe_id=_CWE_WEAK_SESSION,
                        owasp_category=_OWASP_WEAK_SESSION,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Nuclei JSONL output parser
    # ------------------------------------------------------------------

    def _parse_nuclei_output(self, output_lines: list[str]) -> list[dict]:
        """Parse Nuclei JSONL output lines into finding dicts.

        Each non-empty line is expected to be a JSON object emitted by
        ``nuclei -jsonl``.  Malformed lines are silently skipped with a
        warning.

        Returns:
            A list of finding dicts compatible with ``HybridFinding``.
        """
        findings: list[dict] = []

        for line in output_lines:
            stripped = line.strip()
            if not stripped:
                continue

            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed Nuclei JSON line: %s", exc)
                continue

            try:
                info = obj.get("info", {})
                template_id = obj.get("template-id", "unknown")
                severity = info.get("severity", "medium").lower()
                classification = info.get("classification", {})
                matched_at = obj.get("matched-at", obj.get("matched", ""))

                # Extract CWE if present (may be a list or a single string).
                raw_cwe = classification.get("cwe-id", None)
                cwe_id = (raw_cwe[0] if raw_cwe else None) if isinstance(raw_cwe, list) else raw_cwe

                content_hash = int(hashlib.sha256(stripped.encode()).hexdigest()[:8], 16)
                finding_id = _make_finding_id(template_id, matched_at, content_hash)

                finding: dict = {
                    "finding_id": f"nuclei-live-{finding_id}",
                    "source_tool": "nuclei-live",
                    "severity": severity,
                    "category": "security",
                    "title": info.get("name", template_id),
                    "description": info.get("description", "")
                    or f"Nuclei template {template_id} matched at {matched_at}",
                    "file_path": matched_at,
                    "line_number": None,
                    "cwe_id": cwe_id,
                    "owasp_category": ", ".join(info.get("tags", [])),
                }
                findings.append(finding)
            except Exception as exc:
                logger.warning("Error processing Nuclei finding: %s", exc)
                continue

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_nuclei_installed(self) -> bool:
        """Check whether the ``nuclei`` binary is available."""
        if self._nuclei_available is not None:
            return self._nuclei_available

        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._nuclei_available = result.returncode == 0
        except FileNotFoundError:
            self._nuclei_available = False
        except Exception:
            self._nuclei_available = False

        if self._nuclei_available:
            logger.debug("Nuclei binary found at '%s'", self.nuclei_path)
        else:
            logger.debug("Nuclei binary NOT found at '%s'", self.nuclei_path)

        return self._nuclei_available

    def _build_live_command(
        self,
        target_url: str,
        severity_filter: str,
        tags: list[str] | None,
    ) -> list[str]:
        """Build the ``nuclei`` CLI command for a live scan."""
        cmd = [self.nuclei_path, "-u", target_url, "-jsonl", "-silent"]

        if severity_filter:
            cmd.extend(["-severity", severity_filter])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if self.templates_dir:
            cmd.extend(["-t", self.templates_dir])

        return cmd

    @staticmethod
    def _make_source_finding(
        *,
        file_path: str,
        line_number: int,
        severity: str,
        category: str,
        title: str,
        description: str,
        cwe_id: str,
        owasp_category: str,
    ) -> dict:
        """Create a finding dict compatible with ``HybridFinding``."""
        finding_id = _make_finding_id(cwe_id, file_path, line_number)
        return {
            "finding_id": f"nuclei-src-{finding_id}",
            "source_tool": "nuclei-template",
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "file_path": file_path,
            "line_number": line_number,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
        }
