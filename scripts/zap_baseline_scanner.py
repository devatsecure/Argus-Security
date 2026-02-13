#!/usr/bin/env python3
"""
ZAP Baseline Scanner Module

Provides OWASP ZAP integration for passive security checks in the Argus pipeline.
ZAP is installed in Dockerfile.complete but was not previously wired into the pipeline.

Two modes of operation:
1. Live baseline mode: Runs ZAP baseline scan against a live URL using zap-baseline.py
2. Source analysis mode: Detects information disclosure patterns, missing security headers,
   and server configuration issues from source code

Covers DVWA-style findings:
- DVWA-018: Missing Security Headers
- DVWA-019: Information Disclosure
- Cookie security issues
- Server configuration exposure
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None

__all__ = ["ZAPBaselineScanner"]

logger = logging.getLogger(__name__)

# File extensions to scan in source analysis mode
SCANNABLE_EXTENSIONS = {
    ".py",
    ".php",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".rs",
    ".conf",
    ".htaccess",
    ".nginx",
    ".yml",
    ".yaml",
}

# Common ZAP installation paths
ZAP_SEARCH_PATHS = [
    "/usr/share/zaproxy/zap-baseline.py",
    "/opt/zaproxy/zap-baseline.py",
    "/usr/local/bin/zap-baseline.py",
    "/zap/zap-baseline.py",
    "/home/zap/zap-baseline.py",
]

# ZAP alert risk levels mapped to Argus severity
ZAP_RISK_TO_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}


class ZAPBaselineScanner:
    """ZAP-based scanner for passive security checks.

    Covers DVWA-style findings:
    - DVWA-018: Missing Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
    - DVWA-019: Information Disclosure (server version, debug info, stack traces, error messages)
    - Cookie security issues (missing HttpOnly, Secure, SameSite flags)
    - Server configuration exposure (directory listing, backup files accessible via HTTP)
    """

    def __init__(
        self,
        zap_path: Optional[str] = None,
        docker_mode: bool = False,
    ) -> None:
        """Initialize ZAP baseline scanner.

        Args:
            zap_path: Explicit path to zap-baseline.py. If None, searches common paths.
            docker_mode: If True, run ZAP via Docker image ghcr.io/zaproxy/zaproxy:stable.
        """
        self.docker_mode = docker_mode
        self.zap_path = zap_path
        self._finding_counter = 0

        if not self.docker_mode and not self.zap_path:
            self.zap_path = self._find_zap_binary()

        if self.zap_path:
            logger.info("ZAP baseline scanner found at: %s", self.zap_path)
        elif self.docker_mode:
            logger.info("ZAP baseline scanner configured in Docker mode")
        else:
            logger.warning("ZAP binary not found. Live scanning unavailable; source analysis mode will still work.")

        # Compile regex patterns once for performance
        self._compile_patterns()

    # ------------------------------------------------------------------
    # Pattern compilation
    # ------------------------------------------------------------------

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns used in source analysis."""

        # Information disclosure patterns
        self._info_disclosure_patterns = [
            # PHP info/debug functions
            (
                re.compile(r"\bphpinfo\s*\(", re.IGNORECASE),
                "phpinfo() exposes full server configuration",
                "high",
                "CWE-200",
            ),
            (
                re.compile(r"\bvar_dump\s*\(", re.IGNORECASE),
                "var_dump() may expose internal data structures to users",
                "medium",
                "CWE-200",
            ),
            (
                re.compile(r"\bprint_r\s*\(", re.IGNORECASE),
                "print_r() may expose internal data structures to users",
                "medium",
                "CWE-200",
            ),
            # Debug mode enabled
            (
                re.compile(r"\bDEBUG\s*=\s*True\b"),
                "Debug mode enabled in production code",
                "high",
                "CWE-489",
            ),
            (
                re.compile(r"['\"]debug['\"]\s*:\s*[Tt]rue"),
                "Debug mode enabled in configuration",
                "high",
                "CWE-489",
            ),
            (
                re.compile(r"\bapp\.debug\s*=\s*True\b"),
                "Flask/Django debug mode enabled",
                "high",
                "CWE-489",
            ),
            # Stack trace / error detail exposure
            (
                re.compile(
                    r"(traceback\.format_exc|traceback\.print_exc"
                    r"|\.printStackTrace\b|console\.trace\b)",
                    re.IGNORECASE,
                ),
                "Stack trace may be exposed to end users",
                "medium",
                "CWE-209",
            ),
            (
                re.compile(
                    r"(display_errors\s*=\s*[Oo]n"
                    r"|error_reporting\s*\(\s*E_ALL\s*\))",
                    re.IGNORECASE,
                ),
                "Verbose error reporting enabled",
                "medium",
                "CWE-209",
            ),
            # Server version strings in response headers
            (
                re.compile(
                    r'["\']Server["\']\s*:\s*["\'][^"\']*'
                    r"(Apache|nginx|IIS|Tomcat|Express|Kestrel)/[\d.]",
                    re.IGNORECASE,
                ),
                "Server version disclosed in response headers",
                "low",
                "CWE-200",
            ),
            (
                re.compile(
                    r'["\']X-Powered-By["\']\s*:\s*["\'][^"\']+["\']',
                    re.IGNORECASE,
                ),
                "X-Powered-By header exposes technology stack",
                "low",
                "CWE-200",
            ),
            # Error messages exposing internal paths or DB info
            (
                re.compile(
                    r"(mysql_error|pg_last_error|sqlite3?\.\w*error"
                    r"|\.getMessage\s*\(\s*\))",
                    re.IGNORECASE,
                ),
                "Database error messages may be exposed to users",
                "medium",
                "CWE-209",
            ),
            # Detailed exception messages in HTTP responses
            (
                re.compile(
                    r"(return\s+.*str\s*\(\s*e\s*\)"
                    r"|response.*str\s*\(\s*(ex|err|exception)\s*\)"
                    r"|render.*error.*str\s*\(\s*e\s*\))",
                    re.IGNORECASE,
                ),
                "Exception details returned in HTTP response",
                "medium",
                "CWE-209",
            ),
        ]

        # Security header patterns — detect code that builds responses
        # without required security headers
        self._security_headers = {
            "Content-Security-Policy": {
                "aliases": [
                    "Content-Security-Policy",
                    "content_security_policy",
                    "CSP",
                    "csp_header",
                ],
                "cwe": "CWE-1021",
                "severity": "medium",
                "description": ("Missing Content-Security-Policy header allows XSS and data injection attacks"),
            },
            "Strict-Transport-Security": {
                "aliases": [
                    "Strict-Transport-Security",
                    "strict_transport_security",
                    "HSTS",
                    "hsts_header",
                ],
                "cwe": "CWE-319",
                "severity": "medium",
                "description": ("Missing Strict-Transport-Security header allows downgrade attacks"),
            },
            "X-Frame-Options": {
                "aliases": [
                    "X-Frame-Options",
                    "x_frame_options",
                    "XFO",
                    "xfo_header",
                    "DENY",
                    "SAMEORIGIN",
                ],
                "cwe": "CWE-1021",
                "severity": "medium",
                "description": ("Missing X-Frame-Options header allows clickjacking attacks"),
            },
            "X-Content-Type-Options": {
                "aliases": [
                    "X-Content-Type-Options",
                    "x_content_type_options",
                    "nosniff",
                ],
                "cwe": "CWE-16",
                "severity": "low",
                "description": ("Missing X-Content-Type-Options header allows MIME type sniffing"),
            },
            "Referrer-Policy": {
                "aliases": [
                    "Referrer-Policy",
                    "referrer_policy",
                    "referrerPolicy",
                ],
                "cwe": "CWE-200",
                "severity": "low",
                "description": ("Missing Referrer-Policy header may leak sensitive URL information"),
            },
            "Permissions-Policy": {
                "aliases": [
                    "Permissions-Policy",
                    "permissions_policy",
                    "Feature-Policy",
                    "feature_policy",
                ],
                "cwe": "CWE-16",
                "severity": "low",
                "description": ("Missing Permissions-Policy header allows unrestricted access to browser features"),
            },
        }

        # Response-building indicators — files that likely produce HTTP responses
        self._response_indicators = re.compile(
            r"(def\s+(get|post|put|delete|patch|handle|dispatch|response|view)"
            r"|@(app\.(route|get|post|put|delete)|router\."
            r"(get|post|put|delete)|RequestMapping|GetMapping"
            r"|PostMapping|api_view|require_http_methods)"
            r"|class\s+\w+(View|Controller|Handler|Resource|Endpoint)"
            r"|func\s+\w+Handler\b"
            r"|HttpResponse|JsonResponse|Response\s*\("
            r"|res\.(send|json|render|status)\s*\("
            r'|header\s*\(\s*["\'])',
            re.IGNORECASE,
        )

        # Cookie patterns
        self._cookie_patterns = [
            # PHP setcookie — check for missing flags
            (
                re.compile(
                    r'setcookie\s*\(\s*["\'][^"\']+["\']\s*,'
                    r"[^;]*\)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "php_setcookie",
            ),
            # PHP session cookie config
            (
                re.compile(
                    r"session\.cookie_httponly\s*=\s*(false|0|off|no)",
                    re.IGNORECASE,
                ),
                "session_httponly_disabled",
            ),
            (
                re.compile(
                    r"session\.cookie_secure\s*=\s*(false|0|off|no)",
                    re.IGNORECASE,
                ),
                "session_secure_disabled",
            ),
            # Python/Flask/Django cookie setting
            (
                re.compile(
                    r"(set_cookie|response\.cookies)\s*\([^)]*\)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "python_set_cookie",
            ),
            # Express.js cookie
            (
                re.compile(
                    r'res\.cookie\s*\(\s*["\'][^"\']+["\']\s*,'
                    r"[^;]*\)",
                    re.IGNORECASE | re.DOTALL,
                ),
                "express_cookie",
            ),
            # Java cookie
            (
                re.compile(
                    r'new\s+Cookie\s*\(\s*["\'][^"\']+["\']\s*,',
                    re.IGNORECASE,
                ),
                "java_cookie",
            ),
            # Go http.SetCookie
            (
                re.compile(
                    r"http\.SetCookie\s*\(",
                    re.IGNORECASE,
                ),
                "go_cookie",
            ),
        ]

        # Secure cookie flag indicators
        self._secure_cookie_flags = re.compile(
            r"(httponly|http_only|HttpOnly"
            r"|[Ss]ecure\s*[=:]\s*[Tt]rue"
            r"|[Ss]ame[Ss]ite"
            r"|SESSION_COOKIE_SECURE"
            r"|SESSION_COOKIE_HTTPONLY"
            r"|cookie_secure\s*=\s*(true|1|on)"
            r"|cookie_httponly\s*=\s*(true|1|on))",
            re.IGNORECASE,
        )

        # Server config patterns
        self._server_config_patterns = [
            # Apache directory listing
            (
                re.compile(r"Options\s+.*\+?Indexes", re.IGNORECASE),
                "Apache directory listing enabled via Options +Indexes",
                "medium",
                "CWE-548",
            ),
            # Nginx autoindex
            (
                re.compile(r"autoindex\s+on\s*;", re.IGNORECASE),
                "Nginx directory listing enabled via autoindex on",
                "medium",
                "CWE-548",
            ),
            # Server signature
            (
                re.compile(r"ServerSignature\s+On", re.IGNORECASE),
                "Apache ServerSignature exposes server version",
                "low",
                "CWE-200",
            ),
            (
                re.compile(r"server_tokens\s+on\s*;", re.IGNORECASE),
                "Nginx server_tokens exposes server version",
                "low",
                "CWE-200",
            ),
            # Backup/config file access via HTTP
            (
                re.compile(
                    r'<FilesMatch\s+["\'].*\.(bak|backup|old|orig|swp)',
                    re.IGNORECASE,
                ),
                "Backup file access may be allowed via HTTP",
                "medium",
                "CWE-530",
            ),
            # .htaccess allowing dangerous file types
            (
                re.compile(
                    r"AddHandler\s+cgi-script\s+\.",
                    re.IGNORECASE,
                ),
                "CGI handler configured — may allow arbitrary script execution",
                "high",
                "CWE-94",
            ),
            # Exposed .git or .env paths
            (
                re.compile(
                    r"(location|Alias|AliasMatch)\s+.*(/\.git|/\.env|/\.svn)",
                    re.IGNORECASE,
                ),
                "Sensitive directory (.git/.env/.svn) may be web-accessible",
                "high",
                "CWE-538",
            ),
            # CORS wildcard
            (
                re.compile(
                    r"(Access-Control-Allow-Origin|add_header\s+"
                    r'["\']?Access-Control-Allow-Origin)\s*["\']?\s*\*',
                    re.IGNORECASE,
                ),
                "CORS wildcard allows requests from any origin",
                "medium",
                "CWE-942",
            ),
        ]

        # Verbose error handling patterns — exception handlers that expose details
        self._verbose_error_patterns = [
            # Python: except that returns/prints exception details
            (
                re.compile(
                    r"except\s+\w*\s*(as\s+\w+)?:\s*\n"
                    r"[^\n]*\b(print|return|render|send)\b[^\n]*"
                    r"\b(str\s*\(\s*\w*e\w*\)|repr\s*\(\s*\w*e\w*\)"
                    r"|traceback|format_exc)",
                    re.IGNORECASE | re.MULTILINE,
                ),
                "Exception handler exposes error details to users",
                "medium",
                "CWE-209",
            ),
            # PHP: catch with echo/print of exception message
            (
                re.compile(
                    r"catch\s*\([^)]+\$\w+\)\s*\{[^}]*"
                    r"(echo|print|die)\s*\([^)]*\$\w+->getMessage",
                    re.IGNORECASE | re.DOTALL,
                ),
                "PHP catch block exposes exception message to users",
                "medium",
                "CWE-209",
            ),
            # Java: catch with printStackTrace or getMessage in response
            (
                re.compile(
                    r"catch\s*\([^)]+\)\s*\{[^}]*"
                    r"(\.printStackTrace\(\)|\.getMessage\(\))",
                    re.IGNORECASE | re.DOTALL,
                ),
                "Java catch block may expose stack trace or exception message",
                "medium",
                "CWE-209",
            ),
            # JavaScript/TypeScript: catch with res.send/json of error
            (
                re.compile(
                    r"catch\s*\(\s*\w+\s*\)\s*\{[^}]*"
                    r"res\.(send|json)\s*\([^)]*\b(err|error|e)\b"
                    r"(\.(message|stack))?",
                    re.IGNORECASE | re.DOTALL,
                ),
                "Express catch block sends error details in response",
                "medium",
                "CWE-209",
            ),
        ]

    # ------------------------------------------------------------------
    # ZAP binary discovery
    # ------------------------------------------------------------------

    def _find_zap_binary(self) -> Optional[str]:
        """Search for zap-baseline.py in common installation paths."""
        # Check PATH first
        zap_in_path = shutil.which("zap-baseline.py")
        if zap_in_path:
            return zap_in_path

        for path in ZAP_SEARCH_PATHS:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        return None

    # ------------------------------------------------------------------
    # Finding ID generation
    # ------------------------------------------------------------------

    def _generate_finding_id(self, prefix: str, file_path: str, line: int) -> str:
        """Generate a deterministic finding ID."""
        self._finding_counter += 1
        hash_input = f"{prefix}:{file_path}:{line}:{self._finding_counter}"
        short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        return f"ZAP-{prefix}-{short_hash}"

    # ------------------------------------------------------------------
    # Live scanning
    # ------------------------------------------------------------------

    def scan_live(
        self,
        target_url: str,
        timeout: int = 120,
        ajax_spider: bool = False,
    ) -> list[dict]:
        """Run ZAP baseline scan against a live URL.

        Args:
            target_url: URL to scan (must be accessible).
            timeout: Scan timeout in seconds.
            ajax_spider: If True, enable the AJAX spider for JS-heavy apps.

        Returns:
            List of finding dicts compatible with HybridFinding format.
        """
        if not self.docker_mode and not self.zap_path:
            logger.error("ZAP is not available. Install ZAP or use docker_mode=True.")
            return []

        with tempfile.TemporaryDirectory(prefix="zap_scan_") as tmp_dir:
            report_path = os.path.join(tmp_dir, "zap_report.json")

            cmd = self._build_zap_command(target_url, report_path, timeout, ajax_spider)

            logger.info("Running ZAP baseline scan against %s", target_url)
            logger.debug("ZAP command: %s", " ".join(cmd))

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 60,  # extra buffer for startup/teardown
                )

                # ZAP returns non-zero for warnings/failures — that is expected
                if result.returncode not in (0, 1, 2):
                    logger.warning(
                        "ZAP exited with code %d: %s",
                        result.returncode,
                        result.stderr[:500] if result.stderr else "no stderr",
                    )

                if result.stdout:
                    logger.debug("ZAP stdout: %s", result.stdout[:1000])

            except FileNotFoundError:
                logger.error("ZAP binary not found at expected path")
                return []
            except subprocess.TimeoutExpired:
                logger.error("ZAP scan timed out after %d seconds", timeout + 60)
                return []
            except OSError as exc:
                logger.error("Failed to run ZAP: %s", exc)
                return []

            # Parse report
            if os.path.isfile(report_path):
                return self._parse_zap_report(report_path)

            # Try XML fallback
            xml_path = report_path.replace(".json", ".xml")
            if os.path.isfile(xml_path):
                return self._parse_zap_report(xml_path)

            logger.warning("ZAP report not found at %s", report_path)
            return []

    def _build_zap_command(
        self,
        target_url: str,
        report_path: str,
        timeout: int,
        ajax_spider: bool,
    ) -> list[str]:
        """Build the ZAP command line."""
        if self.docker_mode:
            cmd = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{os.path.dirname(report_path)}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
            ]
        else:
            cmd = ["python3", self.zap_path]

        cmd.extend(
            [
                "-t",
                target_url,
                "-J",
                os.path.basename(report_path),
                "-I",  # don't fail on warnings
            ]
        )

        if timeout:
            cmd.extend(["-m", str(timeout // 60 or 1)])

        if ajax_spider:
            cmd.append("-j")

        return cmd

    # ------------------------------------------------------------------
    # Source analysis
    # ------------------------------------------------------------------

    def scan_source(self, target_path: str) -> list[dict]:
        """Source-code-aware analysis for web security issues.

        Walks source files and detects information disclosure patterns,
        missing security headers, insecure cookie settings, server
        configuration issues, and verbose error handling.

        Args:
            target_path: Root directory to scan.

        Returns:
            List of finding dicts compatible with HybridFinding format.
        """
        findings: list[dict] = []
        target = Path(target_path)

        if not target.is_dir():
            logger.error("Target path is not a directory: %s", target_path)
            return findings

        logger.info("Running ZAP source analysis on %s", target_path)

        file_count = 0
        for root, _dirs, files in os.walk(target_path):
            # Skip hidden directories, node_modules, vendor, etc.
            rel_root = os.path.relpath(root, target_path)
            if any(
                part.startswith(".")
                or part in ("node_modules", "vendor", "__pycache__", "venv", ".venv", "dist", "build", ".git")
                for part in Path(rel_root).parts
            ):
                continue

            for fname in files:
                ext = Path(fname).suffix.lower()
                # Also match extensionless files like .htaccess
                basename = fname.lower()
                if ext not in SCANNABLE_EXTENSIONS and basename not in (".htaccess",):
                    continue

                file_path = os.path.join(root, fname)
                try:
                    with open(file_path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (PermissionError, FileNotFoundError) as exc:
                    logger.debug("Cannot read %s: %s", file_path, exc)
                    continue
                except Exception as exc:
                    logger.debug("Error reading %s: %s", file_path, exc)
                    continue

                if not content.strip():
                    continue

                # Skip test files
                if self._is_test_file(file_path):
                    continue

                rel_path = os.path.relpath(file_path, target_path)
                file_count += 1

                findings.extend(self._detect_info_disclosure(rel_path, content))
                findings.extend(self._detect_missing_headers(rel_path, content))
                findings.extend(self._detect_insecure_cookies(rel_path, content))
                findings.extend(self._detect_server_config_issues(rel_path, content))
                findings.extend(self._detect_verbose_errors(rel_path, content))

        logger.info(
            "ZAP source analysis complete: %d files scanned, %d findings",
            file_count,
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _detect_info_disclosure(self, file_path: str, content: str) -> list[dict]:
        """Detect information disclosure patterns in source code.

        Args:
            file_path: Relative path to the file.
            content: File content.

        Returns:
            List of finding dicts.
        """
        findings: list[dict] = []
        lines = content.split("\n")

        for pattern, description, severity, cwe in self._info_disclosure_patterns:
            for i, line in enumerate(lines, start=1):
                if pattern.search(line):
                    # Skip if inside a comment
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "*", "/*")):
                        continue

                    findings.append(
                        {
                            "finding_id": self._generate_finding_id("INFO", file_path, i),
                            "source_tool": "zap-baseline",
                            "severity": severity,
                            "category": "security",
                            "title": f"Information Disclosure: {description}",
                            "description": (
                                f"{description}. Found in {file_path} at line {i}. "
                                f"This may expose sensitive server or application "
                                f"details to attackers."
                            ),
                            "file_path": file_path,
                            "line_number": i,
                            "cwe_id": cwe,
                            "owasp_category": "A01:2021-Broken Access Control",
                        }
                    )

        return findings

    def _detect_missing_headers(self, file_path: str, content: str) -> list[dict]:
        """Detect missing security headers in response-building code.

        Only reports findings for files that appear to build HTTP responses,
        to avoid false positives on utility/model files.

        Args:
            file_path: Relative path to the file.
            content: File content.

        Returns:
            List of finding dicts.
        """
        findings: list[dict] = []

        # Only check files that build HTTP responses
        if not self._response_indicators.search(content):
            return findings

        content_lower = content.lower()

        for header_name, header_info in self._security_headers.items():
            # Check all known aliases for this header
            header_present = any(alias.lower() in content_lower for alias in header_info["aliases"])

            if not header_present:
                # Find the first response-building line for context
                match = self._response_indicators.search(content)
                line_num = content[: match.start()].count("\n") + 1 if match else 1

                findings.append(
                    {
                        "finding_id": self._generate_finding_id("HDR", file_path, line_num),
                        "source_tool": "zap-baseline",
                        "severity": header_info["severity"],
                        "category": "security",
                        "title": f"Missing Security Header: {header_name}",
                        "description": (
                            f"{header_info['description']}. "
                            f"The file {file_path} builds HTTP responses but does "
                            f"not set the {header_name} header."
                        ),
                        "file_path": file_path,
                        "line_number": line_num,
                        "cwe_id": header_info["cwe"],
                        "owasp_category": "A05:2021-Security Misconfiguration",
                    }
                )

        return findings

    def _detect_insecure_cookies(self, file_path: str, content: str) -> list[dict]:
        """Detect insecure cookie settings in source code.

        Args:
            file_path: Relative path to the file.
            content: File content.

        Returns:
            List of finding dicts.
        """
        findings: list[dict] = []
        lines = content.split("\n")

        for pattern, cookie_type in self._cookie_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1

                # Skip if in a comment
                line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                if line_text.startswith(("#", "//", "*", "/*")):
                    continue

                issues = []

                if cookie_type in (
                    "session_httponly_disabled",
                    "session_secure_disabled",
                ):
                    # These are explicit insecure settings
                    flag = "HttpOnly" if "httponly" in cookie_type else "Secure"
                    issues.append(flag)
                else:
                    # Check for missing security flags in the cookie-setting call
                    # Look at surrounding context (up to 5 lines around the match)
                    context_start = max(0, line_num - 3)
                    context_end = min(len(lines), line_num + 5)
                    context = "\n".join(lines[context_start:context_end])

                    if not self._secure_cookie_flags.search(context):
                        issues.extend(["HttpOnly", "Secure", "SameSite"])
                    else:
                        # Check which specific flags are missing
                        context_lower = context.lower()
                        if "httponly" not in context_lower and "http_only" not in context_lower:
                            issues.append("HttpOnly")
                        if not re.search(r"\bsecure\s*[=:]\s*true\b", context_lower):
                            # Avoid matching "secure" in variable names
                            if "secure" not in context_lower.split("cookie")[0] if "cookie" in context_lower else True:
                                issues.append("Secure")
                        if "samesite" not in context_lower and "same_site" not in context_lower:
                            issues.append("SameSite")

                if issues:
                    missing_flags = ", ".join(issues)
                    findings.append(
                        {
                            "finding_id": self._generate_finding_id("COOKIE", file_path, line_num),
                            "source_tool": "zap-baseline",
                            "severity": "medium",
                            "category": "security",
                            "title": (f"Insecure Cookie: Missing {missing_flags} flag(s)"),
                            "description": (
                                f"Cookie set at {file_path}:{line_num} is missing "
                                f"{missing_flags} flag(s). Without these flags, "
                                f"cookies may be vulnerable to theft via XSS "
                                f"(HttpOnly), sent over unencrypted connections "
                                f"(Secure), or used in CSRF attacks (SameSite)."
                            ),
                            "file_path": file_path,
                            "line_number": line_num,
                            "cwe_id": "CWE-614",
                            "owasp_category": "A05:2021-Security Misconfiguration",
                        }
                    )

        return findings

    def _detect_server_config_issues(self, file_path: str, content: str) -> list[dict]:
        """Detect server configuration issues.

        Args:
            file_path: Relative path to the file.
            content: File content.

        Returns:
            List of finding dicts.
        """
        findings: list[dict] = []
        lines = content.split("\n")

        for pattern, description, severity, cwe in self._server_config_patterns:
            for i, line in enumerate(lines, start=1):
                if pattern.search(line):
                    # Skip comments
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "*", "/*")):
                        continue

                    findings.append(
                        {
                            "finding_id": self._generate_finding_id("SRVCONF", file_path, i),
                            "source_tool": "zap-baseline",
                            "severity": severity,
                            "category": "security",
                            "title": f"Server Configuration: {description}",
                            "description": (
                                f"{description}. Found in {file_path} at line {i}. "
                                f"This may expose sensitive information or allow "
                                f"unauthorized access."
                            ),
                            "file_path": file_path,
                            "line_number": i,
                            "cwe_id": cwe,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                        }
                    )

        return findings

    def _detect_verbose_errors(self, file_path: str, content: str) -> list[dict]:
        """Detect verbose error handling that exposes internal details.

        Args:
            file_path: Relative path to the file.
            content: File content.

        Returns:
            List of finding dicts.
        """
        findings: list[dict] = []

        for pattern, description, severity, cwe in self._verbose_error_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1

                findings.append(
                    {
                        "finding_id": self._generate_finding_id("VERR", file_path, line_num),
                        "source_tool": "zap-baseline",
                        "severity": severity,
                        "category": "security",
                        "title": f"Verbose Error Handling: {description}",
                        "description": (
                            f"{description}. Found in {file_path} at line "
                            f"{line_num}. Exposing error details to users can "
                            f"reveal internal application structure, file paths, "
                            f"or database schema information."
                        ),
                        "file_path": file_path,
                        "line_number": line_num,
                        "cwe_id": cwe,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                    }
                )

        return findings

    # ------------------------------------------------------------------
    # ZAP report parsing
    # ------------------------------------------------------------------

    def _parse_zap_report(self, report_path: str) -> list[dict]:
        """Parse ZAP JSON or XML report into finding dicts.

        Args:
            report_path: Path to the ZAP report file.

        Returns:
            List of finding dicts compatible with HybridFinding format.
        """
        if report_path.endswith(".json"):
            return self._parse_json_report(report_path)
        elif report_path.endswith(".xml"):
            return self._parse_xml_report(report_path)
        else:
            # Try JSON first, then XML
            findings = self._parse_json_report(report_path)
            if not findings:
                findings = self._parse_xml_report(report_path)
            return findings

    def _parse_json_report(self, report_path: str) -> list[dict]:
        """Parse ZAP JSON report format."""
        findings: list[dict] = []

        try:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ZAP JSON report: %s", exc)
            return findings
        except FileNotFoundError:
            logger.error("ZAP report not found: %s", report_path)
            return findings
        except PermissionError:
            logger.error("Permission denied reading ZAP report: %s", report_path)
            return findings
        except Exception as exc:
            logger.error("Error reading ZAP report %s: %s", report_path, exc)
            return findings

        # ZAP JSON report has "site" -> [] -> "alerts" -> []
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            alerts = site.get("alerts", [])
            for alert in alerts:
                risk = str(alert.get("riskcode", alert.get("risk", "1")))
                severity = ZAP_RISK_TO_SEVERITY.get(risk, "low")

                # Skip informational findings
                if severity == "info":
                    continue

                cwe_id = alert.get("cweid", "")
                cwe_str = f"CWE-{cwe_id}" if cwe_id else None

                instances = alert.get("instances", [])
                url = instances[0].get("uri", "") if instances else alert.get("url", "")

                finding_id = self._generate_finding_id(
                    "LIVE",
                    alert.get("alertRef", alert.get("pluginid", "unknown")),
                    int(alert.get("pluginid", 0)) if alert.get("pluginid", "").isdigit() else 0,
                )

                findings.append(
                    {
                        "finding_id": finding_id,
                        "source_tool": "zap-baseline",
                        "severity": severity,
                        "category": "security",
                        "title": alert.get("alert", alert.get("name", "ZAP Finding")),
                        "description": (
                            f"{alert.get('desc', alert.get('description', 'No description'))}. "
                            f"URL: {url}. "
                            f"Solution: {alert.get('solution', 'N/A')}"
                        ),
                        "file_path": url,
                        "line_number": None,
                        "cwe_id": cwe_str,
                        "owasp_category": self._map_zap_to_owasp(
                            alert.get("alert", ""),
                            cwe_id,
                        ),
                    }
                )

        logger.info("Parsed %d findings from ZAP JSON report", len(findings))
        return findings

    def _parse_xml_report(self, report_path: str) -> list[dict]:
        """Parse ZAP XML report format."""
        findings: list[dict] = []

        if ET is None:
            logger.error("xml.etree.ElementTree not available")
            return findings

        try:
            tree = ET.parse(report_path)
            root = tree.getroot()
        except ET.ParseError as exc:
            logger.error("Failed to parse ZAP XML report: %s", exc)
            return findings
        except FileNotFoundError:
            logger.error("ZAP report not found: %s", report_path)
            return findings
        except PermissionError:
            logger.error("Permission denied reading ZAP report: %s", report_path)
            return findings
        except Exception as exc:
            logger.error("Error reading ZAP XML report %s: %s", report_path, exc)
            return findings

        # ZAP XML: <OWASPZAPReport> -> <site> -> <alerts> -> <alertitem>
        for site in root.iter("site"):
            for alert in site.iter("alertitem"):
                risk_code = self._xml_text(alert, "riskcode", "1")
                severity = ZAP_RISK_TO_SEVERITY.get(risk_code, "low")

                if severity == "info":
                    continue

                cwe_raw = self._xml_text(alert, "cweid", "")
                cwe_str = f"CWE-{cwe_raw}" if cwe_raw else None

                plugin_id = self._xml_text(alert, "pluginid", "0")
                alert_name = self._xml_text(alert, "alert", "ZAP Finding")
                desc = self._xml_text(alert, "desc", "No description")
                solution = self._xml_text(alert, "solution", "N/A")

                # Get first instance URL
                url = ""
                instances = alert.find("instances")
                if instances is not None:
                    first_instance = instances.find("instance")
                    if first_instance is not None:
                        url = self._xml_text(first_instance, "uri", "")

                finding_id = self._generate_finding_id(
                    "LIVE",
                    plugin_id,
                    int(plugin_id) if plugin_id.isdigit() else 0,
                )

                findings.append(
                    {
                        "finding_id": finding_id,
                        "source_tool": "zap-baseline",
                        "severity": severity,
                        "category": "security",
                        "title": alert_name,
                        "description": (f"{desc}. URL: {url}. Solution: {solution}"),
                        "file_path": url,
                        "line_number": None,
                        "cwe_id": cwe_str,
                        "owasp_category": self._map_zap_to_owasp(alert_name, cwe_raw),
                    }
                )

        logger.info("Parsed %d findings from ZAP XML report", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _xml_text(element: "ET.Element", tag: str, default: str = "") -> str:
        """Safely extract text from an XML element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    @staticmethod
    def _is_test_file(file_path: str) -> bool:
        """Check if a file path is a test file."""
        path_lower = file_path.lower()
        test_indicators = (
            "/test/",
            "/tests/",
            "/__tests__/",
            "/spec/",
            "/specs/",
            "_test.",
            ".test.",
            "_spec.",
            ".spec.",
            "test_",
        )
        basename = os.path.basename(path_lower)
        return any(ind in path_lower for ind in test_indicators) or basename.startswith("test_")

    @staticmethod
    def _map_zap_to_owasp(alert_name: str, cwe_id: str) -> str:
        """Map a ZAP alert to an OWASP Top 10 2021 category.

        Uses alert name keywords and CWE ID for mapping.
        """
        name_lower = alert_name.lower()

        # Keyword-based mapping
        if any(kw in name_lower for kw in ("header", "csp", "hsts", "x-frame")):
            return "A05:2021-Security Misconfiguration"
        if any(kw in name_lower for kw in ("disclosure", "information", "server")):
            return "A01:2021-Broken Access Control"
        if any(kw in name_lower for kw in ("cookie", "session")):
            return "A07:2021-Identification and Authentication Failures"
        if any(kw in name_lower for kw in ("injection", "sql", "xss", "script")):
            return "A03:2021-Injection"
        if any(kw in name_lower for kw in ("crypto", "ssl", "tls", "cipher")):
            return "A02:2021-Cryptographic Failures"

        # CWE-based fallback mapping
        cwe_to_owasp = {
            "200": "A01:2021-Broken Access Control",
            "209": "A05:2021-Security Misconfiguration",
            "319": "A02:2021-Cryptographic Failures",
            "352": "A01:2021-Broken Access Control",
            "548": "A05:2021-Security Misconfiguration",
            "614": "A05:2021-Security Misconfiguration",
            "693": "A05:2021-Security Misconfiguration",
            "942": "A05:2021-Security Misconfiguration",
            "1021": "A05:2021-Security Misconfiguration",
        }
        if cwe_id and str(cwe_id) in cwe_to_owasp:
            return cwe_to_owasp[str(cwe_id)]

        return "A05:2021-Security Misconfiguration"
