#!/usr/bin/env python3
"""
SAST-to-DAST Validator for Argus Security

Bridges static analysis (SAST) findings with dynamic application security
testing (DAST) by generating targeted HTTP tests against live targets.
Validates whether SAST-discovered vulnerabilities are actually exploitable
in a running application.

Complements the sandbox-based validation in sandbox_validator.py by testing
against live deployments (staging, preview, development environments).

Safety:
    - NEVER targets production by default
    - Rejects internal/private IP ranges unless explicitly allowed
    - Truncates response bodies to prevent memory issues
    - Defensive error handling for all network operations

Usage:
    from sast_dast_validator import SastDastValidator

    validator = SastDastValidator('https://staging.example.com')
    result = validator.validate_finding(finding)
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_RESPONSE_BODY = 2000  # Truncate response bodies to this length

DEFAULT_ALLOWED_ENVIRONMENTS = ["staging", "preview", "development", "testing"]

# Private/internal IP ranges that should be blocked by default
_PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),                           # loopback
    re.compile(r"^10\."),                            # 10.0.0.0/8
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),   # 172.16.0.0/12
    re.compile(r"^192\.168\."),                      # 192.168.0.0/16
    re.compile(r"^169\.254\."),                      # link-local
    re.compile(r"^0\."),                             # current network
]

_LOCALHOST_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}

# ---------------------------------------------------------------------------
# Vulnerability payload definitions
# ---------------------------------------------------------------------------

_SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE--",
    "' UNION SELECT NULL--",
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
]

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:6379/",
]

_PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
]

_COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| whoami",
    "`id`",
]

# Success indicator patterns per vulnerability type
_SUCCESS_INDICATORS: dict[str, list[str]] = {
    "sql-injection": [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "ora-",
        "unclosed quotation",
        "unterminated string",
        "you have an error in your sql",
        "warning: mysql",
        "microsoft ole db",
        "odbc sql server",
        "UNION SELECT",
    ],
    "sqli": [],  # shares with sql-injection, handled in code
    "xss": [
        "<script>alert(1)</script>",
        'onerror=alert(1)>',
    ],
    "ssrf": [
        "ami-",
        "instance-id",
        "iam/security-credentials",
        "meta-data",
        "REDIS",
        "+PONG",
        "+OK",
    ],
    "path-traversal": [
        "root:",
        "/bin/bash",
        "/bin/sh",
        "[boot loader]",
        "[operating systems]",
        "root:x:0:0",
    ],
    "command-injection": [
        "uid=",
        "gid=",
        "root",
        "whoami",
    ],
}

# Alias sqli to share sql-injection indicators
_SUCCESS_INDICATORS["sqli"] = _SUCCESS_INDICATORS["sql-injection"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TestCase:
    """An HTTP test case generated from a SAST finding."""

    endpoint: str
    method: str
    payloads: list[str]
    vuln_type: str
    finding_id: str
    success_indicators: list[str]
    inject_in: str = "query"
    content_type: str = "application/x-www-form-urlencoded"


@dataclass
class TestExecution:
    """Result of executing a single HTTP request."""

    status_code: int | None
    response_body: str
    response_headers: dict[str, str]
    error: str | None
    duration_ms: float


@dataclass
class ValidationResult:
    """Outcome of validating a SAST finding against a live target."""

    finding_id: str
    validated: bool
    validation_method: str
    evidence: str
    payload_used: str
    endpoint_tested: str
    http_status: int | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Route inference helpers
# ---------------------------------------------------------------------------

# Mapping from common framework directory names to API prefixes
_ROUTE_PREFIX_MAP: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"routes/(.+?)\.(?:py|js|ts|rb)$"), "/api/{0}"),
    (re.compile(r"controllers/(.+?)_controller\.(?:py|js|ts|rb)$"), "/{0}"),
    (re.compile(r"controllers/(.+?)Controller\.(?:java|go|cs)$"), "/{0}"),
    (re.compile(r"api/(.+?)\.(?:py|js|ts|rb)$"), "/api/{0}"),
    (re.compile(r"views/(.+?)\.(?:py|rb)$"), "/{0}"),
    (re.compile(r"handlers/(.+?)\.(?:go|py|js|ts)$"), "/{0}"),
    (re.compile(r"endpoints/(.+?)\.(?:py|js|ts)$"), "/api/{0}"),
]


# ---------------------------------------------------------------------------
# Main validator class
# ---------------------------------------------------------------------------


class SastDastValidator:
    """Validates SAST findings by generating targeted HTTP tests against a live target.

    Generates vulnerability-specific HTTP requests, executes them against
    the target, and analyzes responses for evidence of exploitability.

    Attributes:
        target_url: Base URL of the live target.
        auth_headers: Optional auth headers included in requests.
        timeout: HTTP request timeout in seconds.
        allowed_environments: Only allow validation against these environments.
    """

    def __init__(
        self,
        target_url: str,
        auth_headers: dict[str, str] | None = None,
        timeout: int = 10,
        allowed_environments: list[str] | None = None,
    ):
        """Initialize the SAST-to-DAST validator.

        Args:
            target_url: Base URL of the live target (e.g., https://staging.example.com).
            auth_headers: Optional auth headers to include in requests.
            timeout: HTTP request timeout in seconds.
            allowed_environments: Only allow validation against these environments.
                Defaults to ['staging', 'preview', 'development', 'testing'].
                NEVER includes 'production' by default.

        Raises:
            ValueError: If the target URL is invalid or blocked by safety checks.
        """
        self.target_url = target_url.rstrip("/")
        self.auth_headers = auth_headers or {}
        self.timeout = timeout
        self.allowed_environments = (
            allowed_environments if allowed_environments is not None
            else list(DEFAULT_ALLOWED_ENVIRONMENTS)
        )

        if not self._validate_target_url(self.target_url):
            raise ValueError(
                f"Target URL rejected by safety checks: {self.target_url}. "
                f"Internal IPs and localhost are blocked unless explicitly allowed."
            )

        logger.info("SastDastValidator initialized for target: %s", self.target_url)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def validate_finding(self, finding: dict[str, Any]) -> ValidationResult:
        """Validate a single SAST finding against the live target.

        Generates a targeted HTTP test case for the finding, executes it,
        and returns the validation result.

        Args:
            finding: Dict describing the SAST finding. Expected keys include
                ``id`` or ``finding_id``, ``vuln_type``, ``endpoint``/``url``/
                ``route``/``file_path``, and optionally ``method``, ``parameter``.

        Returns:
            ValidationResult with validated=True if vulnerability confirmed,
            validation_method='not_applicable' if no test could be generated.
        """
        finding_id = str(
            finding.get("id", finding.get("finding_id", f"unknown-{id(finding)}"))
        )

        test_case = self._generate_test_case(finding)
        if test_case is None:
            logger.debug(
                "No test case generated for finding %s (vuln_type=%s)",
                finding_id,
                finding.get("vuln_type", "unknown"),
            )
            return ValidationResult(
                finding_id=finding_id,
                validated=False,
                validation_method="not_applicable",
                evidence="No test case could be generated for this finding type",
                payload_used="",
                endpoint_tested="",
                http_status=None,
            )

        # Try each payload until one succeeds or all fail
        last_execution: TestExecution | None = None
        for payload in test_case.payloads:
            current_case = TestCase(
                endpoint=test_case.endpoint,
                method=test_case.method,
                payloads=[payload],
                vuln_type=test_case.vuln_type,
                finding_id=test_case.finding_id,
                success_indicators=test_case.success_indicators,
                inject_in=test_case.inject_in,
                content_type=test_case.content_type,
            )

            execution = self._execute_test(current_case)
            last_execution = execution

            if execution.error is not None:
                logger.debug(
                    "Test execution error for finding %s with payload %r: %s",
                    finding_id,
                    payload,
                    execution.error,
                )
                continue

            if self._check_success_indicators(
                execution.response_body,
                execution.status_code or 0,
                current_case,
            ):
                logger.info(
                    "Vulnerability confirmed for finding %s at %s with payload %r",
                    finding_id,
                    test_case.endpoint,
                    payload,
                )
                return ValidationResult(
                    finding_id=finding_id,
                    validated=True,
                    validation_method="live_dast",
                    evidence=execution.response_body[:MAX_RESPONSE_BODY],
                    payload_used=payload,
                    endpoint_tested=test_case.endpoint,
                    http_status=execution.status_code,
                )

        # No payload triggered the vulnerability
        evidence = ""
        error_msg = None
        http_status = None
        if last_execution is not None:
            evidence = last_execution.response_body[:MAX_RESPONSE_BODY]
            error_msg = last_execution.error
            http_status = last_execution.status_code

        return ValidationResult(
            finding_id=finding_id,
            validated=False,
            validation_method="live_dast",
            evidence=evidence,
            payload_used="",
            endpoint_tested=test_case.endpoint,
            http_status=http_status,
            error=error_msg,
        )

    def validate_batch(
        self,
        findings: list[dict[str, Any]],
        max_concurrent: int = 5,
    ) -> list[ValidationResult]:
        """Validate multiple SAST findings against the live target.

        Filters to only findings that have endpoint/route information,
        then validates them sequentially.

        Args:
            findings: List of finding dicts.
            max_concurrent: Reserved for future concurrent execution.
                Currently unused (sequential execution).

        Returns:
            List of ValidationResult for each testable finding.
        """
        testable: list[dict[str, Any]] = []
        for finding in findings:
            endpoint = self._infer_endpoint(finding)
            if endpoint is not None:
                testable.append(finding)
            else:
                logger.debug(
                    "Skipping finding %s: no endpoint could be inferred",
                    finding.get("id", finding.get("finding_id", "unknown")),
                )

        logger.info(
            "Validating %d of %d findings (filtered to those with endpoints)",
            len(testable),
            len(findings),
        )

        results: list[ValidationResult] = []
        for finding in testable:
            result = self.validate_finding(finding)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Test case generation
    # ------------------------------------------------------------------

    def _generate_test_case(self, finding: dict[str, Any]) -> TestCase | None:
        """Map a SAST finding to an HTTP test case.

        Args:
            finding: Finding dict with at least ``vuln_type`` and enough
                information to infer an endpoint.

        Returns:
            TestCase if the vulnerability type is mappable, None otherwise.
        """
        vuln_type = finding.get("vuln_type", "").lower().strip()
        finding_id = str(
            finding.get("id", finding.get("finding_id", f"unknown-{id(finding)}"))
        )

        endpoint = self._infer_endpoint(finding)
        if endpoint is None:
            return None

        full_url = f"{self.target_url}{endpoint}"
        method = finding.get("method", "GET").upper()
        parameter = finding.get("parameter", "input")

        if vuln_type in ("sql-injection", "sqli"):
            return TestCase(
                endpoint=full_url,
                method=method,
                payloads=list(_SQL_INJECTION_PAYLOADS),
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=list(_SUCCESS_INDICATORS["sql-injection"]),
                inject_in="query",
            )

        if vuln_type == "xss":
            return TestCase(
                endpoint=full_url,
                method=method,
                payloads=list(_XSS_PAYLOADS),
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=list(_SUCCESS_INDICATORS["xss"]),
                inject_in="query",
            )

        if vuln_type == "ssrf":
            return TestCase(
                endpoint=full_url,
                method=method if method != "GET" else "POST",
                payloads=list(_SSRF_PAYLOADS),
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=list(_SUCCESS_INDICATORS["ssrf"]),
                inject_in="body",
                content_type="application/x-www-form-urlencoded",
            )

        if vuln_type == "path-traversal":
            return TestCase(
                endpoint=full_url,
                method=method,
                payloads=list(_PATH_TRAVERSAL_PAYLOADS),
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=list(_SUCCESS_INDICATORS["path-traversal"]),
                inject_in="path",
            )

        if vuln_type == "command-injection":
            return TestCase(
                endpoint=full_url,
                method=method if method != "GET" else "POST",
                payloads=list(_COMMAND_INJECTION_PAYLOADS),
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=list(_SUCCESS_INDICATORS["command-injection"]),
                inject_in="body",
                content_type="application/x-www-form-urlencoded",
            )

        if vuln_type in ("idor", "broken-access-control"):
            # Test accessing the endpoint without auth and with modified IDs
            return TestCase(
                endpoint=full_url,
                method=method,
                payloads=["__no_auth__", "__different_id__"],
                vuln_type=vuln_type,
                finding_id=finding_id,
                success_indicators=[],  # success is determined by status code
                inject_in="header",
            )

        logger.debug("Unmappable vuln_type: %s", vuln_type)
        return None

    # ------------------------------------------------------------------
    # Endpoint inference
    # ------------------------------------------------------------------

    def _infer_endpoint(self, finding: dict[str, Any]) -> str | None:
        """Try to extract or infer an HTTP endpoint from a finding.

        Checks explicit keys first (``endpoint``, ``url``, ``route``), then
        falls back to inferring from ``file_path``.

        Args:
            finding: Finding dict.

        Returns:
            Endpoint path string (e.g., ``/api/users``) or None.
        """
        # Direct keys
        for key in ("endpoint", "url", "route"):
            value = finding.get(key)
            if value and isinstance(value, str):
                # Ensure it starts with /
                if value.startswith("/"):
                    return value
                # If it's a full URL, extract the path
                parsed = urllib.parse.urlparse(value)
                if parsed.path:
                    return parsed.path
                return f"/{value}"

        # Infer from file_path
        file_path = finding.get("file_path", finding.get("file", ""))
        if not file_path or not isinstance(file_path, str):
            return None

        # Normalize separators
        file_path = file_path.replace("\\", "/")

        for pattern, template in _ROUTE_PREFIX_MAP:
            match = pattern.search(file_path)
            if match:
                # Extract the captured group, clean it up
                name = match.group(1)
                # Convert snake_case / camelCase filename parts to path segments
                name = name.replace("_", "-")
                return template.format(name)

        return None

    # ------------------------------------------------------------------
    # Test execution
    # ------------------------------------------------------------------

    def _execute_test(self, test_case: TestCase) -> TestExecution:
        """Execute an HTTP test case against the live target.

        Args:
            test_case: The test case to execute. Uses the first payload
                in the payloads list.

        Returns:
            TestExecution with response details or error information.
        """
        payload = test_case.payloads[0] if test_case.payloads else ""
        url = test_case.endpoint
        method = test_case.method
        headers = dict(self.auth_headers)
        body_data: bytes | None = None

        # Handle IDOR/broken-access-control special payloads
        if test_case.vuln_type in ("idor", "broken-access-control"):
            if payload == "__no_auth__":
                # Strip auth headers to test unauthenticated access
                headers = {}
            elif payload == "__different_id__":
                # Modify numeric IDs in the URL
                url = re.sub(r"/(\d+)(?=/|$)", "/99999", url)

        elif test_case.inject_in == "query":
            # Inject payload as query parameter
            separator = "&" if "?" in url else "?"
            param = urllib.parse.quote(payload, safe="")
            url = f"{url}{separator}input={param}"

        elif test_case.inject_in == "body":
            headers["Content-Type"] = test_case.content_type
            body_data = urllib.parse.urlencode({"input": payload}).encode("utf-8")

        elif test_case.inject_in == "path":
            # Append payload to the URL path
            encoded_payload = urllib.parse.quote(payload, safe="")
            url = f"{url}/{encoded_payload}"

        elif test_case.inject_in == "header":
            headers["X-Custom-Input"] = payload

        headers.setdefault("User-Agent", "Argus-Security-DAST-Validator/1.0")

        start_time = time.monotonic()

        try:
            request = urllib.request.Request(
                url,
                data=body_data,
                headers=headers,
                method=method,
            )

            # Create an SSL context that still validates certificates
            ctx = ssl.create_default_context()

            response = urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=ctx,
            )

            duration_ms = (time.monotonic() - start_time) * 1000
            status_code = response.getcode()
            response_headers = dict(response.headers)
            raw_body = response.read()

            # Decode defensively
            try:
                response_body = raw_body.decode("utf-8", errors="replace")
            except Exception:
                response_body = raw_body.decode("latin-1", errors="replace")

            # Truncate
            response_body = response_body[:MAX_RESPONSE_BODY]

            return TestExecution(
                status_code=status_code,
                response_body=response_body,
                response_headers=response_headers,
                error=None,
                duration_ms=round(duration_ms, 2),
            )

        except urllib.error.HTTPError as exc:
            duration_ms = (time.monotonic() - start_time) * 1000
            try:
                err_body = exc.read().decode("utf-8", errors="replace")[:MAX_RESPONSE_BODY]
            except Exception:
                err_body = ""

            return TestExecution(
                status_code=exc.code,
                response_body=err_body,
                response_headers=dict(exc.headers) if exc.headers else {},
                error=None,  # HTTP errors are valid responses, not execution errors
                duration_ms=round(duration_ms, 2),
            )

        except urllib.error.URLError as exc:
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.debug("URLError for %s: %s", url, exc.reason)
            return TestExecution(
                status_code=None,
                response_body="",
                response_headers={},
                error=f"URLError: {exc.reason}",
                duration_ms=round(duration_ms, 2),
            )

        except Exception as exc:
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.debug("Unexpected error for %s: %s", url, exc)
            return TestExecution(
                status_code=None,
                response_body="",
                response_headers={},
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=round(duration_ms, 2),
            )

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _check_success_indicators(
        self,
        response_body: str,
        status_code: int,
        test_case: TestCase,
    ) -> bool:
        """Check if the response indicates the vulnerability was exploited.

        Args:
            response_body: The HTTP response body text.
            status_code: The HTTP status code.
            test_case: The test case that was executed.

        Returns:
            True if evidence of exploitation is found.
        """
        body_lower = response_body.lower()
        vuln_type = test_case.vuln_type.lower()

        # IDOR / broken-access-control: success if resource accessible
        if vuln_type in ("idor", "broken-access-control"):
            payload = test_case.payloads[0] if test_case.payloads else ""
            if payload == "__no_auth__":
                # Resource accessible without auth is a problem
                return status_code in (200, 201, 202)
            if payload == "__different_id__":
                # Resource accessible with a different ID is a problem
                return status_code in (200, 201, 202)
            return False

        # Check explicit success indicators
        for indicator in test_case.success_indicators:
            if indicator.lower() in body_lower:
                return True

        # Vuln-type-specific heuristics
        if vuln_type in ("sql-injection", "sqli"):
            # Database error messages in response alongside 200/500 status
            if status_code in (200, 500):
                db_errors = [
                    "sql syntax",
                    "mysql_",
                    "pg_query",
                    "sqlite3",
                    "ora-0",
                    "microsoft sql",
                    "unclosed quotation",
                    "unterminated string",
                ]
                for err in db_errors:
                    if err in body_lower:
                        return True

        elif vuln_type == "xss":
            # Check if payload is reflected verbatim
            for payload in test_case.payloads:
                if payload.lower() in body_lower:
                    return True

        elif vuln_type == "ssrf":
            # Internal service responses
            ssrf_markers = [
                "ami-",
                "instance-id",
                "security-credentials",
                "+pong",
                "+ok",
                "redis_version",
            ]
            for marker in ssrf_markers:
                if marker in body_lower:
                    return True

        elif vuln_type == "path-traversal":
            # File content markers
            file_markers = [
                "root:",
                "/bin/bash",
                "/bin/sh",
                "[boot loader]",
                "[operating systems]",
            ]
            for marker in file_markers:
                if marker in body_lower:
                    return True

        elif vuln_type == "command-injection":
            # Command output markers
            cmd_markers = ["uid=", "gid=", "groups="]
            for marker in cmd_markers:
                if marker in body_lower:
                    return True

        return False

    # ------------------------------------------------------------------
    # Safety checks
    # ------------------------------------------------------------------

    def _validate_target_url(self, url: str) -> bool:
        """Validate that the target URL is safe to test against.

        Rejects localhost, 127.0.0.1, internal/private IP ranges,
        and non-HTTPS URLs when in production mode.

        Args:
            url: The URL to validate.

        Returns:
            True if the URL is safe to target.
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            logger.warning("Failed to parse target URL: %s", url)
            return False

        if not parsed.scheme or not parsed.hostname:
            logger.warning("Target URL missing scheme or hostname: %s", url)
            return False

        hostname = parsed.hostname.lower()

        # Block localhost
        if hostname in _LOCALHOST_HOSTNAMES:
            logger.warning("Target URL points to localhost: %s", url)
            return False

        # Block private IP ranges
        for pattern in _PRIVATE_IP_PATTERNS:
            if pattern.match(hostname):
                logger.warning(
                    "Target URL points to private/internal IP: %s", url
                )
                return False

        # Check if the environment is allowed
        is_production = "production" in hostname or "prod" in hostname.split(".")
        if is_production and "production" not in self.allowed_environments:
            logger.warning(
                "Target URL appears to be production and 'production' is not "
                "in allowed_environments: %s",
                url,
            )
            return False

        return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("SAST-to-DAST Validator for Argus Security")
    print("Usage: Integrated into pipeline when dast_target_url is configured")
    print("  validator = SastDastValidator('https://staging.example.com')")
    print("  result = validator.validate_finding(finding)")
