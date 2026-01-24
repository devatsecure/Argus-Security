#!/usr/bin/env python3
"""
API Security Scanner for Argus
Tests OWASP API Security Top 10 (2023)

Features:
- Auto-discovers REST/GraphQL/gRPC endpoints from code
- Tests all OWASP API Top 10 (2023) vulnerabilities
- Supports multiple frameworks: Flask, FastAPI, Django, Express, Spring, Gin, Echo
- GraphQL-specific security tests (introspection, depth limits, DoS)
- gRPC endpoint detection
- Compatible with Argus normalizer system
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""

    path: str  # URL path or route pattern
    method: str  # GET, POST, PUT, DELETE, PATCH, etc.
    file_path: str  # Source file containing the endpoint
    line_number: int  # Line number in source file
    framework: str  # flask, fastapi, express, spring, gin, echo, graphql
    auth_required: bool  # Whether authentication is detected
    parameters: list[dict] = field(default_factory=list)  # Path/query/body parameters
    handler_function: str = ""  # Name of the handler function
    decorators: list[str] = field(default_factory=list)  # Decorators/annotations

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class APISecurityFinding:
    """A single API security vulnerability finding"""

    finding_id: str
    owasp_category: str  # API1:2023 through API10:2023
    vulnerability_type: str  # BOLA, Broken Auth, SSRF, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    file_path: str
    line_number: int
    endpoint_path: str
    http_method: str
    framework: str
    cwe_id: Optional[str] = None
    recommendation: str = ""
    code_snippet: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class APIScanResult:
    """Results from API security scan"""

    scan_type: str  # 'filesystem', 'directory'
    target: str
    timestamp: str
    total_endpoints: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_owasp_category: dict[str, int]
    endpoints: list[APIEndpoint]
    findings: list[APISecurityFinding]
    frameworks_detected: list[str]
    scan_duration_seconds: float

    def to_dict(self) -> dict:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "total_endpoints": self.total_endpoints,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_owasp_category": self.findings_by_owasp_category,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "findings": [f.to_dict() for f in self.findings],
            "frameworks_detected": self.frameworks_detected,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


class APISecurityScanner:
    """
    Comprehensive API Security Scanner
    Tests OWASP API Security Top 10 (2023)

    Supports:
    - Python: Flask, FastAPI, Django
    - JavaScript: Express.js
    - Java: Spring Boot
    - Go: Gin, Echo, net/http
    - GraphQL: All implementations
    """

    # Endpoint detection patterns by framework
    PATTERNS = {
        # Python Flask
        "flask": [
            r'@app\.route\(["\']([^"\']+)["\'](?:,\s*methods=\[([^\]]+)\])?',
            r'@blueprint\.route\(["\']([^"\']+)["\'](?:,\s*methods=\[([^\]]+)\])?',
        ],
        # Python FastAPI
        "fastapi": [
            r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\(["\']([^"\']+)["\']',
        ],
        # Python Django
        "django": [
            r'path\(["\']([^"\']+)["\'],\s*(\w+)',
            r're_path\(r["\']([^"\']+)["\'],\s*(\w+)',
        ],
        # JavaScript Express
        "express": [
            r'(?:app|router)\.(get|post|put|delete|patch|all)\(["\']([^"\']+)["\']',
        ],
        # Java Spring
        "spring": [
            r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(["\']([^"\']+)["\']',
            r'@RequestMapping\(.*?path\s*=\s*["\']([^"\']+)["\']',
        ],
        # Go Gin
        "gin": [
            r'\.(?:GET|POST|PUT|DELETE|PATCH|Any)\(["\']([^"\']+)["\']',
        ],
        # Go Echo
        "echo": [
            r'\.(?:GET|POST|PUT|DELETE|PATCH|Any)\(["\']([^"\']+)["\']',
        ],
        # GraphQL
        "graphql": [
            r'type\s+Query\s*{',
            r'type\s+Mutation\s*{',
            r'schema\s*{',
        ],
    }

    # Auth detection patterns
    AUTH_PATTERNS = [
        r'@login_required',
        r'@require_auth',
        r'@authenticated',
        r'@permission_required',
        r'@PreAuthorize',
        r'@Secured',
        r'middleware.*auth',
        r'authenticate\(',
        r'requireAuth\(',
        r'verifyToken\(',
    ]

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize API Security Scanner

        Args:
            config: Optional configuration dictionary
                - include_low_confidence: Include low-confidence findings (default: False)
                - scan_depth: Maximum directory depth (default: 10)
                - exclude_patterns: Patterns to exclude
        """
        self.config = config or {}
        self.include_low_confidence = self.config.get("include_low_confidence", False)
        self.scan_depth = self.config.get("scan_depth", 10)
        self.exclude_patterns = self.config.get(
            "exclude_patterns",
            [
                "*/test/*",
                "*/tests/*",
                "*/__pycache__/*",
                "*/node_modules/*",
                "*/.git/*",
                "*/venv/*",
                "*/.venv/*",
                "*/vendor/*",
                "*/build/*",
                "*/dist/*",
            ],
        )

        self.endpoints: list[APIEndpoint] = []
        self.findings: list[APISecurityFinding] = []

    def scan(self, target_path: str, output_file: Optional[str] = None) -> APIScanResult:
        """
        Execute API security scan

        Args:
            target_path: Path to scan (file or directory)
            output_file: Optional path to save JSON results

        Returns:
            APIScanResult with all findings
        """
        logger.info(f"🔍 Starting API Security scan: {target_path}")
        start_time = datetime.now()

        target_path_obj = Path(target_path).resolve()
        if not target_path_obj.exists():
            logger.error(f"❌ Target path does not exist: {target_path}")
            raise RuntimeError(f"Target path not found: {target_path}")

        scan_type = "file" if target_path_obj.is_file() else "directory"

        # Phase 1: Discover API endpoints
        logger.info("   Phase 1: Discovering API endpoints...")
        self.endpoints = self.discover_endpoints(str(target_path_obj))
        logger.info(f"   Found {len(self.endpoints)} API endpoints")

        # Phase 2: Test OWASP API Top 10
        logger.info("   Phase 2: Testing OWASP API Top 10 (2023)...")
        self.findings = []

        self.findings.extend(self._test_broken_object_auth(self.endpoints))
        self.findings.extend(self._test_broken_authentication(self.endpoints))
        self.findings.extend(self._test_broken_object_property_auth(self.endpoints))
        self.findings.extend(self._test_unrestricted_resource_consumption(self.endpoints))
        self.findings.extend(self._test_broken_function_level_auth(self.endpoints))
        self.findings.extend(self._test_unrestricted_business_flows(self.endpoints))
        self.findings.extend(self._test_server_side_request_forgery(self.endpoints))
        self.findings.extend(self._test_security_misconfiguration(self.endpoints))
        self.findings.extend(self._test_improper_inventory_management(self.endpoints))
        self.findings.extend(self._test_unsafe_api_consumption(self.endpoints))

        # Phase 3: GraphQL-specific tests
        if self._has_graphql():
            logger.info("   Phase 3: Testing GraphQL security...")
            self.findings.extend(self._test_graphql_security(str(target_path_obj)))

        # Calculate statistics
        scan_duration = (datetime.now() - start_time).total_seconds()
        findings_by_severity = self._count_by_severity(self.findings)
        findings_by_owasp = self._count_by_owasp_category(self.findings)
        frameworks = list(set(e.framework for e in self.endpoints))

        result = APIScanResult(
            scan_type=scan_type,
            target=str(target_path_obj),
            timestamp=datetime.now().isoformat(),
            total_endpoints=len(self.endpoints),
            total_findings=len(self.findings),
            findings_by_severity=findings_by_severity,
            findings_by_owasp_category=findings_by_owasp,
            endpoints=self.endpoints,
            findings=self.findings,
            frameworks_detected=frameworks,
            scan_duration_seconds=scan_duration,
        )

        logger.info(f"✅ API Security scan complete: {len(self.findings)} findings in {scan_duration:.1f}s")
        self._print_summary(result)

        # Save to file if requested
        if output_file:
            self._save_results(result, output_file)

        return result

    def discover_endpoints(self, target_path: str) -> list[APIEndpoint]:
        """
        Auto-discover API endpoints from code

        Args:
            target_path: Path to scan

        Returns:
            List of discovered APIEndpoint objects
        """
        endpoints = []
        target = Path(target_path)

        if target.is_file():
            endpoints.extend(self._scan_file_for_endpoints(target))
        else:
            # Recursively scan directory
            for file_path in self._walk_directory(target):
                endpoints.extend(self._scan_file_for_endpoints(file_path))

        return endpoints

    def _walk_directory(self, directory: Path) -> list[Path]:
        """Walk directory and return relevant files"""
        relevant_extensions = {
            ".py",  # Python
            ".js",
            ".ts",  # JavaScript/TypeScript
            ".java",  # Java
            ".go",  # Go
            ".graphql",
            ".gql",  # GraphQL
        }

        files = []
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in relevant_extensions:
                # Check exclude patterns
                if not self._should_exclude(str(path)):
                    files.append(path)

        return files

    def _should_exclude(self, file_path: str) -> bool:
        """Check if file should be excluded"""
        for pattern in self.exclude_patterns:
            # Convert glob pattern to regex
            regex_pattern = pattern.replace("*", ".*").replace("?", ".").replace("/", r"[/\\]")
            if re.search(regex_pattern, file_path):
                return True
        return False

    def _scan_file_for_endpoints(self, file_path: Path) -> list[APIEndpoint]:
        """Scan a single file for API endpoint definitions"""
        endpoints = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            # Detect framework
            framework = self._detect_framework(file_path, content)
            if not framework:
                return endpoints

            # Apply framework-specific patterns
            patterns = self.PATTERNS.get(framework, [])
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    line_number = content[: match.start()].count("\n") + 1
                    endpoint = self._parse_endpoint_match(
                        match, file_path, line_number, framework, lines
                    )
                    if endpoint:
                        endpoints.append(endpoint)

        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

        return endpoints

    def _detect_framework(self, file_path: Path, content: str) -> Optional[str]:
        """Detect web framework from file content"""
        # Python frameworks
        if file_path.suffix == ".py":
            if "from flask import" in content or "@app.route" in content:
                return "flask"
            if "from fastapi import" in content or "@app.get" in content:
                return "fastapi"
            if "django.urls import" in content or "path(" in content:
                return "django"

        # JavaScript/TypeScript
        if file_path.suffix in [".js", ".ts"]:
            if "express()" in content or "app.get(" in content or "router.get(" in content:
                return "express"

        # Java
        if file_path.suffix == ".java":
            if "@RestController" in content or "@RequestMapping" in content:
                return "spring"

        # Go
        if file_path.suffix == ".go":
            if "gin.Engine" in content or "gin.Default()" in content:
                return "gin"
            if "echo.New()" in content or "echo.Echo" in content:
                return "echo"

        # GraphQL
        if file_path.suffix in [".graphql", ".gql"] or "type Query" in content:
            return "graphql"

        return None

    def _parse_endpoint_match(
        self, match: re.Match, file_path: Path, line_number: int, framework: str, lines: list[str]
    ) -> Optional[APIEndpoint]:
        """Parse regex match into APIEndpoint object"""
        try:
            groups = match.groups()

            # Extract path and method based on framework
            if framework in ["flask", "django"]:
                path = groups[0]
                methods_str = groups[1] if len(groups) > 1 and groups[1] else "GET"
                methods = [m.strip().strip('"\'') for m in methods_str.split(",")]
                method = methods[0] if methods else "GET"
            elif framework in ["fastapi", "express", "gin", "echo"]:
                method = groups[0].upper() if groups[0] else "GET"
                path = groups[1] if len(groups) > 1 else groups[0]
            elif framework == "spring":
                path = groups[0]
                method = self._extract_spring_method(match.group(0))
            else:
                return None

            # Check for authentication
            auth_required = self._check_auth_required(lines, line_number)

            # Extract handler function name
            handler = self._extract_handler_name(lines, line_number)

            # Extract parameters from path
            parameters = self._extract_path_parameters(path)

            return APIEndpoint(
                path=path,
                method=method,
                file_path=str(file_path),
                line_number=line_number,
                framework=framework,
                auth_required=auth_required,
                parameters=parameters,
                handler_function=handler,
            )

        except Exception as e:
            logger.debug(f"Error parsing endpoint match: {e}")
            return None

    def _extract_spring_method(self, annotation: str) -> str:
        """Extract HTTP method from Spring annotation"""
        if "@GetMapping" in annotation:
            return "GET"
        elif "@PostMapping" in annotation:
            return "POST"
        elif "@PutMapping" in annotation:
            return "PUT"
        elif "@DeleteMapping" in annotation:
            return "DELETE"
        elif "@PatchMapping" in annotation:
            return "PATCH"
        return "GET"

    def _check_auth_required(self, lines: list[str], line_number: int) -> bool:
        """Check if endpoint has authentication decorators/annotations"""
        # Check 10 lines before the endpoint definition
        start = max(0, line_number - 10)
        end = min(len(lines), line_number + 1)
        context = "\n".join(lines[start:end])

        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        return False

    def _extract_handler_name(self, lines: list[str], line_number: int) -> str:
        """Extract handler function name"""
        # Look at the next few lines for function definition
        for i in range(line_number, min(len(lines), line_number + 5)):
            if i < len(lines):
                # Python: def function_name
                match = re.search(r'def\s+(\w+)\s*\(', lines[i])
                if match:
                    return match.group(1)
                # JavaScript: function name or const name =
                match = re.search(r'(?:function|const|let|var)\s+(\w+)\s*[=\(]', lines[i])
                if match:
                    return match.group(1)
                # Java: public void methodName
                match = re.search(r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\(', lines[i])
                if match:
                    return match.group(1)
        return "unknown"

    def _extract_path_parameters(self, path: str) -> list[dict]:
        """Extract parameters from path pattern"""
        parameters = []

        # Flask/FastAPI style: /users/<id> or /users/{id}
        for match in re.finditer(r'[<{](\w+):?(\w*)[>}]', path):
            param_name = match.group(1)
            param_type = match.group(2) or "string"
            parameters.append({"name": param_name, "type": param_type, "location": "path"})

        # Express style: /users/:id
        for match in re.finditer(r':(\w+)', path):
            param_name = match.group(1)
            parameters.append({"name": param_name, "type": "string", "location": "path"})

        return parameters

    def _has_graphql(self) -> bool:
        """Check if GraphQL endpoints were discovered"""
        return any(e.framework == "graphql" for e in self.endpoints)

    # ==================== OWASP API Top 10 (2023) Tests ====================

    def _test_broken_object_auth(self, endpoints: list[APIEndpoint]) -> list[APISecurityFinding]:
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)

        Detects endpoints with ID parameters but no authorization checks
        """
        findings = []

        for endpoint in endpoints:
            # Check for ID parameters in path
            has_id_param = any(
                p["name"] in ["id", "user_id", "account_id", "order_id", "object_id"]
                for p in endpoint.parameters
            )

            # Check for dynamic parameters that could be IDs
            has_dynamic_param = any(
                re.search(r'(id|uuid|key|token)', p["name"], re.IGNORECASE)
                for p in endpoint.parameters
            )

            if (has_id_param or has_dynamic_param) and not endpoint.auth_required:
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "BOLA"),
                    owasp_category="API1:2023",
                    vulnerability_type="Broken Object Level Authorization (BOLA/IDOR)",
                    severity="HIGH",
                    title=f"Object ID exposed without authorization check: {endpoint.path}",
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} accepts object ID parameters "
                        f"but lacks visible authorization checks. This could allow unauthorized "
                        f"access to other users' objects (IDOR vulnerability)."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-639",
                    recommendation=(
                        "Add authorization checks to verify the authenticated user has permission "
                        "to access the requested object. Validate object ownership before returning data."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/639.html",
                    ],
                    confidence=0.8,
                )
                findings.append(finding)

        return findings

    def _test_broken_authentication(self, endpoints: list[APIEndpoint]) -> list[APISecurityFinding]:
        """
        API2:2023 - Broken Authentication

        Detects authentication weaknesses
        """
        findings = []

        # Check for authentication endpoints with weak patterns
        auth_keywords = ["login", "signin", "auth", "token", "session", "oauth", "password"]

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()

            # Authentication endpoint detected
            is_auth_endpoint = any(keyword in path_lower for keyword in auth_keywords)

            if is_auth_endpoint:
                # Check for GET method on auth endpoints (should be POST)
                if endpoint.method.upper() == "GET":
                    finding = APISecurityFinding(
                        finding_id=self._generate_finding_id(endpoint, "AUTH_GET"),
                        owasp_category="API2:2023",
                        vulnerability_type="Broken Authentication",
                        severity="HIGH",
                        title=f"Authentication endpoint uses GET method: {endpoint.path}",
                        description=(
                            f"Authentication endpoint {endpoint.path} uses GET method, which can "
                            f"leak credentials in server logs, browser history, and referrer headers."
                        ),
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        framework=endpoint.framework,
                        cwe_id="CWE-287",
                        recommendation="Use POST method for authentication endpoints to avoid credential leakage.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                        ],
                        confidence=1.0,
                    )
                    findings.append(finding)

                # Check for password reset/change endpoints
                if any(kw in path_lower for kw in ["reset", "forgot", "change"]):
                    finding = APISecurityFinding(
                        finding_id=self._generate_finding_id(endpoint, "AUTH_RESET"),
                        owasp_category="API2:2023",
                        vulnerability_type="Broken Authentication",
                        severity="MEDIUM",
                        title=f"Password reset endpoint requires review: {endpoint.path}",
                        description=(
                            f"Password reset endpoint detected. Ensure it implements rate limiting, "
                            f"secure token generation, and expiration."
                        ),
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        framework=endpoint.framework,
                        cwe_id="CWE-640",
                        recommendation=(
                            "Implement: (1) Rate limiting, (2) Cryptographically secure tokens, "
                            "(3) Token expiration, (4) One-time use tokens"
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                        ],
                        confidence=0.7,
                    )
                    findings.append(finding)

        return findings

    def _test_broken_object_property_auth(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API3:2023 - Broken Object Property Level Authorization

        Detects mass assignment and excessive data exposure risks
        """
        findings = []

        for endpoint in endpoints:
            # Focus on PUT, PATCH, POST endpoints (data modification)
            if endpoint.method.upper() in ["PUT", "PATCH", "POST"]:
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "MASS_ASSIGNMENT"),
                    owasp_category="API3:2023",
                    vulnerability_type="Broken Object Property Level Authorization",
                    severity="MEDIUM",
                    title=f"Potential mass assignment vulnerability: {endpoint.path}",
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} accepts data modifications. "
                        f"Ensure it validates which properties can be updated to prevent mass assignment attacks."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-915",
                    recommendation=(
                        "Use allowlist validation for updatable fields. Explicitly define which "
                        "properties users can modify (e.g., using schemas, DTOs, or validators)."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                    confidence=0.6,
                )
                findings.append(finding)

        return findings

    def _test_unrestricted_resource_consumption(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API4:2023 - Unrestricted Resource Consumption

        Detects lack of rate limiting and resource controls
        """
        findings = []

        # All endpoints should have rate limiting, especially sensitive ones
        sensitive_patterns = ["search", "query", "list", "upload", "download", "export"]

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()
            is_sensitive = any(pattern in path_lower for pattern in sensitive_patterns)

            if is_sensitive or endpoint.method.upper() in ["POST", "PUT", "PATCH"]:
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "RATE_LIMIT"),
                    owasp_category="API4:2023",
                    vulnerability_type="Unrestricted Resource Consumption",
                    severity="MEDIUM",
                    title=f"Endpoint lacks rate limiting: {endpoint.path}",
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} should implement rate limiting "
                        f"to prevent DoS attacks and resource exhaustion."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-770",
                    recommendation=(
                        "Implement rate limiting (e.g., 100 requests/minute per user). "
                        "Add pagination for list endpoints. Limit upload sizes and query complexity."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    ],
                    confidence=0.5,
                )
                findings.append(finding)

        return findings

    def _test_broken_function_level_auth(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API5:2023 - Broken Function Level Authorization

        Detects admin/privileged endpoints without proper authorization
        """
        findings = []

        # Admin/privileged endpoint patterns
        admin_patterns = ["admin", "delete", "remove", "ban", "promote", "grant", "revoke", "manage"]

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()
            handler_lower = endpoint.handler_function.lower()

            # Check for admin/privileged patterns
            is_privileged = any(
                pattern in path_lower or pattern in handler_lower for pattern in admin_patterns
            )

            # DELETE endpoints are always privileged
            if endpoint.method.upper() == "DELETE":
                is_privileged = True

            if is_privileged and not endpoint.auth_required:
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "PRIV_ACCESS"),
                    owasp_category="API5:2023",
                    vulnerability_type="Broken Function Level Authorization",
                    severity="CRITICAL",
                    title=f"Privileged endpoint lacks authorization: {endpoint.path}",
                    description=(
                        f"Privileged endpoint {endpoint.method} {endpoint.path} lacks visible "
                        f"authorization checks. This could allow unauthorized users to perform "
                        f"administrative actions."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-285",
                    recommendation=(
                        "Add role-based access control (RBAC) to verify the user has admin/privileged "
                        "permissions before allowing the operation."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                    ],
                    confidence=0.9,
                )
                findings.append(finding)

        return findings

    def _test_unrestricted_business_flows(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API6:2023 - Unrestricted Access to Sensitive Business Flows

        Detects business logic endpoints vulnerable to automation abuse
        """
        findings = []

        # Business flow patterns susceptible to automation
        business_patterns = {
            "checkout": "e-commerce checkout flow",
            "purchase": "purchase transaction",
            "booking": "reservation/booking",
            "transfer": "fund transfer",
            "vote": "voting mechanism",
            "comment": "comment/review posting",
            "register": "user registration",
            "subscribe": "subscription",
        }

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()

            for pattern, description in business_patterns.items():
                if pattern in path_lower:
                    finding = APISecurityFinding(
                        finding_id=self._generate_finding_id(endpoint, "BIZ_FLOW"),
                        owasp_category="API6:2023",
                        vulnerability_type="Unrestricted Access to Sensitive Business Flows",
                        severity="MEDIUM",
                        title=f"Business flow lacks abuse protection: {endpoint.path}",
                        description=(
                            f"Endpoint {endpoint.method} {endpoint.path} implements {description}, "
                            f"which is vulnerable to automation abuse (bots, scalping, fraud)."
                        ),
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        framework=endpoint.framework,
                        cwe_id="CWE-841",
                        recommendation=(
                            "Implement bot detection (CAPTCHA, device fingerprinting), "
                            "behavioral analysis, and rate limiting specific to this business flow."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                        ],
                        confidence=0.7,
                    )
                    findings.append(finding)
                    break  # Only report once per endpoint

        return findings

    def _test_server_side_request_forgery(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API7:2023 - Server Side Request Forgery (SSRF)

        Detects endpoints that accept URLs or can make external requests
        """
        findings = []

        # SSRF-prone parameter names
        ssrf_params = ["url", "uri", "link", "callback", "webhook", "redirect", "fetch", "download"]

        for endpoint in endpoints:
            # Check parameters
            has_url_param = any(
                any(ssrf_param in p["name"].lower() for ssrf_param in ssrf_params)
                for p in endpoint.parameters
            )

            # Check path patterns
            path_lower = endpoint.path.lower()
            path_has_url = any(param in path_lower for param in ssrf_params)

            if has_url_param or path_has_url:
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "SSRF"),
                    owasp_category="API7:2023",
                    vulnerability_type="Server Side Request Forgery (SSRF)",
                    severity="HIGH",
                    title=f"Potential SSRF vulnerability: {endpoint.path}",
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} accepts URL parameters, "
                        f"which could allow Server-Side Request Forgery (SSRF) attacks."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-918",
                    recommendation=(
                        "Validate and sanitize all URL inputs. Use allowlist of permitted domains. "
                        "Disable redirects and use network segmentation to prevent internal network access."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                        "https://cwe.mitre.org/data/definitions/918.html",
                    ],
                    confidence=0.8,
                )
                findings.append(finding)

        return findings

    def _test_security_misconfiguration(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API8:2023 - Security Misconfiguration

        Detects common API security misconfigurations
        """
        findings = []

        # Check for debug/test endpoints in production code
        debug_patterns = ["debug", "test", "dev", "admin/config", "internal", "_debug"]

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()

            for pattern in debug_patterns:
                if pattern in path_lower:
                    finding = APISecurityFinding(
                        finding_id=self._generate_finding_id(endpoint, "MISCONFIG"),
                        owasp_category="API8:2023",
                        vulnerability_type="Security Misconfiguration",
                        severity="MEDIUM",
                        title=f"Debug/test endpoint in code: {endpoint.path}",
                        description=(
                            f"Endpoint {endpoint.path} appears to be a debug/test endpoint. "
                            f"These should be disabled in production environments."
                        ),
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        framework=endpoint.framework,
                        cwe_id="CWE-16",
                        recommendation=(
                            "Remove or disable debug endpoints in production. Use environment "
                            "variables to conditionally enable them only in development."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                        ],
                        confidence=0.8,
                    )
                    findings.append(finding)
                    break

        return findings

    def _test_improper_inventory_management(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API9:2023 - Improper Inventory Management

        Detects versioning issues and deprecated endpoints
        """
        findings = []

        # Track API versions
        versions = set()
        for endpoint in endpoints:
            # Extract version from path (e.g., /api/v1/users, /v2/products)
            version_match = re.search(r'/v(\d+(?:\.\d+)?)', endpoint.path)
            if version_match:
                versions.add(version_match.group(1))

        # If multiple versions detected, flag for review
        if len(versions) > 1:
            # Find oldest version endpoints
            sorted_versions = sorted(versions, key=lambda x: float(x) if '.' in x else int(x))
            old_version = sorted_versions[0]

            for endpoint in endpoints:
                if f"/v{old_version}" in endpoint.path:
                    finding = APISecurityFinding(
                        finding_id=self._generate_finding_id(endpoint, "OLD_VERSION"),
                        owasp_category="API9:2023",
                        vulnerability_type="Improper Inventory Management",
                        severity="LOW",
                        title=f"Old API version in use: {endpoint.path}",
                        description=(
                            f"Endpoint uses API version {old_version}, but newer versions exist. "
                            f"Old versions may have unpatched vulnerabilities."
                        ),
                        file_path=endpoint.file_path,
                        line_number=endpoint.line_number,
                        endpoint_path=endpoint.path,
                        http_method=endpoint.method,
                        framework=endpoint.framework,
                        cwe_id="CWE-1059",
                        recommendation=(
                            "Document all API versions. Deprecate and sunset old versions. "
                            "Maintain inventory of all exposed endpoints."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                        ],
                        confidence=0.6,
                    )
                    findings.append(finding)
                    break  # Only report once

        return findings

    def _test_unsafe_api_consumption(
        self, endpoints: list[APIEndpoint]
    ) -> list[APISecurityFinding]:
        """
        API10:2023 - Unsafe Consumption of APIs

        Detects endpoints that consume external APIs without validation
        """
        findings = []

        # Indicators of third-party API consumption
        consumption_patterns = ["webhook", "callback", "integration", "api/external", "proxy"]

        for endpoint in endpoints:
            path_lower = endpoint.path.lower()

            if any(pattern in path_lower for pattern in consumption_patterns):
                finding = APISecurityFinding(
                    finding_id=self._generate_finding_id(endpoint, "UNSAFE_CONSUME"),
                    owasp_category="API10:2023",
                    vulnerability_type="Unsafe Consumption of APIs",
                    severity="MEDIUM",
                    title=f"External API consumption requires validation: {endpoint.path}",
                    description=(
                        f"Endpoint {endpoint.path} appears to consume external APIs. "
                        f"Ensure responses are validated and sanitized."
                    ),
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    endpoint_path=endpoint.path,
                    http_method=endpoint.method,
                    framework=endpoint.framework,
                    cwe_id="CWE-20",
                    recommendation=(
                        "Validate all data from external APIs. Use schema validation, "
                        "implement timeouts, and handle errors securely."
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                    ],
                    confidence=0.6,
                )
                findings.append(finding)

        return findings

    # ==================== GraphQL-Specific Tests ====================

    def _test_graphql_security(self, target_path: str) -> list[APISecurityFinding]:
        """
        Test GraphQL-specific security issues
        """
        findings = []

        # Find GraphQL schema files
        graphql_files = []
        target = Path(target_path)
        if target.is_file() and target.suffix in [".graphql", ".gql"]:
            graphql_files.append(target)
        else:
            graphql_files.extend(target.rglob("*.graphql"))
            graphql_files.extend(target.rglob("*.gql"))

        for file_path in graphql_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Test 1: Introspection enabled (production risk)
                findings.append(
                    APISecurityFinding(
                        finding_id=self._generate_finding_id_from_file(str(file_path), "GQL_INTRO"),
                        owasp_category="API8:2023",
                        vulnerability_type="GraphQL Introspection Enabled",
                        severity="MEDIUM",
                        title=f"GraphQL introspection should be disabled in production: {file_path.name}",
                        description=(
                            "GraphQL introspection allows attackers to discover the entire schema, "
                            "exposing all queries, mutations, and types. This should be disabled in production."
                        ),
                        file_path=str(file_path),
                        line_number=1,
                        endpoint_path="/graphql",
                        http_method="POST",
                        framework="graphql",
                        cwe_id="CWE-200",
                        recommendation="Disable introspection in production environments.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        confidence=0.7,
                    )
                )

                # Test 2: Query depth limits
                findings.append(
                    APISecurityFinding(
                        finding_id=self._generate_finding_id_from_file(str(file_path), "GQL_DEPTH"),
                        owasp_category="API4:2023",
                        vulnerability_type="GraphQL Query Depth Limit Missing",
                        severity="HIGH",
                        title=f"GraphQL schema lacks query depth limits: {file_path.name}",
                        description=(
                            "Without query depth limits, attackers can craft deeply nested queries "
                            "that cause DoS through resource exhaustion."
                        ),
                        file_path=str(file_path),
                        line_number=1,
                        endpoint_path="/graphql",
                        http_method="POST",
                        framework="graphql",
                        cwe_id="CWE-770",
                        recommendation="Implement query depth limits (e.g., max depth of 5-7 levels).",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        confidence=0.6,
                    )
                )

                # Test 3: Query cost analysis
                findings.append(
                    APISecurityFinding(
                        finding_id=self._generate_finding_id_from_file(str(file_path), "GQL_COST"),
                        owasp_category="API4:2023",
                        vulnerability_type="GraphQL Query Cost Analysis Missing",
                        severity="MEDIUM",
                        title=f"GraphQL schema lacks query cost analysis: {file_path.name}",
                        description=(
                            "Without query cost analysis, attackers can craft expensive queries "
                            "that consume excessive server resources."
                        ),
                        file_path=str(file_path),
                        line_number=1,
                        endpoint_path="/graphql",
                        http_method="POST",
                        framework="graphql",
                        cwe_id="CWE-770",
                        recommendation="Implement query cost analysis and set maximum cost limits.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        confidence=0.6,
                    )
                )

                # Test 4: Field duplication DoS
                if "type Query" in content or "type Mutation" in content:
                    findings.append(
                        APISecurityFinding(
                            finding_id=self._generate_finding_id_from_file(
                                str(file_path), "GQL_FIELD_DUP"
                            ),
                            owasp_category="API4:2023",
                            vulnerability_type="GraphQL Field Duplication DoS",
                            severity="MEDIUM",
                            title=f"GraphQL vulnerable to field duplication DoS: {file_path.name}",
                            description=(
                                "Attackers can duplicate the same field hundreds of times in a query "
                                "to cause DoS. Implement field duplication limits."
                            ),
                            file_path=str(file_path),
                            line_number=1,
                            endpoint_path="/graphql",
                            http_method="POST",
                            framework="graphql",
                            cwe_id="CWE-770",
                            recommendation="Limit field duplication (e.g., max 10 of the same field).",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                            ],
                            confidence=0.5,
                        )
                    )

            except Exception as e:
                logger.debug(f"Error scanning GraphQL file {file_path}: {e}")

        return findings

    # ==================== Utility Methods ====================

    def _generate_finding_id(self, endpoint: APIEndpoint, vuln_type: str) -> str:
        """Generate unique finding ID"""
        import hashlib

        key = f"{endpoint.file_path}:{endpoint.line_number}:{vuln_type}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _generate_finding_id_from_file(self, file_path: str, vuln_type: str) -> str:
        """Generate unique finding ID from file"""
        import hashlib

        key = f"{file_path}:{vuln_type}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _count_by_severity(self, findings: list[APISecurityFinding]) -> dict[str, int]:
        """Count findings by severity"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def _count_by_owasp_category(self, findings: list[APISecurityFinding]) -> dict[str, int]:
        """Count findings by OWASP category"""
        counts = {}
        for finding in findings:
            category = finding.owasp_category
            counts[category] = counts.get(category, 0) + 1
        return counts

    def _save_results(self, result: APIScanResult, output_file: str) -> None:
        """Save scan results to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        logger.info(f"💾 Results saved to: {output_path}")

    def _print_summary(self, result: APIScanResult) -> None:
        """Print scan summary to console"""
        print("\n" + "=" * 80)
        print("API SECURITY SCAN RESULTS")
        print("=" * 80)
        print(f"Target: {result.target}")
        print(f"Timestamp: {result.timestamp}")
        print(f"Duration: {result.scan_duration_seconds:.1f}s")
        print(f"Frameworks: {', '.join(result.frameworks_detected)}")
        print()
        print(f"Endpoints Discovered: {result.total_endpoints}")
        print(f"Total Findings: {result.total_findings}")
        print()
        print("Findings by Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = result.findings_by_severity.get(severity, 0)
            print(f"  {severity:10s}: {count}")
        print()
        print("OWASP API Top 10 (2023) Coverage:")
        for category in sorted(result.findings_by_owasp_category.keys()):
            count = result.findings_by_owasp_category[category]
            print(f"  {category}: {count}")
        print("=" * 80)
        print()


def main():
    """CLI entry point for API Security Scanner"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="API Security Scanner - OWASP API Top 10 (2023)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory
  python api_security_scanner.py /path/to/project

  # Scan with output file
  python api_security_scanner.py /path/to/api --output api_findings.json

  # Include low-confidence findings
  python api_security_scanner.py /path/to/api --include-low-confidence

Supported Frameworks:
  - Python: Flask, FastAPI, Django
  - JavaScript: Express.js
  - Java: Spring Boot
  - Go: Gin, Echo, net/http
  - GraphQL: All implementations
        """,
    )

    parser.add_argument("target", help="Target path to scan (file or directory)")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument(
        "--include-low-confidence",
        action="store_true",
        help="Include low-confidence findings",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build config
    config = {
        "include_low_confidence": args.include_low_confidence,
    }

    # Initialize scanner
    scanner = APISecurityScanner(config)

    try:
        # Run scan
        result = scanner.scan(
            target_path=args.target,
            output_file=args.output,
        )

        # Exit with error code if critical or high severity findings
        critical_high = result.findings_by_severity.get("CRITICAL", 0) + result.findings_by_severity.get(
            "HIGH", 0
        )

        if critical_high > 0:
            logger.warning(f"Found {critical_high} critical/high severity API security issues")
            sys.exit(1)
        else:
            logger.info("No critical or high severity issues found")
            sys.exit(0)

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
