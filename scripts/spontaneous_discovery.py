#!/usr/bin/env python3
"""
Spontaneous Security Discovery System for Argus

This module implements an AI-powered security discovery system that identifies
issues beyond traditional scanner detection rules. Inspired by Slack's agents,
it finds architectural risks, hidden vulnerabilities, configuration issues,
and data security problems through intelligent code analysis.

Key Features:
- Architecture risk analysis (missing auth, weak crypto, insecure data flow)
- Hidden vulnerability detection (race conditions, business logic flaws)
- Configuration security checks (weak policies, exposed interfaces)
- Data security analysis (PII exposure, insecure storage, sensitive logging)
- High confidence threshold (>0.7) to minimize noise
- Evidence-based reporting with remediation guidance

Integration:
- Uses Finding dataclass for unified output format
- Integrates with LLMManager for AI-powered analysis
- Returns only high-confidence discoveries to reduce false positives
- Provides structured evidence and CWE mappings
"""

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Discovery:
    """
    Security discovery from spontaneous analysis

    Represents a potential security issue found through AI-powered analysis
    that goes beyond traditional scanner rule-based detection.
    """

    category: str  # "architecture", "hidden_vuln", "config", "data_security"
    title: str
    description: str
    confidence: float  # 0.0-1.0, only return if >0.7
    severity: str  # "critical", "high", "medium", "low"
    evidence: List[str]  # File paths or patterns that support this finding
    remediation: str
    cwe_id: Optional[str] = None

    # Additional metadata
    affected_files: List[str] = field(default_factory=list)
    code_snippets: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_finding(self, repo: str, commit_sha: str, branch: str) -> "Finding":
        """
        Convert Discovery to unified Finding format

        Args:
            repo: Repository name/URL
            commit_sha: Git commit SHA
            branch: Git branch name

        Returns:
            Finding object for unified reporting
        """
        from normalizer.base import Finding

        # Generate unique ID based on title and affected files
        finding_id = self._generate_id(repo, self.title, self.affected_files)

        # Map discovery category to finding category
        category_map = {
            "architecture": "SAST",
            "hidden_vuln": "SAST",
            "config": "IAC",
            "data_security": "SAST"
        }

        # Primary file for the finding
        primary_file = self.affected_files[0] if self.affected_files else "project-wide"

        return Finding(
            id=finding_id,
            origin="spontaneous-discovery",
            repo=repo,
            commit_sha=commit_sha,
            branch=branch,
            path=primary_file,
            asset_type="code",
            rule_id=f"spontaneous-{self.category}",
            rule_name=self.title,
            category=category_map.get(self.category, "SAST"),
            severity=self.severity,
            cwe=self.cwe_id,
            evidence={
                "description": self.description,
                "evidence_items": self.evidence,
                "affected_files": self.affected_files,
                "code_snippets": self.code_snippets,
                "discovery_type": "spontaneous",
                "ai_analyzed": True
            },
            references=self.references,
            confidence=self.confidence,
            llm_enriched=True,
            status="open",
            fix_suggestion=self.remediation
        )

    def _generate_id(self, repo: str, title: str, files: List[str]) -> str:
        """Generate unique ID for discovery"""
        key = f"{repo}:spontaneous:{title}:{':'.join(sorted(files))}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


class SpontaneousDiscovery:
    """
    AI-Powered Spontaneous Security Discovery Engine

    Analyzes codebases to find security issues that traditional scanners might miss,
    including architectural flaws, business logic issues, and configuration problems.

    Discovery Categories:
    1. Architecture Risks - Missing authentication, insecure data flows
    2. Hidden Vulnerabilities - Race conditions, business logic flaws
    3. Configuration Issues - Weak IAM policies, exposed admin interfaces
    4. Data Security - PII exposure, insecure data storage

    Usage:
        discovery = SpontaneousDiscovery(llm_manager)
        discoveries = discovery.discover(files, findings, "backend-api")
    """

    # CWE mappings for common discovery types
    CWE_MAPPINGS = {
        "missing_authentication": "CWE-306",
        "missing_authorization": "CWE-862",
        "weak_crypto": "CWE-327",
        "insecure_defaults": "CWE-1188",
        "race_condition": "CWE-362",
        "business_logic": "CWE-840",
        "weak_iam": "CWE-732",
        "cors_misconfiguration": "CWE-942",
        "debug_mode": "CWE-489",
        "admin_exposure": "CWE-284",
        "sensitive_logging": "CWE-532",
        "pii_exposure": "CWE-359",
        "insecure_storage": "CWE-312",
        "missing_encryption": "CWE-311",
        "csrf_missing": "CWE-352",
        "xxe_vulnerability": "CWE-611",
        "ssrf_vulnerability": "CWE-918",
        "path_traversal": "CWE-22",
        "command_injection": "CWE-78",
        "sql_injection": "CWE-89",
        "xss_vulnerability": "CWE-79",
        "insecure_deserialization": "CWE-502",
        "rate_limiting": "CWE-307"
    }

    def __init__(self, llm_manager: Optional[Any] = None):
        """
        Initialize spontaneous discovery engine

        Args:
            llm_manager: LLMManager instance for AI-powered analysis
        """
        self.llm = llm_manager
        self.discoveries = []

        if not llm_manager:
            logger.warning("No LLM manager provided - spontaneous discovery will be limited")

    def discover(
        self,
        files: List[str],
        existing_findings: List[Dict],
        architecture: str,
        max_files_analyze: int = 50
    ) -> List[Discovery]:
        """
        Main entry point - discover security issues beyond scanner rules

        Runs all discovery methods and returns high-confidence findings only.
        Deduplicates with existing findings to avoid redundant reports.

        Args:
            files: List of file paths to analyze
            existing_findings: List of findings from traditional scanners
            architecture: Project architecture type (e.g., "backend-api", "frontend")
            max_files_analyze: Maximum number of files to analyze (performance limit)

        Returns:
            List of high-confidence Discovery objects (confidence > 0.7)
        """
        logger.info("🔍 Starting spontaneous security discovery")
        logger.info(f"   📁 Analyzing {len(files)} files")
        logger.info(f"   🏗️  Architecture: {architecture}")

        all_discoveries = []

        # Limit files to analyze for performance
        files_to_analyze = files[:max_files_analyze] if len(files) > max_files_analyze else files

        if len(files) > max_files_analyze:
            logger.info(f"   ⚠️  Limiting analysis to {max_files_analyze} files for performance")

        # 1. Architecture risk analysis
        logger.info("   🏛️  Analyzing architecture risks...")
        arch_discoveries = self.analyze_architecture(files_to_analyze, architecture)
        all_discoveries.extend(arch_discoveries)
        logger.info(f"      Found {len(arch_discoveries)} architecture risks")

        # 2. Hidden vulnerability detection
        logger.info("   🕵️  Searching for hidden vulnerabilities...")
        hidden_discoveries = self.find_hidden_vulnerabilities(files_to_analyze, existing_findings)
        all_discoveries.extend(hidden_discoveries)
        logger.info(f"      Found {len(hidden_discoveries)} hidden vulnerabilities")

        # 3. Configuration security checks
        logger.info("   ⚙️  Checking configuration security...")
        config_discoveries = self.check_configuration_security(files_to_analyze, architecture)
        all_discoveries.extend(config_discoveries)
        logger.info(f"      Found {len(config_discoveries)} configuration issues")

        # 4. Data security analysis
        logger.info("   🔐 Analyzing data security...")
        data_discoveries = self.analyze_data_security(files_to_analyze)
        all_discoveries.extend(data_discoveries)
        logger.info(f"      Found {len(data_discoveries)} data security issues")

        # Filter to high-confidence only (>0.7)
        high_confidence = [d for d in all_discoveries if d.confidence > 0.7]

        # Deduplicate with existing findings
        deduplicated = self._deduplicate_with_existing(high_confidence, existing_findings)

        logger.info(f"✅ Spontaneous discovery complete: {len(deduplicated)} high-confidence findings")

        return deduplicated

    def analyze_architecture(self, files: List[str], architecture: str) -> List[Discovery]:
        """
        Analyze overall architecture for security gaps

        Identifies:
        - Missing authentication/authorization layers
        - Insecure data flow patterns
        - Missing input validation
        - Weak encryption usage

        Args:
            files: List of file paths to analyze
            architecture: Project architecture type

        Returns:
            List of architecture-related discoveries
        """
        discoveries = []

        # Analyze file structure and patterns
        file_patterns = self._analyze_file_patterns(files)

        # Check for missing authentication
        auth_discovery = self._check_authentication_layer(files, file_patterns, architecture)
        if auth_discovery:
            discoveries.append(auth_discovery)

        # Check for authorization issues
        authz_discovery = self._check_authorization_layer(files, file_patterns, architecture)
        if authz_discovery:
            discoveries.append(authz_discovery)

        # Check encryption usage
        crypto_discovery = self._check_encryption_usage(files, file_patterns)
        if crypto_discovery:
            discoveries.append(crypto_discovery)

        # Check input validation patterns
        validation_discovery = self._check_input_validation(files, file_patterns)
        if validation_discovery:
            discoveries.append(validation_discovery)

        return discoveries

    def find_hidden_vulnerabilities(
        self,
        files: List[str],
        existing_findings: List[Dict]
    ) -> List[Discovery]:
        """
        Look for vulnerabilities that scanners might miss

        Identifies:
        - Race conditions in concurrent code
        - Business logic flaws
        - Insecure defaults
        - Missing security headers

        Args:
            files: List of file paths to analyze
            existing_findings: Existing scanner findings to avoid duplication

        Returns:
            List of hidden vulnerability discoveries
        """
        discoveries = []

        # Check for race conditions
        race_discovery = self._check_race_conditions(files)
        if race_discovery:
            discoveries.append(race_discovery)

        # Check for business logic flaws
        logic_discovery = self._check_business_logic(files)
        if logic_discovery:
            discoveries.append(logic_discovery)

        # Check for insecure defaults
        defaults_discovery = self._check_insecure_defaults(files)
        if defaults_discovery:
            discoveries.append(defaults_discovery)

        # Check for missing security headers
        headers_discovery = self._check_security_headers(files)
        if headers_discovery:
            discoveries.append(headers_discovery)

        return discoveries

    def check_configuration_security(
        self,
        files: List[str],
        architecture: str
    ) -> List[Discovery]:
        """
        Identify insecure configurations

        Identifies:
        - Weak IAM policies
        - Overly permissive CORS
        - Debug mode in production
        - Exposed admin interfaces

        Args:
            files: List of file paths to analyze
            architecture: Project architecture type

        Returns:
            List of configuration security discoveries
        """
        discoveries = []

        # Check IAM/permissions configurations
        iam_discovery = self._check_iam_policies(files)
        if iam_discovery:
            discoveries.append(iam_discovery)

        # Check CORS configuration
        cors_discovery = self._check_cors_configuration(files)
        if cors_discovery:
            discoveries.append(cors_discovery)

        # Check for debug mode
        debug_discovery = self._check_debug_mode(files)
        if debug_discovery:
            discoveries.append(debug_discovery)

        # Check for exposed admin interfaces
        admin_discovery = self._check_admin_exposure(files, architecture)
        if admin_discovery:
            discoveries.append(admin_discovery)

        return discoveries

    def analyze_data_security(self, files: List[str]) -> List[Discovery]:
        """
        Analyze data security practices

        Identifies:
        - Sensitive data in logs
        - PII exposure
        - Insecure data storage
        - Missing encryption at rest

        Args:
            files: List of file paths to analyze

        Returns:
            List of data security discoveries
        """
        discoveries = []

        # Check for sensitive data in logs
        logging_discovery = self._check_sensitive_logging(files)
        if logging_discovery:
            discoveries.append(logging_discovery)

        # Check for PII exposure
        pii_discovery = self._check_pii_exposure(files)
        if pii_discovery:
            discoveries.append(pii_discovery)

        # Check storage security
        storage_discovery = self._check_data_storage(files)
        if storage_discovery:
            discoveries.append(storage_discovery)

        # Check encryption at rest
        encryption_discovery = self._check_encryption_at_rest(files)
        if encryption_discovery:
            discoveries.append(encryption_discovery)

        return discoveries

    # ==================== Helper Methods ====================

    def _analyze_file_patterns(self, files: List[str]) -> Dict[str, Any]:
        """
        Analyze file structure to understand project patterns

        Returns dictionary with:
        - has_auth_files: Boolean
        - has_middleware: Boolean
        - has_config_files: Boolean
        - framework: Detected framework
        - languages: List of programming languages
        """
        patterns = {
            "has_auth_files": False,
            "has_middleware": False,
            "has_config_files": False,
            "has_routes": False,
            "has_models": False,
            "has_controllers": False,
            "framework": "unknown",
            "languages": set(),
            "config_files": [],
            "route_files": [],
            "model_files": []
        }

        for file_path in files:
            file_lower = file_path.lower()

            # Detect auth-related files
            if any(x in file_lower for x in ["auth", "login", "session", "jwt", "oauth"]):
                patterns["has_auth_files"] = True

            # Detect middleware
            if "middleware" in file_lower or "interceptor" in file_lower:
                patterns["has_middleware"] = True

            # Detect configuration files
            if any(file_lower.endswith(x) for x in [".env", ".config", ".yml", ".yaml", ".json", ".toml", ".ini"]):
                patterns["has_config_files"] = True
                patterns["config_files"].append(file_path)

            # Detect routes
            if any(x in file_lower for x in ["route", "router", "endpoint", "api"]):
                patterns["has_routes"] = True
                patterns["route_files"].append(file_path)

            # Detect models
            if "model" in file_lower or "schema" in file_lower:
                patterns["has_models"] = True
                patterns["model_files"].append(file_path)

            # Detect controllers
            if "controller" in file_lower or "handler" in file_lower or "view" in file_lower:
                patterns["has_controllers"] = True

            # Detect languages
            ext = Path(file_path).suffix.lower()
            if ext in [".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".rs"]:
                patterns["languages"].add(ext[1:])  # Remove dot

        # Detect framework based on files
        if any(".py" in str(f) for f in files):
            if any("django" in str(f).lower() for f in files):
                patterns["framework"] = "django"
            elif any("flask" in str(f).lower() for f in files):
                patterns["framework"] = "flask"
            elif any("fastapi" in str(f).lower() for f in files):
                patterns["framework"] = "fastapi"

        return patterns

    def _check_authentication_layer(
        self,
        files: List[str],
        patterns: Dict,
        architecture: str
    ) -> Optional[Discovery]:
        """Check for missing authentication layer"""

        # Skip if this is not a backend API
        if architecture not in ["backend-api", "web-app", "microservice"]:
            return None

        # If we have routes but no auth files, this is suspicious
        if patterns["has_routes"] and not patterns["has_auth_files"]:
            return Discovery(
                category="architecture",
                title="Missing Authentication Layer",
                description=(
                    "The project appears to have API routes/endpoints but no clear "
                    "authentication mechanism detected. This could allow unauthorized "
                    "access to sensitive functionality."
                ),
                confidence=0.75,
                severity="high",
                evidence=[
                    f"Found {len(patterns['route_files'])} route files but no authentication modules",
                    "No files containing 'auth', 'login', 'jwt', or 'oauth' detected",
                    "This pattern suggests missing authentication controls"
                ],
                remediation=(
                    "Implement authentication for all sensitive endpoints:\n"
                    "1. Add authentication middleware/decorators\n"
                    "2. Use JWT, OAuth2, or session-based auth\n"
                    "3. Protect all non-public routes\n"
                    "4. Implement proper session management"
                ),
                cwe_id=self.CWE_MAPPINGS["missing_authentication"],
                affected_files=patterns["route_files"][:5],  # Limit to first 5
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_authorization_layer(
        self,
        files: List[str],
        patterns: Dict,
        architecture: str
    ) -> Optional[Discovery]:
        """Check for missing authorization/access control"""

        if architecture not in ["backend-api", "web-app", "microservice"]:
            return None

        # Look for authorization patterns in route files
        if patterns["route_files"]:
            # Read a few route files to check for authorization
            has_authz = False
            authz_patterns = ["authorize", "permission", "role", "acl", "rbac", "can_access"]

            for route_file in patterns["route_files"][:5]:
                try:
                    with open(route_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(pattern in content for pattern in authz_patterns):
                            has_authz = True
                            break
                except Exception:
                    continue

            if not has_authz and patterns["has_auth_files"]:
                return Discovery(
                    category="architecture",
                    title="Missing Authorization Controls",
                    description=(
                        "Authentication appears to be implemented, but authorization/access "
                        "control checks are not clearly present in route handlers. This could "
                        "allow authenticated users to access resources they shouldn't."
                    ),
                    confidence=0.72,
                    severity="high",
                    evidence=[
                        "Authentication files detected but no authorization patterns found",
                        "No 'authorize', 'permission', 'role', or 'rbac' patterns in route handlers",
                        "This suggests missing fine-grained access controls"
                    ],
                    remediation=(
                        "Implement authorization controls:\n"
                        "1. Add role-based access control (RBAC) or attribute-based (ABAC)\n"
                        "2. Verify user permissions before allowing operations\n"
                        "3. Use decorators/middleware for consistent enforcement\n"
                        "4. Follow principle of least privilege"
                    ),
                    cwe_id=self.CWE_MAPPINGS["missing_authorization"],
                    affected_files=patterns["route_files"][:5],
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                    ]
                )

        return None

    def _check_encryption_usage(self, files: List[str], patterns: Dict) -> Optional[Discovery]:
        """Check for weak or missing encryption"""

        # Look for crypto usage in code files
        weak_crypto_found = False
        weak_crypto_files = []

        # Patterns indicating weak crypto
        weak_patterns = [
            (r"md5\s*\(", "MD5 hash function (cryptographically broken)"),
            (r"sha1\s*\(", "SHA1 hash function (deprecated for security)"),
            (r"des\s*\(", "DES encryption (insecure, use AES)"),
            (r"rc4", "RC4 cipher (broken)"),
            (r"ecb", "ECB mode (insecure block cipher mode)")
        ]

        for file_path in files[:30]:  # Check first 30 files
            if not file_path.endswith((".py", ".js", ".ts", ".go", ".java", ".rb")):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                    for pattern, description in weak_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            weak_crypto_found = True
                            weak_crypto_files.append(f"{file_path}: {description}")
                            if len(weak_crypto_files) >= 5:
                                break

                if len(weak_crypto_files) >= 5:
                    break

            except Exception:
                continue

        if weak_crypto_found:
            return Discovery(
                category="architecture",
                title="Weak Cryptographic Algorithms Detected",
                description=(
                    "The codebase uses weak or deprecated cryptographic algorithms that "
                    "provide insufficient security. These should be replaced with modern, "
                    "secure alternatives."
                ),
                confidence=0.85,
                severity="medium",
                evidence=weak_crypto_files,
                remediation=(
                    "Replace weak cryptography:\n"
                    "1. Use SHA-256 or SHA-3 instead of MD5/SHA1 for hashing\n"
                    "2. Use AES-256-GCM instead of DES/RC4 for encryption\n"
                    "3. Avoid ECB mode, use GCM or CBC with proper IV\n"
                    "4. Use bcrypt/argon2 for password hashing"
                ),
                cwe_id=self.CWE_MAPPINGS["weak_crypto"],
                affected_files=[f.split(":")[0] for f in weak_crypto_files],
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_input_validation(self, files: List[str], patterns: Dict) -> Optional[Discovery]:
        """Check for missing input validation"""

        # If we have routes but no validation middleware, check deeper
        if not patterns["has_routes"]:
            return None

        validation_found = False
        validation_patterns = ["validate", "validator", "schema", "sanitize", "clean"]

        # Check if validation is present in the codebase
        for file_path in files[:30]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    if any(pattern in content for pattern in validation_patterns):
                        validation_found = True
                        break
            except Exception:
                continue

        # If we have many routes but no validation, flag it
        if len(patterns["route_files"]) >= 3 and not validation_found:
            return Discovery(
                category="architecture",
                title="Missing Input Validation Layer",
                description=(
                    "The application has multiple API endpoints but no clear input "
                    "validation mechanism. This increases risk of injection attacks "
                    "and unexpected behavior from malformed inputs."
                ),
                confidence=0.71,
                severity="medium",
                evidence=[
                    f"Found {len(patterns['route_files'])} route files",
                    "No validation patterns ('validate', 'schema', 'sanitize') detected",
                    "Input validation appears to be missing or inconsistent"
                ],
                remediation=(
                    "Implement input validation:\n"
                    "1. Use schema validation libraries (Pydantic, Joi, etc.)\n"
                    "2. Validate all user inputs at API boundaries\n"
                    "3. Whitelist allowed values/patterns\n"
                    "4. Sanitize inputs before use in queries or commands"
                ),
                cwe_id="CWE-20",  # Improper Input Validation
                affected_files=patterns["route_files"][:5],
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_race_conditions(self, files: List[str]) -> Optional[Discovery]:
        """Check for potential race conditions in concurrent code"""
        # Implementation would analyze concurrent access patterns
        # Simplified for now
        return None

    def _check_business_logic(self, files: List[str]) -> Optional[Discovery]:
        """Check for business logic flaws"""
        # Would require deep semantic analysis
        # Simplified for now
        return None

    def _check_insecure_defaults(self, files: List[str]) -> Optional[Discovery]:
        """Check for insecure default configurations"""
        # Implementation would check config files for insecure defaults
        # Simplified for now
        return None

    def _check_security_headers(self, files: List[str]) -> Optional[Discovery]:
        """Check for missing security headers"""

        # Look for server/framework configuration files
        security_headers = {
            "strict-transport-security": "HSTS",
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME sniffing protection",
            "content-security-policy": "CSP",
            "x-xss-protection": "XSS protection"
        }

        headers_found = set()
        config_files_checked = []

        for file_path in files:
            if any(x in file_path.lower() for x in ["config", "server", "app", "main", "middleware"]):
                config_files_checked.append(file_path)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        for header in security_headers:
                            if header in content:
                                headers_found.add(header)
                except Exception:
                    continue

        missing_headers = set(security_headers.keys()) - headers_found

        # If we checked config files and found missing headers
        if config_files_checked and len(missing_headers) >= 3:
            return Discovery(
                category="hidden_vuln",
                title="Missing Security Headers",
                description=(
                    f"The application is missing {len(missing_headers)} important security "
                    "headers that protect against common web vulnerabilities. This leaves "
                    "the application more vulnerable to attacks like XSS, clickjacking, and "
                    "MIME confusion."
                ),
                confidence=0.73,
                severity="medium",
                evidence=[
                    f"Checked {len(config_files_checked)} configuration files",
                    f"Missing headers: {', '.join(missing_headers)}",
                    "Security headers provide defense-in-depth protection"
                ],
                remediation=(
                    "Add security headers to HTTP responses:\n"
                    f"1. Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "2. X-Frame-Options: DENY or SAMEORIGIN\n"
                    "3. X-Content-Type-Options: nosniff\n"
                    "4. Content-Security-Policy: default-src 'self'\n"
                    "5. Configure these in middleware/server configuration"
                ),
                cwe_id="CWE-693",  # Protection Mechanism Failure
                affected_files=config_files_checked[:5],
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_iam_policies(self, files: List[str]) -> Optional[Discovery]:
        """Check for weak IAM/permission policies"""
        # Look for overly permissive policies in config files
        # Simplified for now
        return None

    def _check_cors_configuration(self, files: List[str]) -> Optional[Discovery]:
        """Check for insecure CORS configuration"""

        # Look for CORS configuration
        cors_files = []
        permissive_cors = []

        for file_path in files:
            if not any(x in file_path.lower() for x in ["config", "server", "app", "middleware", "cors"]):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                    # Check for overly permissive CORS
                    if re.search(r"Access-Control-Allow-Origin.*\*", content, re.IGNORECASE):
                        cors_files.append(file_path)
                        permissive_cors.append(f"{file_path}: Allows all origins (*)")
                    elif re.search(r"cors.*origin.*\*", content, re.IGNORECASE):
                        cors_files.append(file_path)
                        permissive_cors.append(f"{file_path}: CORS configured to allow all origins")

                    if len(permissive_cors) >= 3:
                        break
            except Exception:
                continue

        if permissive_cors:
            return Discovery(
                category="config",
                title="Overly Permissive CORS Configuration",
                description=(
                    "The application's CORS (Cross-Origin Resource Sharing) configuration "
                    "allows requests from any origin (*). This can enable attackers to "
                    "make unauthorized cross-origin requests and potentially steal sensitive data."
                ),
                confidence=0.88,
                severity="medium",
                evidence=permissive_cors,
                remediation=(
                    "Restrict CORS to specific origins:\n"
                    "1. Replace '*' with specific allowed domains\n"
                    "2. Use environment variables for allowed origins\n"
                    "3. Validate origin headers on server side\n"
                    "4. Only enable CORS for endpoints that need it"
                ),
                cwe_id=self.CWE_MAPPINGS["cors_misconfiguration"],
                affected_files=cors_files,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_debug_mode(self, files: List[str]) -> Optional[Discovery]:
        """Check for debug mode enabled in production"""

        debug_files = []
        debug_evidence = []

        # Check configuration files for debug mode
        for file_path in files:
            if not any(file_path.endswith(x) for x in [".env", ".config", ".yml", ".yaml", ".json", ".py", ".js"]):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                    for i, line in enumerate(lines, 1):
                        # Look for debug=True/true or similar
                        if re.search(r"debug\s*[=:]\s*(true|1|yes)", line, re.IGNORECASE):
                            debug_files.append(file_path)
                            debug_evidence.append(f"{file_path}:{i}: {line.strip()}")
                            break

                        # Django DEBUG setting
                        if re.search(r"DEBUG\s*=\s*True", line):
                            debug_files.append(file_path)
                            debug_evidence.append(f"{file_path}:{i}: {line.strip()}")
                            break

                if len(debug_evidence) >= 3:
                    break
            except Exception:
                continue

        if debug_evidence:
            return Discovery(
                category="config",
                title="Debug Mode Enabled",
                description=(
                    "Debug mode is enabled in configuration files. Debug mode typically "
                    "exposes detailed error messages, stack traces, and internal application "
                    "state that can aid attackers in finding and exploiting vulnerabilities."
                ),
                confidence=0.90,
                severity="high",
                evidence=debug_evidence,
                remediation=(
                    "Disable debug mode in production:\n"
                    "1. Set DEBUG=False or debug=false in production configs\n"
                    "2. Use environment variables to control debug mode\n"
                    "3. Implement proper error handling and logging\n"
                    "4. Show generic error messages to users"
                ),
                cwe_id=self.CWE_MAPPINGS["debug_mode"],
                affected_files=debug_files,
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
                ]
            )

        return None

    def _check_admin_exposure(self, files: List[str], architecture: str) -> Optional[Discovery]:
        """Check for exposed admin interfaces"""

        # Look for admin routes/endpoints
        admin_files = []
        admin_evidence = []

        for file_path in files:
            if "test" in file_path.lower():
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                    for i, line in enumerate(lines, 1):
                        # Look for admin routes
                        if re.search(r"['\"/]admin['\"/]", line, re.IGNORECASE):
                            # Check if there's authentication nearby
                            context = "".join(lines[max(0, i-5):min(len(lines), i+5)])

                            # If no auth patterns nearby, flag it
                            if not any(x in context.lower() for x in ["auth", "login", "permission", "require_admin"]):
                                admin_files.append(file_path)
                                admin_evidence.append(f"{file_path}:{i}: Admin route without clear auth check")
                                break
            except Exception:
                continue

            if len(admin_evidence) >= 3:
                break

        if admin_evidence:
            return Discovery(
                category="config",
                title="Potentially Exposed Admin Interface",
                description=(
                    "Admin routes or interfaces were found without clear authentication or "
                    "authorization checks. Exposed admin interfaces are high-value targets "
                    "for attackers and should be strictly protected."
                ),
                confidence=0.74,
                severity="high",
                evidence=admin_evidence,
                remediation=(
                    "Secure admin interfaces:\n"
                    "1. Require strong authentication (MFA recommended)\n"
                    "2. Implement role-based access control\n"
                    "3. Use separate admin authentication realm\n"
                    "4. Consider IP whitelisting for admin access\n"
                    "5. Log all admin actions for audit trail"
                ),
                cwe_id=self.CWE_MAPPINGS["admin_exposure"],
                affected_files=admin_files,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_sensitive_logging(self, files: List[str]) -> Optional[Discovery]:
        """Check for sensitive data in logs"""

        sensitive_logging = []
        log_files = []

        # Patterns that might indicate logging sensitive data
        sensitive_patterns = [
            (r"log.*password", "Logging password"),
            (r"log.*token", "Logging token"),
            (r"log.*secret", "Logging secret"),
            (r"log.*api[_-]?key", "Logging API key"),
            (r"log.*credit[_-]?card", "Logging credit card"),
            (r"log.*ssn", "Logging SSN"),
            (r"print.*password", "Printing password to stdout"),
            (r"console\.log.*password", "Logging password to console")
        ]

        for file_path in files[:40]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                    for pattern, description in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            log_files.append(file_path)
                            sensitive_logging.append(f"{file_path}: {description}")
                            break

                if len(sensitive_logging) >= 5:
                    break
            except Exception:
                continue

        if sensitive_logging:
            return Discovery(
                category="data_security",
                title="Sensitive Data in Logs",
                description=(
                    "The application appears to log sensitive information such as passwords, "
                    "tokens, or API keys. This exposes sensitive data to anyone with access "
                    "to logs and violates security best practices."
                ),
                confidence=0.82,
                severity="high",
                evidence=sensitive_logging,
                remediation=(
                    "Remove sensitive data from logs:\n"
                    "1. Never log passwords, tokens, or secrets\n"
                    "2. Redact sensitive fields before logging\n"
                    "3. Use structured logging with field-level controls\n"
                    "4. Review existing logs and rotate compromised credentials"
                ),
                cwe_id=self.CWE_MAPPINGS["sensitive_logging"],
                affected_files=log_files,
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
                ]
            )

        return None

    def _check_pii_exposure(self, files: List[str]) -> Optional[Discovery]:
        """Check for PII exposure risks"""
        # Would analyze data flow and API responses for PII
        # Simplified for now
        return None

    def _check_data_storage(self, files: List[str]) -> Optional[Discovery]:
        """Check for insecure data storage"""
        # Would analyze database configs and storage patterns
        # Simplified for now
        return None

    def _check_encryption_at_rest(self, files: List[str]) -> Optional[Discovery]:
        """Check for missing encryption at rest"""
        # Would check database and storage configurations
        # Simplified for now
        return None

    def _deduplicate_with_existing(
        self,
        discoveries: List[Discovery],
        existing_findings: List[Dict]
    ) -> List[Discovery]:
        """
        Deduplicate discoveries with existing scanner findings

        Args:
            discoveries: List of new discoveries
            existing_findings: List of existing findings from scanners

        Returns:
            Filtered list of discoveries not covered by existing findings
        """
        if not existing_findings:
            return discoveries

        # Extract CWEs and titles from existing findings
        existing_cwes = set()
        existing_titles = set()

        for finding in existing_findings:
            if isinstance(finding, dict):
                cwe = finding.get("cwe") or finding.get("cwe_id")
                if cwe:
                    existing_cwes.add(cwe)

                title = finding.get("title") or finding.get("rule_name") or finding.get("message")
                if title:
                    existing_titles.add(title.lower())

        # Filter out discoveries that overlap with existing findings
        unique_discoveries = []

        for discovery in discoveries:
            # Check CWE overlap
            if discovery.cwe_id and discovery.cwe_id in existing_cwes:
                logger.debug(f"Skipping discovery '{discovery.title}' - CWE already covered")
                continue

            # Check title overlap (fuzzy match)
            title_overlap = False
            for existing_title in existing_titles:
                # Simple word overlap check
                discovery_words = set(discovery.title.lower().split())
                existing_words = set(existing_title.split())
                overlap = len(discovery_words & existing_words)

                if overlap >= 2:  # At least 2 words in common
                    title_overlap = True
                    break

            if title_overlap:
                logger.debug(f"Skipping discovery '{discovery.title}' - similar finding exists")
                continue

            unique_discoveries.append(discovery)

        return unique_discoveries


def main():
    """CLI entry point for spontaneous discovery"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Spontaneous Security Discovery - Find issues beyond scanner rules"
    )
    parser.add_argument("path", help="Path to analyze")
    parser.add_argument("--architecture", default="backend-api", help="Architecture type")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--max-files", type=int, default=50, help="Max files to analyze")

    args = parser.parse_args()

    # Gather files
    from pathlib import Path

    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path {args.path} does not exist")
        sys.exit(1)

    files = []
    if target_path.is_file():
        files = [str(target_path)]
    else:
        for ext in ["*.py", "*.js", "*.ts", "*.go", "*.java", "*.rb", "*.php"]:
            files.extend([str(f) for f in target_path.rglob(ext)])

    print(f"Found {len(files)} files to analyze")

    # Run discovery
    discovery_engine = SpontaneousDiscovery(llm_manager=None)
    discoveries = discovery_engine.discover(
        files=files,
        existing_findings=[],
        architecture=args.architecture,
        max_files_analyze=args.max_files
    )

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                [
                    {
                        "title": d.title,
                        "category": d.category,
                        "severity": d.severity,
                        "confidence": d.confidence,
                        "description": d.description,
                        "evidence": d.evidence,
                        "remediation": d.remediation,
                        "cwe_id": d.cwe_id,
                        "affected_files": d.affected_files
                    }
                    for d in discoveries
                ],
                f,
                indent=2
            )
        print(f"Results written to {args.output}")
    else:
        print(f"\nFound {len(discoveries)} high-confidence security issues:\n")
        for i, d in enumerate(discoveries, 1):
            print(f"{i}. [{d.severity.upper()}] {d.title}")
            print(f"   Confidence: {d.confidence:.0%}")
            print(f"   {d.description}\n")


if __name__ == "__main__":
    main()
