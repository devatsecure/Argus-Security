#!/usr/bin/env python3
"""
DAST Scanner for Argus
Dynamic Application Security Testing using Nuclei

Features:
- Nuclei integration for dynamic testing (4000+ templates)
- OpenAPI/Swagger endpoint discovery
- Authenticated scanning support
- SQLi, XSS, SSRF, XXE, RCE, LFI, Open Redirect detection
- PoC generation for verified vulnerabilities
- JSON output normalization to Finding format
"""

import json
import logging
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class DASTTarget:
    """Target for DAST scanning"""

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    endpoint_path: str = ""  # e.g., /api/users/{id}
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NucleiFinding:
    """A single Nuclei DAST finding"""

    template_id: str
    template_name: str
    severity: str  # info, low, medium, high, critical
    matched_at: str  # Full URL where vulnerability was found
    extracted_results: list[str]
    curl_command: str
    matcher_name: str
    type: str  # http, dns, network, etc.
    host: str
    ip: Optional[str] = None
    timestamp: str = ""
    request: str = ""
    response: str = ""
    tags: list[str] = field(default_factory=list)
    classification: dict = field(default_factory=dict)  # CWE, CVE info
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DASTScanResult:
    """Results from a DAST scan"""

    scan_type: str  # 'url', 'openapi', 'file'
    target: str
    timestamp: str
    total_requests: int
    total_findings: int
    findings: list[NucleiFinding]
    scan_duration_seconds: float
    nuclei_version: str
    templates_used: list[str] = field(default_factory=list)
    authentication: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "timestamp": self.timestamp,
            "total_requests": self.total_requests,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "nuclei_version": self.nuclei_version,
            "templates_used": self.templates_used,
            "authentication": self.authentication,
        }


class DASTScanner:
    """
    Dynamic Application Security Testing using Nuclei

    Integrates Nuclei for runtime vulnerability detection:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Server-Side Request Forgery (SSRF)
    - XML External Entity (XXE)
    - Remote Code Execution (RCE)
    - Local File Inclusion (LFI)
    - Open Redirects
    - Authentication bypasses
    - API misconfigurations

    Supports OpenAPI spec parsing for comprehensive endpoint coverage.
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        openapi_spec: Optional[str] = None,
        config: Optional[dict] = None,
    ):
        """
        Initialize DAST Scanner

        Args:
            target_url: Base URL to scan (e.g., https://api.example.com)
            openapi_spec: Path to OpenAPI/Swagger spec (JSON or YAML)
            config: Optional configuration dictionary
                - severity: List of severities to include (default: ["critical", "high", "medium"])
                - templates: Custom template paths
                - rate_limit: Requests per second (default: 150)
                - timeout: Request timeout in seconds (default: 5)
                - retries: Number of retries for failed requests (default: 1)
                - headers: Custom HTTP headers for authentication
                - concurrency: Number of concurrent requests (default: 25)
        """
        self.target_url = target_url
        self.openapi_spec = openapi_spec
        self.config = config or {}

        # Configuration
        self.severity = self.config.get("severity", ["critical", "high", "medium"])
        self.templates = self.config.get("templates", [])
        self.rate_limit = self.config.get("rate_limit", 150)
        self.timeout = self.config.get("timeout", 5)
        self.retries = self.config.get("retries", 1)
        self.headers = self.config.get("headers", {})
        self.concurrency = self.config.get("concurrency", 25)

        # Verify installation
        self.nuclei_path = self._find_nuclei()
        if not self.nuclei_path:
            logger.warning("Nuclei not installed. Run install_nuclei() for instructions.")

    def _find_nuclei(self) -> Optional[str]:
        """
        Find nuclei binary

        Returns:
            Path to nuclei binary or None if not found
        """
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info(f"Nuclei detected: {result.stdout.strip()}")
                return "nuclei"
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    def install_nuclei(self) -> bool:
        """
        Provide installation instructions for Nuclei

        Returns:
            True if Nuclei is already installed
        """
        if self._find_nuclei():
            logger.info("Nuclei is already installed")
            return True

        logger.info("Nuclei not found. Installation instructions:")
        logger.info("")
        logger.info("  macOS/Linux (Homebrew):")
        logger.info("    brew install nuclei")
        logger.info("")
        logger.info("  Linux (Binary):")
        logger.info("    wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip")
        logger.info("    unzip nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/")
        logger.info("")
        logger.info("  Go install:")
        logger.info("    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        logger.info("")
        logger.info("  Docker:")
        logger.info("    docker pull projectdiscovery/nuclei:latest")
        logger.info("")

        return False

    def scan(
        self,
        target: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> DASTScanResult:
        """
        Run DAST scan on target

        Args:
            target: Target URL or path (overrides constructor target_url)
            output_file: Optional path to save JSON results

        Returns:
            DASTScanResult with all findings

        Raises:
            RuntimeError: If Nuclei is not installed or scan fails
        """
        target = target or self.target_url

        if not target and not self.openapi_spec:
            raise RuntimeError("Either target URL or OpenAPI spec must be provided")

        if not self.nuclei_path:
            raise RuntimeError("Nuclei not installed. Run install_nuclei() for instructions.")

        logger.info(f"Starting DAST scan: {target or 'OpenAPI spec'}")

        start_time = datetime.now()

        # Determine targets
        targets = self._get_targets(target)
        logger.info(f"  Discovered {len(targets)} endpoints to scan")

        # Run Nuclei
        findings = self._run_nuclei(targets)

        # Calculate duration
        scan_duration = (datetime.now() - start_time).total_seconds()

        # Build result
        scan_result = DASTScanResult(
            scan_type="openapi" if self.openapi_spec else "url",
            target=target or self.openapi_spec or "",
            timestamp=datetime.now().isoformat(),
            total_requests=len(targets),
            total_findings=len(findings),
            findings=findings,
            scan_duration_seconds=scan_duration,
            nuclei_version=self._get_nuclei_version(),
            templates_used=self.templates if self.templates else ["built-in"],
            authentication={"headers": list(self.headers.keys())} if self.headers else {},
        )

        logger.info(f"DAST scan complete: {len(findings)} findings in {scan_duration:.1f}s")

        # Save to file if requested
        if output_file:
            self._save_results(scan_result, output_file)

        # Print summary
        self._print_summary(scan_result)

        return scan_result

    def _get_targets(self, base_url: Optional[str]) -> list[DASTTarget]:
        """
        Get scan targets from OpenAPI spec or base URL

        Args:
            base_url: Base URL for scanning

        Returns:
            List of DASTTarget objects
        """
        targets = []

        if self.openapi_spec:
            # Parse OpenAPI spec
            targets = self._parse_openapi(self.openapi_spec, base_url)
        elif base_url:
            # Single URL target
            targets = [DASTTarget(url=base_url)]
        else:
            raise RuntimeError("No target URL or OpenAPI spec provided")

        return targets

    def _parse_openapi(self, spec_path: str, base_url: Optional[str] = None) -> list[DASTTarget]:
        """
        Parse OpenAPI spec to extract endpoints

        Args:
            spec_path: Path to OpenAPI JSON or YAML file
            base_url: Optional base URL to override spec servers

        Returns:
            List of DASTTarget objects for each endpoint
        """
        logger.info(f"  Parsing OpenAPI spec: {spec_path}")

        spec_path_obj = Path(spec_path)
        if not spec_path_obj.exists():
            raise RuntimeError(f"OpenAPI spec not found: {spec_path}")

        # Read and parse spec
        with open(spec_path_obj) as f:
            if spec_path_obj.suffix in [".yaml", ".yml"]:
                spec = yaml.safe_load(f)
            else:
                spec = json.load(f)

        # Extract base URL from spec or use provided
        if not base_url:
            servers = spec.get("servers", [])
            if servers:
                base_url = servers[0].get("url", "")
            else:
                raise RuntimeError("No base URL provided and none found in OpenAPI spec")

        # Ensure base_url doesn't end with /
        base_url = base_url.rstrip("/")

        targets = []

        # Extract paths and methods
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
                    continue

                # Build full URL (replace path parameters with placeholder)
                endpoint_path = path
                params = {}

                # Extract parameters
                parameters = details.get("parameters", [])
                for param in parameters:
                    param_name = param.get("name", "")
                    param_in = param.get("in", "")

                    if param_in == "path":
                        # Replace {param} with test value
                        endpoint_path = endpoint_path.replace(f"{{{param_name}}}", "1")
                    elif param_in == "query":
                        params[param_name] = "test"

                full_url = f"{base_url}{endpoint_path}"

                # Add query params if GET
                if method.upper() == "GET" and params:
                    query_string = urllib.parse.urlencode(params)
                    full_url = f"{full_url}?{query_string}"

                # Extract request body for POST/PUT/PATCH
                body = None
                if method.upper() in ["POST", "PUT", "PATCH"]:
                    request_body = details.get("requestBody", {})
                    content = request_body.get("content", {})
                    if "application/json" in content:
                        schema = content["application/json"].get("schema", {})
                        # Create minimal valid body from schema
                        body = self._generate_body_from_schema(schema)

                target = DASTTarget(
                    url=full_url,
                    method=method.upper(),
                    headers=self.headers.copy(),
                    body=body,
                    endpoint_path=path,
                    params=params,
                )
                targets.append(target)

        logger.info(f"  Extracted {len(targets)} endpoints from OpenAPI spec")
        return targets

    def _generate_body_from_schema(self, schema: dict) -> str:
        """
        Generate minimal JSON body from OpenAPI schema

        Args:
            schema: OpenAPI schema object

        Returns:
            JSON string
        """
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        body_dict = {}
        for prop_name, prop_schema in properties.items():
            if prop_name in required or len(body_dict) < 3:  # Include at least 3 fields
                prop_type = prop_schema.get("type", "string")
                if prop_type == "string":
                    body_dict[prop_name] = "test"
                elif prop_type == "integer":
                    body_dict[prop_name] = 1
                elif prop_type == "boolean":
                    body_dict[prop_name] = False
                elif prop_type == "array":
                    body_dict[prop_name] = []
                elif prop_type == "object":
                    body_dict[prop_name] = {}

        return json.dumps(body_dict)

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((subprocess.SubprocessError, OSError, RuntimeError)),
    )
    def _execute_nuclei_scan(self, cmd: list[str], target_count: int) -> str:
        """Execute Nuclei scan with retry logic

        Args:
            cmd: Nuclei command to execute
            target_count: Number of targets being scanned

        Returns:
            Nuclei stdout output

        Raises:
            RuntimeError: If scan fails after retries
        """
        logger.info(f"  Running: nuclei with {target_count} targets...")

        # Run Nuclei
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
        )

        # Nuclei returns 0 even with findings
        if result.returncode not in [0, 1]:
            logger.error(f"Nuclei scan failed with exit code {result.returncode}")
            logger.error(f"STDERR: {result.stderr}")
            raise RuntimeError(f"Nuclei scan failed: {result.stderr}")

        return result.stdout

    def _run_nuclei(self, targets: list[DASTTarget]) -> list[NucleiFinding]:
        """
        Execute Nuclei scan on targets

        Args:
            targets: List of targets to scan

        Returns:
            List of NucleiFinding objects
        """
        # Create temporary file with target URLs
        # Use delete=True with context manager for automatic cleanup
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=True) as f:
            target_file_path = f.name
            for target in targets:
                f.write(f"{target.url}\n")
            f.flush()  # Ensure data is written before nuclei reads it

            try:
                # Build nuclei command
                cmd = self._build_nuclei_command(target_file_path)

                # Execute with retry logic
                output = self._execute_nuclei_scan(cmd, len(targets))

                # Parse JSON output
                findings = self._parse_nuclei_output(output)

                logger.info(f"  Nuclei scan complete: {len(findings)} findings")
                return findings

            except subprocess.TimeoutExpired:
                logger.error("Nuclei scan timed out after 10 minutes")
                raise RuntimeError("Nuclei scan timed out")
            except Exception as e:
                logger.error(f"Nuclei scan failed after retries: {e}")
                raise
            # No finally block needed - context manager handles cleanup automatically

    def _build_nuclei_command(self, target_file: str) -> list[str]:
        """
        Build Nuclei command with all options

        Args:
            target_file: Path to file containing target URLs

        Returns:
            Command as list of strings
        """
        cmd = [self.nuclei_path or "nuclei"]

        # Target list
        cmd.extend(["-list", target_file])

        # Output format - JSON for parsing
        cmd.extend(["-jsonl"])

        # Severity filter
        if self.severity:
            cmd.extend(["-severity", ",".join(self.severity)])

        # Custom templates
        if self.templates:
            for template in self.templates:
                cmd.extend(["-t", template])
        else:
            # Use all built-in templates
            cmd.extend(["-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfiguration/"])

        # Rate limiting
        cmd.extend(["-rate-limit", str(self.rate_limit)])

        # Timeout
        cmd.extend(["-timeout", str(self.timeout)])

        # Retries
        cmd.extend(["-retries", str(self.retries)])

        # Concurrency
        cmd.extend(["-concurrency", str(self.concurrency)])

        # Custom headers
        if self.headers:
            for key, value in self.headers.items():
                cmd.extend(["-header", f"{key}: {value}"])

        # Silent mode (suppress progress bar)
        cmd.append("-silent")

        # Include request/response in output
        cmd.append("-include-rr")

        return cmd

    def _parse_nuclei_output(self, raw_output: str) -> list[NucleiFinding]:
        """
        Parse Nuclei JSONL output into NucleiFinding objects

        Args:
            raw_output: Raw JSONL output from Nuclei

        Returns:
            List of NucleiFinding objects
        """
        findings = []

        if not raw_output or not raw_output.strip():
            return findings

        # Parse newline-delimited JSON
        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                result = json.loads(line)

                # Extract info
                template_id = result.get("template-id", "")
                template_name = result.get("info", {}).get("name", "Unknown")
                severity = result.get("info", {}).get("severity", "medium").lower()
                matched_at = result.get("matched-at", result.get("matched", ""))
                extracted = result.get("extracted-results", [])
                curl_command = result.get("curl-command", "")
                matcher_name = result.get("matcher-name", "")
                vuln_type = result.get("type", "http")
                host = result.get("host", "")
                ip = result.get("ip", None)
                timestamp = result.get("timestamp", datetime.now().isoformat())

                # Classification info
                classification = result.get("info", {}).get("classification", {})
                tags = result.get("info", {}).get("tags", [])
                metadata = result.get("info", {}).get("metadata", {})

                # Request/Response (if included)
                request = result.get("request", "")
                response = result.get("response", "")

                finding = NucleiFinding(
                    template_id=template_id,
                    template_name=template_name,
                    severity=severity,
                    matched_at=matched_at,
                    extracted_results=extracted,
                    curl_command=curl_command,
                    matcher_name=matcher_name,
                    type=vuln_type,
                    host=host,
                    ip=ip,
                    timestamp=timestamp,
                    request=request,
                    response=response,
                    tags=tags,
                    classification=classification,
                    metadata=metadata,
                )

                findings.append(finding)

            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Nuclei JSON line: {e}")
                continue
            except Exception as e:
                logger.warning(f"Error processing Nuclei finding: {e}")
                continue

        return findings

    def generate_poc_exploit(self, finding: NucleiFinding) -> str:
        """
        Generate curl PoC command for verified vulnerability

        Args:
            finding: NucleiFinding object

        Returns:
            Curl command string that demonstrates the vulnerability
        """
        # If Nuclei already generated a curl command, use it
        if finding.curl_command:
            return finding.curl_command

        # Otherwise, build a basic curl command
        curl_parts = ["curl", "-X", "GET"]

        # Add URL
        curl_parts.append(f'"{finding.matched_at}"')

        # Add headers if available
        if self.headers:
            for key, value in self.headers.items():
                curl_parts.extend(["-H", f'"{key}: {value}"'])

        # Add verbose flag
        curl_parts.append("-v")

        return " ".join(curl_parts)

    def normalize_to_findings(self, scan_result: DASTScanResult) -> list[dict]:
        """
        Convert DASTScanResult to unified Finding format

        Args:
            scan_result: DAST scan results

        Returns:
            List of Finding dictionaries
        """
        from normalizer.base import Finding

        findings = []

        # Get git context
        git_context = self._get_git_context()

        for nuclei_finding in scan_result.findings:
            # Map Nuclei severity to standard levels
            severity_map = {
                "info": "info",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical",
            }
            severity = severity_map.get(nuclei_finding.severity, "medium")

            # Extract CWE/CVE if available
            cwe = nuclei_finding.classification.get("cwe-id", None)
            cve = nuclei_finding.classification.get("cve-id", None)

            # Build evidence
            evidence = {
                "matched_at": nuclei_finding.matched_at,
                "template_id": nuclei_finding.template_id,
                "matcher_name": nuclei_finding.matcher_name,
                "extracted_results": nuclei_finding.extracted_results,
                "tags": nuclei_finding.tags,
                "poc": self.generate_poc_exploit(nuclei_finding),
            }

            # Include request/response if available
            if nuclei_finding.request:
                evidence["request"] = nuclei_finding.request[:1000]  # Truncate for size
            if nuclei_finding.response:
                evidence["response"] = nuclei_finding.response[:1000]

            finding = Finding(
                id=self._generate_finding_id(nuclei_finding),
                origin="nuclei",
                repo=git_context.get("repo", "unknown"),
                commit_sha=git_context.get("commit_sha", "unknown"),
                branch=git_context.get("branch", "unknown"),
                path=nuclei_finding.matched_at,
                asset_type="api",
                rule_id=nuclei_finding.template_id,
                rule_name=nuclei_finding.template_name,
                category="DAST",
                severity=severity,
                cwe=cwe,
                cve=cve,
                evidence=evidence,
                references=[
                    f"https://github.com/projectdiscovery/nuclei-templates/tree/main/{nuclei_finding.template_id}"
                ],
                exploitability="trivial" if nuclei_finding.extracted_results else "moderate",
                reachability="yes",  # DAST findings are by definition reachable
            )

            findings.append(finding.to_dict())

        return findings

    def _generate_finding_id(self, nuclei_finding: NucleiFinding) -> str:
        """Generate unique ID for Nuclei finding"""
        import hashlib

        key = f"{nuclei_finding.host}:{nuclei_finding.template_id}:{nuclei_finding.matched_at}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _get_git_context(self) -> dict:
        """Get current git context"""
        try:
            repo = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()

            commit_sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()

            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()

            return {"repo": repo, "commit_sha": commit_sha, "branch": branch}
        except Exception:
            return {"repo": "unknown", "commit_sha": "unknown", "branch": "unknown"}

    def _get_nuclei_version(self) -> str:
        """Get Nuclei version"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Extract version from output
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def _save_results(self, scan_result: DASTScanResult, output_file: str) -> None:
        """
        Save scan results to JSON file

        Args:
            scan_result: Scan results
            output_file: Output file path
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(scan_result.to_dict(), f, indent=2)

        logger.info(f"Results saved to: {output_path}")

    def _print_summary(self, scan_result: DASTScanResult) -> None:
        """
        Print scan summary to console

        Args:
            scan_result: Scan results
        """
        print("\n" + "=" * 80)
        print("NUCLEI DAST SCAN RESULTS")
        print("=" * 80)
        print(f"Target: {scan_result.target}")
        print(f"Scan Type: {scan_result.scan_type}")
        print(f"Timestamp: {scan_result.timestamp}")
        print(f"Duration: {scan_result.scan_duration_seconds:.1f}s")
        print(f"Nuclei Version: {scan_result.nuclei_version}")
        print()
        print(f"Total Requests: {scan_result.total_requests}")
        print(f"Total Findings: {scan_result.total_findings}")
        print()

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in scan_result.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        print("Findings by Severity:")
        print(f"  Critical: {severity_counts['critical']}")
        print(f"  High:     {severity_counts['high']}")
        print(f"  Medium:   {severity_counts['medium']}")
        print(f"  Low:      {severity_counts['low']}")
        print(f"  Info:     {severity_counts['info']}")
        print("=" * 80)

        # Show top findings
        if scan_result.findings:
            print("\nTop Findings:")
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                scan_result.findings,
                key=lambda f: severity_order.get(f.severity, 5),
            )

            for i, finding in enumerate(sorted_findings[:5], 1):
                print(f"\n{i}. [{finding.severity.upper()}] {finding.template_id}")
                print(f"   {finding.template_name}")
                print(f"   URL: {finding.matched_at}")
                print(f"   Matcher: {finding.matcher_name}")
                if finding.extracted_results:
                    print(f"   Extracted: {', '.join(finding.extracted_results[:3])}")

        print()


def main():
    """CLI entry point for DAST scanner"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Nuclei DAST Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single URL
  python dast_scanner.py https://api.example.com

  # Scan from OpenAPI spec
  python dast_scanner.py --openapi openapi.yaml --base-url https://api.example.com

  # Scan with custom templates
  python dast_scanner.py https://example.com --templates ./custom-templates/

  # Authenticated scanning
  python dast_scanner.py https://api.example.com --header "Authorization: Bearer token123"

  # Custom severity filter
  python dast_scanner.py https://example.com --severity critical,high

Supported Vulnerability Types:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Server-Side Request Forgery (SSRF)
  - XML External Entity (XXE)
  - Remote Code Execution (RCE)
  - Local File Inclusion (LFI)
  - Open Redirects
  - Authentication Bypasses
  - API Misconfigurations
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL to scan (e.g., https://api.example.com)",
    )
    parser.add_argument(
        "--openapi",
        help="Path to OpenAPI/Swagger spec (JSON or YAML)",
    )
    parser.add_argument(
        "--base-url",
        help="Base URL for OpenAPI endpoints (overrides spec servers)",
    )
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument(
        "--severity",
        "-s",
        help="Comma-separated severities to include (default: critical,high,medium)",
    )
    parser.add_argument(
        "--templates",
        "-t",
        action="append",
        help="Custom template paths (can be used multiple times)",
    )
    parser.add_argument(
        "--header",
        "-H",
        action="append",
        help="Custom HTTP header (format: 'Name: Value')",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=150,
        help="Requests per second (default: 150)",
    )
    parser.add_argument(
        "--concurrency",
        "-c",
        type=int,
        default=25,
        help="Number of concurrent requests (default: 25)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Show Nuclei installation instructions",
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

    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()

    # Parse severity
    severity = args.severity.split(",") if args.severity else ["critical", "high", "medium"]

    # Build config
    config = {
        "severity": severity,
        "templates": args.templates or [],
        "headers": headers,
        "rate_limit": args.rate_limit,
        "timeout": args.timeout,
        "concurrency": args.concurrency,
    }

    # Initialize scanner
    scanner = DASTScanner(
        target_url=args.target or args.base_url,
        openapi_spec=args.openapi,
        config=config,
    )

    # Show install instructions if requested
    if args.install:
        scanner.install_nuclei()
        sys.exit(0)

    # Validate input
    if not args.target and not args.openapi:
        parser.error("Either target URL or --openapi spec must be provided")

    try:
        # Run scan
        result = scanner.scan(
            target=args.target,
            output_file=args.output,
        )

        # Exit with error code if critical or high severity findings
        critical_high = sum(1 for f in result.findings if f.severity in ["critical", "high"])

        if critical_high > 0:
            logger.warning(f"Found {critical_high} critical/high severity vulnerabilities")
            sys.exit(1)
        else:
            logger.info("No critical or high severity vulnerabilities found")
            sys.exit(0)

    except Exception as e:
        logger.error(f"DAST scan failed: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
