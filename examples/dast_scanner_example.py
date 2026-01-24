#!/usr/bin/env python3
"""
Example usage of DAST Scanner for Argus

This demonstrates various ways to use the DASTScanner class.
"""

import json
import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from dast_scanner import DASTScanner, DASTTarget


def example_simple_url_scan():
    """Example 1: Simple URL scan"""
    print("=" * 80)
    print("Example 1: Simple URL Scan")
    print("=" * 80)

    scanner = DASTScanner(
        target_url="https://example.com",
        config={
            "severity": ["critical", "high"],
            "rate_limit": 100,
        },
    )

    # Check if Nuclei is installed
    if not scanner.nuclei_path:
        print("Nuclei not installed. Run: scanner.install_nuclei()")
        scanner.install_nuclei()
        return

    # Run scan
    result = scanner.scan()
    print(f"\nFound {result.total_findings} vulnerabilities")


def example_openapi_scan():
    """Example 2: OpenAPI-based scan"""
    print("\n" + "=" * 80)
    print("Example 2: OpenAPI Spec Scan")
    print("=" * 80)

    # Create sample OpenAPI spec
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}}
                    ],
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                    },
                                    "required": ["name", "email"],
                                }
                            }
                        }
                    },
                },
            },
        },
    }

    # Save spec to temp file
    spec_path = "/tmp/example_openapi.json"
    with open(spec_path, "w") as f:
        json.dump(openapi_spec, f)

    scanner = DASTScanner(openapi_spec=spec_path)

    # Parse targets without scanning
    targets = scanner._get_targets("https://api.example.com")
    print(f"\nExtracted {len(targets)} endpoints:")
    for target in targets:
        print(f"  {target.method} {target.url}")


def example_authenticated_scan():
    """Example 3: Authenticated scanning"""
    print("\n" + "=" * 80)
    print("Example 3: Authenticated Scan")
    print("=" * 80)

    scanner = DASTScanner(
        target_url="https://api.example.com",
        config={
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "X-API-Key": "your-api-key",
            },
            "severity": ["critical", "high", "medium"],
            "timeout": 10,
            "concurrency": 50,
        },
    )

    print(f"Scanner configured with {len(scanner.headers)} authentication headers")


def example_custom_templates():
    """Example 4: Custom Nuclei templates"""
    print("\n" + "=" * 80)
    print("Example 4: Custom Nuclei Templates")
    print("=" * 80)

    scanner = DASTScanner(
        target_url="https://example.com",
        config={
            "templates": [
                "~/nuclei-templates/custom/sqli.yaml",
                "~/nuclei-templates/custom/xss.yaml",
            ],
            "severity": ["critical", "high"],
        },
    )

    print(f"Using {len(scanner.templates)} custom templates")


def example_normalize_findings():
    """Example 5: Normalize to unified Finding format"""
    print("\n" + "=" * 80)
    print("Example 5: Normalize to Finding Format")
    print("=" * 80)

    from dast_scanner import DASTScanResult, NucleiFinding

    # Create mock scan result
    finding = NucleiFinding(
        template_id="CVE-2021-1234",
        template_name="SQL Injection in Login",
        severity="critical",
        matched_at="https://example.com/login?user=admin",
        extracted_results=["admin' OR '1'='1"],
        curl_command="curl -X GET https://example.com/login?user=admin",
        matcher_name="sql-error",
        type="http",
        host="example.com",
        tags=["sqli", "injection", "cve"],
        classification={"cwe-id": "CWE-89", "cvss-score": "9.8"},
    )

    scan_result = DASTScanResult(
        scan_type="url",
        target="https://example.com",
        timestamp="2026-01-15T10:00:00Z",
        total_requests=10,
        total_findings=1,
        findings=[finding],
        scan_duration_seconds=45.2,
        nuclei_version="v3.1.0",
    )

    scanner = DASTScanner(target_url="https://example.com")
    normalized = scanner.normalize_to_findings(scan_result)

    print(f"\nNormalized {len(normalized)} findings:")
    for f in normalized:
        print(f"\n  ID: {f['id'][:16]}...")
        print(f"  Origin: {f['origin']}")
        print(f"  Severity: {f['severity']}")
        print(f"  Category: {f['category']}")
        print(f"  Rule: {f['rule_id']}")
        print(f"  CWE: {f['cwe']}")
        print(f"  Reachability: {f['reachability']}")
        print(f"  Exploitability: {f['exploitability']}")


def example_poc_generation():
    """Example 6: PoC exploit generation"""
    print("\n" + "=" * 80)
    print("Example 6: PoC Exploit Generation")
    print("=" * 80)

    from dast_scanner import NucleiFinding

    finding = NucleiFinding(
        template_id="sql-injection",
        template_name="SQL Injection",
        severity="high",
        matched_at="https://example.com/api/users?id=1",
        extracted_results=[],
        curl_command="",
        matcher_name="sql-error",
        type="http",
        host="example.com",
    )

    scanner = DASTScanner(
        target_url="https://example.com",
        config={
            "headers": {
                "Authorization": "Bearer token123",
                "User-Agent": "Mozilla/5.0",
            }
        },
    )

    poc = scanner.generate_poc_exploit(finding)
    print("\nGenerated PoC:")
    print(f"  {poc}")


if __name__ == "__main__":
    print("DAST Scanner Examples")
    print("=" * 80)

    # Run all examples
    example_simple_url_scan()
    example_openapi_scan()
    example_authenticated_scan()
    example_custom_templates()
    example_normalize_findings()
    example_poc_generation()

    print("\n" + "=" * 80)
    print("Examples complete!")
    print("=" * 80)
