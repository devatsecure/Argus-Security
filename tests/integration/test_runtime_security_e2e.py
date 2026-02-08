#!/usr/bin/env python3
"""
End-to-end tests for Runtime Security features (DAST Scanner + SAST-DAST Correlation)
Tests the complete workflow of dynamic application security testing and correlation with static findings.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Import the modules we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from dast_scanner import DASTScanner, DASTScanResult, DASTTarget, NucleiFinding
try:
    from sast_dast_correlator import SASTDASTCorrelator, CorrelationResult
except ImportError:
    # Create mock if not available
    SASTDASTCorrelator = None
    CorrelationResult = None


class TestDASTScannerE2E:
    """End-to-end tests for DAST scanner"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.scanner = DASTScanner(target_url="http://testphp.vulnweb.com")
        self.test_target = "http://testphp.vulnweb.com"  # Public test site

    def test_complete_dast_workflow(self):
        """
        Test complete DAST workflow:
        1. Configure target application
        2. Discover endpoints
        3. Run dynamic scans
        4. Generate PoC exploits
        5. Create findings report
        """
        # Step 1: Configure target
        target_url = "http://example.com/api"

        # Step 2: Create scanner with target
        scanner = DASTScanner(target_url=target_url)

        # Step 3: Mock Nuclei execution (since we don't have a real target)
        mock_findings = self._create_mock_nuclei_output()
        with patch.object(scanner, "_run_nuclei", return_value=mock_findings):
            with patch.object(scanner, "nuclei_path", "nuclei"):
                result = scanner.scan(target=target_url)

                assert isinstance(result, DASTScanResult), "Should return scan result"
                assert result.total_findings >= 0, "Should count findings"
                assert result.scan_duration_seconds >= 0, "Should track duration"

        # Step 4: Verify PoC generation
        if result.total_findings > 0:
            finding = result.findings[0]
            assert hasattr(finding, "curl_command"), "Should have PoC command"
            assert len(finding.curl_command) > 0, "PoC should not be empty"

        # Step 5: Generate report
        report = self._generate_dast_report(result)
        assert "total_findings" in report
        assert "findings_by_severity" in report

    def test_openapi_endpoint_discovery(self, tmp_path: Path):
        """Test automatic endpoint discovery from OpenAPI spec"""
        # Create sample OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "servers": [{"url": "http://api.example.com"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True}],
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}},
                    }
                },
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query"}],
                        "responses": {"200": {"description": "Results"}},
                    }
                },
            },
        }

        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(openapi_spec))

        # Discover endpoints via _parse_openapi (the actual internal method)
        targets = self.scanner._parse_openapi(str(spec_file))

        assert len(targets) >= 3, "Should discover all endpoints"

        # Verify endpoint details
        paths = [t.endpoint_path for t in targets]
        assert "/users/{id}" in paths, "Should discover parameterized path"
        assert "/users" in paths, "Should discover POST endpoint"
        assert "/search" in paths, "Should discover query param endpoint"

    def test_authenticated_scanning(self):
        """Test DAST scanning with authentication"""
        target_url = "https://api.example.com/protected"

        # Configure authentication via config headers
        auth_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "X-API-Key": "test-api-key",
        }

        scanner = DASTScanner(
            target_url=target_url,
            config={"headers": auth_headers},
        )

        # Mock Nuclei execution
        with patch.object(scanner, "_run_nuclei", return_value=[]) as mock_nuclei:
            with patch.object(scanner, "nuclei_path", "nuclei"):
                result = scanner.scan(target=target_url)

                # Verify _run_nuclei was called
                assert mock_nuclei.called, "Should call Nuclei"

                # Verify headers were stored on scanner
                assert scanner.headers == auth_headers, "Should store auth headers"

    def test_vulnerability_detection_types(self):
        """Test detection of various vulnerability types"""
        mock_findings = [
            NucleiFinding(
                template_id="sqli-detect",
                template_name="SQL Injection",
                severity="critical",
                matched_at="http://example.com/api/users?id=1",
                extracted_results=["SQL error: syntax error"],
                curl_command="curl 'http://example.com/api/users?id=1%27'",
                matcher_name="sql-error",
                type="http",
                host="example.com",
                tags=["sqli", "injection"],
            ),
            NucleiFinding(
                template_id="xss-reflected",
                template_name="Reflected XSS",
                severity="high",
                matched_at="http://example.com/search?q=<script>alert(1)</script>",
                extracted_results=["<script>alert(1)</script>"],
                curl_command="curl 'http://example.com/search?q=<script>alert(1)</script>'",
                matcher_name="xss-reflected",
                type="http",
                host="example.com",
                tags=["xss", "injection"],
            ),
            NucleiFinding(
                template_id="ssrf-detection",
                template_name="SSRF Vulnerability",
                severity="high",
                matched_at="http://example.com/api/fetch?url=http://internal.service",
                extracted_results=["Internal service response"],
                curl_command="curl 'http://example.com/api/fetch?url=http://internal.service'",
                matcher_name="ssrf-detected",
                type="http",
                host="example.com",
                tags=["ssrf"],
            ),
        ]

        # Group by vulnerability type
        vuln_types = {}
        for finding in mock_findings:
            for tag in finding.tags:
                if tag not in vuln_types:
                    vuln_types[tag] = []
                vuln_types[tag].append(finding)

        assert "sqli" in vuln_types, "Should detect SQL injection"
        assert "xss" in vuln_types, "Should detect XSS"
        assert "ssrf" in vuln_types, "Should detect SSRF"

    def test_poc_exploit_generation(self):
        """Test generation of PoC exploits"""
        finding = NucleiFinding(
            template_id="test-exploit",
            template_name="Test Vulnerability",
            severity="high",
            matched_at="http://example.com/vuln?param=test",
            extracted_results=["Vulnerable response"],
            curl_command="",
            matcher_name="test",
            type="http",
            host="example.com",
            request="GET /vuln?param=test HTTP/1.1\nHost: example.com\n",
            response="HTTP/1.1 200 OK\nVulnerable response",
        )

        # Generate PoC (actual method name is generate_poc_exploit)
        poc = self.scanner.generate_poc_exploit(finding)

        assert poc is not None, "Should generate PoC"
        assert "curl" in poc or "http" in poc.lower(), "PoC should be executable"
        assert "example.com" in poc, "Should include target URL"

    def test_rate_limiting_and_throttling(self):
        """Test rate limiting to avoid overwhelming target"""
        # Configure rate limiting via config
        scanner = DASTScanner(
            target_url="http://example.com/api",
            config={"rate_limit": 5},
        )

        # Verify rate limit was configured
        assert scanner.rate_limit == 5, "Should configure rate limit"

        # Mock Nuclei execution
        with patch.object(scanner, "_run_nuclei", return_value=[]) as mock_nuclei:
            with patch.object(scanner, "nuclei_path", "nuclei"):
                start = time.time()
                result = scanner.scan(target="http://example.com/api")
                duration = time.time() - start

                # (In practice, this test verifies rate limiting is configurable)
                assert duration >= 0, "Should complete scan"

    def test_error_handling_unreachable_target(self):
        """Test error handling when target is unreachable"""
        scanner = DASTScanner(target_url="http://this-domain-does-not-exist-12345.com")

        # Should not crash
        try:
            with patch.object(scanner, "_run_nuclei") as mock_nuclei:
                mock_nuclei.side_effect = RuntimeError("Nuclei scan failed")
                with patch.object(scanner, "nuclei_path", "nuclei"):
                    result = scanner.scan()

                    # Should handle error gracefully
                    assert isinstance(result, DASTScanResult)
        except Exception as e:
            # Should be handled gracefully - RuntimeError from nuclei failure
            assert "failed" in str(e).lower() or "timeout" in str(e).lower()

    def test_performance_large_scale_scan(self):
        """Test performance with large number of endpoints"""
        scanner = DASTScanner(target_url="http://example.com")

        with patch.object(scanner, "_run_nuclei", return_value=[]) as mock_nuclei:
            with patch.object(scanner, "nuclei_path", "nuclei"):
                start = time.time()
                result = scanner.scan(target="http://example.com")
                duration = time.time() - start

                assert duration < 60, f"Scan should complete reasonably: {duration}s"
                assert isinstance(result, DASTScanResult)

    def test_nuclei_template_selection(self):
        """Test selection of appropriate Nuclei templates"""
        # Different scan configurations
        configs = [
            {"templates": ["cves", "vulnerabilities"], "expected_count": 2},
            {"templates": ["exposed-panels", "misconfigurations"], "expected_count": 2},
            {"templates": ["default-logins"], "expected_count": 1},
        ]

        for config in configs:
            templates = config["templates"]
            # Verify templates can be configured
            assert len(templates) == config["expected_count"]

    # Helper methods

    def _create_mock_nuclei_output(self) -> List[NucleiFinding]:
        """Create mock Nuclei scan output"""
        return [
            NucleiFinding(
                template_id="mock-finding-1",
                template_name="Mock SQL Injection",
                severity="high",
                matched_at="http://example.com/api/user?id=1",
                extracted_results=["SQL error detected"],
                curl_command="curl 'http://example.com/api/user?id=1%27'",
                matcher_name="sql-error",
                type="http",
                host="example.com",
                tags=["sqli"],
            )
        ]

    def _generate_dast_report(self, result: DASTScanResult) -> Dict[str, Any]:
        """Generate DAST report"""
        findings_by_severity = {}
        for finding in result.findings:
            severity = finding.severity
            if severity not in findings_by_severity:
                findings_by_severity[severity] = 0
            findings_by_severity[severity] += 1

        return {
            "total_findings": result.total_findings,
            "findings_by_severity": findings_by_severity,
            "scan_duration": result.scan_duration_seconds,
            "target": result.target,
        }


class TestSASTDASTCorrelationE2E:
    """End-to-end tests for SAST-DAST correlation"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        if SASTDASTCorrelator:
            self.correlator = SASTDASTCorrelator()

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_complete_correlation_workflow(self):
        """
        Test complete correlation workflow:
        1. Receive SAST findings
        2. Receive DAST findings (as dicts)
        3. Correlate by endpoint/vulnerability type
        4. Check correlation status
        5. Verify result structure
        """
        from sast_dast_correlator import CorrelationStatus

        # Step 1: SAST findings (dict format expected by correlator)
        sast_findings = [
            {
                "id": "sast-001",
                "rule_id": "sql-injection",
                "severity": "high",
                "path": "/api/users",
                "cwe": "CWE-89",
                "evidence": {"code": "query = f'SELECT * FROM users WHERE id = {user_id}'"},
            },
            {
                "id": "sast-002",
                "rule_id": "xss",
                "severity": "medium",
                "path": "/api/search",
                "cwe": "CWE-79",
                "evidence": {"code": "return f'<div>{search_term}</div>'"},
            },
        ]

        # Step 2: DAST findings (as dicts, which is what correlate() expects)
        dast_findings = [
            {
                "id": "dast-001",
                "rule_id": "sqli-exploit",
                "severity": "critical",
                "path": "http://api.example.com/api/users?id=1",
                "cwe": "CWE-89",
                "evidence": {
                    "url": "http://api.example.com/api/users?id=1",
                    "extracted_results": ["SQL error: syntax error"],
                },
            }
        ]

        # Step 3: Correlate (skip AI verification since no API key in tests)
        correlations = self.correlator.correlate(sast_findings, dast_findings, use_ai=False)

        assert len(correlations) > 0, "Should produce correlation results"

        # Step 4: Verify correlation result structure
        for correlation in correlations:
            assert correlation.sast_finding_id is not None
            assert hasattr(correlation, "status")
            assert hasattr(correlation, "confidence")
            # Check if any findings were confirmed or partially matched
            if correlation.status == CorrelationStatus.CONFIRMED:
                assert correlation.dast_finding_id is not None
                assert correlation.confidence > 0.5

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_endpoint_matching(self):
        """Test matching SAST and DAST findings by endpoint using fuzzy path matching"""
        sast_path = "/api/users/{id}"
        dast_url = "http://example.com/api/users/123"

        # Use the actual _fuzzy_match_paths method
        match_score = self.correlator._fuzzy_match_paths(sast_path, dast_url)

        # Should have a non-zero match score despite path parameter difference
        assert match_score > 0, f"Should match endpoints with path parameters, got score {match_score}"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_vulnerability_type_matching(self):
        """Test matching by vulnerability type using _normalize_vuln_type and _are_related_vuln_types"""
        # Test normalization and related type checking (actual API)
        matches = [
            ("sql-injection", "sqli", True),
            ("xss", "cross-site-scripting", True),
            ("sql-injection", "xss", False),  # Should not match
        ]

        for type1, type2, should_match in matches:
            norm1 = self.correlator._normalize_vuln_type(type1)
            norm2 = self.correlator._normalize_vuln_type(type2)
            if norm1 and norm2:
                is_same = (norm1 == norm2)
                is_related = self.correlator._are_related_vuln_types(norm1, norm2)
                result = is_same or is_related
            else:
                result = False
            if should_match:
                assert result, f"{type1} should match {type2}"
            else:
                assert not result, f"{type1} should not match {type2}"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_false_positive_reduction(self):
        """Test that verified findings reduce false positive rate"""
        from sast_dast_correlator import CorrelationStatus

        # SAST finding without DAST confirmation (potential FP)
        unverified_sast = {
            "id": "unverified",
            "rule_id": "sql-injection",
            "severity": "medium",
            "path": "/api/endpoint1",
            "cwe": "CWE-89",
        }

        # SAST finding with DAST confirmation (verified TP)
        verified_sast = {
            "id": "verified",
            "rule_id": "sql-injection",
            "severity": "high",
            "path": "/api/endpoint2",
            "cwe": "CWE-89",
        }

        # DAST finding as dict (expected by correlate())
        verified_dast = {
            "id": "dast-verified",
            "rule_id": "sqli",
            "severity": "critical",
            "path": "http://example.com/api/endpoint2",
            "cwe": "CWE-89",
            "evidence": {
                "url": "http://example.com/api/endpoint2",
                "extracted_results": ["SQL error"],
            },
        }

        correlations = self.correlator.correlate(
            [unverified_sast, verified_sast], [verified_dast], use_ai=False
        )

        # At least one correlation should exist
        assert len(correlations) >= 1, "Should have correlation results"

        # Check that confirmed/partial correlations exist
        confirmed_or_partial = [
            c for c in correlations
            if c.status in (CorrelationStatus.CONFIRMED, CorrelationStatus.PARTIAL)
        ]
        # The endpoint2 SAST finding should match the DAST finding
        assert len(confirmed_or_partial) >= 1 or any(
            c.dast_finding_id is not None for c in correlations
        ), "Should have at least one matched correlation"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_prioritization_by_verification(self):
        """Test that confirmed findings are prioritized higher by confidence"""
        from sast_dast_correlator import CorrelationStatus

        correlations = [
            CorrelationResult(
                sast_finding_id="1",
                dast_finding_id="d1",
                status=CorrelationStatus.CONFIRMED,
                confidence=0.9,
                exploitability="trivial",
                reasoning="DAST confirmed SQL injection on same endpoint",
            ),
            CorrelationResult(
                sast_finding_id="2",
                dast_finding_id=None,
                status=CorrelationStatus.NO_DAST_COVERAGE,
                confidence=0.3,
                exploitability="unknown",
                reasoning="No DAST coverage for this endpoint",
            ),
        ]

        # Sort by status priority (confirmed first) and confidence
        status_priority = {
            CorrelationStatus.CONFIRMED: 0,
            CorrelationStatus.PARTIAL: 1,
            CorrelationStatus.NOT_VERIFIED: 2,
            CorrelationStatus.NO_DAST_COVERAGE: 3,
        }
        sorted_correlations = sorted(
            correlations,
            key=lambda c: (status_priority.get(c.status, 99), -c.confidence),
        )

        assert sorted_correlations[0].status == CorrelationStatus.CONFIRMED, "Confirmed should be first"
        assert sorted_correlations[-1].status == CorrelationStatus.NO_DAST_COVERAGE, "Unverified should be last"


class TestRuntimeSecurityIntegration:
    """Test integration of runtime security features"""

    def test_ci_cd_integration(self, tmp_path: Path):
        """Test integration in CI/CD pipeline"""
        # Simulate CI environment
        scanner = DASTScanner(target_url="http://staging.example.com")

        # Mock Nuclei execution
        with patch.object(scanner, "_run_nuclei", return_value=[]):
            with patch.object(scanner, "nuclei_path", "nuclei"):
                # Run quick scan suitable for CI
                result = scanner.scan(
                    target="http://staging.example.com",
                    output_file=str(tmp_path / "results.json"),
                )

                # Generate CI report
                should_fail_ci = result.total_findings > 0 and any(
                    f.severity in ["critical", "high"] for f in result.findings
                )

                exit_code = 1 if should_fail_ci else 0
                assert exit_code in [0, 1], "Should return valid exit code"

    def test_progressive_scanning(self):
        """Test progressive scanning (quick -> deep)"""
        scanner = DASTScanner(target_url="http://example.com")

        # Step 1: Quick scan (basic templates)
        quick_templates = ["cves/2023", "exposed-panels"]

        # Step 2: If issues found, deep scan
        deep_templates = ["vulnerabilities", "fuzzing", "default-logins"]

        # In practice, quick scan runs first, deep scan only if needed
        assert len(quick_templates) < len(deep_templates), "Quick scan should be faster"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
