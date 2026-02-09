#!/usr/bin/env python3
"""
Trivy CVE Scanner with Foundation-Sec-8B CWE Mapping
Scans container images and filesystems for CVEs, enriches with CWE mappings
"""

import json
import logging
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class CVEFinding:
    """A CVE vulnerability finding from Trivy"""

    cve_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    title: str
    description: str
    references: list[str]
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None  # Enriched by Foundation-Sec
    exploitability: Optional[str] = None  # Enriched by Foundation-Sec
    attack_vector: Optional[str] = None
    file_path: Optional[str] = None


@dataclass
class TrivyScanResult:
    """Results from a Trivy scan"""

    scan_type: str  # 'filesystem', 'image', 'repo'
    target: str
    timestamp: str
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[CVEFinding]
    scan_duration_seconds: float
    trivy_version: str


class TrivyScanner:
    """
    Trivy CVE Scanner

    Scans for known CVEs in:
    - Filesystems (dependencies, config files)
    - Container images
    - Git repositories

    Integrates with Foundation-Sec-8B for CWE mapping and exploitability analysis
    """

    def __init__(self, foundation_sec_enabled: bool = False, foundation_sec_model: Optional[Any] = None):
        """
        Initialize Trivy scanner

        Args:
            foundation_sec_enabled: Enable Foundation-Sec-8B enrichment
            foundation_sec_model: Foundation-Sec model instance for CWE mapping
        """
        self.foundation_sec_enabled = foundation_sec_enabled
        self.foundation_sec_model = foundation_sec_model

        # Check if Trivy is installed
        self._verify_trivy_installation()

    def _verify_trivy_installation(self) -> None:
        """Verify Trivy is installed and accessible"""
        try:
            result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"✅ Trivy installed: {version}")
            else:
                raise RuntimeError("Trivy not found")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("❌ Trivy not installed. Install with:")
            logger.error(
                "   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"
            )
            raise RuntimeError(f"Trivy installation check failed: {e}")

    def scan_filesystem(
        self, target_path: str, severity: str = "CRITICAL,HIGH,MEDIUM,LOW", output_file: Optional[str] = None
    ) -> TrivyScanResult:
        """
        Scan filesystem for CVEs in dependencies

        Args:
            target_path: Path to scan (directory or file)
            severity: Comma-separated severity levels to report
            output_file: Optional path to save JSON results

        Returns:
            TrivyScanResult with all findings
        """
        logger.info(f"🔍 Scanning filesystem: {target_path}")
        logger.info(f"   Severity filter: {severity}")

        start_time = datetime.now()

        # Run Trivy filesystem scan
        cmd = [
            "trivy",
            "filesystem",
            "--format",
            "json",
            "--severity",
            severity,
            "--scanners",
            "vuln",
            "--quiet",
            target_path,
        ]

        try:
            # Set environment to bypass Docker credential helpers
            import os
            env = os.environ.copy()
            env['DOCKER_CONFIG'] = '/tmp/.docker-fake'  # Use fake config to avoid credential helper issues
            env['TRIVY_NO_PROGRESS'] = 'true'

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)  # 5 minute timeout

            if result.returncode != 0:
                logger.error(f"❌ Trivy scan failed: {result.stderr}")
                raise RuntimeError(f"Trivy scan failed with exit code {result.returncode}")

            # Parse JSON output
            trivy_data = json.loads(result.stdout) if result.stdout else {}

        except subprocess.TimeoutExpired:
            logger.error("❌ Trivy scan timed out after 5 minutes")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse Trivy JSON output: {e}")
            raise

        # Extract version
        trivy_version = self._get_trivy_version()

        # Process results
        findings = self._parse_trivy_results(trivy_data)

        # Enrich with Foundation-Sec if enabled
        if self.foundation_sec_enabled and self.foundation_sec_model:
            logger.info("🤖 Enriching CVEs with Foundation-Sec-8B CWE mapping...")
            findings = self._enrich_with_foundation_sec(findings)

        # Calculate statistics
        severity_counts = self._calculate_severity_counts(findings)

        scan_duration = (datetime.now() - start_time).total_seconds()

        scan_result = TrivyScanResult(
            scan_type="filesystem",
            target=target_path,
            timestamp=datetime.now().isoformat(),
            total_vulnerabilities=len(findings),
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            findings=findings,
            scan_duration_seconds=scan_duration,
            trivy_version=trivy_version,
        )

        # Save to file if requested
        if output_file:
            self._save_results(scan_result, output_file)

        # Print summary
        self._print_summary(scan_result)

        return scan_result

    def scan_container_image(
        self, image_name: str, severity: str = "CRITICAL,HIGH", output_file: Optional[str] = None
    ) -> TrivyScanResult:
        """
        Scan container image for CVEs

        Args:
            image_name: Docker image name (e.g., 'nginx:latest')
            severity: Comma-separated severity levels
            output_file: Optional path to save results

        Returns:
            TrivyScanResult with findings
        """
        logger.info(f"🐳 Scanning container image: {image_name}")

        start_time = datetime.now()

        cmd = ["trivy", "image", "--format", "json", "--severity", severity, "--quiet", image_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode != 0:
                logger.error(f"❌ Image scan failed: {result.stderr}")
                raise RuntimeError("Trivy image scan failed")

            trivy_data = json.loads(result.stdout) if result.stdout else {}

        except subprocess.TimeoutExpired:
            logger.error("❌ Image scan timed out after 10 minutes")
            raise

        trivy_version = self._get_trivy_version()
        findings = self._parse_trivy_results(trivy_data)

        if self.foundation_sec_enabled and self.foundation_sec_model:
            findings = self._enrich_with_foundation_sec(findings)

        severity_counts = self._calculate_severity_counts(findings)
        scan_duration = (datetime.now() - start_time).total_seconds()

        scan_result = TrivyScanResult(
            scan_type="image",
            target=image_name,
            timestamp=datetime.now().isoformat(),
            total_vulnerabilities=len(findings),
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            findings=findings,
            scan_duration_seconds=scan_duration,
            trivy_version=trivy_version,
        )

        if output_file:
            self._save_results(scan_result, output_file)

        self._print_summary(scan_result)

        return scan_result

    def _parse_trivy_results(self, trivy_data: dict) -> list[CVEFinding]:
        """Parse Trivy JSON output into CVEFinding objects"""
        findings = []

        # Trivy results structure: Results -> Vulnerabilities
        results = trivy_data.get("Results", [])

        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])
            target = result.get("Target", "")

            for vuln in vulnerabilities:
                finding = CVEFinding(
                    cve_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    package_name=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion"),
                    title=vuln.get("Title", ""),
                    description=vuln.get("Description", ""),
                    references=vuln.get("References", []),
                    cvss_score=self._extract_cvss_score(vuln),
                    file_path=target,
                )
                findings.append(finding)

        return findings

    def _extract_cvss_score(self, vuln: dict) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        cvss = vuln.get("CVSS", {})

        # Try CVSS v3 first
        if "nvd" in cvss and "V3Score" in cvss["nvd"]:
            return cvss["nvd"]["V3Score"]

        # Fall back to any available score
        for _source, data in cvss.items():
            if "V3Score" in data:
                return data["V3Score"]
            if "V2Score" in data:
                return data["V2Score"]

        return None

    def _enrich_with_foundation_sec(self, findings: list[CVEFinding]) -> list[CVEFinding]:
        """
        Enrich CVE findings with Foundation-Sec-8B analysis

        Maps CVE -> CWE and assesses exploitability
        """
        enriched = []

        for finding in findings:
            # Use Foundation-Sec for CWE mapping (as shown in model card example)
            cwe_id = self._map_cve_to_cwe(finding)
            finding.cwe_id = cwe_id

            # Assess exploitability based on CVE + CWE
            exploitability = self._assess_exploitability(finding)
            finding.exploitability = exploitability

            enriched.append(finding)

        return enriched

    def _map_cve_to_cwe(self, finding: CVEFinding) -> Optional[str]:
        """
        Use Foundation-Sec-8B to map CVE to CWE

        Uses the exact prompt format from the model card:
        https://huggingface.co/fdtn-ai/Foundation-Sec-8B
        """
        if not self.foundation_sec_model:
            return None

        try:
            # Format prompt as shown in model card
            prompt = f"""{finding.cve_id} is a vulnerability in {finding.package_name} described as: {finding.description[:200]}

The CWE is CWE-"""

            # Generate CWE prediction
            # Note: Actual implementation depends on how foundation_sec_model is passed
            # This is a placeholder for the interface
            if hasattr(self.foundation_sec_model, "generate"):
                cwe = self.foundation_sec_model.generate(prompt, max_new_tokens=10, temperature=0.1)
                return f"CWE-{cwe.strip()}"

        except Exception as e:
            logger.warning(f"⚠️  CWE mapping failed for {finding.cve_id}: {e}")

        return None

    def _assess_exploitability(self, finding: CVEFinding) -> str:
        """
        Assess exploitability level

        Based on CVSS score and CWE category
        """
        # Simple heuristic (can be enhanced with Foundation-Sec)
        if finding.cvss_score:
            if finding.cvss_score >= 9.0:
                return "trivial"
            elif finding.cvss_score >= 7.0:
                return "moderate"
            elif finding.cvss_score >= 4.0:
                return "complex"
            else:
                return "theoretical"

        # Fallback based on severity
        severity_map = {"CRITICAL": "trivial", "HIGH": "moderate", "MEDIUM": "complex", "LOW": "theoretical"}
        return severity_map.get(finding.severity, "theoretical")

    def _calculate_severity_counts(self, findings: list[CVEFinding]) -> dict[str, int]:
        """Calculate counts by severity level"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for finding in findings:
            severity = finding.severity.upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["UNKNOWN"] += 1

        return counts

    def _get_trivy_version(self) -> str:
        """Get Trivy version"""
        try:
            result = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=5)
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return "unknown"

    def _save_results(self, scan_result: TrivyScanResult, output_file: str) -> None:
        """Save scan results to JSON file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict
        result_dict = asdict(scan_result)

        with open(output_path, "w") as f:
            json.dump(result_dict, f, indent=2)

        logger.info(f"💾 Results saved to: {output_path}")

    def generate_sbom(
        self,
        target_path: str,
        output_dir: str = ".",
        formats: Optional[list[str]] = None,
    ) -> dict:
        """Generate SBOM for the scanned target.

        Uses the SBOMGenerator to produce CycloneDX and/or SPDX SBOMs
        via Trivy's native SBOM generation capabilities.

        Args:
            target_path: Path to scan (directory or container image).
            output_dir: Where to write SBOM files.
            formats: List of formats to generate. Valid values are
                "cyclonedx" and "spdx". Default: both.

        Returns:
            dict with generation results per format. Each format entry
            contains keys: success, sbom_path, component_count, format.
            On error returns a dict with success=False and an error key.
        """
        from scripts.sbom_generator import SBOMGenerator

        valid_formats = {"cyclonedx", "spdx"}
        if formats is None:
            formats = sorted(valid_formats)
        else:
            unknown = set(formats) - valid_formats
            if unknown:
                return {
                    "success": False,
                    "error": (
                        f"Unknown SBOM format(s): {unknown}. "
                        f"Valid formats: {valid_formats}"
                    ),
                }

        try:
            generator = SBOMGenerator(output_dir=output_dir)
        except Exception as e:
            return {"success": False, "error": f"Failed to initialize SBOMGenerator: {e}"}

        results: dict = {}

        if "cyclonedx" in formats:
            results["cyclonedx"] = generator.generate_cyclonedx(target_path)

        if "spdx" in formats:
            results["spdx"] = generator.generate_spdx(target_path)

        return results

    def _print_summary(self, scan_result: TrivyScanResult) -> None:
        """Print scan summary to console"""
        print("\n" + "=" * 80)
        print("🔍 TRIVY CVE SCAN RESULTS")
        print("=" * 80)
        print(f"📁 Target: {scan_result.target}")
        print(f"🕐 Timestamp: {scan_result.timestamp}")
        print(f"⏱️  Duration: {scan_result.scan_duration_seconds:.1f}s")
        print(f"📦 Trivy Version: {scan_result.trivy_version}")
        print()
        print(f"🔴 Critical: {scan_result.critical}")
        print(f"🟠 High:     {scan_result.high}")
        print(f"🟡 Medium:   {scan_result.medium}")
        print(f"🟢 Low:      {scan_result.low}")
        print(f"📊 Total:    {scan_result.total_vulnerabilities}")

        if self.foundation_sec_enabled:
            print()
            print("🤖 Foundation-Sec-8B Enrichment:")
            cwe_mapped = sum(1 for f in scan_result.findings if f.cwe_id)
            print(f"   CWE Mapped: {cwe_mapped}/{len(scan_result.findings)}")

        print("=" * 80)

        # Show top 5 critical/high findings
        critical_high = [f for f in scan_result.findings if f.severity in ["CRITICAL", "HIGH"]]

        if critical_high:
            print("\n🚨 Top Critical/High CVEs:")
            for i, finding in enumerate(critical_high[:5], 1):
                print(f"\n{i}. {finding.cve_id} [{finding.severity}]")
                print(f"   Package: {finding.package_name} {finding.installed_version}")
                print(f"   Title: {finding.title[:80]}")
                if finding.cwe_id:
                    print(f"   CWE: {finding.cwe_id}")
                if finding.fixed_version:
                    print(f"   Fix: Upgrade to {finding.fixed_version}")
                if finding.exploitability:
                    print(f"   Exploitability: {finding.exploitability}")


def main():
    """CLI entry point for Trivy scanner"""
    import argparse

    parser = argparse.ArgumentParser(description="Trivy CVE Scanner with Foundation-Sec-8B enrichment")
    parser.add_argument("target", help="Target to scan (directory path or container image)")
    parser.add_argument(
        "--scan-type", choices=["filesystem", "image"], default="filesystem", help="Type of scan to perform"
    )
    parser.add_argument(
        "--severity", default="CRITICAL,HIGH,MEDIUM,LOW", help="Comma-separated severity levels to report"
    )
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument("--foundation-sec", action="store_true", help="Enable Foundation-Sec-8B CWE mapping")

    args = parser.parse_args()

    # Initialize scanner
    foundation_sec_model = None
    if args.foundation_sec:
        try:
            from providers.foundation_sec import FoundationSecProvider

            logger.info("🤖 Loading Foundation-Sec-8B model...")
            foundation_sec_model = FoundationSecProvider()
        except Exception as e:
            logger.warning(f"⚠️  Could not load Foundation-Sec: {e}")
            logger.warning("   Continuing without CWE enrichment")

    scanner = TrivyScanner(foundation_sec_enabled=args.foundation_sec, foundation_sec_model=foundation_sec_model)

    # Run scan
    if args.scan_type == "filesystem":
        result = scanner.scan_filesystem(args.target, severity=args.severity, output_file=args.output)
    else:
        result = scanner.scan_container_image(args.target, severity=args.severity, output_file=args.output)

    # Exit with error code if critical/high found
    if result.critical > 0 or result.high > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
