"""Trivy normalizer"""

from .base import Finding, Normalizer


class TrivyNormalizer(Normalizer):
    """Normalize Trivy output to Finding format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert Trivy JSON to Finding objects

        Args:
            raw_output: Trivy JSON output

        Returns:
            List of Finding objects
        """
        findings = []
        git_context = self._get_git_context()

        # Trivy format: { Results: [ { Vulnerabilities: [...] } ] }
        results = raw_output.get("Results", [])

        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", [])

            # Validate vulnerabilities is a list
            if not isinstance(vulnerabilities, list):
                continue

            for vuln in vulnerabilities:
                # Skip non-dict vulnerability entries
                if not isinstance(vuln, dict):
                    continue
                finding = Finding(
                    id=self._generate_id(
                        {
                            "repo": git_context["repo"],
                            "path": target,
                            "rule_id": vuln.get("VulnerabilityID", "unknown"),
                            "line": 0,
                        }
                    ),
                    origin="trivy",
                    repo=git_context["repo"],
                    commit_sha=git_context["commit_sha"],
                    branch=git_context["branch"],
                    asset_type="image" if "image" in target else "code",
                    path=target,
                    rule_id=vuln.get("VulnerabilityID", "unknown"),
                    rule_name=f"{vuln.get('PkgName')} - {vuln.get('VulnerabilityID')}",
                    category="DEPS",
                    severity=self._map_severity(vuln.get("Severity", "MEDIUM")),
                    cvss=self._extract_cvss(vuln),
                    cve=vuln.get("VulnerabilityID") if vuln.get("VulnerabilityID", "").startswith("CVE-") else None,
                    cwe=self._extract_cwe(vuln),
                    evidence={
                        "message": vuln.get("Title", vuln.get("Description", "No description")),
                        "snippet": f"Package: {vuln.get('PkgName')} {vuln.get('InstalledVersion')} -> Fix: {vuln.get('FixedVersion', 'N/A')}",
                        "artifact_url": vuln.get("PrimaryURL", ""),
                    },
                    references=[vuln.get("PrimaryURL", "")] + vuln.get("References", []),
                    confidence=0.95,  # Trivy CVE data is high confidence
                )

                finding.risk_score = finding.calculate_risk_score()
                findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> str:
        """Map Trivy severity to standard severity"""
        mapping = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
        return mapping.get(severity.upper(), "medium")

    def _extract_cvss(self, vuln: dict) -> float:
        """Extract CVSS score from vulnerability"""
        cvss = vuln.get("CVSS", {})

        # Try CVSS v3 first, then v2
        for version in ["nvd", "redhat", "vendor"]:
            if version in cvss:
                v3_score = cvss[version].get("V3Score")
                if v3_score:
                    return float(v3_score)
                v2_score = cvss[version].get("V2Score")
                if v2_score:
                    return float(v2_score)

        return None

    def _extract_cwe(self, vuln: dict) -> str:
        """Extract CWE from vulnerability"""
        cwe_ids = vuln.get("CweIDs", [])
        if cwe_ids:
            return cwe_ids[0]
        return None
