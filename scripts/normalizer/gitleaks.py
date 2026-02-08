"""Gitleaks normalizer"""

from .base import Finding, Normalizer


class GitleaksNormalizer(Normalizer):
    """Normalize Gitleaks output to Finding format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert Gitleaks JSON to Finding objects

        Args:
            raw_output: Gitleaks JSON output

        Returns:
            List of Finding objects
        """
        findings = []
        git_context = self._get_git_context()

        # Gitleaks outputs list of findings
        results = raw_output if isinstance(raw_output, list) else [raw_output]

        for result in results:
            # Validate file path - skip empty or dot-only paths
            file_path = result.get("File", "")
            if not file_path or file_path.strip() in ("", "."):
                continue

            # Gitleaks doesn't verify secrets via API by default
            # Mark as unverified unless we add verification later

            finding = Finding(
                id=self._generate_id(
                    {
                        "repo": git_context["repo"],
                        "path": result.get("File", "unknown"),
                        "rule_id": result.get("RuleID", "gitleaks-secret"),
                        "line": result.get("StartLine", 0),
                    }
                ),
                origin="gitleaks",
                repo=git_context["repo"],
                commit_sha=result.get("Commit", git_context["commit_sha"]),
                branch=git_context["branch"],
                asset_type="code",
                path=result.get("File", "unknown"),
                line=result.get("StartLine"),
                rule_id=result.get("RuleID", "gitleaks-secret"),
                rule_name=result.get("Description", "Secret Detected"),
                category="SECRETS",
                severity=self._map_severity(result),
                evidence={
                    "message": result.get("Message", "Potential secret detected"),
                    "snippet": self._redact_secret(result.get("Secret", "")),
                    "artifact_url": "",
                },
                references=[
                    "https://github.com/gitleaks/gitleaks",
                ],
                secret_verified="false",  # Gitleaks doesn't verify by default
                confidence=0.7,  # Medium confidence (pattern-based)
            )

            finding.risk_score = finding.calculate_risk_score()
            findings.append(finding)

        return findings

    def _map_severity(self, result: dict) -> str:
        """Map Gitleaks severity to standard severity"""
        # Gitleaks doesn't provide severity, default to high for secrets
        return "high"

    def _redact_secret(self, raw_secret: str) -> str:
        """Redact secret for evidence"""
        if len(raw_secret) <= 8:
            return "***REDACTED***"
        return f"{raw_secret[:4]}{'*' * (len(raw_secret) - 8)}{raw_secret[-4:]}"
