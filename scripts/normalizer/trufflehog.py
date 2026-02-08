"""TruffleHog normalizer - VERIFIED SECRETS ONLY"""

from .base import Finding, Normalizer


class TruffleHogNormalizer(Normalizer):
    """Normalize TruffleHog output to Finding format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert TruffleHog JSON to Finding objects

        IMPORTANT: Only include VERIFIED secrets (verified=True)
        This prevents false positives from entropy-based detection

        Args:
            raw_output: TruffleHog JSON output (list of findings)

        Returns:
            List of Finding objects (verified secrets only)
        """
        findings = []
        git_context = self._get_git_context()

        # TruffleHog outputs list of findings
        for result in raw_output if isinstance(raw_output, list) else [raw_output]:
            # CRITICAL: Only include verified secrets
            if not result.get("verified", False):
                continue  # Skip unverified findings

            # Extract source location
            source_metadata = result.get("source_metadata", {})

            # Validate source_metadata is a dict
            if not isinstance(source_metadata, dict):
                continue

            data = source_metadata.get("data", {})

            # Validate data is a dict
            if not isinstance(data, dict):
                continue

            git_data = data.get("Git", {})

            # Build finding
            finding = Finding(
                id=self._generate_id(
                    {
                        "repo": git_context["repo"],
                        "path": git_data.get("file", "unknown"),
                        "rule_id": result.get("detector_type", "trufflehog-secret"),
                        "line": git_data.get("line", 0),
                    }
                ),
                origin="trufflehog",
                repo=git_context["repo"],
                commit_sha=git_data.get("commit", git_context["commit_sha"]),
                branch=git_context["branch"],
                asset_type="code",
                path=git_data.get("file", "unknown"),
                line=git_data.get("line"),
                rule_id=result.get("detector_type", "trufflehog-secret"),
                rule_name=f"Verified {result.get('detector_name', 'Secret')} Detected",
                category="SECRETS",
                severity="critical",  # All verified secrets are critical
                evidence={
                    "message": f"Verified {result.get('detector_name')} secret detected",
                    "snippet": self._redact_secret(result.get("raw", "")),
                    "artifact_url": git_data.get("url", ""),
                },
                references=[
                    "https://github.com/trufflesecurity/trufflehog",
                ],
                secret_verified="true",  # VERIFIED by API
                confidence=0.95,  # High confidence for verified secrets
            )

            # Calculate risk score (will be high due to verified secret)
            finding.risk_score = finding.calculate_risk_score()

            findings.append(finding)

        return findings

    def _redact_secret(self, raw_secret: str) -> str:
        """Redact secret for evidence (show first/last 4 chars)"""
        if len(raw_secret) <= 8:
            return "***REDACTED***"
        return f"{raw_secret[:4]}{'*' * (len(raw_secret) - 8)}{raw_secret[-4:]}"
