"""
Argus Finding Normalizer
Converts security tool outputs to unified Finding format
"""

from .base import Finding, Normalizer
from .checkov import CheckovNormalizer
from .gitleaks import GitleaksNormalizer
from .semgrep import SemgrepNormalizer
from .trivy import TrivyNormalizer
from .trufflehog import TruffleHogNormalizer

__all__ = [
    "Finding",
    "Normalizer",
    "SemgrepNormalizer",
    "TrivyNormalizer",
    "TruffleHogNormalizer",
    "GitleaksNormalizer",
    "CheckovNormalizer",
    "UnifiedNormalizer",
]


class UnifiedNormalizer:
    """Unified normalizer that handles all security tools"""

    def __init__(self):
        self.normalizers = {
            "semgrep": SemgrepNormalizer(),
            "trivy": TrivyNormalizer(),
            "trufflehog": TruffleHogNormalizer(),
            "gitleaks": GitleaksNormalizer(),
            "checkov": CheckovNormalizer(),
        }

    def normalize(self, tool: str, raw_output: dict) -> list[Finding]:
        """
        Convert tool-specific output to unified Finding format

        Args:
            tool: Name of the tool (semgrep, trivy, etc.)
            raw_output: Raw JSON/dict output from tool

        Returns:
            List of Finding objects

        Raises:
            ValueError: If tool is not supported
        """
        normalizer = self.normalizers.get(tool)
        if not normalizer:
            raise ValueError(f"Unsupported tool: {tool}. Supported: {list(self.normalizers.keys())}")

        findings = normalizer.normalize(raw_output)

        # Deduplicate
        return self._deduplicate(findings)

    def normalize_all(self, tool_outputs: dict) -> list[Finding]:
        """
        Normalize outputs from multiple tools

        Args:
            tool_outputs: Dict of {tool_name: raw_output}

        Returns:
            Deduplicated list of Finding objects
        """
        all_findings = []

        for tool, output in tool_outputs.items():
            try:
                findings = self.normalize(tool, output)
                all_findings.extend(findings)
            except Exception as e:
                print(f"Warning: Failed to normalize {tool} output: {e}")
                continue

        return self._deduplicate(all_findings)

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on dedup key"""
        seen = set()
        unique = []

        for finding in findings:
            key = finding.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
