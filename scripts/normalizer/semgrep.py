"""Semgrep SARIF normalizer"""

from .base import Finding, Normalizer


class SemgrepNormalizer(Normalizer):
    """Normalize Semgrep SARIF output to Finding format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert Semgrep SARIF to Finding objects

        Args:
            raw_output: Semgrep SARIF 2.1.0 output

        Returns:
            List of Finding objects
        """
        findings = []
        git_context = self._get_git_context()

        # SARIF format: { runs: [ { results: [...] } ] }
        runs = raw_output.get("runs", [])

        for run in runs:
            results = run.get("results", [])

            for result in results:
                # Extract location
                locations = result.get("locations", [])
                if not locations:
                    continue

                location = locations[0]
                physical_location = location.get("physicalLocation", {})
                artifact_location = physical_location.get("artifactLocation", {})
                region = physical_location.get("region", {})

                path = artifact_location.get("uri", "unknown")
                line = region.get("startLine", 0)

                # Validate file path - skip empty or dot-only paths
                if not path or path.strip() in ("", "."):
                    continue

                # Extract rule info
                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {}).get("text", "No description")

                # Get rule metadata from run.tool.driver.rules
                rule_metadata = self._get_rule_metadata(run, rule_id)

                finding = Finding(
                    id=self._generate_id({"repo": git_context["repo"], "path": path, "rule_id": rule_id, "line": line}),
                    origin="semgrep",
                    repo=git_context["repo"],
                    commit_sha=git_context["commit_sha"],
                    branch=git_context["branch"],
                    asset_type="code",
                    path=path,
                    line=line,
                    rule_id=rule_id,
                    rule_name=rule_metadata.get("name", rule_id),
                    category="SAST",
                    severity=self._map_severity(result.get("level", "warning")),
                    cwe=self._extract_cwe(rule_metadata),
                    evidence={
                        "message": message,
                        "snippet": region.get("snippet", {}).get("text", ""),
                        "artifact_url": "",
                    },
                    references=rule_metadata.get("helpUri", "").split(",") if rule_metadata.get("helpUri") else [],
                    confidence=0.85,  # Semgrep has good accuracy
                )

                finding.risk_score = finding.calculate_risk_score()
                findings.append(finding)

        return findings

    def _get_rule_metadata(self, run: dict, rule_id: str) -> dict:
        """Extract rule metadata from SARIF run"""
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        rules = driver.get("rules", [])

        for rule in rules:
            if rule.get("id") == rule_id:
                return rule

        return {}

    def _map_severity(self, level: str) -> str:
        """Map SARIF level to standard severity"""
        mapping = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
        return mapping.get(level, "medium")

    def _extract_cwe(self, rule_metadata: dict) -> str:
        """Extract CWE from rule metadata"""
        properties = rule_metadata.get("properties", {})
        tags = properties.get("tags", [])

        for tag in tags:
            if tag.startswith("CWE-"):
                return tag

        return None
