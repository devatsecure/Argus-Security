#!/usr/bin/env python3
"""
Semgrep SAST Scanner for Agent OS
Integrates Semgrep static analysis with LLM-powered triage

Features:
- Fast pattern-based vulnerability detection
- 2,000+ security rules
- Language-agnostic scanning
- JSON output for LLM processing
"""

import json
import logging
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SemgrepFinding:
    """A single Semgrep finding"""

    rule_id: str
    severity: str  # ERROR, WARNING, INFO
    message: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: str = "HIGH"

    def to_dict(self) -> dict:
        return asdict(self)


class SemgrepScanner:
    """Wrapper for Semgrep SAST scanning"""

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize Semgrep scanner

        Args:
            config: Optional configuration
                - semgrep_rules: Custom rules path or 'auto' (default)
                - languages: List of languages to scan
                - exclude_patterns: Patterns to exclude
        """
        self.config = config or {}
        self.semgrep_rules = self.config.get("semgrep_rules", "auto")
        self.languages = self.config.get("languages", [])
        self.exclude_patterns = self.config.get(
            "exclude_patterns",
            ["*/test/*", "*/tests/*", "*/.git/*", "*/node_modules/*", "*/.venv/*", "*/venv/*", "*/build/*", "*/dist/*"],
        )

        # Resolve semgrep binary path (shutil.which + common fallbacks)
        self._semgrep_bin = self._resolve_semgrep_path()
        if not self._semgrep_bin:
            logger.warning("Semgrep not installed. Install with: pip install semgrep")

    def _resolve_semgrep_path(self) -> Optional[str]:
        """Resolve the full path to the semgrep binary."""
        bin_path = shutil.which("semgrep")
        if bin_path:
            return bin_path
        # Fallback: common install locations not always on PATH in subprocesses
        for candidate in ["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep", "/usr/bin/semgrep"]:
            if Path(candidate).is_file():
                return candidate
        return None

    def _check_semgrep_installed(self) -> bool:
        """Check if semgrep is available"""
        if not self._semgrep_bin:
            return False
        try:
            result = subprocess.run([self._semgrep_bin, "--version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def scan(self, target_path: str, output_format: str = "json") -> dict[str, Any]:
        """
        Run Semgrep scan on target path

        Args:
            target_path: Path to scan (file or directory)
            output_format: Output format ('json', 'sarif', or 'text')

        Returns:
            Scan results as dictionary
        """
        logger.info(f"🔍 Starting Semgrep scan: {target_path}")

        if not self._check_semgrep_installed():
            logger.error("Semgrep not installed")
            return {"error": "semgrep_not_installed", "findings": []}

        target_path = Path(target_path).resolve()
        if not target_path.exists():
            logger.error(f"Target path does not exist: {target_path}")
            return {"error": "path_not_found", "findings": []}

        # Build semgrep command
        cmd = [
            self._semgrep_bin,
            "--config",
            self.semgrep_rules if self.semgrep_rules != "auto" else "p/security-audit",
            "--json",
            "--quiet",
            "--metrics=off",
        ]

        # Add exclude patterns
        for pattern in self.exclude_patterns:
            cmd.extend(["--exclude", pattern])

        # Add target
        cmd.append(str(target_path))

        try:
            logger.info(f"   Running: {' '.join(cmd[:5])}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minute timeout

            if result.returncode not in [0, 1]:  # 1 = findings found (normal)
                logger.error(f"Semgrep failed: {result.stderr}")
                return {"error": "semgrep_failed", "findings": [], "stderr": result.stderr}

            # Parse JSON output
            semgrep_output = json.loads(result.stdout)
            findings = self._parse_semgrep_output(semgrep_output)

            logger.info(f"✅ Semgrep scan complete: {len(findings)} findings")

            return {
                "tool": "semgrep",
                "version": self._get_semgrep_version(),
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "target": str(target_path),
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "raw_output": semgrep_output if self.config.get("include_raw") else None,
            }

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return {"error": "timeout", "findings": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            return {"error": "parse_failed", "findings": [], "raw_output": result.stdout}
        except Exception as e:
            logger.error(f"Semgrep scan error: {e}")
            return {"error": str(e), "findings": []}

    def _parse_semgrep_output(self, semgrep_output: dict) -> list[SemgrepFinding]:
        """Parse Semgrep JSON output into SemgrepFinding objects"""
        findings = []

        for result in semgrep_output.get("results", []):
            # Extract metadata
            check_id = result.get("check_id", "unknown")

            # Map Semgrep severity to standard levels
            # ERROR = critical (most severe)
            # WARNING = high (important security issues)
            # INFO = medium (informational but worth reviewing)
            severity_map = {"ERROR": "critical", "WARNING": "high", "INFO": "medium"}
            raw_severity = result.get("extra", {}).get("severity", "WARNING")
            severity = severity_map.get(raw_severity, "medium")

            # Extract CWE if available
            cwe = None
            owasp = None
            metadata = result.get("extra", {}).get("metadata", {})
            if "cwe" in metadata:
                cwe_list = metadata["cwe"]
                if isinstance(cwe_list, list) and cwe_list:
                    cwe = cwe_list[0]
            if "owasp" in metadata:
                owasp_list = metadata["owasp"]
                if isinstance(owasp_list, list) and owasp_list:
                    owasp = owasp_list[0]

            # Extract location
            file_path = result.get("path", "")
            start_line = result.get("start", {}).get("line", 0)
            end_line = result.get("end", {}).get("line", 0)

            # Extract code snippet
            code_snippet = result.get("extra", {}).get("lines", "")

            finding = SemgrepFinding(
                rule_id=check_id,
                severity=severity,
                message=result.get("extra", {}).get("message", ""),
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                code_snippet=code_snippet,
                cwe=cwe,
                owasp=owasp,
                confidence="HIGH",  # Semgrep has low false positive rate
            )

            findings.append(finding)

        return findings

    def _get_semgrep_version(self) -> str:
        """Get Semgrep version"""
        try:
            result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def save_results(self, results: dict, output_path: str):
        """Save scan results to file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"💾 Results saved to: {output_path}")


def main():
    """CLI interface for standalone usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Semgrep SAST Scanner")
    parser.add_argument("target", help="Target path to scan")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--rules", default="auto", help="Semgrep rules (default: auto)")
    parser.add_argument("--exclude", action="append", help="Patterns to exclude")

    args = parser.parse_args()

    config = {"semgrep_rules": args.rules, "exclude_patterns": args.exclude or []}

    scanner = SemgrepScanner(config)
    results = scanner.scan(args.target)

    if args.output:
        scanner.save_results(results, args.output)
    else:
        print(json.dumps(results, indent=2))

    # Exit with error code if findings found
    if results.get("findings_count", 0) > 0:
        print(f"\n⚠️  Found {results['findings_count']} potential issues")
        return 1
    else:
        print("\n✅ No issues found")
        return 0


if __name__ == "__main__":
    exit(main())
