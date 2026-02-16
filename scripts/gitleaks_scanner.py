#!/usr/bin/env python3
"""
Gitleaks Secret Scanner for Argus Security Pipeline.

Scans git repositories and filesystems for secrets using Gitleaks.
Pattern-based detection complements TruffleHog's verified-secret detection.

Features:
- Pattern-based secret detection (API keys, tokens, passwords)
- Git history scanning with commit context
- JSON output format for pipeline processing
- Graceful handling when Gitleaks binary is not installed
- Safe subprocess execution (no shell=True)
"""

import json
import logging
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class GitleaksFinding:
    """A single Gitleaks secret finding."""

    rule_id: str  # e.g., "aws-access-key", "generic-api-key"
    description: str  # Human-readable description of the rule
    file_path: str  # Path to file containing the secret
    start_line: int  # Line number where the secret starts
    end_line: int  # Line number where the secret ends
    start_column: int  # Column number where the match starts
    end_column: int  # Column number where the match ends
    match: str  # The matched text (redacted for display)
    secret: str  # The actual secret (should be redacted in output)
    commit: Optional[str] = None  # Git commit SHA (if git scan)
    author: Optional[str] = None  # Commit author
    email: Optional[str] = None  # Commit author email
    date: Optional[str] = None  # Commit date
    message: Optional[str] = None  # Commit message
    entropy: Optional[float] = None  # Shannon entropy of the secret
    tags: Optional[list[str]] = None  # Tags from Gitleaks rules

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class GitleaksScanner:
    """
    Gitleaks Secret Scanner.

    Scans repositories and filesystems for secrets using Gitleaks pattern-based
    detection. This complements TruffleHog by catching secrets that pattern
    matching identifies but that cannot be API-verified.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize Gitleaks scanner.

        Args:
            config: Optional configuration dictionary
                - scan_depth: How many commits to scan (default: all)
                - config_path: Path to custom .gitleaks.toml config
                - exclude_patterns: Patterns to exclude from scanning
                - redact: Redact secrets in output (default: True)
        """
        self.config = config or {}
        self.scan_depth = self.config.get("scan_depth", None)
        self.config_path = self.config.get("config_path", None)
        self.redact = self.config.get("redact", True)
        self._installed: Optional[bool] = None

        # Check if gitleaks is installed
        if not self._check_gitleaks_installed():
            logger.warning(
                "Gitleaks not installed. Install via: brew install gitleaks (macOS) "
                "or download from https://github.com/gitleaks/gitleaks/releases"
            )

    def _check_gitleaks_installed(self) -> bool:
        """
        Check if Gitleaks binary is installed and accessible.

        Returns:
            True if Gitleaks is available, False otherwise.
        """
        if self._installed is not None:
            return self._installed

        try:
            result = subprocess.run(
                ["gitleaks", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Gitleaks detected: {version}")
                self._installed = True
                return True
            self._installed = False
            return False
        except FileNotFoundError:
            self._installed = False
            return False
        except subprocess.SubprocessError:
            self._installed = False
            return False
        except OSError:
            self._installed = False
            return False

    def scan(self, target_path: str, scan_type: str = "filesystem") -> dict[str, Any]:
        """
        Execute Gitleaks scan on target path.

        Args:
            target_path: Path to git repository or filesystem directory to scan.
            scan_type: Type of scan - "git" or "filesystem" (default: "filesystem").

        Returns:
            Dictionary containing scan results:
                - tool: "gitleaks"
                - version: Gitleaks version
                - timestamp: ISO format timestamp
                - target: Path that was scanned
                - scan_type: Type of scan performed
                - findings_count: Number of findings
                - findings: List of GitleaksFinding dicts
        """
        logger.info(f"Starting Gitleaks scan: {target_path}")
        logger.info(f"   Scan type: {scan_type}")

        if not self._check_gitleaks_installed():
            logger.warning("Gitleaks not installed -- returning empty results")
            return {
                "tool": "gitleaks",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "gitleaks_not_installed",
                "findings": [],
                "message": "Install gitleaks: brew install gitleaks (macOS) or download from GitHub releases",
            }

        target = Path(target_path).resolve()
        if not target.exists():
            logger.error(f"Target path does not exist: {target}")
            return {
                "tool": "gitleaks",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "path_not_found",
                "findings": [],
            }

        # Build gitleaks command
        cmd = ["gitleaks"]

        if scan_type == "git":
            cmd.append("git")
        else:
            cmd.append("dir")

        # Source path
        cmd.extend(["--source", str(target)])

        # JSON report to stdout
        cmd.extend(["--report-format", "json"])
        cmd.extend(["--report-path", "/dev/stdout"])

        # Verbose for better logging
        cmd.append("--verbose")

        # No-git flag for filesystem scans (skip .git history)
        if scan_type == "filesystem":
            cmd.append("--no-git")

        # Depth limit for git scans
        if self.scan_depth and scan_type == "git":
            cmd.extend(["--log-opts", f"--max-count={self.scan_depth}"])

        # Custom config
        if self.config_path:
            cmd.extend(["--config", str(self.config_path)])

        # Redact secrets
        if self.redact:
            cmd.append("--redact")

        try:
            logger.info(f"   Running: {' '.join(cmd[:4])}...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                check=False,  # Don't raise on non-zero exit
            )

            # Gitleaks exit codes:
            # 0 = no leaks found
            # 1 = leaks found
            # Other = error
            if result.returncode not in (0, 1):
                logger.error(f"Gitleaks scan failed (exit {result.returncode}): {result.stderr}")
                return {
                    "tool": "gitleaks",
                    "scan_type": scan_type,
                    "findings_count": 0,
                    "error": "gitleaks_failed",
                    "findings": [],
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                }

            # Parse JSON output
            findings = self._parse_output(result.stdout)

            logger.info(f"Gitleaks scan complete: {len(findings)} findings")

            return {
                "tool": "gitleaks",
                "version": self._get_gitleaks_version(),
                "timestamp": datetime.now().isoformat(),
                "target": str(target),
                "scan_type": scan_type,
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
                "config": {
                    "scan_depth": self.scan_depth,
                    "redact": self.redact,
                },
            }

        except subprocess.TimeoutExpired:
            logger.error("Gitleaks scan timed out after 10 minutes")
            return {
                "tool": "gitleaks",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "timeout",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"Gitleaks scan error: {e}")
            return {
                "tool": "gitleaks",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": str(e),
                "findings": [],
            }

    def _parse_output(self, raw_output: str) -> list[GitleaksFinding]:
        """
        Parse Gitleaks JSON output into GitleaksFinding objects.

        Gitleaks outputs a JSON array of finding objects.

        Args:
            raw_output: Raw JSON output string from Gitleaks.

        Returns:
            List of GitleaksFinding objects.
        """
        findings: list[GitleaksFinding] = []

        if not raw_output or not raw_output.strip():
            return findings

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Gitleaks JSON output: {e}")
            return findings

        if not isinstance(data, list):
            logger.warning(f"Expected JSON array from Gitleaks, got {type(data).__name__}")
            return findings

        for item in data:
            if not isinstance(item, dict):
                logger.warning(f"Skipping non-dict Gitleaks finding: {type(item).__name__}")
                continue

            # Validate required File field
            file_path = item.get("File", "")
            if not file_path or file_path.strip() in ("", "."):
                logger.warning("Skipping Gitleaks finding with empty file path")
                continue

            try:
                finding = GitleaksFinding(
                    rule_id=item.get("RuleID", "unknown"),
                    description=item.get("Description", "Secret detected"),
                    file_path=file_path,
                    start_line=item.get("StartLine", 0),
                    end_line=item.get("EndLine", 0),
                    start_column=item.get("StartColumn", 0),
                    end_column=item.get("EndColumn", 0),
                    match=item.get("Match", ""),
                    secret=item.get("Secret", ""),
                    commit=item.get("Commit", None),
                    author=item.get("Author", None),
                    email=item.get("Email", None),
                    date=item.get("Date", None),
                    message=item.get("Message", None),
                    entropy=item.get("Entropy", None),
                    tags=item.get("Tags", []),
                )
                findings.append(finding)
            except Exception as e:
                logger.warning(f"Error processing Gitleaks finding: {e}")
                continue

        return findings

    def _get_gitleaks_version(self) -> str:
        """
        Get Gitleaks version string.

        Returns:
            Version string or "unknown".
        """
        try:
            result = subprocess.run(
                ["gitleaks", "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def _redact_secret(self, secret: str) -> str:
        """
        Redact secret for safe display.

        Shows first 4 and last 4 characters, replaces middle with asterisks.

        Args:
            secret: The raw secret string.

        Returns:
            Redacted secret string.
        """
        if not secret:
            return "***REDACTED***"

        if len(secret) <= 8:
            return "***REDACTED***"

        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def save_results(self, results: dict, output_path: str) -> None:
        """
        Save scan results to JSON file.

        Args:
            results: Scan results dictionary.
            output_path: Path to output JSON file.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        # Redact secrets before saving
        if "findings" in results:
            for finding in results["findings"]:
                if "secret" in finding:
                    finding["secret"] = self._redact_secret(finding["secret"])
                if "match" in finding:
                    finding["match"] = self._redact_secret(finding["match"])

        with open(out, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Results saved to: {out}")


def main():
    """CLI interface for standalone usage."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Gitleaks Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan filesystem (current files only)
  python gitleaks_scanner.py /path/to/code

  # Scan git repository (full history)
  python gitleaks_scanner.py /path/to/repo --scan-type git

  # Scan with depth limit
  python gitleaks_scanner.py /path/to/repo --scan-type git --depth 100

  # Save results to file
  python gitleaks_scanner.py /path/to/code -o results.json
        """,
    )
    parser.add_argument("target", help="Target path to scan (git repo or directory)")
    parser.add_argument(
        "--scan-type",
        choices=["git", "filesystem"],
        default="filesystem",
        help="Scan type: git (full history) or filesystem (current files)",
    )
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument(
        "--depth",
        type=int,
        help="Max commit depth for git scans (default: all commits)",
    )
    parser.add_argument(
        "--config",
        help="Path to custom .gitleaks.toml config file",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Do not redact secrets in output",
    )

    args = parser.parse_args()

    config = {
        "scan_depth": args.depth,
        "config_path": args.config,
        "redact": not args.no_redact,
    }

    scanner = GitleaksScanner(config)
    results = scanner.scan(args.target, scan_type=args.scan_type)

    if args.output:
        scanner.save_results(results, args.output)
    else:
        # Redact secrets before printing
        if "findings" in results:
            for finding in results["findings"]:
                if "secret" in finding:
                    finding["secret"] = scanner._redact_secret(finding["secret"])
                if "match" in finding:
                    finding["match"] = scanner._redact_secret(finding["match"])
        print(json.dumps(results, indent=2))

    findings_count = results.get("findings_count", 0)
    if findings_count > 0:
        print(f"\n  Found {findings_count} potential secrets", file=sys.stderr)
        return 1

    if "error" in results:
        print(f"\n  Scan error: {results['error']}", file=sys.stderr)
        return 2

    print("\n  No secrets detected", file=sys.stderr)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
