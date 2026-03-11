#!/usr/bin/env python3
"""
TruffleHog v3 Secret Scanner for Agent OS
Scans git repositories for verified secrets using TruffleHog

Features:
- Verified secrets detection (API-validated credentials)
- Git history scanning with commit context
- JSON output format for LLM processing
- Support for 800+ secret detectors
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
class TruffleHogFinding:
    """A single TruffleHog secret finding"""

    detector_type: str  # e.g., "AWS", "GitHub", "Slack"
    detector_name: str  # Human-readable detector name
    verified: bool  # Whether secret was verified via API
    raw: str  # The actual secret (should be redacted in output)
    file_path: str  # Path to file containing secret
    commit: str  # Git commit SHA
    line: int  # Line number in file
    timestamp: str  # When secret was committed
    author: str  # Commit author
    email: str  # Commit author email
    repository_url: Optional[str] = None
    redacted: str = ""  # Redacted version for safe display

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)


class TruffleHogScanner:
    """
    TruffleHog v3 Secret Scanner

    Scans git repositories for secrets using TruffleHog's verified detection.
    Only reports secrets that are verified via API calls to prevent false positives.
    """

    def __init__(self, config: Optional[dict] = None):
        """
        Initialize TruffleHog scanner

        Args:
            config: Optional configuration dictionary
                - verified_only: Only report verified secrets (default: True)
                - scan_depth: How many commits to scan (default: all)
                - exclude_patterns: Patterns to exclude from scanning
                - include_unverified: Include unverified secrets (default: False)
                - json_output: Output in JSON format (default: True)
        """
        self.config = config or {}
        self.verified_only = self.config.get("verified_only", True)
        self.scan_depth = self.config.get("scan_depth", None)
        self.exclude_patterns = self.config.get(
            "exclude_patterns",
            [
                "*/test/*",
                "*/tests/*",
                "*/testdata/*",
                "*/.git/*",
                "*/node_modules/*",
                "*/.venv/*",
                "*/venv/*",
                "*/vendor/*",
            ],
        )
        self.include_unverified = self.config.get("include_unverified", False)

        # Check if trufflehog is installed
        if not self._check_trufflehog_installed():
            logger.warning("TruffleHog not installed. Run: install_trufflehog()")

    def _check_trufflehog_installed(self) -> bool:
        """
        Check if TruffleHog binary is installed

        Returns:
            True if TruffleHog is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info(f"TruffleHog detected: {result.stdout.strip()}")
                return True
            return False
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def install_trufflehog(self) -> bool:
        """
        Check/install TruffleHog binary

        Returns:
            True if TruffleHog is available after installation attempt
        """
        if self._check_trufflehog_installed():
            logger.info("✅ TruffleHog already installed")
            return True

        logger.info("📦 TruffleHog not found. Installation instructions:")
        logger.info("")
        logger.info("   macOS (Homebrew):")
        logger.info("   brew install trufflehog")
        logger.info("")
        logger.info("   Linux/macOS (Binary):")
        logger.info(
            "   curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        )
        logger.info("")
        logger.info("   Docker:")
        logger.info("   docker pull trufflesecurity/trufflehog:latest")
        logger.info("")

        return False

    def scan(self, target_path: str, scan_type: str = "filesystem") -> dict[str, Any]:
        """
        Execute TruffleHog scan on repository

        Args:
            target_path: Path to git repository or filesystem to scan
            scan_type: Type of scan - "git" or "filesystem" (default: "filesystem")

        Returns:
            Dictionary containing scan results:
                - tool: "trufflehog"
                - version: TruffleHog version
                - timestamp: ISO format timestamp
                - target: Path that was scanned
                - findings_count: Number of findings
                - findings: List of TruffleHogFinding objects
                - verified_count: Number of verified secrets
                - unverified_count: Number of unverified secrets
        """
        logger.info(f"🔍 Starting TruffleHog scan: {target_path}")
        logger.info(f"   Scan type: {scan_type}")
        logger.info(f"   Verified only: {self.verified_only}")

        if not self._check_trufflehog_installed():
            logger.error("❌ TruffleHog not installed")
            return {
                "tool": "trufflehog",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "trufflehog_not_installed",
                "findings": [],
                "message": "Run install_trufflehog() for installation instructions",
            }

        target_path = Path(target_path).resolve()
        if not target_path.exists():
            logger.error(f"❌ Target path does not exist: {target_path}")
            return {
                "tool": "trufflehog",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "path_not_found",
                "findings": [],
            }

        # Build trufflehog command
        cmd = ["trufflehog"]

        # Choose scan type
        if scan_type == "git":
            cmd.extend(["git", f"file://{target_path}"])
        else:
            cmd.extend(["filesystem", str(target_path)])

        # Add JSON output flag and suppress update checks
        cmd.append("--json")
        cmd.append("--no-update")

        # Add verification options
        if self.verified_only:
            cmd.append("--only-verified")

        # Add depth limit if specified
        if self.scan_depth and scan_type == "git":
            cmd.extend(["--max-depth", str(self.scan_depth)])

        # Exclude patterns (TruffleHog v3 uses --exclude-paths with a file)
        # For now, we'll skip exclude patterns for filesystem scans
        # Git scans can filter results post-scan if needed
        # TODO: Create temporary exclude file if patterns are specified

        try:
            logger.info(f"   Running: {' '.join(cmd[:4])}...")

            # Run TruffleHog - SECURE: No shell=True
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                check=False,  # Don't raise on non-zero exit (findings cause exit code 1)
            )

            # Filter update-available noise from stderr
            stderr_lines = result.stderr.splitlines() if result.stderr else []
            filtered_stderr = "\n".join(
                line
                for line in stderr_lines
                if not any(kw in line.lower() for kw in ["new version", "update available", "upgrade"])
            ).strip()

            # TruffleHog returns exit code 183 if secrets are found
            # Exit code 0 means no secrets found
            if result.returncode not in [0, 183]:
                logger.error(f"❌ TruffleHog scan failed: {filtered_stderr}")
                return {
                    "tool": "trufflehog",
                    "scan_type": scan_type,
                    "findings_count": 0,
                    "error": "trufflehog_failed",
                    "findings": [],
                    "stderr": filtered_stderr,
                    "exit_code": result.returncode,
                }

            # Parse JSON output (one JSON object per line)
            findings = self._parse_output(result.stdout)

            # Filter verified only if requested
            if self.verified_only:
                findings = [f for f in findings if f.verified]

            verified_count = sum(1 for f in findings if f.verified)
            unverified_count = len(findings) - verified_count

            logger.info("✅ TruffleHog scan complete:")
            logger.info(f"   Total findings: {len(findings)}")
            logger.info(f"   Verified: {verified_count}")
            logger.info(f"   Unverified: {unverified_count}")

            return {
                "tool": "trufflehog",
                "version": self._get_trufflehog_version(),
                "timestamp": datetime.now().isoformat(),
                "target": str(target_path),
                "scan_type": scan_type,
                "findings_count": len(findings),
                "verified_count": verified_count,
                "unverified_count": unverified_count,
                "findings": [f.to_dict() for f in findings],
                "config": {
                    "verified_only": self.verified_only,
                    "scan_depth": self.scan_depth,
                },
            }

        except subprocess.TimeoutExpired:
            logger.error("❌ TruffleHog scan timed out after 10 minutes")
            return {
                "tool": "trufflehog",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": "timeout",
                "findings": [],
            }
        except Exception as e:
            logger.error(f"❌ TruffleHog scan error: {e}")
            return {
                "tool": "trufflehog",
                "scan_type": scan_type,
                "findings_count": 0,
                "error": str(e),
                "findings": [],
            }

    def scan_file(self, file_path: str) -> dict[str, Any]:
        """
        Scan individual file for secrets

        Args:
            file_path: Path to file to scan

        Returns:
            Dictionary containing scan results for the specific file
        """
        logger.info(f"🔍 Scanning file: {file_path}")

        file_path = Path(file_path).resolve()
        if not file_path.exists():
            logger.error(f"❌ File does not exist: {file_path}")
            return {
                "tool": "trufflehog",
                "scan_type": "filesystem",
                "findings_count": 0,
                "error": "file_not_found",
                "findings": [],
            }

        if not file_path.is_file():
            logger.error(f"❌ Path is not a file: {file_path}")
            return {
                "tool": "trufflehog",
                "scan_type": "filesystem",
                "findings_count": 0,
                "error": "not_a_file",
                "findings": [],
            }

        # Scan the parent directory, then filter to just this file
        parent_dir = file_path.parent
        result = self.scan(str(parent_dir), scan_type="filesystem")

        # Filter findings to only this file
        if "findings" in result and result["findings"]:
            file_findings = [f for f in result["findings"] if Path(f["file_path"]).name == file_path.name]
            result["findings"] = file_findings
            result["findings_count"] = len(file_findings)
            result["verified_count"] = sum(1 for f in file_findings if f.get("verified", False))
            result["target"] = str(file_path)

            logger.info(f"✅ File scan complete: {len(file_findings)} findings in {file_path.name}")

        return result

    def parse_output(self, raw_output: str) -> list[TruffleHogFinding]:
        """
        Parse TruffleHog JSON output

        This is a public wrapper around _parse_output for external use.

        Args:
            raw_output: Raw JSON output string from TruffleHog (newline-delimited JSON)

        Returns:
            List of TruffleHogFinding objects
        """
        return self._parse_output(raw_output)

    def _parse_output(self, raw_output: str) -> list[TruffleHogFinding]:
        """
        Parse TruffleHog JSON output into TruffleHogFinding objects

        TruffleHog outputs newline-delimited JSON (one JSON object per line).
        Each line represents a single finding.

        Args:
            raw_output: Raw JSON output string from TruffleHog

        Returns:
            List of TruffleHogFinding objects
        """
        findings = []

        if not raw_output or not raw_output.strip():
            return findings

        # Parse newline-delimited JSON
        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                result = json.loads(line)

                # Extract source metadata (git or filesystem)
                source_metadata = result.get("SourceMetadata", {})
                data = source_metadata.get("Data", {})

                # Try Git metadata first
                git_data = data.get("Git", {})
                if git_data:
                    file_path = git_data.get("file", "")
                    commit = git_data.get("commit", "")
                    timestamp = git_data.get("timestamp", "")
                    author = git_data.get("author", "")
                    email = git_data.get("email", "")
                    line = git_data.get("line", 0)
                    repo_url = git_data.get("repository", "")
                else:
                    # Fallback to filesystem metadata
                    fs_data = data.get("Filesystem", {})
                    file_path = fs_data.get("file", "")
                    commit = ""
                    timestamp = datetime.now().isoformat()
                    author = ""
                    email = ""
                    line = fs_data.get("line", 0)
                    repo_url = None

                # Extract detector info
                detector_type = result.get("DetectorType", "unknown")
                detector_name = result.get("DetectorName", detector_type)

                # Extract secret
                raw_secret = result.get("Raw", "")
                redacted_secret = result.get("Redacted", self._redact_secret(raw_secret))

                # Verification status
                verified = result.get("Verified", False)

                finding = TruffleHogFinding(
                    detector_type=detector_type,
                    detector_name=detector_name,
                    verified=verified,
                    raw=raw_secret,
                    redacted=redacted_secret,
                    file_path=file_path,
                    commit=commit,
                    line=line,
                    timestamp=timestamp,
                    author=author,
                    email=email,
                    repository_url=repo_url,
                )

                findings.append(finding)

            except json.JSONDecodeError as e:
                logger.warning(f"⚠️  Failed to parse TruffleHog JSON line: {e}")
                continue
            except Exception as e:
                logger.warning(f"⚠️  Error processing TruffleHog finding: {e}")
                continue

        return findings

    def _redact_secret(self, secret: str) -> str:
        """
        Redact secret for safe display

        Shows first 4 and last 4 characters, replaces middle with asterisks.

        Args:
            secret: The raw secret string

        Returns:
            Redacted secret string
        """
        if not secret:
            return "***REDACTED***"

        if len(secret) <= 8:
            return "***REDACTED***"

        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _get_trufflehog_version(self) -> str:
        """
        Get TruffleHog version

        Returns:
            Version string or "unknown"
        """
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def save_results(self, results: dict, output_path: str) -> None:
        """
        Save scan results to JSON file

        Args:
            results: Scan results dictionary
            output_path: Path to output JSON file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Redact raw secrets before saving
        if "findings" in results:
            for finding in results["findings"]:
                if "raw" in finding:
                    # Keep redacted version, remove raw
                    finding["raw"] = finding.get("redacted", "***REDACTED***")

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"💾 Results saved to: {output_path}")


def main():
    """CLI interface for standalone usage"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="TruffleHog v3 Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan git repository (verified secrets only)
  python trufflehog_scanner.py /path/to/repo --scan-type git

  # Scan filesystem including unverified secrets
  python trufflehog_scanner.py /path/to/code --include-unverified

  # Scan single file
  python trufflehog_scanner.py /path/to/file.py --file

  # Scan with depth limit (last 100 commits)
  python trufflehog_scanner.py /path/to/repo --scan-type git --depth 100
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
        "--include-unverified",
        action="store_true",
        help="Include unverified secrets (may have false positives)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        help="Max commit depth for git scans (default: all commits)",
    )
    parser.add_argument(
        "--file",
        action="store_true",
        help="Scan single file instead of directory",
    )
    parser.add_argument(
        "--check-install",
        action="store_true",
        help="Check if TruffleHog is installed",
    )

    args = parser.parse_args()

    # Build config
    config = {
        "verified_only": not args.include_unverified,
        "scan_depth": args.depth,
        "include_unverified": args.include_unverified,
    }

    scanner = TruffleHogScanner(config)

    # Check installation if requested
    if args.check_install:
        scanner.install_trufflehog()
        return 0

    # Run scan
    results = scanner.scan_file(args.target) if args.file else scanner.scan(args.target, scan_type=args.scan_type)

    # Save to file if requested
    if args.output:
        scanner.save_results(results, args.output)
    else:
        # Print to stdout (with secrets redacted)
        if "findings" in results:
            for finding in results["findings"]:
                if "raw" in finding:
                    finding["raw"] = finding.get("redacted", "***REDACTED***")
        print(json.dumps(results, indent=2))

    # Exit with error code if verified secrets found
    verified_count = results.get("verified_count", 0)
    if verified_count > 0:
        print(f"\n🚨 ALERT: Found {verified_count} VERIFIED secrets!", file=sys.stderr)
        print("   These are confirmed valid credentials that should be rotated immediately.", file=sys.stderr)
        return 1

    total_findings = results.get("findings_count", 0)
    if total_findings > 0:
        print(f"\n⚠️  Found {total_findings} potential secrets", file=sys.stderr)
        return 1

    print("\n✅ No secrets detected", file=sys.stderr)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
