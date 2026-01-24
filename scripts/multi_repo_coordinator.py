#!/usr/bin/env python3
"""
Multi-Repo Coordinator
Scans multiple repositories with controlled concurrency and backpressure
All open source: Python asyncio + subprocess
"""

import asyncio
import json
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ScanConfig:
    """Configuration for a repository scan"""

    repo_url: str
    repo_name: str
    branch: str = "main"
    scan_types: list[str] = None  # ['secrets', 'sast', 'iac', 'vuln']

    def __post_init__(self):
        if self.scan_types is None:
            self.scan_types = ["secrets", "sast", "iac", "vuln"]


@dataclass
class ScanResult:
    """Result of a repository scan"""

    repo_name: str
    status: str  # 'success', 'failed', 'timeout'
    duration_seconds: float
    findings_count: int
    findings_path: str
    error: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


class MultiRepoCoordinator:
    """Coordinate scans across multiple repositories"""

    def __init__(self, max_concurrent: int = 3, timeout_seconds: int = 600, output_dir: str = "scan_results"):
        """
        Initialize coordinator

        Args:
            max_concurrent: Maximum concurrent scans
            timeout_seconds: Timeout per scan (default 10 min)
            output_dir: Directory to store scan results
        """
        self.max_concurrent = max_concurrent
        self.timeout_seconds = timeout_seconds
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Queue and backpressure
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results: list[ScanResult] = []

    async def scan_repos(self, configs: list[ScanConfig]) -> list[ScanResult]:
        """
        Scan multiple repositories concurrently

        Args:
            configs: List of scan configurations

        Returns:
            List[ScanResult]: Results for all scans
        """
        print(f"🚀 Starting scans for {len(configs)} repositories")
        print(f"   Max concurrent: {self.max_concurrent}")
        print(f"   Timeout: {self.timeout_seconds}s")
        print()

        # Create scan tasks
        tasks = [self._scan_repo(config) for config in configs]

        # Run with progress tracking
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            result = await task
            self.results.append(result)

            status_emoji = "✅" if result.status == "success" else "❌"
            print(
                f"{status_emoji} [{i}/{len(configs)}] {result.repo_name}: {result.status} "
                f"({result.findings_count} findings, {result.duration_seconds:.1f}s)"
            )

        # Print summary
        self._print_summary()

        return self.results

    async def _scan_repo(self, config: ScanConfig) -> ScanResult:
        """Scan a single repository"""
        async with self.semaphore:  # Backpressure control
            return await self._execute_scan(config)

    async def _execute_scan(self, config: ScanConfig) -> ScanResult:
        """Execute scan for a repository"""
        start_time = datetime.now()
        started_at = start_time.isoformat()

        temp_dir = None
        try:
            # Clone repository
            temp_dir = tempfile.mkdtemp(prefix="argus_scan_")
            clone_success = await self._clone_repo(config.repo_url, temp_dir, config.branch)

            if not clone_success:
                return ScanResult(
                    repo_name=config.repo_name,
                    status="failed",
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    findings_count=0,
                    findings_path="",
                    error="Failed to clone repository",
                    started_at=started_at,
                    finished_at=datetime.now().isoformat(),
                )

            # Run scans
            all_findings = []

            for scan_type in config.scan_types:
                findings = await self._run_scan(temp_dir, scan_type)
                all_findings.extend(findings)

            # Save findings
            findings_file = self.output_dir / f"{config.repo_name.replace('/', '_')}_findings.json"
            with open(findings_file, "w") as f:
                json.dump(all_findings, f, indent=2)

            # Success
            end_time = datetime.now()
            return ScanResult(
                repo_name=config.repo_name,
                status="success",
                duration_seconds=(end_time - start_time).total_seconds(),
                findings_count=len(all_findings),
                findings_path=str(findings_file),
                started_at=started_at,
                finished_at=end_time.isoformat(),
            )

        except asyncio.TimeoutError:
            return ScanResult(
                repo_name=config.repo_name,
                status="timeout",
                duration_seconds=self.timeout_seconds,
                findings_count=0,
                findings_path="",
                error="Scan timed out",
                started_at=started_at,
                finished_at=datetime.now().isoformat(),
            )
        except Exception as e:
            return ScanResult(
                repo_name=config.repo_name,
                status="failed",
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                findings_count=0,
                findings_path="",
                error=str(e),
                started_at=started_at,
                finished_at=datetime.now().isoformat(),
            )
        finally:
            # Cleanup
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    async def _clone_repo(self, repo_url: str, target_dir: str, branch: str) -> bool:
        """Clone repository"""
        try:
            cmd = ["git", "clone", "--depth", "1", "--branch", branch, "--single-branch", repo_url, target_dir]

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )

            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)  # 2 min timeout for clone

            return proc.returncode == 0

        except Exception:
            return False

    async def _run_scan(self, repo_path: str, scan_type: str) -> list[dict]:
        """Run a specific type of scan"""
        try:
            if scan_type == "secrets":
                return await self._scan_secrets(repo_path)
            elif scan_type == "sast":
                return await self._scan_sast(repo_path)
            elif scan_type == "iac":
                return await self._scan_iac(repo_path)
            elif scan_type == "vuln":
                return await self._scan_vulnerabilities(repo_path)
            else:
                return []
        except Exception as e:
            print(f"   Warning: {scan_type} scan failed: {e}")
            return []

    async def _scan_secrets(self, repo_path: str) -> list[dict]:
        """Run TruffleHog secret scan"""
        try:
            cmd = ["trufflehog", "filesystem", repo_path, "--json", "--no-verification"]  # Fast mode, verify later

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )

            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)

            # Parse JSON lines
            findings = []
            for line in stdout.decode().split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

            return findings

        except asyncio.TimeoutError:
            print("   Warning: Secret scan timed out")
            return []
        except Exception:
            return []

    async def _scan_sast(self, repo_path: str) -> list[dict]:
        """Run Semgrep SAST scan"""
        try:
            cmd = ["semgrep", "scan", "--config", "p/ci", "--json", "--quiet", repo_path]

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )

            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)

            result = json.loads(stdout.decode())
            return result.get("results", [])

        except asyncio.TimeoutError:
            print("   Warning: SAST scan timed out")
            return []
        except Exception:
            return []

    async def _scan_iac(self, repo_path: str) -> list[dict]:
        """Run Checkov IaC scan"""
        try:
            cmd = ["checkov", "--directory", repo_path, "--output", "json", "--quiet"]

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )

            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)

            result = json.loads(stdout.decode())
            return result.get("results", {}).get("failed_checks", [])

        except asyncio.TimeoutError:
            print("   Warning: IaC scan timed out")
            return []
        except Exception:
            return []

    async def _scan_vulnerabilities(self, repo_path: str) -> list[dict]:
        """Run Trivy vulnerability scan"""
        try:
            cmd = ["trivy", "fs", "--format", "json", "--quiet", repo_path]

            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )

            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)

            result = json.loads(stdout.decode())

            # Extract vulnerabilities
            findings = []
            for target in result.get("Results", []):
                findings.extend(target.get("Vulnerabilities", []))

            return findings

        except asyncio.TimeoutError:
            print("   Warning: Vulnerability scan timed out")
            return []
        except Exception:
            return []

    def _print_summary(self):
        """Print scan summary"""
        if not self.results:
            return

        successful = sum(1 for r in self.results if r.status == "success")
        failed = sum(1 for r in self.results if r.status == "failed")
        timeout = sum(1 for r in self.results if r.status == "timeout")
        total_findings = sum(r.findings_count for r in self.results)
        avg_duration = sum(r.duration_seconds for r in self.results) / len(self.results)

        print("\n" + "=" * 60)
        print("📊 Multi-Repo Scan Summary")
        print("=" * 60)
        print(f"Total Repositories: {len(self.results)}")
        print(f"  ✅ Successful: {successful}")
        print(f"  ❌ Failed: {failed}")
        print(f"  ⏱️  Timeout: {timeout}")
        print(f"Total Findings: {total_findings}")
        print(f"Average Duration: {avg_duration:.1f}s")
        print(f"\nResults saved to: {self.output_dir}")
        print("=" * 60)

    def save_summary(self, output_file: str = "scan_summary.json"):
        """Save summary to JSON file"""
        summary = {
            "scan_date": datetime.now().isoformat(),
            "total_repos": len(self.results),
            "successful": sum(1 for r in self.results if r.status == "success"),
            "failed": sum(1 for r in self.results if r.status == "failed"),
            "timeout": sum(1 for r in self.results if r.status == "timeout"),
            "total_findings": sum(r.findings_count for r in self.results),
            "results": [asdict(r) for r in self.results],
        }

        output_path = self.output_dir / output_file
        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"✅ Summary saved to {output_path}")


async def main_async():
    """Async CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Multi-repository security scanner coordinator")
    parser.add_argument("config", help="Path to repos config JSON file")
    parser.add_argument("--concurrent", type=int, default=3, help="Maximum concurrent scans (default: 3)")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout per scan in seconds (default: 600)")
    parser.add_argument("-o", "--output-dir", default="scan_results", help="Output directory (default: scan_results)")

    args = parser.parse_args()

    # Load config
    with open(args.config) as f:
        config_data = json.load(f)

    # Parse configs
    configs = [ScanConfig(**repo) for repo in config_data["repositories"]]

    # Create coordinator
    coordinator = MultiRepoCoordinator(
        max_concurrent=args.concurrent, timeout_seconds=args.timeout, output_dir=args.output_dir
    )

    # Run scans
    results = await coordinator.scan_repos(configs)

    # Save summary
    coordinator.save_summary()

    # Exit with error if any scans failed
    failed_count = sum(1 for r in results if r.status != "success")
    exit(1 if failed_count > 0 else 0)


def main():
    """CLI entry point"""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
