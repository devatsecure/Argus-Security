#!/usr/bin/env python3
"""
DAST Orchestrator for Argus Multi-Agent System
Coordinates Nuclei and ZAP agents with intelligent parallel execution
"""

import concurrent.futures
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add agents to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.nuclei_agent import NucleiAgent, NucleiConfig
from agents.zap_agent import ZAPAgent, ZAPConfig, ScanProfile
from dast_auth_config import DASTAuthConfig, load_dast_auth_config

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for DAST orchestrator"""
    
    max_duration: int = 900  # 15 minutes total
    parallel_agents: bool = True
    failure_threshold: float = 0.5  # Allow 50% agent failures
    enable_nuclei: bool = True
    enable_zap: bool = True
    enable_correlation: bool = True
    enable_deduplication: bool = True
    project_path: Optional[str] = None
    
    # Agent-specific configs
    nuclei_config: Optional[NucleiConfig] = None
    zap_config: Optional[ZAPConfig] = None

    # DAST auth config path (loaded from pipeline config)
    dast_auth_config_path: str = ""


@dataclass
class DASTScanResult:
    """Complete DAST scan results"""
    
    timestamp: str
    target_url: str
    duration_seconds: float
    agents_run: list[str]
    agents_succeeded: list[str]
    agents_failed: list[str]
    total_findings: int
    nuclei_results: Optional[dict] = None
    zap_results: Optional[dict] = None
    aggregated_findings: list[dict] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "target_url": self.target_url,
            "duration_seconds": self.duration_seconds,
            "agents_run": self.agents_run,
            "agents_succeeded": self.agents_succeeded,
            "agents_failed": self.agents_failed,
            "total_findings": self.total_findings,
            "nuclei_results": self.nuclei_results,
            "zap_results": self.zap_results,
            "aggregated_findings": self.aggregated_findings,
            "severity_counts": self.severity_counts,
            "metadata": self.metadata,
        }


class DASTOrchestrator:
    """
    Orchestrates multiple DAST agents with intelligent coordination
    """
    
    def __init__(self, config: Optional[OrchestratorConfig] = None):
        """
        Initialize DAST orchestrator
        
        Args:
            config: Orchestrator configuration
        """
        self.config = config or OrchestratorConfig()
        self.dast_auth: Optional[DASTAuthConfig] = None

        # Load DAST auth config if path is specified
        if self.config.dast_auth_config_path:
            try:
                self.dast_auth = load_dast_auth_config(
                    self.config.dast_auth_config_path
                )
                logger.info(
                    "Loaded DAST auth config: type=%s, url=%s",
                    self.dast_auth.login_type,
                    self.dast_auth.login_url or "(none)",
                )
            except (FileNotFoundError, ValueError) as exc:
                logger.warning("DAST auth config load failed: %s", exc)

        # Initialize agents
        self.nuclei_agent = None
        self.zap_agent = None

        if self.config.enable_nuclei:
            nuclei_cfg = self.config.nuclei_config or NucleiConfig()
            if self.dast_auth:
                nuclei_cfg.dast_auth_config = self.dast_auth
                # Merge auth headers into Nuclei headers
                nuclei_cfg.headers.update(self.dast_auth.headers)
            self.nuclei_agent = NucleiAgent(
                config=nuclei_cfg,
                project_path=self.config.project_path,
            )

        if self.config.enable_zap:
            zap_cfg = self.config.zap_config or ZAPConfig()
            if self.dast_auth:
                zap_cfg.dast_auth_config = self.dast_auth
                # Merge auth headers into ZAP custom headers
                zap_cfg.custom_headers.update(self.dast_auth.headers)
            self.zap_agent = ZAPAgent(config=zap_cfg)
    
    def scan(
        self,
        target_url: str,
        openapi_spec: Optional[str] = None,
        additional_targets: Optional[list[str]] = None,
        output_dir: Optional[str] = None,
    ) -> DASTScanResult:
        """
        Run complete DAST scan with all enabled agents
        
        Args:
            target_url: Primary target URL
            openapi_spec: Optional OpenAPI spec for endpoint discovery
            additional_targets: Additional URLs to scan
            output_dir: Directory to save results
            
        Returns:
            Complete scan results
        """
        logger.info("=" * 80)
        logger.info("🚀 DAST ORCHESTRATOR - Multi-Agent Security Scan")
        logger.info("=" * 80)
        logger.info(f"Target: {target_url}")
        logger.info(f"OpenAPI Spec: {openapi_spec or 'None'}")
        logger.info(f"Agents: {self._get_enabled_agents()}")
        logger.info(f"Parallel Execution: {self.config.parallel_agents}")
        logger.info("")
        
        start_time = datetime.now()
        agents_run = []
        agents_succeeded = []
        agents_failed = []
        
        # Prepare target list
        targets = [target_url]
        if additional_targets:
            targets.extend(additional_targets)
        
        # Parse OpenAPI spec for additional endpoints if provided
        if openapi_spec:
            openapi_targets = self._parse_openapi_targets(openapi_spec, target_url)
            targets.extend(openapi_targets)
            logger.info(f"📄 Discovered {len(openapi_targets)} endpoints from OpenAPI spec")
        
        targets = list(set(targets))  # Deduplicate
        logger.info(f"📊 Total targets to scan: {len(targets)}")
        logger.info("")
        
        # Run agents
        nuclei_results = None
        zap_results = None
        
        if self.config.parallel_agents and self.nuclei_agent and self.zap_agent:
            # Parallel execution
            logger.info("⚡ Running agents in parallel...")
            nuclei_results, zap_results = self._run_parallel(
                targets,
                target_url,
                openapi_spec,
                agents_run,
                agents_succeeded,
                agents_failed,
            )
        else:
            # Sequential execution
            logger.info("🔄 Running agents sequentially...")
            nuclei_results = self._run_nuclei(targets, agents_run, agents_succeeded, agents_failed)
            zap_results = self._run_zap(target_url, openapi_spec, agents_run, agents_succeeded, agents_failed)
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        # Aggregate results
        logger.info("")
        logger.info("📊 Aggregating results...")
        aggregated_findings = self._aggregate_findings(nuclei_results, zap_results)
        
        # Deduplicate if enabled
        if self.config.enable_deduplication:
            logger.info(f"   Deduplicating {len(aggregated_findings)} findings...")
            aggregated_findings = self._deduplicate_findings(aggregated_findings)
            logger.info(f"   After deduplication: {len(aggregated_findings)} findings")
        
        # Count by severity
        severity_counts = self._count_by_severity(aggregated_findings)
        
        # Build result
        result = DASTScanResult(
            timestamp=datetime.now().isoformat(),
            target_url=target_url,
            duration_seconds=duration,
            agents_run=agents_run,
            agents_succeeded=agents_succeeded,
            agents_failed=agents_failed,
            total_findings=len(aggregated_findings),
            nuclei_results=nuclei_results,
            zap_results=zap_results,
            aggregated_findings=aggregated_findings,
            severity_counts=severity_counts,
            metadata={
                "targets_scanned": len(targets),
                "openapi_spec": openapi_spec,
                "parallel_execution": self.config.parallel_agents,
            },
        )
        
        # Print summary
        self._print_summary(result)
        
        # Save results
        if output_dir:
            self._save_results(result, output_dir)
        
        return result
    
    def _run_parallel(
        self,
        targets: list[str],
        target_url: str,
        openapi_spec: Optional[str],
        agents_run: list[str],
        agents_succeeded: list[str],
        agents_failed: list[str],
    ) -> tuple[Optional[dict], Optional[dict]]:
        """Run agents in parallel"""
        nuclei_results = None
        zap_results = None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {}
            
            # Submit Nuclei task
            if self.nuclei_agent:
                agents_run.append("nuclei")
                futures["nuclei"] = executor.submit(self._run_nuclei_safe, targets)
            
            # Submit ZAP task
            if self.zap_agent:
                agents_run.append("zap")
                futures["zap"] = executor.submit(self._run_zap_safe, target_url, openapi_spec)
            
            # Wait for completion with timeout
            timeout_remaining = self.config.max_duration
            for agent_name, future in futures.items():
                try:
                    result = future.result(timeout=timeout_remaining)
                    if result:
                        agents_succeeded.append(agent_name)
                        if agent_name == "nuclei":
                            nuclei_results = result
                        elif agent_name == "zap":
                            zap_results = result
                    else:
                        agents_failed.append(agent_name)
                except concurrent.futures.TimeoutError:
                    logger.error(f"   ❌ {agent_name.upper()} timed out")
                    agents_failed.append(agent_name)
                except Exception as e:
                    logger.error(f"   ❌ {agent_name.upper()} failed: {e}")
                    agents_failed.append(agent_name)
        
        return nuclei_results, zap_results
    
    def _run_nuclei(
        self,
        targets: list[str],
        agents_run: list[str],
        agents_succeeded: list[str],
        agents_failed: list[str],
    ) -> Optional[dict]:
        """Run Nuclei agent"""
        if not self.nuclei_agent:
            return None
        
        agents_run.append("nuclei")
        try:
            results = self.nuclei_agent.scan(targets)
            agents_succeeded.append("nuclei")
            return results
        except Exception as e:
            logger.error(f"Nuclei agent failed: {e}")
            agents_failed.append("nuclei")
            return None
    
    def _run_zap(
        self,
        target_url: str,
        openapi_spec: Optional[str],
        agents_run: list[str],
        agents_succeeded: list[str],
        agents_failed: list[str],
    ) -> Optional[dict]:
        """Run ZAP agent"""
        if not self.zap_agent:
            return None
        
        agents_run.append("zap")
        try:
            results = self.zap_agent.scan(target_url, openapi_spec)
            agents_succeeded.append("zap")
            return results
        except Exception as e:
            logger.error(f"ZAP agent failed: {e}")
            agents_failed.append("zap")
            return None
    
    def _run_nuclei_safe(self, targets: list[str]) -> Optional[dict]:
        """Safe Nuclei execution for parallel mode"""
        try:
            return self.nuclei_agent.scan(targets)
        except Exception as e:
            logger.error(f"Nuclei agent failed: {e}")
            return None
    
    def _run_zap_safe(self, target_url: str, openapi_spec: Optional[str]) -> Optional[dict]:
        """Safe ZAP execution for parallel mode"""
        try:
            return self.zap_agent.scan(target_url, openapi_spec)
        except Exception as e:
            logger.error(f"ZAP agent failed: {e}")
            return None
    
    def _parse_openapi_targets(self, openapi_spec: str, base_url: str) -> list[str]:
        """Parse OpenAPI spec to extract endpoint URLs"""
        # This is a simplified version - the full version would use OpenAPI parser
        # For now, just return empty list
        # TODO: Implement full OpenAPI parsing
        return []
    
    def _aggregate_findings(
        self,
        nuclei_results: Optional[dict],
        zap_results: Optional[dict],
    ) -> list[dict]:
        """Aggregate findings from all agents"""
        findings = []
        
        # Add Nuclei findings
        if nuclei_results:
            for finding in nuclei_results.get("findings", []):
                findings.append({
                    "source": "nuclei",
                    "severity": finding.get("severity", "medium"),
                    "name": finding.get("name", "Unknown"),
                    "url": finding.get("matched_at", ""),
                    "description": finding.get("name", ""),
                    "evidence": finding.get("extracted_results", []),
                    "raw": finding,
                })
        
        # Add ZAP findings
        if zap_results:
            for finding in zap_results.get("findings", []):
                findings.append({
                    "source": "zap",
                    "severity": finding.get("severity", "medium"),
                    "name": finding.get("alert", "Unknown"),
                    "url": finding.get("url", ""),
                    "description": finding.get("description", ""),
                    "evidence": finding.get("evidence", ""),
                    "raw": finding,
                })
        
        return findings
    
    def _deduplicate_findings(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings"""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create signature for deduplication
            sig = f"{finding['name']}:{finding['url']}:{finding['severity']}"
            if sig not in seen:
                seen.add(sig)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _count_by_severity(self, findings: list[dict]) -> dict[str, int]:
        """Count findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _get_enabled_agents(self) -> str:
        """Get list of enabled agents"""
        agents = []
        if self.config.enable_nuclei:
            agents.append("Nuclei")
        if self.config.enable_zap:
            agents.append("ZAP")
        return ", ".join(agents) if agents else "None"
    
    def _print_summary(self, result: DASTScanResult) -> None:
        """Print scan summary"""
        logger.info("")
        logger.info("=" * 80)
        logger.info("✅ DAST SCAN COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Duration: {result.duration_seconds:.1f}s ({result.duration_seconds / 60:.1f} min)")
        logger.info(f"Agents Run: {', '.join(result.agents_run)}")
        logger.info(f"Agents Succeeded: {', '.join(result.agents_succeeded)}")
        if result.agents_failed:
            logger.warning(f"Agents Failed: {', '.join(result.agents_failed)}")
        logger.info("")
        logger.info(f"Total Findings: {result.total_findings}")
        logger.info("")
        logger.info("Findings by Severity:")
        for severity, count in result.severity_counts.items():
            if count > 0:
                logger.info(f"  {severity.upper():12s}: {count}")
        logger.info("")
        
        # Agent-specific summaries
        if result.nuclei_results:
            nuclei_count = result.nuclei_results.get("total_findings", 0)
            logger.info(f"Nuclei: {nuclei_count} findings")
        
        if result.zap_results:
            zap_count = result.zap_results.get("total_findings", 0)
            logger.info(f"ZAP: {zap_count} findings")
        
        logger.info("=" * 80)
    
    def _save_results(self, result: DASTScanResult, output_dir: str) -> None:
        """Save results to directory"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save aggregated results
        aggregated_file = output_path / "dast-results.json"
        with open(aggregated_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        
        logger.info(f"\n📁 Results saved to: {output_path}")
        logger.info(f"   Main report: {aggregated_file.name}")
        
        # Save agent-specific results
        if result.nuclei_results:
            nuclei_file = output_path / "nuclei-results.json"
            with open(nuclei_file, "w") as f:
                json.dump(result.nuclei_results, f, indent=2)
            logger.info(f"   Nuclei report: {nuclei_file.name}")
        
        if result.zap_results:
            zap_file = output_path / "zap-results.json"
            with open(zap_file, "w") as f:
                json.dump(result.zap_results, f, indent=2)
            logger.info(f"   ZAP report: {zap_file.name}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DAST Orchestrator - Multi-Agent Security Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--openapi", help="OpenAPI spec file")
    parser.add_argument("--output", "-o", help="Output directory", default="./dast-results")
    parser.add_argument("--agents", help="Comma-separated agents (nuclei,zap)", default="nuclei,zap")
    parser.add_argument("--profile", choices=["fast", "balanced", "comprehensive"], default="balanced")
    parser.add_argument("--project-path", help="Project path for tech stack detection")
    parser.add_argument("--sequential", action="store_true", help="Run agents sequentially (not parallel)")
    parser.add_argument("--max-duration", type=int, default=900, help="Max scan duration (seconds)")
    parser.add_argument("--dast-auth-config", help="Path to DAST auth config YAML")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    
    # Parse enabled agents
    enabled_agents = [a.strip().lower() for a in args.agents.split(",")]
    
    # Build config
    config = OrchestratorConfig(
        max_duration=args.max_duration,
        parallel_agents=not args.sequential,
        enable_nuclei="nuclei" in enabled_agents,
        enable_zap="zap" in enabled_agents,
        project_path=args.project_path,
        nuclei_config=NucleiConfig() if "nuclei" in enabled_agents else None,
        zap_config=ZAPConfig(profile=ScanProfile(args.profile)) if "zap" in enabled_agents else None,
        dast_auth_config_path=args.dast_auth_config or "",
    )
    
    # Create orchestrator
    orchestrator = DASTOrchestrator(config=config)
    
    # Run scan
    try:
        result = orchestrator.scan(
            target_url=args.target,
            openapi_spec=args.openapi,
            output_dir=args.output,
        )
        
        # Exit with error code if critical/high findings
        critical_high = result.severity_counts.get("critical", 0) + result.severity_counts.get("high", 0)
        if critical_high > 0:
            logger.warning(f"\n⚠️  Found {critical_high} critical/high severity vulnerabilities")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"\n❌ DAST scan failed: {e}", exc_info=args.verbose)
        return 2


if __name__ == "__main__":
    sys.exit(main())
