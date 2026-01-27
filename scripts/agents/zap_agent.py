#!/usr/bin/env python3
"""
OWASP ZAP Agent for Argus Multi-Agent DAST
Spider, active scan, API testing, and authentication support
"""

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ScanProfile(Enum):
    """ZAP scan profiles"""
    FAST = "fast"  # Spider + passive scan (2-3 min)
    BALANCED = "balanced"  # Spider + limited active scan (5-10 min)
    COMPREHENSIVE = "comprehensive"  # Full active scan (15-30 min)


class AuthType(Enum):
    """Authentication types"""
    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    COOKIE = "cookie"
    FORM = "form"


@dataclass
class ZAPConfig:
    """Configuration for ZAP agent"""
    
    profile: ScanProfile = ScanProfile.BALANCED
    spider_max_depth: int = 3
    spider_max_duration: int = 300  # 5 minutes
    spider_max_children: int = 10
    ajax_spider: bool = True
    ajax_max_duration: int = 120  # 2 minutes
    active_scan: bool = True
    active_scan_policy: str = "Default Policy"
    active_max_duration: int = 600  # 10 minutes
    api_scan: bool = True
    api_format: Optional[str] = None  # openapi, soap, graphql
    auth_type: AuthType = AuthType.NONE
    auth_credentials: dict = field(default_factory=dict)
    custom_headers: dict = field(default_factory=dict)
    target_exclusions: list[str] = field(default_factory=list)
    alert_threshold: str = "medium"  # low, medium, high
    max_alerts_per_url: int = 10


@dataclass
class ZAPFinding:
    """A ZAP security finding"""
    
    alert: str
    risk: str  # High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    url: str
    method: str
    param: str
    attack: str
    evidence: str
    description: str
    solution: str
    reference: str
    cwe_id: Optional[int]
    wasc_id: Optional[int]
    plugin_id: int
    other_info: str = ""
    
    def to_dict(self) -> dict:
        return {
            "alert": self.alert,
            "risk": self.risk,
            "confidence": self.confidence,
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "attack": self.attack,
            "evidence": self.evidence,
            "description": self.description,
            "solution": self.solution,
            "reference": self.reference,
            "cwe_id": self.cwe_id,
            "wasc_id": self.wasc_id,
            "plugin_id": self.plugin_id,
            "other_info": self.other_info,
        }


class ZAPAgent:
    """
    OWASP ZAP agent for dynamic application security testing
    """
    
    def __init__(self, config: Optional[ZAPConfig] = None):
        """
        Initialize ZAP agent
        
        Args:
            config: Agent configuration
        """
        self.config = config or ZAPConfig()
        self.zap_available = self._check_zap()
        
        if not self.zap_available:
            logger.warning("ZAP not available - using Docker mode")
    
    def _check_zap(self) -> bool:
        """Check if ZAP is installed"""
        try:
            # Try zap-cli
            result = subprocess.run(
                ["zap-cli", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.debug("ZAP CLI detected")
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Check for Docker
        try:
            result = subprocess.run(
                ["docker", "images", "ghcr.io/zaproxy/zaproxy"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "zaproxy" in result.stdout:
                logger.debug("ZAP Docker image detected")
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return False
    
    def scan(
        self,
        target_url: str,
        openapi_spec: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Run ZAP scan
        
        Args:
            target_url: Target URL to scan
            openapi_spec: Optional OpenAPI spec for API scanning
            output_file: Optional path to save results
            
        Returns:
            Scan results dictionary
        """
        logger.info(f"🕷️  ZAP Agent scanning: {target_url}")
        start_time = datetime.now()
        
        # Use Docker-based ZAP scan
        findings = self._run_docker_scan(target_url, openapi_spec)
        
        # Calculate duration
        duration = (datetime.now() - start_time).total_seconds()
        
        # Build result
        scan_result = {
            "agent": "zap",
            "version": self._get_version(),
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "profile": self.config.profile.value,
            "openapi_spec": openapi_spec,
            "findings": findings,
            "total_findings": len(findings),
            "duration_seconds": duration,
            "risk_counts": self._count_by_risk(findings),
        }
        
        logger.info(f"   ✅ ZAP complete: {len(findings)} findings in {duration:.1f}s")
        
        # Save if requested
        if output_file:
            self._save_results(scan_result, output_file)
        
        return scan_result
    
    def _run_docker_scan(
        self,
        target_url: str,
        openapi_spec: Optional[str] = None,
    ) -> list[dict]:
        """
        Run ZAP scan using Docker
        
        Args:
            target_url: Target URL
            openapi_spec: Optional OpenAPI spec path
            
        Returns:
            List of findings
        """
        # Determine scan type based on profile
        if self.config.profile == ScanProfile.FAST:
            scan_script = "zap-baseline.py"
        elif openapi_spec:
            scan_script = "zap-api-scan.py"
        else:
            scan_script = "zap-full-scan.py"
        
        # Create temp output file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name
        
        try:
            # Build Docker command
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{Path(output_file).parent}:/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                scan_script,
                "-t", target_url,
                "-J", Path(output_file).name,
                "-T", str(self.config.spider_max_duration),
            ]
            
            # Add OpenAPI spec if provided
            if openapi_spec and Path(openapi_spec).exists():
                cmd.extend(["-f", "openapi"])
            
            # Add headers
            for key, value in self.config.custom_headers.items():
                cmd.extend(["-z", f"-config replacer.full_list(0).description={key}"])
            
            logger.info(f"   Running ZAP Docker scan ({self.config.profile.value})...")
            
            # Execute scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.spider_max_duration + self.config.active_max_duration + 60,
            )
            
            # ZAP returns non-zero if findings found
            if result.returncode not in [0, 1, 2]:
                logger.warning(f"ZAP scan returned code {result.returncode}")
                logger.debug(f"STDERR: {result.stderr}")
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file) as f:
                    zap_data = json.load(f)
                return self._parse_zap_output(zap_data)
            else:
                logger.warning("No ZAP output file generated")
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("ZAP scan timed out")
            raise RuntimeError("ZAP scan timeout")
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            raise
        finally:
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
    
    def _parse_zap_output(self, zap_data: dict) -> list[dict]:
        """Parse ZAP JSON output"""
        findings = []
        
        # ZAP format: {"site": [...], "alerts": [...]}
        site_data = zap_data.get("site", [])
        
        for site in site_data:
            alerts = site.get("alerts", [])
            
            for alert in alerts:
                # Map ZAP risk to standard severity
                risk = alert.get("riskdesc", "Medium").split()[0]  # "High (Medium)" -> "High"
                severity_map = {
                    "High": "high",
                    "Medium": "medium",
                    "Low": "low",
                    "Informational": "info",
                }
                severity = severity_map.get(risk, "medium")
                
                # Extract instances
                instances = alert.get("instances", [])
                for instance in instances:
                    finding = {
                        "alert": alert.get("alert", "Unknown"),
                        "severity": severity,
                        "risk": risk,
                        "confidence": alert.get("confidence", "Medium"),
                        "url": instance.get("uri", alert.get("url", "")),
                        "method": instance.get("method", "GET"),
                        "param": instance.get("param", alert.get("param", "")),
                        "attack": instance.get("attack", alert.get("attack", "")),
                        "evidence": instance.get("evidence", alert.get("evidence", "")),
                        "description": alert.get("desc", ""),
                        "solution": alert.get("solution", ""),
                        "reference": alert.get("reference", ""),
                        "cwe_id": alert.get("cweid"),
                        "wasc_id": alert.get("wascid"),
                        "plugin_id": alert.get("pluginid", 0),
                        "other_info": alert.get("other", ""),
                    }
                    findings.append(finding)
        
        return findings
    
    def _count_by_risk(self, findings: list[dict]) -> dict[str, int]:
        """Count findings by risk level"""
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _get_version(self) -> str:
        """Get ZAP version"""
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "ghcr.io/zaproxy/zaproxy:stable", "zap.sh", "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"
    
    def _save_results(self, results: dict, output_file: str) -> None:
        """Save results to file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"   Results saved to: {output_path}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OWASP ZAP Agent")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--openapi", help="OpenAPI spec file")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--profile", choices=["fast", "balanced", "comprehensive"], default="balanced")
    parser.add_argument("--spider-depth", type=int, default=3)
    parser.add_argument("--spider-duration", type=int, default=300)
    parser.add_argument("--no-ajax", action="store_true", help="Disable AJAX spider")
    parser.add_argument("--no-active-scan", action="store_true", help="Disable active scan")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Build config
    config = ZAPConfig(
        profile=ScanProfile(args.profile),
        spider_max_depth=args.spider_depth,
        spider_max_duration=args.spider_duration,
        ajax_spider=not args.no_ajax,
        active_scan=not args.no_active_scan,
    )
    
    # Create agent
    agent = ZAPAgent(config=config)
    
    # Run scan
    try:
        result = agent.scan(
            target_url=args.target,
            openapi_spec=args.openapi,
            output_file=args.output,
        )
        print(f"\n✅ Scan complete: {result['total_findings']} findings")
        print(f"Duration: {result['duration_seconds']:.1f}s")
        print("\nFindings by risk:")
        for risk, count in result['risk_counts'].items():
            print(f"  {risk.upper()}: {count}")
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
