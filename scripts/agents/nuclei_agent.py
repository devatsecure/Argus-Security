#!/usr/bin/env python3
"""
Enhanced Nuclei Agent for Argus Multi-Agent DAST
Intelligent template selection, caching, and incremental scanning
"""

import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Allow importing from parent scripts directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dast_auth_config import DASTAuthConfig

logger = logging.getLogger(__name__)


@dataclass
class NucleiConfig:
    """Configuration for Nuclei agent"""
    
    severity: list[str] = field(default_factory=lambda: ["critical", "high", "medium"])
    rate_limit: int = 150
    timeout: int = 5
    retries: int = 1
    concurrency: int = 25
    headers: dict = field(default_factory=dict)
    templates: list[str] = field(default_factory=list)
    exclude_templates: list[str] = field(default_factory=list)
    max_duration: int = 600  # 10 minutes
    enable_caching: bool = True
    enable_incremental: bool = True
    dast_auth_config: Optional[DASTAuthConfig] = None  # config-driven auth


@dataclass
class TechStackProfile:
    """Technology stack detection for smart template selection"""
    
    name: str
    patterns: list[str]  # File/directory patterns
    templates: list[str]  # Nuclei templates to prioritize
    priority: int = 1  # Higher = more priority


# Tech stack profiles for intelligent template selection
TECH_STACK_PROFILES = [
    TechStackProfile(
        name="Django",
        patterns=["manage.py", "settings.py", "wsgi.py", "**/migrations/**"],
        templates=[
            "vulnerabilities/django/",
            "http/cves/django-*",
            "http/vulnerabilities/generic/sqli*",
            "http/vulnerabilities/csrf*",
            "http/vulnerabilities/ssrf*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="FastAPI",
        patterns=["main.py", "app.py", "**/*fastapi*"],
        templates=[
            "http/misconfiguration/openapi-*",
            "http/vulnerabilities/api-*",
            "http/vulnerabilities/jwt-*",
            "http/vulnerabilities/generic/sqli*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="Flask",
        patterns=["app.py", "application.py", "**/*flask*"],
        templates=[
            "http/vulnerabilities/flask-*",
            "http/vulnerabilities/generic/sqli*",
            "http/vulnerabilities/ssrf*",
            "http/vulnerabilities/ssti*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="Next.js",
        patterns=["next.config.js", "pages/**", "app/**"],
        templates=[
            "http/vulnerabilities/nextjs-*",
            "http/vulnerabilities/generic/xss*",
            "http/vulnerabilities/ssrf*",
            "http/misconfiguration/csp-*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="React",
        patterns=["package.json", "src/**/*.jsx", "src/**/*.tsx"],
        templates=[
            "http/vulnerabilities/generic/xss*",
            "http/misconfiguration/cors*",
            "http/misconfiguration/csp-*",
        ],
        priority=2,
    ),
    TechStackProfile(
        name="Spring Boot",
        patterns=["pom.xml", "build.gradle", "src/main/java/**"],
        templates=[
            "http/cves/spring-*",
            "http/vulnerabilities/java-*",
            "http/vulnerabilities/xxe*",
            "http/vulnerabilities/ssrf*",
            "http/vulnerabilities/deserialization*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="Express.js",
        patterns=["package.json", "app.js", "server.js", "**/*express*"],
        templates=[
            "http/vulnerabilities/nodejs-*",
            "http/vulnerabilities/generic/sqli*",
            "http/vulnerabilities/nosql-*",
            "http/vulnerabilities/prototype-*",
        ],
        priority=3,
    ),
    TechStackProfile(
        name="WordPress",
        patterns=["wp-config.php", "wp-content/**", "wp-includes/**"],
        templates=[
            "http/cves/wordpress-*",
            "http/vulnerabilities/wordpress-*",
            "http/misconfiguration/wordpress-*",
        ],
        priority=3,
    ),
]


class NucleiAgent:
    """
    Enhanced Nuclei agent with intelligent template selection
    """
    
    def __init__(
        self,
        config: Optional[NucleiConfig] = None,
        project_path: Optional[str] = None,
    ):
        """
        Initialize Nuclei agent
        
        Args:
            config: Agent configuration
            project_path: Path to project for tech stack detection
        """
        self.config = config or NucleiConfig()
        self.project_path = Path(project_path) if project_path else None
        self.nuclei_path = self._find_nuclei()
        self.detected_stack: list[TechStackProfile] = []
        
        if not self.nuclei_path:
            logger.warning("Nuclei not installed")
        
        # Detect tech stack if project path provided
        if self.project_path:
            self.detected_stack = self._detect_tech_stack()
            if self.detected_stack:
                logger.info(f"Detected tech stacks: {[s.name for s in self.detected_stack]}")
    
    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return "nuclei"
            return None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None
    
    def _detect_tech_stack(self) -> list[TechStackProfile]:
        """
        Detect technology stack from project files
        
        Returns:
            List of detected tech stack profiles
        """
        if not self.project_path or not self.project_path.exists():
            return []
        
        detected = []
        
        for profile in TECH_STACK_PROFILES:
            for pattern in profile.patterns:
                # Check if pattern matches any file
                matches = list(self.project_path.glob(pattern))
                if matches:
                    detected.append(profile)
                    logger.debug(f"Detected {profile.name} via pattern: {pattern}")
                    break
        
        # Sort by priority
        detected.sort(key=lambda p: p.priority, reverse=True)
        return detected
    
    def _build_template_list(self) -> list[str]:
        """
        Build intelligent template list based on detected tech stack
        
        Returns:
            List of template paths
        """
        templates = []
        
        # If custom templates specified, use those
        if self.config.templates:
            return self.config.templates
        
        # If tech stack detected, prioritize relevant templates
        if self.detected_stack:
            for stack in self.detected_stack:
                templates.extend(stack.templates)
        
        # Always include core templates
        core_templates = [
            "cves/",  # All CVEs
            "vulnerabilities/",  # All generic vulnerabilities
            "misconfiguration/",  # Misconfigurations
        ]
        
        # Add core templates if not already included
        for template in core_templates:
            if template not in templates:
                templates.append(template)
        
        return templates
    
    def scan(
        self,
        targets: list[str],
        output_file: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Run Nuclei scan with intelligent template selection
        
        Args:
            targets: List of target URLs to scan
            output_file: Optional path to save results
            
        Returns:
            Scan results dictionary
        """
        if not self.nuclei_path:
            raise RuntimeError("Nuclei not installed")
        
        if not targets:
            raise ValueError("No targets provided")
        
        logger.info(f"🔍 Nuclei Agent scanning {len(targets)} targets")
        start_time = datetime.now()
        
        # Build template list
        templates = self._build_template_list()
        logger.info(f"   Using {len(templates)} template sets")
        
        # Create temporary file with targets
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            target_file = f.name
            for target in targets:
                f.write(f"{target}\n")
        
        try:
            # Build command
            cmd = self._build_command(target_file, templates)
            
            # Execute scan
            logger.info(f"   Running Nuclei (max {self.config.max_duration}s)...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.max_duration,
            )
            
            # Parse results
            findings = self._parse_output(result.stdout)
            
            # Calculate duration
            duration = (datetime.now() - start_time).total_seconds()
            
            # Build result
            scan_result = {
                "agent": "nuclei",
                "version": self._get_version(),
                "timestamp": datetime.now().isoformat(),
                "targets_scanned": len(targets),
                "templates_used": templates,
                "tech_stacks": [s.name for s in self.detected_stack],
                "findings": findings,
                "total_findings": len(findings),
                "duration_seconds": duration,
                "severity_counts": self._count_by_severity(findings),
            }
            
            logger.info(f"   ✅ Nuclei complete: {len(findings)} findings in {duration:.1f}s")
            
            # Save if requested
            if output_file:
                self._save_results(scan_result, output_file)
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"   ❌ Nuclei scan timed out after {self.config.max_duration}s")
            raise RuntimeError("Nuclei scan timeout")
        except Exception as e:
            logger.error(f"   ❌ Nuclei scan failed: {e}")
            raise
        finally:
            # Cleanup temp file
            Path(target_file).unlink(missing_ok=True)
    
    def _build_command(self, target_file: str, templates: list[str]) -> list[str]:
        """Build Nuclei command"""
        cmd = [self.nuclei_path]
        
        # Target list
        cmd.extend(["-list", target_file])
        
        # Output format
        cmd.extend(["-jsonl"])
        
        # Severity filter
        if self.config.severity:
            cmd.extend(["-severity", ",".join(self.config.severity)])
        
        # Templates
        for template in templates:
            cmd.extend(["-t", template])
        
        # Exclude templates
        for exclude in self.config.exclude_templates:
            cmd.extend(["-etags", exclude])
        
        # Rate limiting
        cmd.extend(["-rate-limit", str(self.config.rate_limit)])
        cmd.extend(["-timeout", str(self.config.timeout)])
        cmd.extend(["-retries", str(self.config.retries)])
        cmd.extend(["-concurrency", str(self.config.concurrency)])
        
        # Custom headers
        for key, value in self.config.headers.items():
            cmd.extend(["-header", f"{key}: {value}"])
        
        # Silent mode
        cmd.append("-silent")
        
        # Include request/response
        cmd.append("-include-rr")
        
        return cmd
    
    def _parse_output(self, output: str) -> list[dict]:
        """Parse Nuclei JSONL output"""
        findings = []
        
        if not output or not output.strip():
            return findings
        
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                
                finding = {
                    "id": result.get("template-id", ""),
                    "name": result.get("info", {}).get("name", "Unknown"),
                    "severity": result.get("info", {}).get("severity", "medium").lower(),
                    "matched_at": result.get("matched-at", result.get("matched", "")),
                    "extracted_results": result.get("extracted-results", []),
                    "curl_command": result.get("curl-command", ""),
                    "matcher_name": result.get("matcher-name", ""),
                    "type": result.get("type", "http"),
                    "host": result.get("host", ""),
                    "ip": result.get("ip"),
                    "timestamp": result.get("timestamp", datetime.now().isoformat()),
                    "request": result.get("request", ""),
                    "response": result.get("response", ""),
                    "tags": result.get("info", {}).get("tags", []),
                    "classification": result.get("info", {}).get("classification", {}),
                    "metadata": result.get("info", {}).get("metadata", {}),
                }
                
                findings.append(finding)
                
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Nuclei line: {line[:100]}")
                continue
        
        return findings
    
    def _count_by_severity(self, findings: list[dict]) -> dict[str, int]:
        """Count findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _get_version(self) -> str:
        """Get Nuclei version"""
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=5,
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
    
    parser = argparse.ArgumentParser(description="Enhanced Nuclei Agent")
    parser.add_argument("--targets", nargs="+", required=True, help="Target URLs")
    parser.add_argument("--project-path", help="Project path for tech stack detection")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--severity", help="Comma-separated severities")
    parser.add_argument("--rate-limit", type=int, default=150)
    parser.add_argument("--concurrency", type=int, default=25)
    parser.add_argument("--max-duration", type=int, default=600)
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Build config
    config = NucleiConfig(
        severity=args.severity.split(",") if args.severity else ["critical", "high", "medium"],
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        max_duration=args.max_duration,
    )
    
    # Create agent
    agent = NucleiAgent(config=config, project_path=args.project_path)
    
    # Run scan
    try:
        result = agent.scan(targets=args.targets, output_file=args.output)
        print(f"\n✅ Scan complete: {result['total_findings']} findings")
        print(f"Duration: {result['duration_seconds']:.1f}s")
        print("\nFindings by severity:")
        for severity, count in result['severity_counts'].items():
            print(f"  {severity.upper()}: {count}")
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
