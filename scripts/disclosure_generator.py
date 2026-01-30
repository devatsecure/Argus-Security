#!/usr/bin/env python3
"""
Responsible Disclosure Generator

Generates responsible disclosure reports from Argus security findings.
Supports:
- Private disclosure reports (full details)
- Public-safe issue templates (no exploit details)
- GitHub Discussion creation for security contact
- Automated sanitization of sensitive data

Part of the Argus Security Pipeline - Phase 6.5: Disclosure
"""

import argparse
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = ["DisclosureGenerator", "DisclosureReport"]


@dataclass
class DisclosureReport:
    """Generated disclosure report"""
    private_report: str
    public_safe_report: str
    repo_owner: str
    repo_name: str
    has_security_policy: bool
    has_discussions: bool
    has_private_reporting: bool
    high_findings: list
    dependency_findings: list
    disclosure_timeline: dict


class DisclosureGenerator:
    """
    Generates responsible disclosure reports from security findings.
    
    Features:
    - Separates code vulnerabilities from dependency CVEs
    - Sanitizes machine-specific paths
    - Removes exploit details from public reports
    - Checks for private reporting options
    - Generates disclosure timelines
    """
    
    def __init__(self, repo_url: Optional[str] = None):
        """
        Initialize disclosure generator.
        
        Args:
            repo_url: GitHub repository URL (e.g., https://github.com/owner/repo)
        """
        self.repo_url = repo_url
        self.repo_owner = None
        self.repo_name = None
        
        if repo_url:
            self._parse_repo_url(repo_url)
    
    def _parse_repo_url(self, url: str):
        """Extract owner and repo name from GitHub URL"""
        # Handle various GitHub URL formats
        patterns = [
            r'github\.com[/:]([^/]+)/([^/\.]+)',
            r'^([^/]+)/([^/]+)$',  # owner/repo format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                self.repo_owner = match.group(1)
                self.repo_name = match.group(2).replace('.git', '')
                return
        
        logger.warning(f"Could not parse repo URL: {url}")
    
    def _sanitize_path(self, path: str) -> str:
        """Remove machine-specific path prefixes"""
        # Common temp/private path prefixes to remove
        prefixes = [
            r'/private/tmp/[^/]+/',
            r'/tmp/[^/]+/',
            r'/var/folders/[^/]+/[^/]+/[^/]+/',
            r'/Users/[^/]+/[^/]+/',
            r'C:\\Users\\[^\\]+\\',
        ]
        
        result = path
        for prefix in prefixes:
            result = re.sub(prefix, '', result)
        
        return result
    
    def _check_repo_security_options(self) -> dict:
        """Check what security reporting options are available"""
        options = {
            'has_security_policy': False,
            'has_discussions': False,
            'has_private_reporting': False,
            'security_email': None,
        }
        
        if not self.repo_owner or not self.repo_name:
            return options
        
        try:
            # Check for SECURITY.md
            result = subprocess.run(
                ['gh', 'api', f'repos/{self.repo_owner}/{self.repo_name}/contents/SECURITY.md'],
                capture_output=True, text=True, timeout=10
            )
            options['has_security_policy'] = result.returncode == 0
            
            # Check repo features
            result = subprocess.run(
                ['gh', 'api', f'repos/{self.repo_owner}/{self.repo_name}',
                 '--jq', '{has_discussions: .has_discussions, has_issues: .has_issues}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                options['has_discussions'] = data.get('has_discussions', False)
            
            # Check for private vulnerability reporting
            result = subprocess.run(
                ['gh', 'api', f'repos/{self.repo_owner}/{self.repo_name}',
                 '--jq', '.security_and_analysis.secret_scanning.status // "disabled"'],
                capture_output=True, text=True, timeout=10
            )
            # Private reporting is usually enabled if security features are on
            options['has_private_reporting'] = 'enabled' in result.stdout.lower()
            
        except Exception as e:
            logger.warning(f"Could not check repo security options: {e}")
        
        return options
    
    def _categorize_findings(self, findings: list) -> tuple:
        """
        Separate findings into code vulnerabilities and dependency CVEs.
        
        Returns:
            Tuple of (code_findings, dependency_findings)
        """
        code_findings = []
        dependency_findings = []
        
        for finding in findings:
            source = finding.get('source_tool', finding.get('source', ''))
            file_path = finding.get('file_path', finding.get('file', ''))
            
            # Dependency findings are from Trivy scanning lockfiles
            is_dependency = (
                source.lower() == 'trivy' or
                any(lock in file_path.lower() for lock in [
                    'lock', 'package.json', 'requirements', 'pyproject.toml',
                    'cargo.toml', 'go.mod', 'gemfile'
                ])
            )
            
            if is_dependency:
                dependency_findings.append(finding)
            else:
                code_findings.append(finding)
        
        return code_findings, dependency_findings
    
    def _get_high_severity_findings(self, findings: list) -> list:
        """Filter to only high/critical findings"""
        return [
            f for f in findings
            if f.get('severity', '').lower() in ['critical', 'high']
        ]
    
    def _generate_private_report(
        self,
        code_findings: list,
        dependency_findings: list,
        reporter_name: str = "[Your Name/Organization]"
    ) -> str:
        """Generate full private disclosure report"""
        
        today = datetime.now()
        followup_date = today + timedelta(days=14)
        public_date = today + timedelta(days=30)
        
        report = f"""# Security Vulnerability Report: {self.repo_name or 'Target Repository'}

**Date**: {today.strftime('%Y-%m-%d')}
**Reporter**: {reporter_name}
**Severity**: High (CVSS estimated 7.0-8.0)

---

## Summary

During a security review, we identified:
- **{len(code_findings)} code vulnerabilities** requiring fixes
- **{len(dependency_findings)} dependency CVEs** with available updates

We are reporting this privately to allow time for patches before any public disclosure.

---

## A) Code Vulnerabilities (Actionable)

"""
        
        if code_findings:
            for i, finding in enumerate(code_findings, 1):
                title = finding.get('title', finding.get('rule_id', 'Unknown Issue'))
                file_path = self._sanitize_path(finding.get('file_path', finding.get('file', 'Unknown')))
                line = finding.get('line_number', finding.get('line', ''))
                description = finding.get('description', finding.get('message', ''))
                cwe = finding.get('cwe_id', finding.get('cwe', ''))
                recommendation = finding.get('recommendation', '')
                
                report += f"""### {i}. {title}

**File**: `{file_path}`{f' (line {line})' if line else ''}
"""
                if cwe:
                    report += f"**CWE**: {cwe}\n"
                
                # Truncate long descriptions
                if len(description) > 500:
                    description = description[:500] + "..."
                
                report += f"""
**Description**: {description}

"""
                if recommendation:
                    report += f"**Recommended Fix**: {recommendation}\n\n"
                
                report += "---\n\n"
        else:
            report += "*No code vulnerabilities found.*\n\n---\n\n"
        
        report += """## B) Dependency CVEs (Lockfile Updates)

"""
        
        if dependency_findings:
            # Group by severity
            high_deps = [f for f in dependency_findings if f.get('severity', '').lower() in ['critical', 'high']]
            medium_deps = [f for f in dependency_findings if f.get('severity', '').lower() == 'medium']
            
            if high_deps:
                report += "### High/Critical Priority\n\n"
                report += "| Package | Current | Fixed | CVE |\n"
                report += "|---------|---------|-------|-----|\n"
                
                for finding in high_deps[:10]:  # Limit to top 10
                    title = finding.get('title', '')
                    cve = finding.get('cve_id', finding.get('cve', 'N/A'))
                    # Try to extract package info from title
                    package = title.split(' in ')[-1] if ' in ' in title else title[:30]
                    recommendation = finding.get('recommendation', '')
                    fixed = 'See advisory' if not recommendation else recommendation.split()[-1]
                    
                    report += f"| {package} | - | {fixed} | {cve} |\n"
                
                report += "\n"
            
            if medium_deps:
                report += f"### Medium Priority ({len(medium_deps)} findings)\n\n"
                report += "See full scan results for complete list.\n\n"
        else:
            report += "*No dependency CVEs found.*\n\n"
        
        report += f"""---

## Disclosure Timeline

| Date | Action |
|------|--------|
| {today.strftime('%Y-%m-%d')} | Initial private report sent |
| {followup_date.strftime('%Y-%m-%d')} | Follow-up if no response (14 days) |
| {public_date.strftime('%Y-%m-%d')} | Coordinated public disclosure (30 days) |

We're happy to extend timelines if patches are in progress.

---

## Contact

Please reply to confirm receipt. We can provide additional details or clarification as needed.

---

*Report generated by Argus Security Platform*
"""
        
        return report
    
    def _generate_public_safe_report(
        self,
        code_findings: list,
        dependency_findings: list
    ) -> str:
        """Generate high-level public report without exploit details"""
        
        # Count by category
        api_issues = sum(1 for f in code_findings if 'api' in f.get('source_tool', '').lower())
        auth_issues = sum(1 for f in code_findings if any(
            kw in f.get('title', '').lower() + f.get('description', '').lower()
            for kw in ['auth', 'idor', 'authorization', 'permission']
        ))
        
        # Get unique affected packages
        packages = set()
        for f in dependency_findings:
            title = f.get('title', '')
            if ' in ' in title:
                packages.add(title.split(' in ')[-1].split()[0])
        
        report = f"""# [Security] Potential security improvements identified

## Summary

During a security review, we identified areas that may benefit from security hardening:

### 1. API Authorization

Some endpoints may benefit from additional authorization checks.

"""
        
        if auth_issues > 0:
            report += f"**Affected areas**: ~{auth_issues} endpoint(s) in the web API\n\n"
        
        report += """### 2. Dependency Updates

Several dependencies have published security advisories with available fixes:

| Package | Action Needed |
|---------|---------------|
"""
        
        # List top packages needing updates
        for package in list(packages)[:5]:
            report += f"| {package} | Update to latest |\n"
        
        if len(packages) > 5:
            report += f"| *...and {len(packages) - 5} more* | See lockfile |\n"
        
        report += """
## Next Steps

We'd be happy to:
- Discuss details privately
- Submit a PR with fixes
- Provide additional context

Please let us know the preferred contact method for security-related discussions.

---

*Reported responsibly - detailed findings available upon request*
"""
        
        return report
    
    def generate(
        self,
        findings: list,
        output_dir: Optional[str] = None,
        reporter_name: str = "[Your Name/Organization]"
    ) -> DisclosureReport:
        """
        Generate disclosure reports from findings.
        
        Args:
            findings: List of security findings (from Argus scan)
            output_dir: Directory to save reports (optional)
            reporter_name: Name/org for attribution
            
        Returns:
            DisclosureReport with generated content
        """
        logger.info(f"Generating disclosure reports for {len(findings)} findings")
        
        # Check repo security options
        security_options = self._check_repo_security_options()
        
        # Categorize findings
        code_findings, dependency_findings = self._categorize_findings(findings)
        high_findings = self._get_high_severity_findings(code_findings)
        
        logger.info(f"  Code vulnerabilities: {len(code_findings)} ({len(high_findings)} high/critical)")
        logger.info(f"  Dependency CVEs: {len(dependency_findings)}")
        
        # Generate reports
        private_report = self._generate_private_report(
            code_findings, dependency_findings, reporter_name
        )
        public_report = self._generate_public_safe_report(
            code_findings, dependency_findings
        )
        
        # Calculate timeline
        today = datetime.now()
        timeline = {
            'reported': today.strftime('%Y-%m-%d'),
            'followup': (today + timedelta(days=14)).strftime('%Y-%m-%d'),
            'public_disclosure': (today + timedelta(days=30)).strftime('%Y-%m-%d'),
        }
        
        # Save if output dir specified
        if output_dir:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            private_path = output_path / 'DISCLOSURE_PRIVATE.md'
            public_path = output_path / 'ISSUE_PUBLIC_SAFE.md'
            
            private_path.write_text(private_report)
            public_path.write_text(public_report)
            
            logger.info(f"  Saved: {private_path}")
            logger.info(f"  Saved: {public_path}")
        
        return DisclosureReport(
            private_report=private_report,
            public_safe_report=public_report,
            repo_owner=self.repo_owner or '',
            repo_name=self.repo_name or '',
            has_security_policy=security_options['has_security_policy'],
            has_discussions=security_options['has_discussions'],
            has_private_reporting=security_options['has_private_reporting'],
            high_findings=high_findings,
            dependency_findings=dependency_findings,
            disclosure_timeline=timeline,
        )
    
    def create_github_discussion(
        self,
        title: str = "Security Contact Request - Potential vulnerabilities to report"
    ) -> Optional[str]:
        """
        Create a GitHub Discussion to request security contact.
        
        Returns:
            Discussion URL if successful, None otherwise
        """
        if not self.repo_owner or not self.repo_name:
            logger.error("Repository owner/name not set")
            return None
        
        try:
            # Get repository ID
            result = subprocess.run(
                ['gh', 'api', 'graphql', '-f', f'''query{{
                    repository(owner: "{self.repo_owner}", name: "{self.repo_name}") {{
                        id
                        discussionCategories(first: 10) {{
                            nodes {{ id name slug }}
                        }}
                    }}
                }}'''],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get repo info: {result.stderr}")
                return None
            
            data = json.loads(result.stdout)
            repo_id = data['data']['repository']['id']
            
            # Find General category
            categories = data['data']['repository']['discussionCategories']['nodes']
            category_id = None
            for cat in categories:
                if cat['slug'] in ['general', 'q-a', 'ideas']:
                    category_id = cat['id']
                    break
            
            if not category_id:
                logger.error("No suitable discussion category found")
                return None
            
            # Create discussion
            body = """Hi maintainers,

During a security review, we identified some potential security issues that we would like to report responsibly:

1. **API Authorization**: Possible missing authorization checks in some endpoints
2. **Dependency Updates**: Several dependencies have published security advisories with available fixes

We have detailed findings ready to share privately. Could you please provide:
- A security contact email, OR
- Confirm we can share details in this discussion, OR
- Enable GitHub Private Vulnerability Reporting

We are committed to responsible disclosure and will not publish details publicly until patches are available.

Thank you for your time!

---
*This is a good-faith security report. No exploit details are included in this message.*"""
            
            # Escape for GraphQL
            body_escaped = body.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            title_escaped = title.replace('"', '\\"')
            
            result = subprocess.run(
                ['gh', 'api', 'graphql', '-f', f'''mutation{{
                    createDiscussion(input: {{
                        repositoryId: "{repo_id}"
                        categoryId: "{category_id}"
                        title: "{title_escaped}"
                        body: "{body_escaped}"
                    }}) {{
                        discussion {{ url number }}
                    }}
                }}'''],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to create discussion: {result.stderr}")
                return None
            
            data = json.loads(result.stdout)
            url = data['data']['createDiscussion']['discussion']['url']
            logger.info(f"Created discussion: {url}")
            return url
            
        except Exception as e:
            logger.error(f"Failed to create discussion: {e}")
            return None


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Generate responsible disclosure reports from Argus findings"
    )
    parser.add_argument('--input', '-i', required=True, help='Input findings JSON file')
    parser.add_argument('--output', '-o', help='Output directory for reports')
    parser.add_argument('--repo', '-r', help='GitHub repository URL or owner/name')
    parser.add_argument('--reporter', default='Security Researcher', help='Reporter name/org')
    parser.add_argument('--create-discussion', action='store_true', help='Create GitHub discussion')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Load findings
    with open(args.input) as f:
        data = json.load(f)
        findings = data.get('findings', data) if isinstance(data, dict) else data
    
    # Generate reports
    generator = DisclosureGenerator(repo_url=args.repo)
    report = generator.generate(
        findings=findings,
        output_dir=args.output,
        reporter_name=args.reporter
    )
    
    # Print summary
    print(f"\n{'='*60}")
    print("DISCLOSURE REPORT GENERATED")
    print('='*60)
    print(f"Repository: {report.repo_owner}/{report.repo_name}")
    print(f"Security Policy: {'Yes' if report.has_security_policy else 'No'}")
    print(f"Discussions Enabled: {'Yes' if report.has_discussions else 'No'}")
    print(f"Private Reporting: {'Yes' if report.has_private_reporting else 'No'}")
    print(f"\nFindings:")
    print(f"  High/Critical: {len(report.high_findings)}")
    print(f"  Dependencies: {len(report.dependency_findings)}")
    print(f"\nTimeline:")
    print(f"  Reported: {report.disclosure_timeline['reported']}")
    print(f"  Follow-up: {report.disclosure_timeline['followup']}")
    print(f"  Public: {report.disclosure_timeline['public_disclosure']}")
    
    # Create discussion if requested
    if args.create_discussion:
        if report.has_discussions:
            url = generator.create_github_discussion()
            if url:
                print(f"\nDiscussion created: {url}")
        else:
            print("\nDiscussions not enabled for this repository")
    
    print('='*60)
    
    return 0


if __name__ == "__main__":
    exit(main())
