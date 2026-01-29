#!/usr/bin/env python3
"""
Responsible Disclosure Workflow Manager
Ensures ethical vulnerability disclosure to maintainers before public release
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests


@dataclass
class SecurityContact:
    """Security contact information for a repository"""

    repo_url: str
    repo_name: str
    contact_method: str  # 'security.md', 'email', 'github_advisory', 'maintainer_email'
    contact_value: str
    last_verified: Optional[str] = None


@dataclass
class DisclosureTracking:
    """Track disclosure timeline for a vulnerability"""

    disclosure_id: str
    repo_url: str
    repo_name: str
    vulnerability_summary: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    contact_date: str
    deadline_date: str  # 90 days from contact
    status: str  # 'contacted', 'acknowledged', 'patched', 'disclosed', 'overdue'
    contact_method: str
    contact_email: Optional[str] = None
    maintainer_response: Optional[str] = None
    patch_url: Optional[str] = None
    public_advisory_url: Optional[str] = None
    notes: list[str] = None

    def __post_init__(self):
        if self.notes is None:
            self.notes = []


class ResponsibleDisclosureManager:
    """Manage responsible disclosure workflow"""

    def __init__(self, tracking_file: str = ".argus/disclosures.json"):
        """
        Initialize disclosure manager

        Args:
            tracking_file: Path to disclosure tracking JSON file
        """
        self.tracking_file = Path(tracking_file)
        self.tracking_file.parent.mkdir(parents=True, exist_ok=True)
        self.disclosures: list[DisclosureTracking] = []
        self._load_tracking()

    def _load_tracking(self):
        """Load existing disclosure tracking"""
        if self.tracking_file.exists():
            with open(self.tracking_file) as f:
                data = json.load(f)
                self.disclosures = [DisclosureTracking(**d) for d in data.get("disclosures", [])]

    def _save_tracking(self):
        """Save disclosure tracking"""
        data = {
            "last_updated": datetime.now().isoformat(),
            "disclosures": [asdict(d) for d in self.disclosures],
        }
        with open(self.tracking_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Tracking saved to {self.tracking_file}")

    def find_security_contact(self, repo_url: str) -> Optional[SecurityContact]:
        """
        Find security contact for a repository

        Priority:
        1. SECURITY.md file
        2. security@domain email
        3. GitHub security advisories
        4. Maintainer email from commits

        Args:
            repo_url: Repository URL

        Returns:
            SecurityContact or None
        """
        print(f"\nFinding security contact for {repo_url}")

        # Parse repo info
        parsed = urlparse(repo_url)
        if "github.com" in parsed.netloc:
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                owner, repo = path_parts[0], path_parts[1]
                repo_name = f"{owner}/{repo}"
            else:
                print("Error: Invalid GitHub URL")
                return None
        else:
            print("Error: Only GitHub repositories supported currently")
            return None

        # 1. Check for SECURITY.md
        security_md_urls = [
            f"https://raw.githubusercontent.com/{owner}/{repo}/main/SECURITY.md",
            f"https://raw.githubusercontent.com/{owner}/{repo}/master/SECURITY.md",
            f"https://raw.githubusercontent.com/{owner}/{repo}/main/.github/SECURITY.md",
        ]

        for url in security_md_urls:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    # Extract email from SECURITY.md
                    emails = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", resp.text)
                    if emails:
                        print(f"Found SECURITY.md with contact: {emails[0]}")
                        return SecurityContact(
                            repo_url=repo_url,
                            repo_name=repo_name,
                            contact_method="security.md",
                            contact_value=emails[0],
                            last_verified=datetime.now().isoformat(),
                        )
                    else:
                        print("Found SECURITY.md but no email address")
                        return SecurityContact(
                            repo_url=repo_url,
                            repo_name=repo_name,
                            contact_method="security.md",
                            contact_value=url,
                            last_verified=datetime.now().isoformat(),
                        )
            except Exception:
                continue

        # 2. Try security@domain
        if "github.com" in repo_url:
            # Try to get project website from GitHub API
            try:
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                resp = requests.get(api_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    homepage = data.get("homepage", "")
                    if homepage:
                        domain = urlparse(homepage).netloc
                        security_email = f"security@{domain}"
                        print(f"Suggesting security email: {security_email}")
                        return SecurityContact(
                            repo_url=repo_url,
                            repo_name=repo_name,
                            contact_method="email",
                            contact_value=security_email,
                            last_verified=datetime.now().isoformat(),
                        )
            except Exception:
                pass

        # 3. GitHub Security Advisories (always available for public repos)
        print(f"Recommending GitHub Security Advisory for {repo_name}")
        return SecurityContact(
            repo_url=repo_url,
            repo_name=repo_name,
            contact_method="github_advisory",
            contact_value=f"https://github.com/{owner}/{repo}/security/advisories/new",
            last_verified=datetime.now().isoformat(),
        )

    def generate_disclosure_email(
        self, report_file: str, contact: SecurityContact, template_file: Optional[str] = None
    ) -> str:
        """
        Generate disclosure email from report and template

        Args:
            report_file: Path to vulnerability report JSON
            contact: Security contact
            template_file: Optional custom template path

        Returns:
            Formatted email content
        """
        # Load report
        with open(report_file) as f:
            report = json.load(f)

        # Load template
        if template_file:
            template_path = Path(template_file)
        else:
            template_path = Path(__file__).parent.parent / "templates" / "security-disclosure-email.md"

        with open(template_path) as f:
            template = f.read()

        # Extract key info from report
        vuln_count = len(report.get("findings", []))
        critical_count = sum(1 for f in report.get("findings", []) if f.get("severity") == "critical")
        high_count = sum(1 for f in report.get("findings", []) if f.get("severity") == "high")

        # Calculate 90-day deadline
        contact_date = datetime.now()
        deadline_date = contact_date + timedelta(days=90)

        # Format template
        email_content = template.format(
            repo_name=contact.repo_name,
            repo_url=contact.repo_url,
            vuln_count=vuln_count,
            critical_count=critical_count,
            high_count=high_count,
            contact_date=contact_date.strftime("%Y-%m-%d"),
            deadline_date=deadline_date.strftime("%Y-%m-%d"),
            contact_email="security@argus-security.io",  # Replace with actual contact
        )

        return email_content

    def create_disclosure(
        self,
        repo_url: str,
        report_file: str,
        severity: str = "high",
        contact_method: Optional[str] = None,
        contact_email: Optional[str] = None,
    ) -> DisclosureTracking:
        """
        Create new disclosure tracking entry

        Args:
            repo_url: Repository URL
            report_file: Path to vulnerability report JSON
            severity: Vulnerability severity
            contact_method: Override contact method
            contact_email: Override contact email

        Returns:
            DisclosureTracking
        """
        # Find contact if not provided
        if not contact_method or not contact_email:
            contact = self.find_security_contact(repo_url)
            if not contact:
                print("Error: Could not find security contact")
                sys.exit(1)
            contact_method = contact.contact_method
            contact_email = contact.contact_value

        # Load report
        with open(report_file) as f:
            report = json.load(f)

        # Generate disclosure ID
        disclosure_id = f"ARGUS-{datetime.now().strftime('%Y%m%d')}-{len(self.disclosures) + 1:03d}"

        # Create summary
        vuln_count = len(report.get("findings", []))
        summary = f"{vuln_count} security vulnerabilities found in {repo_url}"

        # Calculate dates
        contact_date = datetime.now()
        deadline_date = contact_date + timedelta(days=90)

        # Create tracking entry
        disclosure = DisclosureTracking(
            disclosure_id=disclosure_id,
            repo_url=repo_url,
            repo_name=urlparse(repo_url).path.strip("/"),
            vulnerability_summary=summary,
            severity=severity,
            contact_date=contact_date.isoformat(),
            deadline_date=deadline_date.isoformat(),
            status="contacted",
            contact_method=contact_method,
            contact_email=contact_email,
            notes=[f"Initial disclosure created on {contact_date.strftime('%Y-%m-%d')}"],
        )

        self.disclosures.append(disclosure)
        self._save_tracking()

        print(f"\nDisclosure tracking created: {disclosure_id}")
        print(f"  Severity: {severity}")
        print(f"  Contact: {contact_email}")
        print(f"  Deadline: {deadline_date.strftime('%Y-%m-%d')} (90 days)")

        return disclosure

    def update_status(self, disclosure_id: str, new_status: str, notes: Optional[str] = None):
        """
        Update disclosure status

        Args:
            disclosure_id: Disclosure ID
            new_status: New status
            notes: Additional notes
        """
        for disclosure in self.disclosures:
            if disclosure.disclosure_id == disclosure_id:
                disclosure.status = new_status
                if notes:
                    disclosure.notes.append(f"[{datetime.now().strftime('%Y-%m-%d')}] {notes}")
                self._save_tracking()
                print(f"Updated {disclosure_id} status to: {new_status}")
                return

        print(f"Error: Disclosure {disclosure_id} not found")

    def list_disclosures(self, show_all: bool = False):
        """
        List tracked disclosures

        Args:
            show_all: Show all or only active disclosures
        """
        if not self.disclosures:
            print("No disclosures tracked")
            return

        print("\nResponsible Disclosure Tracking")
        print("=" * 80)

        for disclosure in self.disclosures:
            if not show_all and disclosure.status in ["disclosed", "patched"]:
                continue

            # Check if overdue
            deadline = datetime.fromisoformat(disclosure.deadline_date)
            days_remaining = (deadline - datetime.now()).days

            status_emoji = {
                "contacted": "📧",
                "acknowledged": "👍",
                "patched": "✅",
                "disclosed": "📢",
                "overdue": "⚠️",
            }.get(disclosure.status, "❓")

            print(f"\n{status_emoji} {disclosure.disclosure_id} - {disclosure.repo_name}")
            print(f"   Severity: {disclosure.severity.upper()}")
            print(f"   Status: {disclosure.status}")
            print(f"   Contact: {disclosure.contact_email}")
            print(f"   Deadline: {disclosure.deadline_date} ({days_remaining} days remaining)")

            if disclosure.maintainer_response:
                print(f"   Response: {disclosure.maintainer_response}")

        print("\n" + "=" * 80)

    def check_overdue(self):
        """Check for overdue disclosures"""
        now = datetime.now()
        overdue_count = 0

        for disclosure in self.disclosures:
            if disclosure.status in ["disclosed", "patched"]:
                continue

            deadline = datetime.fromisoformat(disclosure.deadline_date)
            if now > deadline and disclosure.status != "overdue":
                disclosure.status = "overdue"
                disclosure.notes.append(f"[{now.strftime('%Y-%m-%d')}] Disclosure deadline passed")
                overdue_count += 1

        if overdue_count > 0:
            self._save_tracking()
            print(f"\nWarning: {overdue_count} disclosure(s) are now overdue for public release")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Responsible Disclosure Workflow Manager")
    parser.add_argument("--repo", help="Repository URL")
    parser.add_argument("--report", help="Path to vulnerability report JSON")
    parser.add_argument("--severity", default="high", choices=["critical", "high", "medium", "low"], help="Severity")
    parser.add_argument("--find-contact", action="store_true", help="Find security contact for repository")
    parser.add_argument(
        "--generate-email", action="store_true", help="Generate disclosure email (requires --repo and --report)"
    )
    parser.add_argument("--create", action="store_true", help="Create disclosure tracking (requires --repo and --report)")
    parser.add_argument("--update", help="Update disclosure status (requires --status)")
    parser.add_argument("--status", help="New status for disclosure update")
    parser.add_argument("--notes", help="Notes for status update")
    parser.add_argument("--list", action="store_true", help="List all tracked disclosures")
    parser.add_argument("--list-all", action="store_true", help="List all disclosures including closed")
    parser.add_argument("--check-overdue", action="store_true", help="Check for overdue disclosures")
    parser.add_argument(
        "--tracking-file", default=".argus/disclosures.json", help="Disclosure tracking file (default: .argus/disclosures.json)"
    )

    args = parser.parse_args()

    # Initialize manager
    manager = ResponsibleDisclosureManager(tracking_file=args.tracking_file)

    # Execute commands
    if args.find_contact:
        if not args.repo:
            print("Error: --repo required for --find-contact")
            sys.exit(1)
        contact = manager.find_security_contact(args.repo)
        if contact:
            print(f"\nSecurity Contact Found:")
            print(f"  Method: {contact.contact_method}")
            print(f"  Contact: {contact.contact_value}")

    elif args.generate_email:
        if not args.repo or not args.report:
            print("Error: --repo and --report required for --generate-email")
            sys.exit(1)
        contact = manager.find_security_contact(args.repo)
        if contact:
            email = manager.generate_disclosure_email(args.report, contact)
            output_file = f"disclosure_email_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(output_file, "w") as f:
                f.write(email)
            print(f"\nDisclosure email generated: {output_file}")
            print("\n" + "=" * 80)
            print(email)
            print("=" * 80)

    elif args.create:
        if not args.repo or not args.report:
            print("Error: --repo and --report required for --create")
            sys.exit(1)
        disclosure = manager.create_disclosure(args.repo, args.report, severity=args.severity)
        print(f"\nNext steps:")
        print(f"1. Review generated email in disclosure_email_*.txt")
        print(f"2. Send to: {disclosure.contact_email}")
        print(f"3. Update status with: python responsible_disclosure.py --update {disclosure.disclosure_id} --status acknowledged")

    elif args.update:
        if not args.status:
            print("Error: --status required for --update")
            sys.exit(1)
        manager.update_status(args.update, args.status, args.notes)

    elif args.list or args.list_all:
        manager.list_disclosures(show_all=args.list_all)

    elif args.check_overdue:
        manager.check_overdue()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
