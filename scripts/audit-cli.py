#!/usr/bin/env python3
"""
Agent OS Audit CLI Tool
Automated codebase auditing for multiple repositories
"""

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path


class AgentOSAudit:
    """CLI tool for running Agent OS audits on repositories"""

    def __init__(self, config_file: str = "audit-config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.audit_dir = Path("/tmp/argus-security-audits")
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def load_config(self) -> dict:
        """Load audit configuration"""
        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                return json.load(f)
        return {
            "repositories": [],
            "audit_types": ["comprehensive"],
            "create_pr": True,
            "git_user": "devatsecure",
            "git_email": "devatsecure@users.noreply.github.com",
        }

    def save_config(self):
        """Save audit configuration"""
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)

    def add_repository(self, repo_url: str):
        """Add repository to audit list"""
        if repo_url not in self.config["repositories"]:
            self.config["repositories"].append(repo_url)
            self.save_config()
            print(f"✅ Added: {repo_url}")
        else:
            print(f"⚠️  Already exists: {repo_url}")

    def list_repositories(self):
        """List all repositories in audit configuration"""
        print("\n📋 Repositories configured for audit:")
        print("=" * 60)
        for i, repo in enumerate(self.config["repositories"], 1):
            print(f"{i}. {repo}")
        print(f"\nTotal: {len(self.config['repositories'])} repositories")

    def audit_repository(self, repo_url: str, audit_type: str = "comprehensive"):
        """Run audit on a single repository"""
        print(f"\n🔍 Auditing: {repo_url}")
        print("=" * 60)

        # Extract repo name
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = self.audit_dir / repo_name

        try:
            # Clone or update repository
            if repo_path.exists():
                print(f"📥 Updating {repo_name}...")
                subprocess.run(["git", "pull"], cwd=repo_path, check=True, capture_output=True)
            else:
                print(f"📥 Cloning {repo_name}...")
                subprocess.run(["git", "clone", repo_url, str(repo_path)], check=True, capture_output=True)

            # Create audit reports directory
            audit_reports_dir = repo_path / "audit-reports" / audit_type
            audit_reports_dir.mkdir(parents=True, exist_ok=True)

            # Run audit (this would call your Agent OS audit logic)
            print(f"🤖 Running {audit_type} audit...")
            self._run_audit_analysis(repo_path, audit_reports_dir, audit_type)

            # Create PR if configured
            if self.config.get("create_pr", True):
                self._create_pull_request(repo_path, audit_type)

            print(f"✅ Audit complete: {repo_name}")
            return True

        except Exception as e:
            print(f"❌ Error auditing {repo_name}: {str(e)}")
            return False

    def _run_audit_analysis(self, repo_path: Path, output_dir: Path, audit_type: str):
        """Run the actual audit analysis"""
        # This is where you'd integrate with your Agent OS audit logic
        # For now, this is a placeholder
        print("   📊 Analyzing codebase...")
        print("   🔒 Security analysis...")
        print("   ⚡ Performance analysis...")
        print("   🧪 Test coverage analysis...")
        print("   📝 Code quality analysis...")

        # Create sample reports (replace with actual Agent OS logic)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        summary = f"""# Audit Summary - {repo_path.name}

**Audit Date:** {timestamp}
**Audit Type:** {audit_type}
**Status:** ✅ Complete

## Next Steps
1. Review audit findings
2. Address critical issues
3. Plan improvements
"""

        with open(output_dir / "audit-summary.md", "w") as f:
            f.write(summary)

    def _create_pull_request(self, repo_path: Path, audit_type: str):
        """Create pull request with audit findings"""
        print("   📤 Creating pull request...")

        try:
            # Configure git user
            subprocess.run(["git", "config", "user.name", self.config["git_user"]], cwd=repo_path, check=True)
            subprocess.run(["git", "config", "user.email", self.config["git_email"]], cwd=repo_path, check=True)

            # Create branch
            branch_name = f"audit/{audit_type}-{datetime.now().strftime('%Y%m%d')}"
            subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_path, check=True, capture_output=True)

            # Add and commit
            subprocess.run(["git", "add", "audit-reports/"], cwd=repo_path, check=True)

            commit_message = f"""Add {audit_type} audit findings

Automated audit performed by Agent OS
Date: {datetime.now().strftime("%Y-%m-%d")}
"""

            subprocess.run(["git", "commit", "-m", commit_message], cwd=repo_path, check=True)

            # Push
            subprocess.run(["git", "push", "origin", branch_name], cwd=repo_path, check=True)

            print(f"   ✅ Pull request branch created: {branch_name}")

        except subprocess.CalledProcessError as e:
            print(f"   ⚠️  Could not create PR: {str(e)}")

    def audit_all(self, audit_type: str = "comprehensive"):
        """Run audit on all configured repositories"""
        print("\n🚀 Starting batch audit...")
        print(f"📊 Repositories to audit: {len(self.config['repositories'])}")
        print(f"🔍 Audit type: {audit_type}")
        print("=" * 60)

        results = []
        for repo_url in self.config["repositories"]:
            success = self.audit_repository(repo_url, audit_type)
            results.append((repo_url, success))

        # Summary
        print("\n" + "=" * 60)
        print("📊 Audit Summary")
        print("=" * 60)

        successful = sum(1 for _, success in results if success)
        failed = len(results) - successful

        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Total: {len(results)}")

        if failed > 0:
            print("\n❌ Failed audits:")
            for repo_url, success in results:
                if not success:
                    print(f"   - {repo_url}")


def main():
    parser = argparse.ArgumentParser(description="Agent OS Audit CLI - Automated codebase auditing")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Add repository
    add_parser = subparsers.add_parser("add", help="Add repository to audit list")
    add_parser.add_argument("repo_url", help="Repository URL")

    # List repositories
    subparsers.add_parser("list", help="List configured repositories")

    # Audit single repository
    audit_parser = subparsers.add_parser("audit", help="Audit a single repository")
    audit_parser.add_argument("repo_url", help="Repository URL")
    audit_parser.add_argument(
        "--type", default="comprehensive", choices=["comprehensive", "security", "quick"], help="Audit type"
    )

    # Audit all repositories
    audit_all_parser = subparsers.add_parser("audit-all", help="Audit all configured repositories")
    audit_all_parser.add_argument(
        "--type", default="comprehensive", choices=["comprehensive", "security", "quick"], help="Audit type"
    )

    # Configure
    config_parser = subparsers.add_parser("config", help="Configure audit settings")
    config_parser.add_argument("--git-user", help="Git username")
    config_parser.add_argument("--git-email", help="Git email")
    config_parser.add_argument("--no-pr", action="store_true", help="Disable PR creation")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    audit_tool = AgentOSAudit()

    if args.command == "add":
        audit_tool.add_repository(args.repo_url)

    elif args.command == "list":
        audit_tool.list_repositories()

    elif args.command == "audit":
        audit_tool.audit_repository(args.repo_url, args.type)

    elif args.command == "audit-all":
        audit_tool.audit_all(args.type)

    elif args.command == "config":
        if args.git_user:
            audit_tool.config["git_user"] = args.git_user
        if args.git_email:
            audit_tool.config["git_email"] = args.git_email
        if args.no_pr:
            audit_tool.config["create_pr"] = False
        audit_tool.save_config()
        print("✅ Configuration updated")


if __name__ == "__main__":
    main()
