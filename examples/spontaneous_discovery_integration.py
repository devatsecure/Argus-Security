#!/usr/bin/env python3
"""
Integration Example: Spontaneous Discovery with Argus

This example demonstrates how to integrate spontaneous discovery
into your security scanning workflow alongside traditional scanners.

The spontaneous discovery system finds issues that rule-based scanners
might miss, such as:
- Missing authentication/authorization layers
- Weak cryptographic practices
- Configuration security issues
- Data security problems

Usage:
    python examples/spontaneous_discovery_integration.py /path/to/project
"""

import json
import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from spontaneous_discovery import SpontaneousDiscovery
from normalizer.base import Finding


def integrate_spontaneous_discovery_example():
    """
    Example of integrating spontaneous discovery into security workflow

    This shows how to:
    1. Run traditional scanners (Semgrep, Trivy, etc.)
    2. Run spontaneous discovery to find additional issues
    3. Combine results into unified findings
    4. Filter and deduplicate
    """

    # Step 1: Gather files to analyze
    project_path = Path(".")  # Current directory
    files = []

    print("🔍 Gathering files to analyze...")
    for ext in ["*.py", "*.js", "*.ts", "*.go", "*.java"]:
        files.extend([str(f) for f in project_path.rglob(ext)])

    print(f"   Found {len(files)} files")

    # Step 2: Simulate existing scanner findings
    # In a real scenario, you would run Semgrep, Trivy, etc. first
    existing_findings = [
        {
            "title": "SQL Injection vulnerability",
            "cwe": "CWE-89",
            "severity": "high",
            "file_path": "app/routes.py",
            "line": 42
        },
        {
            "title": "Hardcoded secret",
            "cwe": "CWE-798",
            "severity": "critical",
            "file_path": "config/settings.py",
            "line": 15
        }
    ]

    print(f"📊 {len(existing_findings)} findings from traditional scanners")

    # Step 3: Run spontaneous discovery
    print("\n🎯 Running spontaneous discovery...")

    discovery_engine = SpontaneousDiscovery(llm_manager=None)

    # Discover issues beyond scanner rules
    discoveries = discovery_engine.discover(
        files=files,
        existing_findings=existing_findings,
        architecture="backend-api",  # or "frontend", "microservice", etc.
        max_files_analyze=50  # Limit for performance
    )

    print(f"✅ Found {len(discoveries)} additional security issues")

    # Step 4: Convert discoveries to unified Finding format
    print("\n📋 Converting to unified format...")

    git_context = {
        "repo": "example-project",
        "commit_sha": "abc123",
        "branch": "main"
    }

    unified_findings = []
    for discovery in discoveries:
        finding = discovery.to_finding(
            repo=git_context["repo"],
            commit_sha=git_context["commit_sha"],
            branch=git_context["branch"]
        )
        unified_findings.append(finding)

    # Step 5: Report results
    print(f"\n📈 Security Scan Summary")
    print(f"=" * 60)
    print(f"Traditional scanner findings: {len(existing_findings)}")
    print(f"Spontaneous discoveries:      {len(discoveries)}")
    print(f"Total findings:               {len(existing_findings) + len(discoveries)}")
    print(f"=" * 60)

    # Show discoveries by category
    by_category = {}
    for d in discoveries:
        by_category.setdefault(d.category, []).append(d)

    print(f"\n📊 Discoveries by Category:")
    for category, items in by_category.items():
        print(f"   {category:20s}: {len(items)}")

    # Show top findings
    print(f"\n🔥 Top Spontaneous Discoveries:")
    sorted_discoveries = sorted(discoveries, key=lambda x: x.confidence, reverse=True)

    for i, d in enumerate(sorted_discoveries[:5], 1):
        print(f"\n   {i}. [{d.severity.upper()}] {d.title}")
        print(f"      Confidence: {d.confidence:.0%}")
        print(f"      Category: {d.category}")
        print(f"      CWE: {d.cwe_id}")
        print(f"      Affected files: {len(d.affected_files)}")
        print(f"      {d.description[:100]}...")

    # Step 6: Export results
    output_file = "spontaneous_discoveries.json"
    with open(output_file, "w") as f:
        json.dump(
            [
                {
                    "id": finding.id,
                    "origin": finding.origin,
                    "title": finding.rule_name,
                    "category": finding.category,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "description": finding.evidence.get("description"),
                    "evidence": finding.evidence.get("evidence_items"),
                    "remediation": finding.fix_suggestion,
                    "affected_files": finding.evidence.get("affected_files")
                }
                for finding in unified_findings
            ],
            f,
            indent=2
        )

    print(f"\n✅ Results exported to {output_file}")

    return discoveries, unified_findings


def integrate_with_hybrid_analyzer():
    """
    Example of integrating with HybridSecurityAnalyzer

    This shows how spontaneous discovery can complement the
    existing hybrid analyzer workflow.
    """
    print("\n" + "=" * 60)
    print("Integration with HybridSecurityAnalyzer")
    print("=" * 60)

    print("""
To integrate spontaneous discovery into hybrid_analyzer.py:

1. Add to HybridSecurityAnalyzer.__init__():

   self.enable_spontaneous_discovery = enable_spontaneous_discovery
   if self.enable_spontaneous_discovery:
       from spontaneous_discovery import SpontaneousDiscovery
       self.spontaneous_discovery = SpontaneousDiscovery(
           llm_manager=self.llm_manager
       )

2. Add to scan() method after Phase 2:

   # Phase 2.5: Spontaneous Discovery (Optional)
   if self.enable_spontaneous_discovery and self.spontaneous_discovery:
       logger.info("🎯 Phase 2.5: Spontaneous Discovery")
       discoveries = self.spontaneous_discovery.discover(
           files=scanned_files,
           existing_findings=all_findings,
           architecture=project_type
       )

       # Convert to HybridFinding format
       for discovery in discoveries:
           finding = discovery.to_finding(repo, commit_sha, branch)
           all_findings.append(finding)

       logger.info(f"   Found {len(discoveries)} additional issues")

3. Add CLI argument:

   parser.add_argument(
       "--enable-spontaneous-discovery",
       action="store_true",
       help="Enable AI-powered spontaneous discovery"
   )

4. Use in action.yml:

   - name: Run Security Audit
     uses: devatsecure/Argus-Security@v1
     with:
       enable-spontaneous-discovery: true
       anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    """)


def main():
    """Main entry point"""
    print("🚀 Spontaneous Discovery Integration Example\n")

    try:
        # Run the example
        discoveries, findings = integrate_spontaneous_discovery_example()

        # Show integration guidance
        integrate_with_hybrid_analyzer()

        print("\n✅ Example complete!")
        print(f"\n💡 Tip: Use --enable-spontaneous-discovery in run_ai_audit.py")
        print("   to enable this feature in your security scans")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
