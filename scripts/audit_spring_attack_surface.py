#!/usr/bin/env python3
"""
Audit spring-attack-surface repository using enhanced multi-agent review
"""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.real_multi_agent_review import RealMultiAgentReview


async def main():
    """Audit spring-attack-surface repository"""
    print("🔍 Spring Attack Surface - Enhanced Multi-Agent Security Audit")
    print("=" * 70)
    print()

    # Get API keys
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")

    if not anthropic_key:
        print("❌ ANTHROPIC_API_KEY not found")
        print("   Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        return

    # Initialize enhanced reviewer
    reviewer = RealMultiAgentReview(
        anthropic_api_key=anthropic_key,
        openai_api_key=None,  # Using only Anthropic for now
    )

    print()

    # Repository path
    repo_path = "/Users/waseem.ahmed/Repos/spring-attack-surface"
    repo_name = "spring-attack-surface"

    if not Path(repo_path).exists():
        print(f"❌ Repository not found: {repo_path}")
        return

    # Critical files to audit (security-sensitive)
    critical_files = [
        # Core domain logic
        "src/core/domain/attack_path_processing_service.py",
        "src/core/domain/attack_path_generation_service.py",
        "src/core/domain/attack_path_service.py",
        "src/core/domain/blast_radius_algorithm.py",
        "src/core/domain/blast_radius_service.py",
        "src/core/domain/tenant_service.py",
        "src/core/domain/attack_path_modules/public_ec2_module.py",
        # API endpoints (input validation)
        "src/adapters/input/http/api_router.py",
        "src/adapters/input/http/middleware/auth.py",
        "src/adapters/input/http/middleware/tenant_auth_middleware.py",
        # Repositories (SQL injection risks)
        "src/adapters/output/attack_path_repository.py",
        "src/adapters/output/tenant_repository.py",
        "src/adapters/output/blast_radius_repository.py",
        # External integrations (injection/SSRF risks)
        "src/infrastructure/external_services/opensearch_client.py",
        "src/infrastructure/external_services/trino_client.py",
        "src/infrastructure/external_services/neo4j_client.py",
        # Database migrations (schema security)
        "src/infrastructure/database/migration_service.py",
        # Main entry point
        "src/main.py",
    ]

    # Filter to existing files
    files_to_review = []
    for file_path in critical_files:
        full_path = Path(repo_path) / file_path
        if full_path.exists():
            files_to_review.append(file_path)
        else:
            print(f"⚠️  Skipping (not found): {file_path}")

    print(f"📂 Repository: {repo_name}")
    print(f"📄 Files to audit: {len(files_to_review)}")
    print("🎯 Using: Category-specific passes + Heuristics + Context injection + Test generation")
    print()

    # Review all files
    all_findings = []

    for i, file_path in enumerate(files_to_review, 1):
        print(f"📄 [{i}/{len(files_to_review)}] Reviewing: {file_path}")
        try:
            findings = await reviewer.review_file(file_path, repo_path)
            all_findings.extend(findings)
            print(f"    ✅ Found {len(findings)} potential issue(s)")
        except Exception as e:
            print(f"    ❌ Error: {e}")
        print()

    print(f"✅ Total findings across all files: {len(all_findings)}")
    print()

    # Build consensus
    print("🔄 Building consensus with location-sensitive grouping...")
    consensus_results = reviewer.build_consensus(all_findings)
    print(f"✅ Consensus findings: {len(consensus_results)}")
    print()

    # Generate test cases for high/critical
    print("🧪 Generating test cases for high/critical findings...")
    consensus_results = await reviewer.enhance_findings_with_tests(consensus_results)
    print()

    # Generate comprehensive report
    print("📝 Generating comprehensive audit report...")
    report = reviewer.generate_report(consensus_results, repo_name)

    # Save reports
    output_dir = Path(repo_path) / "audit-results"
    output_dir.mkdir(exist_ok=True)

    # Main report
    main_report_path = output_dir / "enhanced-audit-report.md"
    with open(main_report_path, "w") as f:
        f.write(report)

    # Also save to argus/reviews for comparison
    comparison_path = Path(repo_path) / "argus" / "reviews" / "enhanced-audit-report.md"
    with open(comparison_path, "w") as f:
        f.write(report)

    print("✅ Report saved:")
    print(f"   - {main_report_path}")
    print(f"   - {comparison_path}")
    print()

    # Generate summary
    critical = len([r for r in consensus_results if r.final_classification == "critical_fix"])
    high = len([r for r in consensus_results if r.final_classification == "high_priority"])
    dev_issues = len([r for r in consensus_results if r.final_classification == "dev_issue"])
    suggestions = len([r for r in consensus_results if r.final_classification == "suggestion"])

    print("📊 Audit Summary:")
    print(f"  🔴 Critical Fixes: {critical}")
    print(f"  🟠 High Priority: {high}")
    print(f"  🔧 Dev Infrastructure Issues: {dev_issues}")
    print(f"  🟡 Suggestions: {suggestions}")
    print()

    # Comparison section
    print("📈 Comparison with Previous Audit (Oct 21, 2025):")
    print("  Previous: Empty reports (no findings documented)")
    print(f"  Current: {len(consensus_results)} consensus findings")
    print(f"  New Critical Issues: {critical}")
    print(f"  New High Priority: {high}")
    print()
    print("  ℹ️  Previous audits had no detailed findings.")
    print("  ℹ️  This enhanced audit provides:")
    print("      - Heuristic pre-scanning")
    print("      - Category-specific analysis (security/performance/quality)")
    print("      - Git context awareness")
    print("      - Automated test case generation")
    print("      - Location-sensitive consensus")
    print()

    print("🎉 Enhanced security audit complete!")
    print(f"📄 View full report: {main_report_path}")
    print()

    # Print top 3 critical/high issues if any
    top_issues = [r for r in consensus_results if r.final_classification in ["critical_fix", "high_priority"]][:3]
    if top_issues:
        print("🚨 Top Security Concerns:")
        for i, issue in enumerate(top_issues, 1):
            print(f"{i}. {issue.issue_type.replace('-', ' ').title()}")
            print(f"   File: {issue.file}:{issue.line}")
            print(f"   Severity: {issue.severity.upper()}")
            print(f"   Votes: {issue.votes}/{issue.total_agents}")
            if issue.heuristic_flags:
                print(f"   Heuristic Flags: {', '.join(issue.heuristic_flags)}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
