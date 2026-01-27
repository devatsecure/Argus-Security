#!/usr/bin/env python3
"""
Example: Phase 1 MVP DAST Multi-Agent Scan
Demonstrates the enhanced DAST integration with Nuclei + ZAP
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from dast_orchestrator import DASTOrchestrator, OrchestratorConfig
from agents.nuclei_agent import NucleiConfig
from agents.zap_agent import ZAPConfig, ScanProfile
from sast_dast_correlation_v2 import SASTDASTCorrelator


def example_simple_scan():
    """Example 1: Simple scan with default settings"""
    print("=" * 80)
    print("Example 1: Simple DAST Scan (Nuclei + ZAP)")
    print("=" * 80)
    
    # Create orchestrator with defaults
    orchestrator = DASTOrchestrator()
    
    # Run scan
    result = orchestrator.scan(
        target_url="https://example.com",
        output_dir="./examples/dast-results-simple",
    )
    
    print(f"\n✅ Scan complete!")
    print(f"   Total findings: {result.total_findings}")
    print(f"   Duration: {result.duration_seconds:.1f}s")


def example_api_scan():
    """Example 2: API scan with OpenAPI spec"""
    print("\n" + "=" * 80)
    print("Example 2: API Scan with OpenAPI Spec")
    print("=" * 80)
    
    # Configure for API testing
    config = OrchestratorConfig(
        parallel_agents=True,
        enable_nuclei=True,
        enable_zap=True,
        nuclei_config=NucleiConfig(
            severity=["critical", "high", "medium"],
            rate_limit=200,  # Higher rate for APIs
            concurrency=30,
        ),
        zap_config=ZAPConfig(
            profile=ScanProfile.BALANCED,
            api_scan=True,
        ),
    )
    
    orchestrator = DASTOrchestrator(config=config)
    
    # Run scan with OpenAPI spec
    result = orchestrator.scan(
        target_url="https://api.example.com",
        openapi_spec="./examples/openapi.yaml",
        output_dir="./examples/dast-results-api",
    )
    
    print(f"\n✅ API scan complete!")
    print(f"   Endpoints tested: {result.metadata.get('targets_scanned', 0)}")
    print(f"   Findings: {result.total_findings}")


def example_authenticated_scan():
    """Example 3: Authenticated scan with custom headers"""
    print("\n" + "=" * 80)
    print("Example 3: Authenticated Scan")
    print("=" * 80)
    
    # Configure with authentication
    config = OrchestratorConfig(
        nuclei_config=NucleiConfig(
            headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs...",
                "X-API-Key": "your-api-key",
            },
        ),
        zap_config=ZAPConfig(
            custom_headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs...",
            },
        ),
    )
    
    orchestrator = DASTOrchestrator(config=config)
    
    result = orchestrator.scan(
        target_url="https://app.example.com",
        output_dir="./examples/dast-results-auth",
    )
    
    print(f"\n✅ Authenticated scan complete!")
    print(f"   Findings: {result.total_findings}")


def example_fast_scan():
    """Example 4: Fast scan (Nuclei only)"""
    print("\n" + "=" * 80)
    print("Example 4: Fast Scan (Nuclei Only)")
    print("=" * 80)
    
    # Disable ZAP for faster scans
    config = OrchestratorConfig(
        enable_nuclei=True,
        enable_zap=False,
        nuclei_config=NucleiConfig(
            severity=["critical", "high"],
            max_duration=300,  # 5 minutes
        ),
    )
    
    orchestrator = DASTOrchestrator(config=config)
    
    result = orchestrator.scan(
        target_url="https://example.com",
        output_dir="./examples/dast-results-fast",
    )
    
    print(f"\n✅ Fast scan complete!")
    print(f"   Duration: {result.duration_seconds:.1f}s")
    print(f"   Findings: {result.total_findings}")


def example_comprehensive_scan():
    """Example 5: Comprehensive scan (all features)"""
    print("\n" + "=" * 80)
    print("Example 5: Comprehensive Scan")
    print("=" * 80)
    
    # Enable all features
    config = OrchestratorConfig(
        max_duration=1800,  # 30 minutes
        parallel_agents=True,
        enable_nuclei=True,
        enable_zap=True,
        enable_correlation=True,
        enable_deduplication=True,
        project_path="./examples/sample-project",
        nuclei_config=NucleiConfig(
            severity=["critical", "high", "medium", "low"],
            max_duration=900,
        ),
        zap_config=ZAPConfig(
            profile=ScanProfile.COMPREHENSIVE,
            spider_max_depth=5,
            ajax_spider=True,
            active_scan=True,
        ),
    )
    
    orchestrator = DASTOrchestrator(config=config)
    
    result = orchestrator.scan(
        target_url="https://app.example.com",
        openapi_spec="./examples/openapi.yaml",
        output_dir="./examples/dast-results-comprehensive",
    )
    
    print(f"\n✅ Comprehensive scan complete!")
    print(f"   Duration: {result.duration_seconds / 60:.1f} minutes")
    print(f"   Agents: {', '.join(result.agents_succeeded)}")
    print(f"   Total findings: {result.total_findings}")
    print(f"\n   Breakdown by severity:")
    for severity, count in result.severity_counts.items():
        if count > 0:
            print(f"      {severity.upper()}: {count}")


def example_sast_dast_correlation():
    """Example 6: SAST-DAST correlation"""
    print("\n" + "=" * 80)
    print("Example 6: SAST-DAST Correlation")
    print("=" * 80)
    
    # Assume we have SAST results from a previous scan
    sast_findings = [
        {
            "id": "semgrep-sqli-001",
            "rule_id": "python.sql-injection",
            "severity": "high",
            "path": "api/users.py",
            "line": 42,
        }
    ]
    
    # Run DAST scan
    orchestrator = DASTOrchestrator()
    dast_result = orchestrator.scan(
        target_url="https://api.example.com",
        output_dir="./examples/dast-results-corr",
    )
    
    # Correlate findings
    correlator = SASTDASTCorrelator(confidence_threshold=0.7)
    correlation = correlator.correlate(
        sast_findings=sast_findings,
        dast_findings=dast_result.aggregated_findings,
    )
    
    print(f"\n✅ Correlation complete!")
    print(f"   Correlated findings: {correlation['stats']['correlated']}")
    print(f"   SAST only: {correlation['stats']['sast_only']}")
    print(f"   DAST only: {correlation['stats']['dast_only']}")
    print(f"   Correlation rate: {correlation['stats']['correlation_rate']:.1%}")


def main():
    """Run all examples"""
    print("🚀 Argus DAST Phase 1 MVP Examples")
    print("=" * 80)
    print()
    print("These examples demonstrate the multi-agent DAST system:")
    print("  1. Simple scan")
    print("  2. API scan with OpenAPI")
    print("  3. Authenticated scan")
    print("  4. Fast scan (Nuclei only)")
    print("  5. Comprehensive scan")
    print("  6. SAST-DAST correlation")
    print()
    print("Note: Examples use placeholder URLs. Replace with actual targets.")
    print("=" * 80)
    
    # For demo purposes, just show the configurations
    # Uncomment to run actual scans
    
    # example_simple_scan()
    # example_api_scan()
    # example_authenticated_scan()
    # example_fast_scan()
    # example_comprehensive_scan()
    # example_sast_dast_correlation()
    
    print("\n✅ Examples ready to run!")
    print("   Uncomment function calls in main() to execute scans")


if __name__ == "__main__":
    main()
