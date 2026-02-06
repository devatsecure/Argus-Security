"""CLI entry point for hybrid analyzer.

This module provides the command-line interface for the Hybrid Security Analyzer,
which combines multiple security scanning tools (Semgrep, Trivy, Checkov) with
AI enrichment capabilities.
"""

import argparse
import logging
import os
import sys

from hybrid_analyzer import HybridSecurityAnalyzer


def get_bool_env(key: str, default: bool) -> bool:
    """Get boolean from environment variable.

    Args:
        key: Environment variable name
        default: Default value if not set

    Returns:
        Boolean value from environment or default
    """
    val = os.getenv(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes")


def get_int_env(key: str, default: int) -> int:
    """Get integer from environment variable.

    Args:
        key: Environment variable name
        default: Default value if not set

    Returns:
        Integer value from environment or default
    """
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def main():
    """CLI entry point for hybrid analyzer"""
    parser = argparse.ArgumentParser(
        description="Hybrid Security Analyzer - Combines Semgrep, Trivy, Checkov, and AI enrichment (Claude/OpenAI)"
    )
    parser.add_argument("target", help="Target path to analyze (repository or directory)")
    parser.add_argument(
        "--output-dir",
        default=".argus/hybrid-results",
        help="Output directory for results (default: .argus/hybrid-results)",
    )
    parser.add_argument("--enable-semgrep", action="store_true", default=True, help="Enable Semgrep SAST")
    parser.add_argument("--enable-trivy", action="store_true", default=True, help="Enable Trivy CVE scanning")
    parser.add_argument("--enable-checkov", action="store_true", default=True, help="Enable Checkov IaC scanning")
    parser.add_argument("--enable-api-security", action="store_true", default=True, help="Enable API Security scanning")
    parser.add_argument("--enable-dast", action="store_true", default=False, help="Enable DAST scanning")
    parser.add_argument("--enable-supply-chain", action="store_true", default=True, help="Enable Supply Chain Attack Detection")
    parser.add_argument("--enable-fuzzing", action="store_true", default=False, help="Enable Intelligent Fuzzing Engine")
    parser.add_argument("--enable-threat-intel", action="store_true", default=True, help="Enable Threat Intelligence Enrichment")
    parser.add_argument("--enable-remediation", action="store_true", default=True, help="Enable Automated Remediation Engine")
    parser.add_argument("--enable-runtime-security", action="store_true", default=False, help="Enable Container Runtime Security Monitoring")
    parser.add_argument("--enable-regression-testing", action="store_true", default=True, help="Enable Security Regression Testing")
    parser.add_argument(
        "--enable-ai-enrichment",
        action="store_true",
        default=False,
        help="Enable AI enrichment with Claude/OpenAI",
    )
    parser.add_argument(
        "--enable-iris",
        action="store_true",
        default=True,
        help="Enable IRIS semantic analysis (research-proven 2x improvement, arXiv 2405.17238)",
    )
    parser.add_argument("--ai-provider", help="AI provider (anthropic, openai, ollama)")
    parser.add_argument("--dast-target-url", help="Target URL for DAST scanning (required if --enable-dast)")
    parser.add_argument("--fuzzing-duration", type=int, default=300, help="Fuzzing duration in seconds (default: 300)")
    parser.add_argument("--runtime-monitoring-duration", type=int, default=60, help="Runtime monitoring duration in seconds (default: 60)")
    parser.add_argument("--severity-filter", help="Comma-separated severity levels to report (e.g., critical,high)")
    parser.add_argument(
        "--enable-multi-agent",
        action="store_true",
        default=True,
        help="Enable multi-agent persona review (SecretHunter, ExploitAssessor, etc.)",
    )
    parser.add_argument(
        "--enable-spontaneous-discovery",
        action="store_true",
        default=True,
        help="Enable spontaneous discovery (find issues beyond scanner rules)",
    )
    parser.add_argument(
        "--enable-collaborative-reasoning",
        action="store_true",
        default=False,
        help="Enable collaborative reasoning (multi-agent discussion, adds cost)",
    )
    parser.add_argument(
        "--enable-disclosure-report",
        action="store_true",
        default=False,
        help="Generate responsible disclosure reports (private + public-safe)",
    )
    parser.add_argument(
        "--disclosure-repo",
        help="Target repository for disclosure (e.g., owner/repo or GitHub URL)",
    )
    parser.add_argument(
        "--disclosure-reporter",
        default="Security Researcher",
        help="Reporter name/organization for disclosure attribution",
    )
    parser.add_argument(
        "--disclosure-create-discussion",
        action="store_true",
        default=False,
        help="Create GitHub Discussion to request security contact",
    )

    args = parser.parse_args()

    # Build config from environment
    config = {
        "ai_provider": args.ai_provider or os.getenv("INPUT_AI_PROVIDER", "auto"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "ollama_endpoint": os.getenv("OLLAMA_ENDPOINT"),
    }

    # Read feature flags from environment variables (GitHub Action inputs)
    # These override defaults but are overridden by explicit CLI args
    enable_api_security = get_bool_env("ENABLE_API_SECURITY", args.enable_api_security)
    enable_dast = get_bool_env("ENABLE_DAST", args.enable_dast)
    enable_supply_chain = get_bool_env("ENABLE_SUPPLY_CHAIN", args.enable_supply_chain)
    enable_fuzzing = get_bool_env("ENABLE_FUZZING", args.enable_fuzzing)
    enable_threat_intel = get_bool_env("ENABLE_THREAT_INTEL", args.enable_threat_intel)
    enable_remediation = get_bool_env("ENABLE_REMEDIATION", args.enable_remediation)
    enable_runtime_security = get_bool_env("ENABLE_RUNTIME_SECURITY", args.enable_runtime_security)
    enable_regression_testing = get_bool_env("ENABLE_REGRESSION_TESTING", args.enable_regression_testing)
    enable_multi_agent = get_bool_env("ENABLE_MULTI_AGENT", args.enable_multi_agent)
    enable_spontaneous_discovery = get_bool_env("ENABLE_SPONTANEOUS_DISCOVERY", args.enable_spontaneous_discovery)
    enable_collaborative_reasoning = get_bool_env("ENABLE_COLLABORATIVE_REASONING", args.enable_collaborative_reasoning)

    # Disclosure options (set via environment for pipeline use)
    if args.enable_disclosure_report:
        os.environ["ENABLE_DISCLOSURE_REPORT"] = "true"
    if args.disclosure_repo:
        os.environ["DISCLOSURE_REPO_URL"] = args.disclosure_repo
    if args.disclosure_reporter:
        os.environ["DISCLOSURE_REPORTER"] = args.disclosure_reporter
    if args.disclosure_create_discussion:
        os.environ["DISCLOSURE_CREATE_DISCUSSION"] = "true"

    dast_target_url = args.dast_target_url or os.getenv("DAST_TARGET_URL")
    fuzzing_duration = get_int_env("FUZZING_DURATION", args.fuzzing_duration)
    runtime_monitoring_duration = get_int_env("RUNTIME_MONITORING_DURATION", args.runtime_monitoring_duration)

    # Initialize analyzer
    analyzer = HybridSecurityAnalyzer(
        enable_semgrep=args.enable_semgrep,
        enable_trivy=args.enable_trivy,
        enable_checkov=args.enable_checkov,
        enable_api_security=enable_api_security,
        enable_dast=enable_dast,
        enable_supply_chain=enable_supply_chain,
        enable_fuzzing=enable_fuzzing,
        enable_threat_intel=enable_threat_intel,
        enable_remediation=enable_remediation,
        enable_runtime_security=enable_runtime_security,
        enable_regression_testing=enable_regression_testing,
        enable_ai_enrichment=args.enable_ai_enrichment,
        enable_multi_agent=enable_multi_agent,
        enable_spontaneous_discovery=enable_spontaneous_discovery,
        enable_collaborative_reasoning=enable_collaborative_reasoning,
        enable_iris=args.enable_iris,  # IRIS semantic analysis
        ai_provider=args.ai_provider,
        dast_target_url=dast_target_url,
        fuzzing_duration=fuzzing_duration,
        runtime_monitoring_duration=runtime_monitoring_duration,
        config=config,
    )

    # Parse severity filter
    severity_filter = None
    if args.severity_filter:
        severity_filter = [s.strip() for s in args.severity_filter.split(",")]

    # Run analysis
    result = analyzer.analyze(target_path=args.target, output_dir=args.output_dir, severity_filter=severity_filter)

    # Exit with error code if critical/high found
    if result.findings_by_severity["critical"] > 0 or result.findings_by_severity["high"] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
