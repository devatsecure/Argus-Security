"""CLI entry point for hybrid analyzer.

This module provides the command-line interface for the Hybrid Security Analyzer,
which combines multiple security scanning tools (Semgrep, Trivy, Checkov) with
AI enrichment capabilities.
"""

import argparse
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
    # Scanner toggles — BooleanOptionalAction creates --enable-X / --no-enable-X
    # default=None means "not specified on CLI" — env var / config default fills in
    parser.add_argument(
        "--enable-semgrep", action=argparse.BooleanOptionalAction, default=None, help="Enable Semgrep SAST"
    )
    parser.add_argument(
        "--enable-trivy", action=argparse.BooleanOptionalAction, default=None, help="Enable Trivy CVE scanning"
    )
    parser.add_argument(
        "--enable-checkov", action=argparse.BooleanOptionalAction, default=None, help="Enable Checkov IaC scanning"
    )
    parser.add_argument(
        "--enable-trufflehog",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable TruffleHog secret scanning",
    )
    parser.add_argument(
        "--enable-api-security",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable API Security scanning",
    )
    parser.add_argument(
        "--enable-dast", action=argparse.BooleanOptionalAction, default=None, help="Enable DAST scanning"
    )
    parser.add_argument(
        "--enable-supply-chain",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Supply Chain Attack Detection",
    )
    parser.add_argument(
        "--enable-fuzzing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Intelligent Fuzzing Engine",
    )
    parser.add_argument(
        "--enable-threat-intel",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Threat Intelligence Enrichment",
    )
    parser.add_argument(
        "--enable-remediation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Automated Remediation Engine",
    )
    parser.add_argument(
        "--enable-runtime-security",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Container Runtime Security Monitoring",
    )
    parser.add_argument(
        "--enable-regression-testing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable Security Regression Testing",
    )
    parser.add_argument(
        "--enable-ai-enrichment",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable AI enrichment with Claude/OpenAI",
    )
    parser.add_argument(
        "--enable-iris",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable IRIS semantic analysis (research-proven 2x improvement, arXiv 2405.17238)",
    )
    parser.add_argument("--ai-provider", help="AI provider (anthropic, openai, ollama, claude-cli)")
    parser.add_argument("--dast-target-url", help="Target URL for DAST scanning (required if --enable-dast)")
    parser.add_argument("--fuzzing-duration", type=int, default=300, help="Fuzzing duration in seconds (default: 300)")
    parser.add_argument(
        "--runtime-monitoring-duration",
        type=int,
        default=60,
        help="Runtime monitoring duration in seconds (default: 60)",
    )
    parser.add_argument("--severity-filter", help="Comma-separated severity levels to report (e.g., critical,high)")
    parser.add_argument(
        "--enable-multi-agent",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable multi-agent persona review (SecretHunter, ExploitAssessor, etc.)",
    )
    parser.add_argument(
        "--enable-spontaneous-discovery",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable spontaneous discovery (find issues beyond scanner rules)",
    )
    parser.add_argument(
        "--enable-collaborative-reasoning",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable collaborative reasoning (multi-agent discussion)",
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

    # Resolve feature flags: CLI arg > env var > config_loader default
    from config_loader import get_default_config

    _defaults = get_default_config()

    def _resolve_flag(cli_val, env_key, config_key):
        """CLI arg (if not None) > env var (if set) > config_loader default."""
        if cli_val is not None:
            return cli_val
        return get_bool_env(env_key, _defaults.get(config_key, False))

    enable_semgrep = _resolve_flag(args.enable_semgrep, "ENABLE_SEMGREP", "enable_semgrep")
    enable_trivy = _resolve_flag(args.enable_trivy, "ENABLE_TRIVY", "enable_trivy")
    enable_checkov = _resolve_flag(args.enable_checkov, "ENABLE_CHECKOV", "enable_checkov")
    enable_trufflehog = _resolve_flag(args.enable_trufflehog, "ENABLE_TRUFFLEHOG", "enable_trufflehog")
    enable_api_security = _resolve_flag(args.enable_api_security, "ENABLE_API_SECURITY", "enable_api_security")
    enable_dast = _resolve_flag(args.enable_dast, "ENABLE_DAST", "enable_dast")
    enable_supply_chain = _resolve_flag(args.enable_supply_chain, "ENABLE_SUPPLY_CHAIN", "enable_supply_chain")
    enable_fuzzing = _resolve_flag(args.enable_fuzzing, "ENABLE_FUZZING", "enable_fuzzing")
    enable_threat_intel = _resolve_flag(args.enable_threat_intel, "ENABLE_THREAT_INTEL", "enable_threat_intel")
    enable_remediation = _resolve_flag(args.enable_remediation, "ENABLE_REMEDIATION", "enable_remediation")
    enable_runtime_security = _resolve_flag(
        args.enable_runtime_security, "ENABLE_RUNTIME_SECURITY", "enable_runtime_security"
    )
    enable_regression_testing = _resolve_flag(
        args.enable_regression_testing, "ENABLE_REGRESSION_TESTING", "enable_regression_testing"
    )
    enable_ai_enrichment = _resolve_flag(args.enable_ai_enrichment, "ENABLE_AI_ENRICHMENT", "enable_ai_enrichment")
    enable_iris = _resolve_flag(args.enable_iris, "ENABLE_IRIS", "enable_iris")
    enable_multi_agent = _resolve_flag(args.enable_multi_agent, "ENABLE_MULTI_AGENT", "enable_multi_agent")
    enable_spontaneous_discovery = _resolve_flag(
        args.enable_spontaneous_discovery, "ENABLE_SPONTANEOUS_DISCOVERY", "enable_spontaneous_discovery"
    )
    enable_collaborative_reasoning = _resolve_flag(
        args.enable_collaborative_reasoning, "ENABLE_COLLABORATIVE_REASONING", "enable_collaborative_reasoning"
    )

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
        enable_semgrep=enable_semgrep,
        enable_trufflehog=enable_trufflehog,
        enable_trivy=enable_trivy,
        enable_checkov=enable_checkov,
        enable_api_security=enable_api_security,
        enable_dast=enable_dast,
        enable_supply_chain=enable_supply_chain,
        enable_fuzzing=enable_fuzzing,
        enable_threat_intel=enable_threat_intel,
        enable_remediation=enable_remediation,
        enable_runtime_security=enable_runtime_security,
        enable_regression_testing=enable_regression_testing,
        enable_ai_enrichment=enable_ai_enrichment,
        enable_multi_agent=enable_multi_agent,
        enable_spontaneous_discovery=enable_spontaneous_discovery,
        enable_collaborative_reasoning=enable_collaborative_reasoning,
        enable_iris=enable_iris,
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
