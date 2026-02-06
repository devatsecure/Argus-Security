"""
Configuration management and CLI argument parsing for Argus Security.

This module provides configuration loading from environment variables,
validation, CLI argument parsing, and cost estimation utilities.
"""

import argparse
import logging
import os

logger = logging.getLogger(__name__)

# Cost estimates for different review modes
COST_ESTIMATES = {
    "single_agent": 0.20,
    "multi_agent_sequential": 1.00,
    "per_agent": {
        "security-reviewer": 0.10,
        "exploit-analyst": 0.05,
        "security-test-generator": 0.05,
        "performance-reviewer": 0.08,
        "test-coverage-reviewer": 0.08,
        "code-quality-reviewer": 0.08,
        "review-orchestrator": 0.06,
    },
}


def load_config_from_env():
    """Load configuration from environment variables"""
    return {
        "ai_provider": os.environ.get("AI_PROVIDER", os.environ.get("INPUT_AI_PROVIDER", "auto")),
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "openai_api_key": os.environ.get("OPENAI_API_KEY", ""),
        "ollama_endpoint": os.environ.get("OLLAMA_ENDPOINT", ""),
        "foundation_sec_enabled": os.environ.get("FOUNDATION_SEC_ENABLED", "false").lower() == "true",
        "foundation_sec_model": os.environ.get("FOUNDATION_SEC_MODEL", "cisco-ai/foundation-sec-8b-instruct"),
        "foundation_sec_device": os.environ.get("FOUNDATION_SEC_DEVICE", ""),
        "model": os.environ.get("MODEL", os.environ.get("INPUT_MODEL", "auto")),
        "multi_agent_mode": os.environ.get("MULTI_AGENT_MODE", os.environ.get("INPUT_MULTI_AGENT_MODE", "single")),
        "only_changed": os.environ.get("ONLY_CHANGED", os.environ.get("INPUT_ONLY_CHANGED", "false")).lower() == "true",
        "include_paths": os.environ.get("INCLUDE_PATHS", os.environ.get("INPUT_INCLUDE_PATHS", "")),
        "exclude_paths": os.environ.get("EXCLUDE_PATHS", os.environ.get("INPUT_EXCLUDE_PATHS", "")),
        "max_file_size": os.environ.get("MAX_FILE_SIZE", os.environ.get("INPUT_MAX_FILE_SIZE", "50000")),
        "max_files": os.environ.get("MAX_FILES", os.environ.get("INPUT_MAX_FILES", "100")),
        "max_tokens": os.environ.get("MAX_TOKENS", os.environ.get("INPUT_MAX_TOKENS", "8000")),
        "cost_limit": os.environ.get("COST_LIMIT", os.environ.get("INPUT_COST_LIMIT", "1.0")),
        "fail_on": os.environ.get("FAIL_ON", os.environ.get("INPUT_FAIL_ON", "")),
        "enable_threat_modeling": os.environ.get("ENABLE_THREAT_MODELING", "true").lower() == "true",
        "enable_sandbox_validation": os.environ.get("ENABLE_SANDBOX_VALIDATION", "true").lower() == "true",
        "enable_heuristics": os.environ.get("ENABLE_HEURISTICS", "true").lower() == "true",
        "enable_consensus": os.environ.get("ENABLE_CONSENSUS", "true").lower() == "true",
        "consensus_threshold": float(os.environ.get("CONSENSUS_THRESHOLD", "0.5")),
        "category_passes": os.environ.get("CATEGORY_PASSES", "true").lower() == "true",
        "enable_semgrep": os.environ.get("SEMGREP_ENABLED", "true").lower() == "true",
    }


def validate_config(config):
    """Validate configuration"""
    provider = config.get("ai_provider", "auto")

    if provider == "anthropic":
        if not config.get("anthropic_api_key"):
            raise ValueError("Anthropic API key is required")
    elif provider == "openai":
        if not config.get("openai_api_key"):
            raise ValueError("OpenAI API key is required")
    elif provider not in ["auto", "ollama", "foundation-sec"]:
        raise ValueError(f"Invalid AI provider: {provider}")

    return True


def estimate_cost(files, max_tokens, provider):
    """Estimate cost before running analysis"""
    total_chars = sum(len(f["content"]) for f in files)
    # Rough estimate: 4 chars per token
    estimated_input_tokens = total_chars // 4
    estimated_output_tokens = max_tokens

    if provider == "anthropic":
        input_cost = (estimated_input_tokens / 1_000_000) * 3.0
        output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    elif provider == "openai":
        input_cost = (estimated_input_tokens / 1_000_000) * 10.0
        output_cost = (estimated_output_tokens / 1_000_000) * 30.0
    else:  # ollama or other local models
        input_cost = 0.0
        output_cost = 0.0

    total_cost = input_cost + output_cost

    return total_cost, estimated_input_tokens, estimated_output_tokens


def estimate_review_cost(mode="single", num_files=50):
    """Estimate cost of review based on mode and file count

    Args:
        mode: 'single' or 'multi'
        num_files: Number of files to review

    Returns:
        Estimated cost in USD
    """
    base_cost = COST_ESTIMATES["single_agent"] if mode == "single" else COST_ESTIMATES["multi_agent_sequential"]

    # Adjust for file count
    file_factor = num_files / 50.0  # 50 files is baseline
    estimated_cost = base_cost * file_factor

    return round(estimated_cost, 2)


def estimate_tokens(text):
    """Estimate number of tokens in text"""
    # Rough estimation: ~4 characters per token
    return len(text) // 4


def read_file_safe(file_path, max_size=1_000_000):
    """Safely read a file with size limits"""
    try:
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            raise ValueError(f"File too large: {file_size} bytes (max: {max_size})")

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        raise OSError(f"Error reading file {file_path}: {e}") from e


def classify_finding_category(finding):
    """Classify finding into a category"""
    # Handle both dict and string inputs
    if isinstance(finding, str):
        text = finding.lower()
        title = text
        description = text
    else:
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()

    # Security categories
    if any(term in title or term in description for term in ["injection", "xss", "csrf", "auth", "secret", "crypto"]):
        return "security"
    elif any(term in title or term in description for term in ["performance", "memory", "cpu", "slow"]):
        return "performance"
    elif any(term in title or term in description for term in ["bug", "error", "exception", "crash"]):
        return "reliability"
    elif any(term in title or term in description for term in ["style", "format", "naming", "convention"]):
        return "style"
    else:
        return "general"


def should_review_file(filename):
    """Check if file should be reviewed based on extension"""
    code_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".rb",
        ".php",
        ".swift",
        ".kt",
        ".scala",
        ".sh",
        ".bash",
        ".yml",
        ".yaml",
        ".json",
        ".tf",
        ".hcl",
        ".sql",
        ".r",
        ".m",
        ".mm",
        ".pl",
        ".pm",
        ".lua",
        ".vim",
        ".el",
        ".clj",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".hs",
        ".ml",
        ".fs",
        ".fsx",
        ".fsi",
        ".vb",
        ".pas",
        ".pp",
        ".asm",
        ".s",
        ".dart",
        ".nim",
        ".cr",
        ".v",
        ".sv",
        ".vhd",
        ".vhdl",
        ".tcl",
        ".groovy",
        ".gradle",
        ".cmake",
        ".mk",
        ".dockerfile",
        ".vue",
        ".svelte",
        ".astro",
    }
    return any(filename.lower().endswith(ext) for ext in code_extensions)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="AI-powered code audit")
    parser.add_argument("repo_path", nargs="?", default=".", help="Path to repository")
    parser.add_argument("review_type", nargs="?", default="audit", help="Type of review")
    parser.add_argument("--provider", help="AI provider")
    parser.add_argument("--model", help="Model name")
    parser.add_argument("--max-files", type=int, help="Maximum files to review")
    parser.add_argument("--cost-limit", type=float, help="Cost limit in USD")

    # Deep Analysis Engine (Phase 2.7) feature flags
    parser.add_argument(
        "--enable-deep-analysis",
        action="store_true",
        help="Enable Deep Analysis Engine (Phase 2.7) with conservative mode. Shorthand for --deep-analysis-mode=conservative"
    )
    parser.add_argument(
        "--deep-analysis-mode",
        choices=["off", "semantic-only", "conservative", "full"],
        default=None,  # None means use env var or default to "off"
        help="Deep analysis mode: off (skip Phase 2.7), semantic-only (code twin only), "
             "conservative (semantic + proactive), full (all modules). Default: off"
    )
    parser.add_argument(
        "--max-files-deep-analysis",
        type=int,
        default=None,
        help="Maximum files for deep analysis (default: 50, respects DEEP_ANALYSIS_MAX_FILES env)"
    )
    parser.add_argument(
        "--deep-analysis-timeout",
        type=int,
        default=None,
        help="Timeout for deep analysis in seconds (default: 300 = 5 min, respects DEEP_ANALYSIS_TIMEOUT env)"
    )
    parser.add_argument(
        "--deep-analysis-cost-ceiling",
        type=float,
        default=None,
        help="Cost ceiling for deep analysis in USD (default: 5.0, respects DEEP_ANALYSIS_COST_CEILING env)"
    )
    parser.add_argument(
        "--deep-analysis-dry-run",
        action="store_true",
        help="Estimate deep analysis cost/time without running LLM calls"
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Enable detailed benchmark reporting for Deep Analysis Engine (Phase 2.7)"
    )

    return parser.parse_args()


def build_config(args=None):
    """Build configuration from arguments and environment"""
    config = load_config_from_env()

    if args:
        if hasattr(args, "provider") and args.provider:
            config["ai_provider"] = args.provider
        if hasattr(args, "model") and args.model:
            config["model"] = args.model
        if hasattr(args, "max_files") and args.max_files:
            config["max_files"] = str(args.max_files)
        if hasattr(args, "cost_limit") and args.cost_limit:
            config["cost_limit"] = str(args.cost_limit)

        # Deep Analysis Engine configuration
        # Handle --enable-deep-analysis shorthand
        if hasattr(args, "enable_deep_analysis") and args.enable_deep_analysis:
            config["deep_analysis_mode"] = "conservative"
        if hasattr(args, "deep_analysis_mode") and args.deep_analysis_mode:
            config["deep_analysis_mode"] = args.deep_analysis_mode
        if hasattr(args, "max_files_deep_analysis") and args.max_files_deep_analysis:
            config["deep_analysis_max_files"] = str(args.max_files_deep_analysis)
        if hasattr(args, "deep_analysis_timeout") and args.deep_analysis_timeout:
            config["deep_analysis_timeout"] = str(args.deep_analysis_timeout)
        if hasattr(args, "deep_analysis_cost_ceiling") and args.deep_analysis_cost_ceiling:
            config["deep_analysis_cost_ceiling"] = str(args.deep_analysis_cost_ceiling)
        if hasattr(args, "deep_analysis_dry_run") and args.deep_analysis_dry_run:
            config["deep_analysis_dry_run"] = "true"
        if hasattr(args, "benchmark") and args.benchmark:
            config["benchmark"] = "true"

    return config


__all__ = [
    "COST_ESTIMATES",
    "load_config_from_env",
    "validate_config",
    "estimate_cost",
    "estimate_review_cost",
    "estimate_tokens",
    "read_file_safe",
    "classify_finding_category",
    "should_review_file",
    "parse_args",
    "build_config",
]
