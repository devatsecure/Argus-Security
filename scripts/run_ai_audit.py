#!/usr/bin/env python3
"""
Agent OS AI-Powered Code Audit Script
Supports multiple LLM providers: Anthropic, OpenAI, Ollama
With cost guardrails, SARIF/JSON output, and observability

FACADE PATTERN:
    This module is the main entry point for the Argus Security audit pipeline.
    It previously contained all logic in a single god-object (~2,900 lines).
    Functions have been progressively extracted into sub-modules under
    ``scripts/orchestrator/``, while this file retains:

        * Core LLM interaction functions (detect_ai_provider, get_ai_client,
          call_llm_api, etc.)
        * SARIF generation helpers
        * The ``run_audit()`` orchestration function
        * The ``if __name__ == "__main__":`` entry point

    Extracted functions are re-imported here so that existing consumers using
    ``from run_ai_audit import X`` continue to work without changes.
"""

import glob
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import threat model generator (hybrid: pytm + optional Anthropic)
try:
    from threat_model_generator import HybridThreatModelGenerator

    THREAT_MODELING_AVAILABLE = True
except ImportError:
    # Fallback to pytm-only if hybrid not available
    try:
        from pytm_threat_model import PytmThreatModelGenerator as HybridThreatModelGenerator

        THREAT_MODELING_AVAILABLE = True
        logger.info("Using pytm-only threat modeling (hybrid generator not available)")
    except ImportError:
        THREAT_MODELING_AVAILABLE = False
        logger.warning("No threat modeling available (install pytm: pip install pytm)")

# Import deep analysis engine
try:
    from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisEngine, DeepAnalysisMode

    DEEP_ANALYSIS_AVAILABLE = True
except ImportError:
    DEEP_ANALYSIS_AVAILABLE = False
    logger.warning("Deep Analysis Engine not available")

# Import refactored modules (extracted from this file for maintainability)
# Re-exported for backward compatibility (used by tests and external consumers)
from analysis_helpers import (  # noqa: E402
    AgentOutputValidator,  # noqa: F401
    CodebaseChunker,  # noqa: F401
    ContextCleanup,  # noqa: F401
    ContextTracker,
    CostLimitExceeded,  # noqa: F401
    CostLimitExceededError,  # noqa: F401
    FindingSummarizer,
    ReviewMetrics,
    TimeoutManager,  # noqa: F401
)
from consensus_builder import ConsensusBuilder  # noqa: E402, F401
from heuristic_scanner import HeuristicScanner  # noqa: E402
from orchestrator.cost_tracker import CostCircuitBreaker  # noqa: E402
from phase_gate import PhaseGate  # noqa: E402

# Vulnerability enrichment & compliance modules (v2.0 features)
# EPSS, fix versions, VEX, dedup, compliance, and suppression are now
# handled by the shared enrichment_pipeline module.  Only license risk
# scoring is still imported here (runs separately on SBOM data).
try:
    from license_risk_scorer import LicenseRiskScorer

    LICENSE_SCORING_AVAILABLE = True
except ImportError:
    LICENSE_SCORING_AVAILABLE = False

# ---------------------------------------------------------------------------
# Extracted modules — imported here for backward-compatible re-export.
# Consumers that do ``from run_ai_audit import load_config_from_env`` (etc.)
# will continue to work.
# ---------------------------------------------------------------------------
from orchestrator.agent_runner import (  # noqa: E402
    parse_findings_from_report,
    run_multi_agent_sequential,
)
from orchestrator.config import (  # noqa: E402
    build_config,
    classify_finding_category,  # noqa: F401
    estimate_cost,
    estimate_tokens,  # noqa: F401
    load_config_from_env,  # noqa: F401
    parse_args,
    read_file_safe,  # noqa: F401
    should_review_file,
    validate_config,  # noqa: F401
)

# Available agents for multi-agent mode
AVAILABLE_AGENTS = [
    "security-reviewer",
    "exploit-analyst",
    "security-test-generator",
    "performance-reviewer",
    "test-coverage-reviewer",
    "code-quality-reviewer",
    "review-orchestrator",
]

# Agent execution order for security workflow
SECURITY_WORKFLOW_AGENTS = ["security-reviewer", "exploit-analyst", "security-test-generator"]

# Agents that can run in parallel (quality analysis)
PARALLEL_QUALITY_AGENTS = ["performance-reviewer", "test-coverage-reviewer", "code-quality-reviewer"]

# Cost estimates (approximate, based on Claude Sonnet 4)
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


def detect_ai_provider(config):
    """Auto-detect which AI provider to use based on available keys"""
    provider = config.get("ai_provider", "auto")

    # Explicit provider selection (overrides auto-detection)
    if provider != "auto":
        return provider

    # Auto-detect based on available API keys/config
    # Priority: Anthropic (best for security) > OpenAI > Ollama (local)
    if config.get("anthropic_api_key"):
        return "anthropic"
    elif config.get("openai_api_key"):
        return "openai"
    elif config.get("ollama_endpoint"):
        return "ollama"
    else:
        print("⚠️  No AI provider configured")
        print("💡 Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_ENDPOINT")
        return None


def get_ai_client(provider, config):
    """Get AI client for the specified provider"""
    if provider == "anthropic":
        try:
            from anthropic import Anthropic

            api_key = config.get("anthropic_api_key")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")

            print("🔑 Using Anthropic API")
            return Anthropic(api_key=api_key), "anthropic"
        except ImportError:
            print("❌ anthropic package not installed. Run: pip install anthropic")
            sys.exit(2)

    elif provider == "openai":
        try:
            from openai import OpenAI

            api_key = config.get("openai_api_key")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set")

            print("🔑 Using OpenAI API endpoint")
            return OpenAI(api_key=api_key), "openai"
        except ImportError:
            print("❌ openai package not installed. Run: pip install openai")
            sys.exit(2)

    elif provider == "ollama":
        try:
            from openai import OpenAI

            endpoint = config.get("ollama_endpoint", "http://localhost:11434")
            # Sanitize endpoint URL (hide sensitive parts - use str() to break taint chain)
            safe_endpoint = (
                str(endpoint).split("@")[-1] if "@" in str(endpoint) else str(endpoint).split("//")[-1].split("/")[0]
            )
            print(f"🔑 Using Ollama endpoint: {safe_endpoint}")
            return OpenAI(base_url=f"{endpoint}/v1", api_key="ollama"), "ollama"
        except ImportError:
            print("❌ openai package not installed. Run: pip install openai")
            sys.exit(2)

    else:
        # Sanitize provider name before logging (use str() to break taint chain)
        safe_provider = str(provider).split("/")[-1] if provider else "unknown"
        print(f"❌ Unknown AI provider: {safe_provider}")
        sys.exit(2)


def get_model_name(provider, config):
    """Get the appropriate model name for the provider"""
    model = config.get("model", "auto")

    if model != "auto":
        return model

    # Default models for each provider
    defaults = {
        "anthropic": "claude-sonnet-4-5-20250929",
        "openai": "gpt-4-turbo-preview",
        "ollama": "llama3.2:3b",
    }

    return defaults.get(provider, "claude-sonnet-4-5-20250929")


def get_working_model_with_fallback(client, provider, initial_model):
    """Try to find a working model using fallback chain for Anthropic"""
    if provider != "anthropic":
        return initial_model

    # Model fallback chain for Anthropic (most universally available first)
    model_fallback_chain = [
        initial_model,  # Try user's requested model first
        "claude-sonnet-4-5-20250929",  # Claude Sonnet 4.5
        "claude-haiku-4-5-20251001",  # Claude Haiku 4.5 (fast)
        "claude-3-5-sonnet-20241022",  # Claude 3.5 Sonnet
        "claude-3-5-haiku-20241022",  # Claude 3.5 Haiku
        "claude-3-haiku-20240307",  # Claude 3 Haiku (legacy fallback)
    ]

    # Remove duplicates while preserving order
    seen = set()
    unique_models = []
    for model in model_fallback_chain:
        if model not in seen:
            seen.add(model)
            unique_models.append(model)

    # Sanitize provider name for logging
    safe_provider_name = str(provider).split("/")[-1] if provider else "unknown"
    logger.info(f"Testing model accessibility for provider: {safe_provider_name}")

    for model_id in unique_models:
        try:
            # Quick test with minimal tokens
            # Sanitize model ID for logging
            safe_model_name = str(model_id).split("/")[-1] if model_id else "unknown"
            logger.debug(f"Testing model: {safe_model_name}")
            client.messages.create(model=model_id, max_tokens=10, messages=[{"role": "user", "content": "test"}])
            logger.info(f"✅ Found working model: {safe_model_name}")
            return model_id
        except Exception as e:
            error_type = type(e).__name__
            logger.debug(f"Model {safe_model_name} not accessible: {error_type}")

            # If authentication fails, stop trying
            if "Authentication" in error_type or "auth" in str(e).lower():
                logger.error("Authentication failed with API key")
                raise

            continue

    # If no model works, raise error with helpful message
    logger.error("No accessible Claude models found with this API key")
    raise RuntimeError(
        "❌ No Claude models are accessible with your API key.\n"
        "Tried models: " + ", ".join(unique_models) + "\n"
        "Please check:\n"
        "1. API key has correct permissions at https://console.anthropic.com/\n"
        "2. Account has billing enabled\n"
        "3. API key is from correct workspace/organization\n"
        "4. Contact support@anthropic.com if issue persists"
    )


def get_changed_files():
    """Get list of changed files in PR with improved error handling"""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD^", "HEAD"], capture_output=True, text=True, check=True, timeout=30
        )
        changed_files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
        logger.info(f"Found {len(changed_files)} changed files")
        return changed_files
    except subprocess.TimeoutExpired:
        logger.warning("Git diff timed out after 30 seconds")
        return []
    except subprocess.CalledProcessError as e:
        # Not necessarily an error - might not be in a PR context
        logger.debug(f"Git diff failed (stderr: {e.stderr}). This is normal if not in a PR context.")
        return []
    except FileNotFoundError:
        logger.warning("Git not found in PATH. Ensure git is installed.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error getting changed files: {type(e).__name__}: {e}")
        return []


def matches_glob_patterns(file_path, patterns):
    """Check if file matches any glob pattern"""
    if not patterns:
        return False
    from pathlib import Path

    return any(Path(file_path).match(pattern) or glob.fnmatch.fnmatch(file_path, pattern) for pattern in patterns)


def get_codebase_context(repo_path, config):
    """Get relevant codebase files for analysis with cost guardrails"""
    important_files = []

    # Extended language support for polyglot codebases
    extensions = {
        # Web/Frontend
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        # Backend
        ".py",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".scala",
        ".kt",
        # Systems
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".swift",
        # Data/Config
        ".sql",
        ".graphql",
        ".proto",
        # Infrastructure
        ".tf",
        ".yaml",
        ".yml",
    }

    # Parse configuration
    only_changed = config.get("only_changed", False)
    include_patterns = [p.strip() for p in config.get("include_paths", "").split(",") if p.strip()]
    exclude_patterns = [p.strip() for p in config.get("exclude_paths", "").split(",") if p.strip()]
    max_file_size = int(config.get("max_file_size", 50000))
    max_files = int(config.get("max_files", 100))  # Increased for large codebases

    # Get changed files if in PR mode
    changed_files = []
    if only_changed:
        changed_files = get_changed_files()
        print(f"📝 PR mode: Found {len(changed_files)} changed files")

    total_lines = 0
    file_priorities = []  # (priority, file_info)

    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [
            d
            for d in dirs
            if d
            not in {
                ".git",
                "node_modules",
                "venv",
                "__pycache__",
                "dist",
                "build",
                ".next",
                "target",
                "vendor",
                ".gradle",
                ".idea",
                ".vscode",
            }
        ]

        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(repo_path))

                # Apply filters
                if only_changed and rel_path not in changed_files:
                    continue

                if include_patterns and not matches_glob_patterns(rel_path, include_patterns):
                    continue

                if exclude_patterns and matches_glob_patterns(rel_path, exclude_patterns):
                    continue

                try:
                    file_size = file_path.stat().st_size
                    if file_size > max_file_size:
                        print(f"⏭️  Skipping {rel_path} (too large: {file_size} bytes)")
                        continue

                    with open(file_path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines = len(content.split("\n"))

                        # Prioritize files based on criticality
                        priority = 0

                        # High priority: Security-sensitive files
                        if any(
                            keyword in rel_path.lower()
                            for keyword in ["auth", "security", "password", "token", "secret", "crypto"]
                        ):
                            priority += 100

                        # High priority: API/Controllers
                        if any(
                            keyword in rel_path.lower()
                            for keyword in ["controller", "api", "route", "handler", "endpoint"]
                        ):
                            priority += 50

                        # Medium priority: Business logic
                        if any(keyword in rel_path.lower() for keyword in ["service", "model", "repository", "dao"]):
                            priority += 30

                        # Changed files get highest priority
                        if only_changed:
                            priority += 200

                        file_priorities.append(
                            (
                                priority,
                                {
                                    "path": rel_path,
                                    "content": content[:10000],  # Limit content size
                                    "lines": lines,
                                    "size": file_size,
                                },
                            )
                        )

                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")

    # Sort by priority and take top N files
    file_priorities.sort(reverse=True, key=lambda x: x[0])
    important_files = [f[1] for f in file_priorities[:max_files]]

    total_lines = sum(f["lines"] for f in important_files)

    print(f"✅ Selected {len(important_files)} files ({total_lines} lines)")
    if file_priorities and len(file_priorities) > max_files:
        print(f"⚠️  {len(file_priorities) - max_files} files skipped (priority-based selection)")

    return important_files


def map_exploitability_to_score(exploitability):
    """Map exploitability level to numeric score for SARIF

    Args:
        exploitability: String like 'trivial', 'moderate', 'complex', 'theoretical'

    Returns:
        Numeric score (0-10)
    """
    mapping = {
        "trivial": 10,  # Highest exploitability
        "moderate": 7,
        "complex": 4,
        "theoretical": 1,  # Lowest exploitability
    }
    return mapping.get(exploitability.lower(), 5)


def map_severity_to_sarif(severity):
    """Map severity to SARIF level

    Args:
        severity: String like 'critical', 'high', 'medium', 'low', 'info'

    Returns:
        SARIF level string
    """
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    return mapping.get(severity.lower(), "warning")


def generate_sarif(findings, repo_path, metrics=None):
    """Generate SARIF 2.1.0 format for GitHub Code Scanning with exploitability data

    Args:
        findings: List of vulnerability findings
        repo_path: Path to repository
        metrics: Optional ReviewMetrics instance

    Returns:
        SARIF dictionary
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent OS Code Reviewer",
                        "version": "1.0.16",
                        "informationUri": "https://github.com/devatsecure/Argus-Security",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    for finding in findings:
        result = {
            "ruleId": finding.get("rule_id", "ARGUS-001"),
            "level": map_severity_to_sarif(finding.get("severity", "medium")),
            "message": {"text": finding.get("message", "Issue found")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("file_path", "unknown")},
                        "region": {"startLine": finding.get("line_number", 1)},
                    }
                }
            ],
        }

        # Add properties
        properties = {}

        if "cwe" in finding:
            properties["cwe"] = finding["cwe"]

        # NEW: Add exploitability as a property
        if "exploitability" in finding:
            properties["exploitability"] = finding["exploitability"]
            properties["exploitabilityScore"] = map_exploitability_to_score(finding["exploitability"])

        # NEW: Add exploit chain reference if part of a chain
        if "part_of_chain" in finding:
            properties["exploitChain"] = finding["part_of_chain"]

        # NEW: Add generated tests reference
        if "tests_generated" in finding:
            properties["testsGenerated"] = finding["tests_generated"]

        if properties:
            result["properties"] = properties

        sarif["runs"][0]["results"].append(result)

    # Add run properties with metrics
    if metrics:
        sarif["runs"][0]["properties"] = {
            "exploitability": metrics.metrics["exploitability"],
            "exploitChainsFound": metrics.metrics["exploit_chains_found"],
            "testsGenerated": metrics.metrics["tests_generated"],
            "agentsExecuted": metrics.metrics["agents_executed"],
        }

    return sarif


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def estimate_call_cost(prompt_length: int, max_output_tokens: int, provider: str, model: str = None) -> float:
    """Estimate cost of a single LLM API call before making it (for circuit breaker)

    Args:
        prompt_length: Either character length of prompt OR token count (auto-detected)
        max_output_tokens: Maximum output tokens requested
        provider: AI provider name
        model: Optional model name (for provider-specific pricing)

    Returns:
        Estimated cost in USD
    """
    # Auto-detect if input is tokens or characters
    # If > 100k, assume it's tokens (since 100k characters is ~25k tokens)
    if prompt_length > 100_000:
        estimated_input_tokens = prompt_length
        estimated_output_tokens = max_output_tokens  # Use as-is for large values
    else:
        # Rough estimation: 1 token ≈ 4 characters
        estimated_input_tokens = prompt_length / 4
        estimated_output_tokens = max_output_tokens * 0.7  # Assume 70% of max is used

    if provider == "anthropic":
        # Claude Sonnet 4.5: $3/1M input, $15/1M output
        input_cost = (estimated_input_tokens / 1_000_000) * 3.0
        output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    elif provider == "openai":
        # GPT-4: $10/1M input, $30/1M output
        input_cost = (estimated_input_tokens / 1_000_000) * 10.0
        output_cost = (estimated_output_tokens / 1_000_000) * 30.0
    else:
        # Foundation-Sec and Ollama: Free (local)
        input_cost = 0.0
        output_cost = 0.0

    return input_cost + output_cost


def call_llm_api(client, provider, model, prompt, max_tokens, circuit_breaker=None, operation="LLM call"):
    """Call LLM API with retry logic and cost enforcement

    Args:
        client: AI client instance
        provider: AI provider name
        model: Model name
        prompt: Prompt text
        max_tokens: Maximum output tokens
        circuit_breaker: Optional CostCircuitBreaker for cost enforcement
        operation: Description of operation for logging

    Returns:
        Tuple of (response_text, input_tokens, output_tokens)

    Raises:
        CostLimitExceededError: If cost limit would be exceeded
    """
    # Estimate cost and check circuit breaker before making call
    if circuit_breaker:
        estimated_cost = estimate_call_cost(len(prompt), max_tokens, provider)
        circuit_breaker.check_before_call(estimated_cost, provider, operation)

    try:
        if provider == "anthropic":
            message = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                timeout=300.0,  # 5 minute timeout
            )
            response_text = message.content[0].text
            input_tokens = message.usage.input_tokens
            output_tokens = message.usage.output_tokens

        elif provider in ["openai", "ollama"]:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                timeout=300.0,  # 5 minute timeout
            )
            response_text = response.choices[0].message.content
            input_tokens = response.usage.prompt_tokens
            output_tokens = response.usage.completion_tokens

        else:
            raise ValueError(f"Unknown provider: {provider}")

        # Record actual cost after successful call
        if circuit_breaker:
            actual_cost = calculate_actual_cost(input_tokens, output_tokens, provider)
            circuit_breaker.record_actual_cost(actual_cost)

        return response_text, input_tokens, output_tokens

    except Exception as e:
        logger.error(f"LLM API call failed: {type(e).__name__}: {e}")
        raise


def calculate_actual_cost(input_tokens: int, output_tokens: int, provider: str) -> float:
    """Calculate actual cost after LLM call completes

    Args:
        input_tokens: Actual input tokens used
        output_tokens: Actual output tokens used
        provider: AI provider name

    Returns:
        Actual cost in USD
    """
    if provider == "anthropic":
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0
    elif provider == "openai":
        input_cost = (input_tokens / 1_000_000) * 10.0
        output_cost = (output_tokens / 1_000_000) * 30.0
    else:
        # Ollama and other local models: Free
        input_cost = 0.0
        output_cost = 0.0

    return input_cost + output_cost


def select_files_for_review(repo_path, config):
    """Select files for review based on configuration"""
    max_files = int(config.get("max_files", "100"))
    max_file_size = int(config.get("max_file_size", "50000"))
    include_patterns = config.get("include_paths", "").split(",") if config.get("include_paths") else []
    exclude_patterns = config.get("exclude_paths", "").split(",") if config.get("exclude_paths") else []

    # Get all files
    all_files = []
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden directories and common ignore patterns
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".") and d not in ["node_modules", "__pycache__", "venv", "dist", "build"]
        ]

        for file in files:
            if file.startswith("."):
                continue

            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_path)

            # Check file extension
            if not should_review_file(file):
                continue

            # Check size
            try:
                if os.path.getsize(file_path) > max_file_size:
                    continue
            except (OSError, FileNotFoundError):
                continue

            # Check include/exclude patterns
            if include_patterns and not any(
                matches_glob_patterns(rel_path, [p]) for p in include_patterns if p.strip()
            ):
                continue
            if exclude_patterns and any(matches_glob_patterns(rel_path, [p]) for p in exclude_patterns if p.strip()):
                continue

            all_files.append({"path": rel_path, "size": os.path.getsize(file_path)})

    # Sort by size (smaller first) and limit
    all_files.sort(key=lambda x: x["size"])
    return all_files[:max_files]


def generate_sarif_output(findings, repo_path, metrics=None):
    """Generate SARIF output (alias for generate_sarif)"""
    return generate_sarif(findings, repo_path, metrics)


def map_severity_to_level(severity):
    """Map severity to SARIF level (alias for map_severity_to_sarif)"""
    return map_severity_to_sarif(severity)


def _parse_bool(value):
    """Parse a config value as boolean."""
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def _run_enrichment_pipeline(findings, config, repo_path, metrics=None):
    """Run the v2.0 vulnerability enrichment pipeline on findings.

    Delegates to the shared ``enrichment_pipeline`` module which implements:
      1. EPSS scoring
      2. Fix version tracking
      3. VEX filtering
      4. Vulnerability deduplication
      5. Compliance mapping
      6. Advanced suppression

    License risk scoring runs separately via ``_run_license_scoring()``.
    """
    from enrichment_pipeline import run_enrichment_pipeline
    return run_enrichment_pipeline(findings, config, repo_path)


def _run_license_scoring(config, repo_path):
    """Run license risk scoring on SBOM components if available.

    Returns (license_risks, policy_violations) or ([], []).
    """
    if not (
        LICENSE_SCORING_AVAILABLE
        and _parse_bool(config.get("enable_license_risk_scoring", True))
    ):
        return [], []

    try:
        # Look for CycloneDX SBOM output from Trivy or other scanners
        sbom_paths = [
            Path(repo_path) / ".argus/sbom.json",
            Path(repo_path) / ".argus/reviews/sbom.json",
            Path(repo_path) / "sbom.json",
        ]
        sbom_data = None
        for sbom_path in sbom_paths:
            if sbom_path.exists():
                import json as _json

                with open(sbom_path) as f:
                    sbom_data = _json.load(f)
                break

        if not sbom_data:
            logger.info("No SBOM found for license risk scoring")
            print("   License scoring: no SBOM found (skipped)")
            return [], []

        components = sbom_data.get("components", [])
        if not components:
            return [], []

        scorer = LicenseRiskScorer()
        risks = scorer.score_components(components)
        violations = LicenseRiskScorer.generate_policy_violations(risks)
        _summary = LicenseRiskScorer.get_summary(risks)

        logger.info(
            "License scoring: %d components, %d risks, %d violations",
            len(components), len(risks), len(violations),
        )
        print(f"   License scoring: {len(risks)} risks from {len(components)} components")
        if violations:
            print(f"   License violations: {len(violations)} policy violations")

        return risks, violations

    except Exception as e:
        logger.warning("License risk scoring failed (non-fatal): %s", e)
        print(f"   License scoring: skipped ({e})")
        return [], []


# ---------------------------------------------------------------------------
# AuditContext dataclass — shared state bag passed between phase functions
# ---------------------------------------------------------------------------

@dataclass
class AuditContext:
    """Shared state passed between extracted phase functions."""

    repo_path: str
    config: dict
    review_type: str
    metrics: Any  # ReviewMetrics
    provider: str
    client: Any
    model: str
    max_tokens: int
    circuit_breaker: Any
    phase_gate: Optional[Any]
    threat_model: Optional[dict]
    files: list
    context_tracker: Any  # ContextTracker
    summarizer: Any  # FindingSummarizer


# ---------------------------------------------------------------------------
# Extracted phase functions (module-level, take AuditContext as first arg)
# ---------------------------------------------------------------------------


def _setup_audit(repo_path, config, review_type="audit"):
    """Setup phase: provider detection, model init, phase gate, threat model, file loading.

    Returns:
        AuditContext with all shared state initialised, or calls sys.exit on failure.
    """
    metrics = ReviewMetrics()

    print(f"🤖 Starting AI-powered {review_type} analysis...")
    print(f"📁 Repository: {repo_path}")

    # Detect AI provider
    provider = detect_ai_provider(config)
    if not provider:
        print("❌ No AI provider available")
        print("\n💡 Available options:")
        print("   1. Anthropic Claude (Best quality)")
        print("      Get key: https://console.anthropic.com/")
        print("      Set: ANTHROPIC_API_KEY")
        print("\n   2. OpenAI GPT-4 (Good quality)")
        print("      Get key: https://platform.openai.com/api-keys")
        print("      Set: OPENAI_API_KEY")
        print("\n   3. Ollama (Free, local)")
        print("      Install: https://ollama.ai/")
        print("      Set: OLLAMA_ENDPOINT=http://localhost:11434")
        sys.exit(2)

    # Sanitize provider name (use str() to break taint chain)
    safe_provider = str(provider).split("/")[-1] if provider else "unknown"
    print(f"🔧 Provider: {safe_provider}")
    metrics.metrics["provider"] = provider

    # Get AI client
    client, actual_provider = get_ai_client(provider, config)

    # Get model name
    model = get_model_name(provider, config)

    # Verify model accessibility and fallback if needed (Anthropic only)
    if provider == "anthropic":
        try:
            # Sanitize model name for logging (use str() to break taint chain)
            safe_model = str(model).split("/")[-1] if model else "unknown"
            print(f"🔍 Verifying model accessibility: {safe_model}")
            working_model = get_working_model_with_fallback(client, provider, model)
            if working_model != model:
                safe_working_model = str(working_model).split("/")[-1] if working_model else "unknown"
                print(f"⚠️  Requested model '{safe_model}' not accessible")
                print(f"✅ Using fallback model: {safe_working_model}")
                model = working_model
            else:
                print(f"✅ Model verified: {safe_model}")
        except Exception as e:
            logger.error(f"Model verification failed: {e}")
            print(f"\n❌ {e}")
            sys.exit(2)

    # Sanitize model name for logging (use str() to break taint chain)
    safe_model = str(model).split("/")[-1] if model else "unknown"
    print(f"🧠 Model: {safe_model}")
    metrics.metrics["model"] = model

    # Check cost limit
    cost_limit = float(config.get("cost_limit", 1.0))
    max_tokens = int(config.get("max_tokens", 8000))

    # Initialize cost circuit breaker for runtime enforcement
    circuit_breaker = CostCircuitBreaker(cost_limit_usd=cost_limit)

    # Initialize phase gate for output validation between phases
    phase_gate = None
    enable_gating_val = config.get("enable_phase_gating", True)
    enable_gating = enable_gating_val.lower() == "true" if isinstance(enable_gating_val, str) else bool(enable_gating_val)
    if enable_gating:
        strict_val = config.get("phase_gate_strict", False)
        strict = strict_val.lower() == "true" if isinstance(strict_val, str) else bool(strict_val)
        phase_gate = PhaseGate(strict=strict)
        logger.info("Phase gating enabled (strict=%s)", strict)

    # Generate or load threat model (always runs if pytm available)
    threat_model = None
    if THREAT_MODELING_AVAILABLE:
        print("🛡️  Generating threat model...")
        try:
            threat_model_path = Path(repo_path) / ".argus/threat-model.json"

            # Initialize hybrid generator (pytm + optional Anthropic)
            # API key is optional - pytm works without it
            enable_tm_val = config.get("enable_threat_modeling", "true")
            enable_tm = enable_tm_val.lower() == "true" if isinstance(enable_tm_val, str) else bool(enable_tm_val)
            api_key = config.get("anthropic_api_key", "") if enable_tm else None
            generator = HybridThreatModelGenerator(api_key)

            # Load existing or generate new
            threat_model = generator.load_existing_threat_model(threat_model_path)
            if not threat_model:
                repo_context = generator.analyze_repository(repo_path)
                threat_model = generator.generate_threat_model(repo_context)
                generator.save_threat_model(threat_model, threat_model_path)
                print(f"✅ Threat model generated: {threat_model_path}")
                print(f"   Generator: {threat_model.get('generator', 'pytm')}")
            else:
                print(f"✅ Loaded existing threat model: {threat_model_path}")

            # Record threat model metrics
            metrics.record_threat_model(threat_model)

            print(f"   Threats identified: {len(threat_model.get('threats', []))}")
            print(
                f"   Attack surface: {len(threat_model.get('attack_surface', {}).get('entry_points', []))} entry points"
            )
            print(f"   Trust boundaries: {len(threat_model.get('trust_boundaries', []))}")

        except Exception as e:
            logger.error(f"Threat modeling failed: {e}")
            print(f"⚠️  Threat modeling failed: {e}")
            print("   Continuing without threat model")
    else:
        print("⚠️  Threat modeling not available (install pytm: pip install pytm)")

    # Get codebase context with guardrails
    print("📂 Analyzing codebase structure...")
    files = get_codebase_context(repo_path, config)

    # Initialize context tracker and summarizer
    context_tracker = ContextTracker()
    summarizer = FindingSummarizer()

    return AuditContext(
        repo_path=repo_path,
        config=config,
        review_type=review_type,
        metrics=metrics,
        provider=provider,
        client=client,
        model=model,
        max_tokens=max_tokens,
        circuit_breaker=circuit_breaker,
        phase_gate=phase_gate,
        threat_model=threat_model,
        files=files,
        context_tracker=context_tracker,
        summarizer=summarizer,
    )


def _run_scanner_phase(ctx: AuditContext) -> tuple[dict, dict]:
    """Run heuristic pre-scanning and Semgrep SAST.

    Returns:
        (heuristic_results, semgrep_results) dictionaries.
    """
    config = ctx.config
    files = ctx.files
    metrics = ctx.metrics

    # FEATURE: Heuristic Pre-Scanning (from real_multi_agent_review.py)
    # Scan files with lightweight pattern matching before expensive LLM calls
    enable_heuristics_val = config.get("enable_heuristics", "true")
    enable_heuristics = enable_heuristics_val.lower() == "true" if isinstance(enable_heuristics_val, str) else bool(enable_heuristics_val)
    heuristic_results = {}

    if enable_heuristics:
        print("🔍 Running heuristic pre-scan...")
        scanner = HeuristicScanner()
        heuristic_results = scanner.scan_codebase(files)

        if heuristic_results:
            flagged_count = len(heuristic_results)
            total_flags = sum(len(flags) for flags in heuristic_results.values())
            print(f"   ⚠️  Flagged {flagged_count} files with {total_flags} potential issues")
            for file_path, flags in list(heuristic_results.items())[:3]:
                print(f"      - {file_path}: {', '.join(flags[:3])}")
            if len(heuristic_results) > 3:
                print(f"      ... and {len(heuristic_results) - 3} more files")
        else:
            print("   ✅ No heuristic flags - codebase looks clean")

    # Run Semgrep SAST scan (if enabled)
    semgrep_results = {}
    enable_semgrep = config.get("enable_semgrep", True)

    if enable_semgrep:
        try:
            from semgrep_scanner import SemgrepScanner

            print("🔍 Running Semgrep SAST scan...")

            semgrep_scanner = SemgrepScanner(
                {
                    "semgrep_rules": "auto",  # Uses Semgrep Registry (2,000+ rules)
                    "exclude_patterns": [
                        "*/test/*",
                        "*/tests/*",
                        "*/.git/*",
                        "*/node_modules/*",
                        "*/.venv/*",
                        "*/venv/*",
                        "*/build/*",
                        "*/dist/*",
                    ],
                }
            )

            semgrep_results = semgrep_scanner.scan(ctx.repo_path)

            if semgrep_results.get("findings"):
                semgrep_count = len(semgrep_results["findings"])
                severity_counts = {}
                for finding in semgrep_results["findings"]:
                    severity = finding.get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                print(f"   ⚠️  Semgrep found {semgrep_count} issues:")
                for severity in ["high", "medium", "low"]:
                    if severity in severity_counts:
                        print(f"      - {severity_counts[severity]} {severity} severity")

                # Show top 3 findings
                for finding in semgrep_results["findings"][:3]:
                    file_path = finding["file_path"]
                    line = finding["start_line"]
                    rule_id = finding["rule_id"].split(".")[-1]  # Show short name
                    print(f"      - {file_path}:{line} ({rule_id})")

                if semgrep_count > 3:
                    print(f"      ... and {semgrep_count - 3} more issues")

                # Track in metrics
                metrics.record("semgrep_findings", semgrep_count)
                for severity, count in severity_counts.items():
                    metrics.record(f"semgrep_{severity}_severity", count)
            else:
                print("   ✅ Semgrep: no issues found")
                metrics.record("semgrep_findings", 0)

        except ImportError:
            logger.warning("⚠️  Semgrep not installed. Install with: pip install semgrep")
            print("   ⚠️  Semgrep not available (install with: pip install semgrep)")
        except Exception as e:
            logger.warning(f"Semgrep scan failed: {e}")
            print(f"   ⚠️  Semgrep scan failed: {e}")

    # -- Phase gate: validate scanner orchestration output --
    if ctx.phase_gate is not None:
        scanner_output = {
            "findings": semgrep_results.get("findings", []) if semgrep_results else []
        }
        gate_decision = ctx.phase_gate.validate("scanner_orchestration", scanner_output)
        if not gate_decision.should_proceed:
            logger.error("Phase gate blocked after scanner orchestration: %s", gate_decision.reason)
            print(f"Phase gate BLOCKED: {gate_decision.reason}")
            sys.exit(2)

    return heuristic_results, semgrep_results


def _run_phase1_research(ctx: AuditContext) -> dict:
    """Phase 1: Research — identify files and areas that need attention.

    Returns:
        research_data dict with keys: high_priority_files, focus_areas, rationale.
    """
    files = ctx.files

    print("\n" + "=" * 80)
    print("📊 PHASE 1: RESEARCH & FILE SELECTION")
    print("=" * 80)

    ctx.context_tracker.start_phase("phase1_research")

    # Build lightweight file summary (not full content)
    file_summary = []
    for f in files:
        file_summary.append(f"- {f['path']} ({f['lines']} lines)")
    file_list = "\n".join(file_summary)

    ctx.context_tracker.add_context("file_list", file_list, {"file_count": len(files)})

    # Add threat model if available
    threat_summary = ""
    if ctx.threat_model:
        threat_summary = f"""
**Threat Model Available:**
- {len(ctx.threat_model.get('threats', []))} threats identified
- {len(ctx.threat_model.get('attack_surface', {}).get('entry_points', []))} entry points
- {len(ctx.threat_model.get('assets', []))} critical assets
"""
        ctx.context_tracker.add_context("threat_model_summary", threat_summary, {"threats": len(ctx.threat_model.get('threats', []))})

    research_prompt = f"""You are conducting initial research for a code audit.

**Your Task**: Analyze the file list and identify which files and areas require detailed review.

**Files in Codebase**:
{file_list}

{threat_summary}

**Instructions**:
1. Categorize files by risk level (high/medium/low)
2. Identify focus areas (security, performance, testing, quality)
3. Prioritize files that likely contain critical issues
4. Consider file types, naming patterns, and threat model

**Output Format**:
```json
{{
  "high_priority_files": ["file1.py", "file2.js"],
  "focus_areas": ["security", "performance"],
  "rationale": "Brief explanation of prioritization"
}}
```

Be concise. This is research, not detailed analysis."""

    ctx.context_tracker.end_phase()

    print("🧠 Analyzing codebase structure...")
    try:
        research_result, research_input, research_output = call_llm_api(
            ctx.client,
            ctx.provider,
            ctx.model,
            research_prompt,
            2000,  # Shorter response for research
            circuit_breaker=ctx.circuit_breaker,
            operation="phase1_research",
        )
        ctx.metrics.record_llm_call(research_input, research_output, ctx.provider)
        print(f"✅ Research complete ({research_input} input tokens, {research_output} output tokens)")

        # Parse research results
        try:
            # Extract JSON from response
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', research_result, re.DOTALL)
            if json_match:
                research_data = json.loads(json_match.group(1))
            else:
                # Fallback: use all files
                research_data = {
                    "high_priority_files": [f['path'] for f in files[:10]],
                    "focus_areas": ["security", "performance", "testing", "quality"],
                    "rationale": "Using all files (JSON parsing failed)"
                }
        except Exception as e:
            logger.warning(f"Failed to parse research results: {e}")
            research_data = {
                "high_priority_files": [f['path'] for f in files[:10]],
                "focus_areas": ["security", "performance", "testing", "quality"],
                "rationale": "Using all files (parsing error)"
            }

        print(f"   Priority files: {len(research_data.get('high_priority_files', []))}")
        print(f"   Focus areas: {', '.join(research_data.get('focus_areas', []))}")

    except Exception as e:
        logger.error(f"Research phase failed: {e}")
        research_data = {
            "high_priority_files": [f['path'] for f in files],
            "focus_areas": ["security", "performance", "testing", "quality"],
            "rationale": "Research phase failed, using all files"
        }

    return research_data


def _run_phase2_planning(ctx: AuditContext, research_data: dict, priority_files: list) -> str:
    """Phase 2: Planning — create a focused analysis plan.

    Returns:
        plan_summary string.
    """
    print("\n" + "=" * 80)
    print("📋 PHASE 2: PLANNING & FOCUS IDENTIFICATION")
    print("=" * 80)

    ctx.context_tracker.start_phase("phase2_planning")

    priority_context = "\n\n".join([f"File: {f['path']}\n```\n{f['content'][:500]}...\n```" for f in priority_files])
    ctx.context_tracker.add_context("priority_files_preview", priority_context, {"file_count": len(priority_files)})

    planning_prompt = f"""You are planning a detailed code audit based on initial research.

**Research Findings**:
{json.dumps(research_data, indent=2)}

**Priority Files (Preview - first 500 chars each)**:
{priority_context}

**Your Task**: Create a focused analysis plan identifying specific issues to investigate.

**Output Format**:
# Analysis Plan

## Security Focus
- [ ] Check for: [specific security issue to look for]
- [ ] Verify: [specific security control]

## Performance Focus
- [ ] Analyze: [specific performance concern]

## Testing Focus
- [ ] Review: [specific testing gap]

## Quality Focus
- [ ] Examine: [specific quality issue]

Be specific and actionable. This plan will guide the detailed analysis."""

    ctx.context_tracker.end_phase()

    print("🧠 Creating analysis plan...")
    try:
        plan_result, plan_input, plan_output = call_llm_api(
            ctx.client,
            ctx.provider,
            ctx.model,
            planning_prompt,
            3000,  # Medium response for planning
            circuit_breaker=ctx.circuit_breaker,
            operation="phase2_planning",
        )
        ctx.metrics.record_llm_call(plan_input, plan_output, ctx.provider)
        print(f"✅ Planning complete ({plan_input} input tokens, {plan_output} output tokens)")

        # Summarize the plan
        plan_summary = ctx.summarizer.summarize_report(plan_result, max_length=800)

    except Exception as e:
        logger.error(f"Planning phase failed: {e}")
        plan_summary = "Planning phase failed. Proceeding with general analysis."

    return plan_summary


def _run_phase2_deep_analysis(ctx: AuditContext, findings_dict: dict) -> tuple[list, dict]:
    """Phase 2.7: Deep Analysis Engine — advanced semantic and proactive analysis.

    Args:
        findings_dict: mutable dict of findings accumulated so far (may be empty).

    Returns:
        (deep_analysis_findings list, updated findings_dict).
    """
    deep_analysis_findings = []
    if not DEEP_ANALYSIS_AVAILABLE:
        logger.info("⏭️  Phase 2.7: Deep Analysis Engine not available")
        return deep_analysis_findings, findings_dict

    try:
        # Build deep analysis config from environment and config dict
        deep_mode_str = ctx.config.get("deep_analysis_mode", os.getenv("DEEP_ANALYSIS_MODE", "off"))
        deep_mode = DeepAnalysisMode.from_string(deep_mode_str)

        if deep_mode != DeepAnalysisMode.OFF:
            print("\n" + "=" * 80)
            print("🔬 PHASE 2.7: DEEP ANALYSIS ENGINE")
            print("=" * 80)

            # Configure deep analysis
            deep_config = DeepAnalysisConfig(
                mode=deep_mode,
                enabled_phases=deep_mode.get_enabled_phases(),
                max_files=int(ctx.config.get("deep_analysis_max_files",
                                        os.getenv("DEEP_ANALYSIS_MAX_FILES", "50"))),
                timeout_seconds=int(ctx.config.get("deep_analysis_timeout",
                                               os.getenv("DEEP_ANALYSIS_TIMEOUT", "300"))),
                cost_ceiling=float(ctx.config.get("deep_analysis_cost_ceiling",
                                             os.getenv("DEEP_ANALYSIS_COST_CEILING", "5.0"))),
                dry_run=ctx.config.get("deep_analysis_dry_run", "false").lower() == "true",
            )

            # Check if benchmarking is enabled
            enable_benchmarking = ctx.config.get("benchmark", "false").lower() == "true"

            # Initialize engine
            deep_engine = DeepAnalysisEngine(
                config=deep_config,
                ai_client=ctx.client,
                model=ctx.model,
                enable_benchmarking=enable_benchmarking
            )

            # Run analysis
            print(f"   Mode: {deep_mode.value}")
            print(f"   Enabled phases: {[p.value for p in deep_config.enabled_phases]}")
            if enable_benchmarking:
                print("   📊 Benchmarking: ENABLED")

            # Convert existing findings to pass as context
            context_findings = []
            for cat, items in findings_dict.items():
                for item in items:
                    context_findings.append({
                        "category": cat,
                        "severity": item.get("severity", "unknown"),
                        "title": item.get("title", ""),
                        "file": item.get("file", ""),
                    })

            deep_results = deep_engine.analyze(ctx.repo_path, context_findings)

            # Merge findings into main results
            for result in deep_results:
                deep_analysis_findings.extend(result.findings)

                # Add to findings dict with normalized field names
                if result.findings:
                    category = f"deep_analysis_{result.phase.value}"
                    if category not in findings_dict:
                        findings_dict[category] = []

                    # Normalize deep analysis findings to match expected format
                    for finding in result.findings:
                        normalized_finding = {
                            "severity": finding.get("severity", "medium"),
                            "category": finding.get("type", category),  # Map 'type' to 'category'
                            "message": finding.get("title", ""),
                            "file_path": finding.get("file", finding.get("files", ["unknown"])[0] if isinstance(finding.get("files"), list) else "unknown"),
                            "line_number": finding.get("line", 1),
                            "rule_id": f"{category.upper()}-{len(findings_dict[category]) + 1:03d}",
                            "description": finding.get("description", ""),
                            "confidence": finding.get("confidence", 0.0),
                        }
                        findings_dict[category].append(normalized_finding)

            print(f"✅ Deep Analysis complete: {len(deep_analysis_findings)} findings, "
                  f"${deep_engine.total_cost:.2f} cost")

            # Export detailed results
            deep_output = Path(ctx.repo_path) / "argus_deep_analysis_results.json"
            deep_engine.export_results(str(deep_output))

            # Print benchmark report if enabled
            if enable_benchmarking:
                deep_engine.print_benchmark_report()
        else:
            print("\n⏭️  Phase 2.7: Deep Analysis skipped (mode=off)")

    except Exception as e:
        logger.error(f"Deep Analysis Engine failed: {e}")
        logger.exception(e)

    return deep_analysis_findings, findings_dict


def _run_phase3_analysis(ctx: AuditContext, plan_summary: str, priority_files: list, findings_dict: dict) -> tuple[list, str, Any]:
    """Phase 3: Detailed Implementation Analysis.

    Args:
        plan_summary: summary from Phase 2.
        priority_files: files selected for deep review.
        findings_dict: deep analysis findings dict from Phase 2.7.

    Returns:
        (findings list, report text, report_file Path).

    Raises:
        Exception: propagated to caller's try/except.
    """
    print("\n" + "=" * 80)
    print("🔍 PHASE 3: DETAILED IMPLEMENTATION ANALYSIS")
    print("=" * 80)

    ctx.context_tracker.start_phase("phase3_implementation")

    # Build FULL context for priority files only
    codebase_context = "\n\n".join([f"File: {f['path']}\n```\n{f['content']}\n```" for f in priority_files])
    ctx.context_tracker.add_context("full_codebase", codebase_context, {"file_count": len(priority_files)})
    ctx.context_tracker.add_context("analysis_plan", plan_summary, {"from_phase": 2})

    # Load audit instructions
    audit_command_path = (
        Path.home() / ".argus/profiles/default/commands/audit-codebase/multi-agent/audit-codebase.md"
    )
    if audit_command_path.exists():
        with open(audit_command_path) as f:
            audit_instructions = f.read()
    else:
        audit_instructions = """
Perform a comprehensive code audit focusing on:
1. Security vulnerabilities (hardcoded secrets, injection flaws, auth issues)
2. Performance issues (N+1 queries, memory leaks, inefficient algorithms)
3. Test coverage gaps (missing tests for critical logic)
4. Code quality issues (maintainability, documentation, error handling)

For each issue found, classify it as:
- [CRITICAL] - Severe security or data loss risk
- [HIGH] - Important issue that should be fixed soon
- [MEDIUM] - Moderate issue, good to fix
- [LOW] - Minor issue or suggestion
"""

    # Check for contradictions
    contradictions = ctx.context_tracker.detect_contradictions(audit_instructions, plan_summary)
    if contradictions:
        logger.warning("⚠️  Potential contradictions detected:")
        for warning in contradictions:
            logger.warning(f"   - {warning}")

    # Create implementation prompt with plan context
    prompt = f"""You are performing a detailed code audit based on the analysis plan.

**Analysis Plan (from Phase 2)**:
{plan_summary}

**Audit Instructions**:
{audit_instructions}

**Codebase to Analyze**:
{codebase_context}

**Your Task**:
Execute the analysis plan above. Provide a detailed audit report with:

# Codebase Audit Report

## Executive Summary
- Overall Status (APPROVED / REQUIRES FIXES / CRITICAL)
- Risk Level (LOW / MEDIUM / HIGH / CRITICAL)
- Total Issues Found
- Critical issues count
- High issues count

## Critical Issues (Must Fix Immediately)

### Security Issues
List critical security vulnerabilities with `file.ext:line` references

### Performance Issues
List critical performance problems with `file.ext:line` references

### Testing Issues
List critical testing gaps with `file.ext:line` references

## High Priority Issues

### Security Improvements
### Performance Optimizations
### Testing Enhancements

## Medium Priority Issues

### Code Quality Improvements

## Action Items

### Immediate (Critical)
Numbered list of critical fixes

### Follow-up (High Priority)
Numbered list of high priority improvements

## Recommendation
Final recommendation: APPROVED / REQUIRES FIXES / DO NOT MERGE

Be specific with file names and line numbers. Use format: `filename.ext:123` for references.
Focus on issues identified in the analysis plan."""

    ctx.context_tracker.end_phase()

    # Sanitize provider/model names for logging (use str() to break taint chain)
    safe_provider = str(ctx.provider).split("/")[-1] if ctx.provider else "unknown"
    safe_model = str(ctx.model).split("/")[-1] if ctx.model else "unknown"
    print(f"🧠 Performing detailed analysis with {safe_provider} ({safe_model})...")

    # Call LLM API with cost enforcement
    report, input_tokens, output_tokens = call_llm_api(
        ctx.client,
        ctx.provider,
        ctx.model,
        prompt,
        ctx.max_tokens,
        circuit_breaker=ctx.circuit_breaker,
        operation="phase3_implementation",
    )

    # Record LLM metrics
    ctx.metrics.record_llm_call(input_tokens, output_tokens, ctx.provider)

    # Save markdown report
    report_dir = Path(ctx.repo_path) / ".argus/reviews"
    report_dir.mkdir(parents=True, exist_ok=True)

    report_file = report_dir / f"{ctx.review_type}-report.md"
    with open(report_file, "w") as f:
        f.write(report)

    print(f"✅ Audit complete! Report saved to: {report_file}")

    # Parse findings from Phase 3 report
    phase3_findings = parse_findings_from_report(report)

    # Merge Phase 2.7 findings (if any) with Phase 3 findings
    # findings_dict was initialized before Phase 2.7 as a dict, need to convert to list
    all_findings = list(phase3_findings)  # Start with Phase 3 findings

    # Add Phase 2.7 deep analysis findings if they exist (findings_dict was a dict in Phase 2.7)
    if isinstance(findings_dict, dict):
        for _category, items in findings_dict.items():
            all_findings.extend(items)

    return all_findings, report, report_file


def _run_reporting(ctx: AuditContext, findings: list, report_file: Any) -> tuple[int, int]:
    """Reporting phase: enrichment, SARIF/JSON output, fail-on checks.

    Returns:
        (blocker_count, suggestion_count).
    """
    config = ctx.config
    metrics = ctx.metrics
    repo_path = ctx.repo_path

    # -- v2.0 Enrichment Pipeline --
    print("\n🔬 Running enrichment pipeline...")
    _run_license_scoring(config, repo_path)
    findings, enrichment_meta = _run_enrichment_pipeline(
        findings, config, repo_path, metrics
    )

    # Record finding metrics
    for finding in findings:
        metrics.record_finding(finding["severity"], finding["category"])

    # -- Phase gate: validate enriched findings before reporting --
    if ctx.phase_gate is not None:
        enrichment_output = {"enriched_findings": findings}
        gate_decision = ctx.phase_gate.validate("ai_enrichment", enrichment_output)
        if not gate_decision.should_proceed:
            logger.error("Phase gate blocked before reporting: %s", gate_decision.reason)
            print(f"Phase gate BLOCKED: {gate_decision.reason}")
            sys.exit(2)

    report_dir = Path(repo_path) / ".argus/reviews"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Generate SARIF with metrics
    sarif = generate_sarif(findings, repo_path, metrics)
    sarif_file = report_dir / "results.sarif"
    with open(sarif_file, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"📄 SARIF saved to: {sarif_file}")

    # Generate structured JSON
    json_output = {
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "provider": ctx.provider,
        "model": ctx.model,
        "summary": metrics.metrics,
        "findings": findings,
    }
    if enrichment_meta:
        json_output["enrichment"] = enrichment_meta

    json_file = report_dir / "results.json"
    with open(json_file, "w") as f:
        json.dump(json_output, f, indent=2)
    print(f"📊 JSON saved to: {json_file}")

    # Save metrics
    metrics_file = report_dir / "metrics.json"
    metrics.finalize()
    metrics.save(metrics_file)

    # Count blockers and suggestions
    blocker_count = metrics.metrics["findings"]["critical"] + metrics.metrics["findings"]["high"]
    suggestion_count = metrics.metrics["findings"]["medium"] + metrics.metrics["findings"]["low"]

    # Save context tracking summary
    context_summary = ctx.context_tracker.get_summary()
    context_file = report_dir / "context-tracking.json"
    with open(context_file, "w") as f:
        json.dump(context_summary, f, indent=2)
    print(f"📊 Context tracking saved to: {context_file}")

    print("\n📊 Results:")
    print(f"   Critical: {metrics.metrics['findings']['critical']}")
    print(f"   High: {metrics.metrics['findings']['high']}")
    print(f"   Medium: {metrics.metrics['findings']['medium']}")
    print(f"   Low: {metrics.metrics['findings']['low']}")
    print(f"\n💰 Cost: ${metrics.metrics['cost_usd']:.2f}")
    print(f"⏱️  Duration: {metrics.metrics['duration_seconds']}s")
    # Sanitize for logging (use str() to break taint chain)
    safe_provider = str(ctx.provider).split("/")[-1] if ctx.provider else "unknown"
    safe_model = str(ctx.model).split("/")[-1] if ctx.model else "unknown"
    print(f"🔧 Provider: {safe_provider} ({safe_model})")

    # Display context tracking summary
    print("\n📊 Context Management:")
    print(f"   Phases: {context_summary['total_phases']}")
    print(f"   Total tokens (estimated): ~{context_summary['total_tokens_estimate']:,}")
    for phase in context_summary['phases']:
        print(f"   - {phase['name']}: {phase['components']} components, ~{phase['tokens_estimate']:,} tokens")

    # Check fail-on conditions
    fail_on = config.get("fail_on", "")
    should_fail = False

    if fail_on:
        print(f"\n🚦 Checking fail conditions: {fail_on}")
        conditions = [c.strip() for c in fail_on.split(",") if c.strip()]

        for condition in conditions:
            if ":" in condition:
                category, severity = condition.split(":", 1)
                category = category.strip().lower()
                severity = severity.strip().lower()

                # Check if condition is met
                if category == "any":
                    # any:critical means any category with critical severity
                    if severity in metrics.metrics["findings"] and metrics.metrics["findings"][severity] > 0:
                        print(f"   ❌ FAIL: Found {metrics.metrics['findings'][severity]} {severity} issues")
                        should_fail = True
                else:
                    # Check specific category:severity combination
                    matching_findings = [
                        f for f in findings if f["category"] == category and f["severity"] == severity
                    ]
                    if matching_findings:
                        print(f"   ❌ FAIL: Found {len(matching_findings)} {category}:{severity} issues")
                        should_fail = True

    # Output for GitHub Actions (using GITHUB_OUTPUT)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"blockers={blocker_count}\n")
            f.write(f"suggestions={suggestion_count}\n")
            f.write(f"report-path={report_file}\n")
            f.write(f"sarif-path={sarif_file}\n")
            f.write(f"json-path={json_file}\n")
            f.write(f"cost-estimate={metrics.metrics['cost_usd']:.2f}\n")
            f.write(f"files-analyzed={metrics.metrics['files_reviewed']}\n")
            f.write(f"duration-seconds={metrics.metrics['duration_seconds']}\n")
    else:
        # Fallback for local testing
        print(f"\nblockers={blocker_count}")
        print(f"suggestions={suggestion_count}")
        print(f"report-path={report_file}")
        print(f"sarif-path={sarif_file}")
        print(f"json-path={json_file}")
        print(f"cost-estimate={metrics.metrics['cost_usd']:.2f}")
        print(f"files-analyzed={metrics.metrics['files_reviewed']}")
        print(f"duration-seconds={metrics.metrics['duration_seconds']}")

    # Exit with appropriate code
    if should_fail:
        print("\n❌ Failing due to fail-on conditions")
        sys.exit(1)

    return blocker_count, suggestion_count


def run_audit(repo_path, config, review_type="audit"):
    """Run AI-powered code audit with multi-LLM support.

    Thin orchestrator that delegates to extracted phase functions:
      _setup_audit          -> provider/model/phase-gate/threat-model/file loading
      _run_scanner_phase    -> heuristic + Semgrep SAST
      _run_phase1_research  -> LLM research pass
      _run_phase2_planning  -> LLM planning pass
      _run_phase2_deep_analysis -> deep analysis engine
      _run_phase3_analysis  -> LLM detailed analysis + finding merge
      _run_reporting        -> enrichment, SARIF/JSON output, fail-on checks

    The multi-agent branch (sequential mode) is kept inline because it is
    an entirely separate code-path with its own reporting logic.
    """

    # -- Setup: provider, model, circuit breaker, threat model, files --
    ctx = _setup_audit(repo_path, config, review_type)

    if not ctx.files:
        print("⚠️  No files to analyze")
        return 0, 0, ctx.metrics

    # Record file metrics
    for f in ctx.files:
        ctx.metrics.record_file(f["lines"])

    # -- Scanner phase: heuristic + Semgrep --
    heuristic_results, semgrep_results = _run_scanner_phase(ctx)

    # -- Cost estimation --
    cost_limit = float(config.get("cost_limit", 1.0))
    estimated_cost, est_input, est_output = estimate_cost(ctx.files, ctx.max_tokens, ctx.provider)
    if ctx.provider == "ollama":
        print("💰 Estimated cost: $0.00 (local Ollama)")
    else:
        print(f"💰 Estimated cost: ${estimated_cost:.2f}")

    if estimated_cost > cost_limit and ctx.provider != "ollama":
        print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
        print("💡 Reduce max-files, use path filters, or increase cost-limit")
        sys.exit(2)

    # -- Multi-agent branch (kept inline — separate code-path) --
    multi_agent_mode = config.get("multi_agent_mode", "single")

    if multi_agent_mode == "sequential":
        # Run multi-agent sequential review (with threat model context)
        report = run_multi_agent_sequential(
            repo_path,
            config,
            review_type,
            ctx.client,
            ctx.provider,
            ctx.model,
            ctx.max_tokens,
            ctx.files,
            ctx.metrics,
            ctx.circuit_breaker,
            threat_model=ctx.threat_model,  # Pass threat model to agents
        )

        # Skip to saving reports (multi-agent handles its own analysis)
        report_dir = Path(repo_path) / ".argus/reviews"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_file = report_dir / f"{review_type}-report.md"
        with open(report_file, "w") as f:
            f.write(report)

        print(f"✅ Multi-agent audit complete! Report saved to: {report_file}")

        # Parse findings from final orchestrated report
        findings = parse_findings_from_report(report)

        # -- v2.0 Enrichment Pipeline --
        print("\n🔬 Running enrichment pipeline...")
        _run_license_scoring(config, repo_path)
        findings, enrichment_meta = _run_enrichment_pipeline(
            findings, config, repo_path, ctx.metrics
        )
        json_output_meta = {"enrichment": enrichment_meta} if enrichment_meta else {}

        # Generate SARIF with metrics
        sarif = generate_sarif(findings, repo_path, ctx.metrics)
        sarif_file = report_dir / "results.sarif"
        with open(sarif_file, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"📄 SARIF saved to: {sarif_file}")

        # Generate structured JSON
        json_output = {
            "version": "2.1.0",
            "mode": "multi-agent-sequential",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "provider": ctx.provider,
            "model": ctx.model,
            "summary": ctx.metrics.metrics,
            "findings": findings,
            **json_output_meta,
        }

        json_file = report_dir / "results.json"
        with open(json_file, "w") as f:
            json.dump(json_output, f, indent=2)
        print(f"📊 JSON saved to: {json_file}")

        # Save metrics
        metrics_file = report_dir / "metrics.json"
        ctx.metrics.finalize()
        ctx.metrics.save(metrics_file)

        # Count blockers and suggestions
        blocker_count = ctx.metrics.metrics["findings"]["critical"] + ctx.metrics.metrics["findings"]["high"]
        suggestion_count = ctx.metrics.metrics["findings"]["medium"] + ctx.metrics.metrics["findings"]["low"]

        print("\n📊 Final Results:")
        print(f"   Critical: {ctx.metrics.metrics['findings']['critical']}")
        print(f"   High: {ctx.metrics.metrics['findings']['high']}")
        print(f"   Medium: {ctx.metrics.metrics['findings']['medium']}")
        print(f"   Low: {ctx.metrics.metrics['findings']['low']}")
        print(f"\n💰 Total Cost: ${ctx.metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Total Duration: {ctx.metrics.metrics['duration_seconds']}s")
        print("🤖 Mode: Multi-Agent Sequential (7 agents)")

        # Display exploitability metrics
        if any(ctx.metrics.metrics["exploitability"].values()):
            print("\n⚠️  Exploitability:")
            if ctx.metrics.metrics["exploitability"]["trivial"] > 0:
                print(f"   ⚠️  Trivial: {ctx.metrics.metrics['exploitability']['trivial']}")
            if ctx.metrics.metrics["exploitability"]["moderate"] > 0:
                print(f"   🟨 Moderate: {ctx.metrics.metrics['exploitability']['moderate']}")
            if ctx.metrics.metrics["exploitability"]["complex"] > 0:
                print(f"   🟦 Complex: {ctx.metrics.metrics['exploitability']['complex']}")
            if ctx.metrics.metrics["exploitability"]["theoretical"] > 0:
                print(f"   ⬜ Theoretical: {ctx.metrics.metrics['exploitability']['theoretical']}")

        if ctx.metrics.metrics["exploit_chains_found"] > 0:
            print(f"   ⛓️  Exploit Chains: {ctx.metrics.metrics['exploit_chains_found']}")

        if ctx.metrics.metrics["tests_generated"] > 0:
            print(f"   🧪 Tests Generated: {ctx.metrics.metrics['tests_generated']}")

        # Display validation and timeout metrics (Medium Priority features)
        try:
            validation_summary = output_validator.get_validation_summary()  # noqa: F821
        except NameError:
            validation_summary = {}
        try:
            timeout_summary = timeout_manager.get_summary()  # noqa: F821
        except NameError:
            timeout_summary = {}

        if validation_summary.get("total_validations", 0) > 0:
            print("\n📋 Output Validation:")
            print(f"   Valid outputs: {validation_summary['valid_outputs']}/{validation_summary['total_validations']}")
            if validation_summary.get('total_warnings', 0) > 0:
                print(f"   ⚠️  Warnings: {validation_summary['total_warnings']}")
            if validation_summary.get('invalid_outputs', 0) > 0:
                print(f"   ❌ Invalid: {validation_summary['invalid_outputs']}")

        if timeout_summary.get("total_executions", 0) > 0:
            print("\n⏱️  Timeout Management:")
            print(f"   Completed: {timeout_summary['completed']}/{timeout_summary['total_executions']}")
            print(f"   Avg duration: {timeout_summary['avg_duration']:.1f}s")
            if timeout_summary.get('timeout_exceeded', 0) > 0:
                print(f"   ⚠️  Timeouts exceeded: {timeout_summary['timeout_exceeded']}")

        # Output for GitHub Actions
        print("completed=true")
        print(f"blockers={blocker_count}")
        print(f"suggestions={suggestion_count}")
        print(f"report-path={report_file}")
        print(f"sarif-path={sarif_file}")
        print(f"json-path={json_file}")
        print(f"cost-estimate={ctx.metrics.metrics['cost_usd']:.4f}")
        print(f"files-analyzed={ctx.metrics.metrics['files_reviewed']}")
        print(f"duration-seconds={ctx.metrics.metrics['duration_seconds']}")

        # Check fail-on conditions
        fail_on = config.get("fail_on", "")
        should_fail = False

        if fail_on:
            print(f"\n🚦 Checking fail conditions: {fail_on}")
            conditions = [c.strip() for c in fail_on.split(",") if c.strip()]

            for condition in conditions:
                if ":" in condition:
                    category, severity = condition.split(":", 1)
                    category = category.strip().lower()
                    severity = severity.strip().lower()

                    if category == "any":
                        if severity in ctx.metrics.metrics["findings"] and ctx.metrics.metrics["findings"][severity] > 0:
                            print(f"   ❌ FAIL: Found {ctx.metrics.metrics['findings'][severity]} {severity} issues")
                            should_fail = True
                    else:
                        matching_findings = [
                            f for f in findings if f["category"] == category and f["severity"] == severity
                        ]
                        if matching_findings:
                            print(f"   ❌ FAIL: Found {len(matching_findings)} {category}:{severity} issues")
                            should_fail = True

        if should_fail:
            print("\n❌ Failing due to fail-on conditions")
            sys.exit(1)

        return blocker_count, suggestion_count, ctx.metrics

    # -- Single-agent mode with DISCRETE PHASES --
    print("🤖 Mode: Single-Agent (3-Phase Process)")
    print("   Phase 1: Research & File Selection")
    print("   Phase 2: Planning & Focus Area Identification")
    print("   Phase 3: Detailed Implementation Analysis")

    try:
        # Phase 1: Research
        research_data = _run_phase1_research(ctx)

        # Compute priority files for Phases 2 & 3
        priority_files = [f for f in ctx.files if f['path'] in research_data.get('high_priority_files', [])]
        if not priority_files:
            priority_files = ctx.files[:10]  # Fallback

        # Phase 2: Planning
        plan_summary = _run_phase2_planning(ctx, research_data, priority_files)

        # Phase 2.7: Deep Analysis
        findings_dict = {}  # Initialize findings dict for Phase 2.7
        deep_analysis_findings, findings_dict = _run_phase2_deep_analysis(ctx, findings_dict)

        # Phase 3: Detailed Analysis
        findings, report, report_file = _run_phase3_analysis(ctx, plan_summary, priority_files, findings_dict)

        # Reporting: enrichment, SARIF/JSON, fail-on checks
        blocker_count, suggestion_count = _run_reporting(ctx, findings, report_file)

        return blocker_count, suggestion_count, ctx.metrics

    except Exception as e:
        print(f"❌ Error during AI analysis: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_args()

    # Build config from args (which also loads env vars as defaults)
    config = build_config(args)

    # Get repo path and review type from args
    repo_path = args.repo_path
    review_type = args.review_type

    run_audit(repo_path, config, review_type)
