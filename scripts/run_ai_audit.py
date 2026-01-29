#!/usr/bin/env python3
"""
Agent OS AI-Powered Code Audit Script
Supports multiple LLM providers: Anthropic, OpenAI, Ollama
With cost guardrails, SARIF/JSON output, and observability
"""

import ast
import glob
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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

# Import AST deduplicator for enhanced consensus grouping
from ast_deduplicator import ASTDeduplicator

# Import sandbox validator
try:
    from sandbox_validator import ExploitConfig, ExploitType, SandboxValidator, ValidationResult

    SANDBOX_VALIDATION_AVAILABLE = True
except ImportError:
    SANDBOX_VALIDATION_AVAILABLE = False
    logger.warning("Sandbox validator not available")

# Import deep analysis engine
try:
    from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisEngine, DeepAnalysisMode

    DEEP_ANALYSIS_AVAILABLE = True
except ImportError:
    DEEP_ANALYSIS_AVAILABLE = False
    logger.warning("Deep Analysis Engine not available")

# Import refactored modules (extracted from this file for maintainability)
from heuristic_scanner import HeuristicScanner
from consensus_builder import ConsensusBuilder
from analysis_helpers import (
    ContextTracker,
    FindingSummarizer,
    AgentOutputValidator,
    TimeoutManager,
    CodebaseChunker,
    ContextCleanup,
    ReviewMetrics,
    CostLimitExceededError,
    CostLimitExceeded,
)


# CostCircuitBreaker class is defined below after the removed inline classes
# The HeuristicScanner, ConsensusBuilder, and helper classes are now imported from:
# - heuristic_scanner.py
# - consensus_builder.py
# - analysis_helpers.py

# --- START OF REMOVED INLINE CLASSES (now imported) ---
# The following classes were moved to separate modules:
# - HeuristicScanner -> heuristic_scanner.py
# - ConsensusBuilder -> consensus_builder.py
# - ContextTracker, FindingSummarizer, AgentOutputValidator,
#   TimeoutManager, CodebaseChunker, ContextCleanup, ReviewMetrics,
#   CostLimitExceededError -> analysis_helpers.py
# --- END OF REMOVED INLINE CLASSES ---


class CostCircuitBreaker:
    """Runtime cost enforcement to prevent budget overruns

    This class provides real-time cost tracking and enforcement:
    - Checks before each LLM call if limit would be exceeded
    - Maintains 10% safety buffer to prevent overage
    - Logs warnings at 50%, 75%, 90% thresholds
    - Raises CostLimitExceededError when limit reached

    Example:
        breaker = CostCircuitBreaker(cost_limit_usd=1.0)
        breaker.check_before_call(estimated_cost=0.15, provider='anthropic')
        # ... make LLM call ...
        breaker.record_actual_cost(0.14)
    """

    def __init__(self, cost_limit_usd: float, safety_buffer_percent: float = 10.0):
        """Initialize cost circuit breaker

        Args:
            cost_limit_usd: Maximum cost allowed in USD
            safety_buffer_percent: Safety buffer percentage (default: 10%)
        """
        self.cost_limit = cost_limit_usd
        self.safety_buffer = safety_buffer_percent / 100.0
        self.effective_limit = cost_limit_usd * (1.0 - self.safety_buffer)
        self.current_cost = 0.0
        self.warned_thresholds = set()

        logger.info(
            f"💰 Cost Circuit Breaker initialized: ${cost_limit_usd:.2f} limit "
            f"(${self.effective_limit:.2f} effective with {safety_buffer_percent}% buffer)"
        )

    def check_before_call(self, estimated_cost: float, provider: str, operation: str = "LLM call"):
        """Check if estimated cost would exceed limit

        Args:
            estimated_cost: Estimated cost of the operation in USD
            provider: AI provider name (for logging)
            operation: Description of operation (for logging)

        Raises:
            CostLimitExceededError: If operation would exceed cost limit
        """
        projected_cost = self.current_cost + estimated_cost
        utilization = (self.current_cost / self.effective_limit) * 100 if self.effective_limit > 0 else 0

        # Check threshold warnings (50%, 75%, 90%)
        for threshold in [50, 75, 90]:
            if utilization >= threshold and threshold not in self.warned_thresholds:
                self.warned_thresholds.add(threshold)
                logger.warning(
                    f"⚠️  Cost at {utilization:.1f}% of limit (${self.current_cost:.3f} / ${self.effective_limit:.2f})"
                )

        # Check if we would exceed the limit
        if projected_cost > self.effective_limit:
            remaining = self.effective_limit - self.current_cost
            message = (
                f"Cost limit exceeded! "
                f"Operation would cost ${estimated_cost:.3f}, "
                f"but only ${remaining:.3f} remaining of ${self.cost_limit:.2f} limit. "
                f"Current cost: ${self.current_cost:.3f}"
            )
            logger.error(f"🚨 {message}")
            raise CostLimitExceededError(message)

        # Log the check (sanitize provider name - use str() to break taint chain)
        safe_provider = str(provider).split("/")[-1] if provider else "unknown"
        logger.debug(
            f"✓ Cost check passed: ${estimated_cost:.3f} {operation} ({safe_provider}), "
            f"projected: ${projected_cost:.3f} / ${self.effective_limit:.2f}"
        )

    def record_actual_cost(self, actual_cost: float):
        """Record actual cost after operation completes

        Args:
            actual_cost: Actual cost incurred in USD
        """
        self.current_cost += actual_cost
        logger.debug(f"💵 Cost updated: +${actual_cost:.3f} → ${self.current_cost:.3f}")

    def get_remaining_budget(self) -> float:
        """Get remaining budget in USD

        Returns:
            Remaining budget considering safety buffer
        """
        return max(0.0, self.effective_limit - self.current_cost)

    def get_utilization_percent(self) -> float:
        """Get current cost utilization as percentage

        Returns:
            Utilization percentage (0-100+)
        """
        if self.effective_limit == 0:
            return 0.0
        return (self.current_cost / self.effective_limit) * 100

    def get_summary(self) -> dict:
        """Get cost summary for reporting

        Returns:
            Dictionary with cost details
        """
        return {
            "cost_limit_usd": self.cost_limit,
            "effective_limit_usd": self.effective_limit,
            "safety_buffer_percent": self.safety_buffer * 100,
            "current_cost_usd": self.current_cost,
            "remaining_budget_usd": self.get_remaining_budget(),
            "utilization_percent": self.get_utilization_percent(),
            "limit_exceeded": self.current_cost > self.effective_limit,
        }


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
        "claude-3-haiku-20240307",  # Most lightweight and universally available
        "claude-3-sonnet-20240229",  # Balanced
        "claude-sonnet-4-5-20250929",  # Latest Claude Sonnet 4.5
        "claude-3-5-sonnet-20241022",  # Claude 3.5 Sonnet
        "claude-3-5-sonnet-20240620",  # Stable
        "claude-3-opus-20240229",  # Most powerful
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


def parse_findings_from_report(report_text):
    """Parse findings from markdown report"""
    import re

    findings = []
    lines = report_text.split("\n")

    # Track current section for categorization
    current_section = None
    current_severity = None

    for i, line in enumerate(lines):
        # Detect sections
        if "## Critical Issues" in line or "## Critical" in line:
            current_severity = "critical"
            continue
        elif "## High Priority" in line or "## High" in line:
            current_severity = "high"
            continue
        elif "## Medium Priority" in line or "## Medium" in line:
            current_severity = "medium"
            continue
        elif "## Low Priority" in line or "## Low" in line:
            current_severity = "low"
            continue

        # Detect category subsections
        if "### Security" in line:
            current_section = "security"
            continue
        elif "### Performance" in line:
            current_section = "performance"
            continue
        elif "### Testing" in line or "### Test" in line:
            current_section = "testing"
            continue
        elif "### Code Quality" in line or "### Quality" in line:
            current_section = "quality"
            continue

        # Look for numbered findings (e.g., "1. **Issue Name**" or "14. **Issue Name**")
        numbered_match = re.match(
            r"^\d+\.\s+\*\*(.+?)\*\*\s*-?\s*`?([^`\n]+\.(?:ts|js|py|java|go|rs|rb|php|cs))?:?(\d+)?", line
        )
        if numbered_match:
            issue_name = numbered_match.group(1)
            file_path = numbered_match.group(2) if numbered_match.group(2) else "unknown"
            line_num = int(numbered_match.group(3)) if numbered_match.group(3) else 1

            # Get description from next lines
            description_lines = []
            for j in range(i + 1, min(i + 5, len(lines))):
                if lines[j].strip() and not lines[j].startswith("#") and not re.match(r"^\d+\.", lines[j]):
                    description_lines.append(lines[j].strip())
                elif lines[j].startswith("#") or re.match(r"^\d+\.", lines[j]):
                    break

            description = " ".join(description_lines[:2]) if description_lines else issue_name

            # Determine category and severity
            category = current_section or "quality"
            severity = current_severity or "medium"

            # Override category based on keywords
            lower_text = (issue_name + " " + description).lower()
            if any(kw in lower_text for kw in ["security", "sql", "xss", "csrf", "auth", "jwt", "secret", "injection"]):
                category = "security"
            elif any(kw in lower_text for kw in ["performance", "n+1", "memory", "leak", "slow", "inefficient"]):
                category = "performance"
            elif any(kw in lower_text for kw in ["test", "coverage", "testing"]):
                category = "testing"

            findings.append(
                {
                    "severity": severity,
                    "category": category,
                    "message": f"{issue_name}: {description[:200]}",
                    "file_path": file_path,
                    "line_number": line_num,
                    "rule_id": f"{category.upper()}-{len([f for f in findings if f['category'] == category]) + 1:03d}",
                }
            )

    return findings


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


def load_agent_prompt(agent_name):
    """Load specialized agent prompt from profiles"""
    agent_prompts = {
        "security": "security-agent-prompt.md",
        "security-reviewer": "security-reviewer.md",
        "exploit-analyst": "exploit-analyst.md",
        "security-test-generator": "security-test-generator.md",
        "performance": "performance-agent-prompt.md",
        "performance-reviewer": "performance-reviewer.md",
        "testing": "testing-agent-prompt.md",
        "test-coverage-reviewer": "test-coverage-reviewer.md",
        "quality": "quality-agent-prompt.md",
        "code-quality-reviewer": "code-quality-reviewer.md",
        "orchestrator": "orchestrator-agent-prompt.md",
        "review-orchestrator": "review-orchestrator.md",
    }

    prompt_file = agent_prompts.get(agent_name)
    if not prompt_file:
        # Fallback: try to find prompt file by agent name
        prompt_file = f"{agent_name}.md"

    # Try multiple locations
    possible_paths = [
        Path.home() / f".argus/profiles/default/agents/{prompt_file}",
        Path.home() / f".argus/profiles/default/agents/{agent_name}.md",
        Path(".argus") / f"profiles/default/agents/{prompt_file}",
        Path(".argus") / f"profiles/default/agents/{agent_name}.md",
    ]

    for prompt_path in possible_paths:
        if prompt_path.exists():
            with open(prompt_path) as f:
                return f.read()

    print(f"⚠️  Agent prompt not found for: {agent_name}")
    return f"You are a {agent_name} code reviewer. Analyze the code for {agent_name}-related issues."


def build_enhanced_agent_prompt(
    agent_prompt_template,
    codebase_context,
    agent_name,
    category="general",
    heuristic_flags=None,
    is_production=True,
    previous_findings=None,
):
    """Build enhanced agent prompt with rubrics and self-consistency checks

    Feature: Enhanced Prompts (from real_multi_agent_review.py)
    This function adds severity rubrics, self-verification checklists, and category focus
    to agent prompts for more consistent and accurate findings.

    Args:
        agent_prompt_template: Base prompt template for the agent
        codebase_context: Code to review
        agent_name: Name of the agent
        category: Focus category (security, performance, quality, general)
        heuristic_flags: List of heuristic flags from pre-scan
        is_production: Whether this is production code
        previous_findings: Findings from previous agents (for chaining)

    Returns:
        Enhanced prompt string with rubrics and checks
    """

    # Category-specific focus instructions
    category_focus = {
        "security": """**YOUR FOCUS: SECURITY ONLY**
Focus exclusively on: authentication, authorization, input validation, SQL injection, XSS,
CSRF, cryptography, secrets management, session handling, API security, dependency vulnerabilities.
Ignore performance and code quality unless it creates a security risk.""",
        "performance": """**YOUR FOCUS: PERFORMANCE ONLY**
Focus exclusively on: N+1 queries, inefficient algorithms, memory leaks, blocking I/O,
database query optimization, caching opportunities, unnecessary computations, resource exhaustion.
Ignore security and code style unless it impacts performance.""",
        "quality": """**YOUR FOCUS: CODE QUALITY ONLY**
Focus exclusively on: code complexity, maintainability, design patterns, SOLID principles,
error handling, logging, documentation, dead code, code duplication, naming conventions.
Ignore security and performance unless code quality creates those risks.""",
        "general": """**YOUR FOCUS: COMPREHENSIVE REVIEW**
Review all aspects: security, performance, and code quality.""",
    }

    heuristic_context = ""
    if heuristic_flags:
        heuristic_context = f"""
**⚠️  PRE-SCAN ALERTS**: Heuristic analysis flagged: {", ".join(heuristic_flags)}
These are lightweight pattern matches. Verify each one carefully before reporting."""

    previous_context = ""
    if previous_findings:
        previous_context = f"""
## Previous Agent Findings

Earlier agents identified the following:

{previous_findings}

Use this as context but focus on your specialized area."""

    # Severity rubric for consistent scoring
    severity_rubric = """
**SEVERITY RUBRIC** (Use this to score consistently):
- **CRITICAL** (0.9-1.0 confidence): Exploitable security flaw, production data loss, system-wide outage
  Examples: SQL injection, hardcoded secrets, authentication bypass, RCE

- **HIGH** (0.7-0.89 confidence): Major security gap, significant performance degradation, data corruption risk
  Examples: Missing auth checks, N+1 queries causing timeouts, memory leaks

- **MEDIUM** (0.5-0.69 confidence): Moderate issue with workaround, sub-optimal design
  Examples: Weak validation, inefficient algorithm, poor error handling

- **LOW** (0.3-0.49 confidence): Minor issue, edge case, defensive improvement
  Examples: Missing logging, minor optimization opportunity

- **INFO** (0.0-0.29 confidence): Style, optional refactoring, best practice
  Examples: Variable naming, code organization, documentation
"""

    # Self-verification checklist
    verification_checklist = """
**SELF-VERIFICATION CHECKLIST** (Ask yourself before reporting):
1. Is this issue ACTUALLY exploitable/harmful in this context?
2. Would this issue cause real problems in production?
3. Is my recommendation actionable and specific?
4. Am I considering the full context (dev vs prod, test vs runtime)?
5. If I'm unsure, have I lowered my confidence score appropriately?
"""

    # Build the enhanced prompt
    enhanced_prompt = f"""{agent_prompt_template}

{category_focus.get(category, category_focus["general"])}

**CODE TYPE**: {"Production code" if is_production else "Development/Test infrastructure"}{heuristic_context}

{previous_context}

## Codebase to Analyze

{codebase_context}

{severity_rubric}

{verification_checklist}

**YOUR TASK**:
1. Review the code through the lens of {category if category != "general" else agent_name}
2. For each potential issue, run the self-verification checklist
3. Use the severity rubric to assign accurate severity and confidence
4. Report ONLY issues that pass verification

**RESPONSE FORMAT**:
Use your standard report format, but ensure each finding includes:
- Clear severity level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Confidence score (0.0-1.0)
- Specific file path and line number
- Actionable recommendation

Be thorough but precise. Quality over quantity.
"""

    return enhanced_prompt


def run_multi_agent_sequential(
    repo_path,
    config,
    review_type,
    client,
    provider,
    model,
    max_tokens,
    files,
    metrics,
    circuit_breaker,
    threat_model=None,
):
    """Run multi-agent sequential review with specialized agents and cost enforcement
    
    BEST PRACTICE IMPLEMENTATION:
    - Uses discrete phases with context tracking (Practice #2)
    - Passes distilled conclusions between agents (Practice #1)
    - Monitors execution with circuit breaker (Practice #3)

    Args:
        threat_model: Optional threat model to provide context to agents
    """

    print("\n" + "=" * 80)
    print("🤖 MULTI-AGENT SEQUENTIAL MODE")
    print("=" * 80)
    print("Running 7 specialized agents in sequence:")
    print("  1️⃣  Security Reviewer")
    print("  2️⃣  Exploit Analyst")
    print("  3️⃣  Security Test Generator")
    print("  4️⃣  Performance Reviewer")
    print("  5️⃣  Testing Reviewer")
    print("  6️⃣  Code Quality Reviewer")
    print("  7️⃣  Review Orchestrator")
    print("=" * 80 + "\n")

    # Initialize context tracker and finding summarizer
    context_tracker = ContextTracker()
    summarizer = FindingSummarizer()
    
    # Initialize output validator and timeout manager (Medium Priority features)
    output_validator = AgentOutputValidator()
    timeout_manager = TimeoutManager(default_timeout=300)  # 5 minutes default
    
    # Set custom timeouts for specific agents
    timeout_manager.set_agent_timeout("security", 600)  # 10 minutes for security
    timeout_manager.set_agent_timeout("exploit-analyst", 480)  # 8 minutes
    timeout_manager.set_agent_timeout("orchestrator", 600)  # 10 minutes

    # Build codebase context once
    codebase_context = "\n\n".join([f"File: {f['path']}\n```\n{f['content']}\n```" for f in files])

    # Build threat model context for agents (if available)
    threat_model_context = ""
    if threat_model:
        threat_model_context = f"""
## THREAT MODEL CONTEXT

You have access to the following threat model for this codebase:

### Attack Surface
- **Entry Points**: {", ".join(threat_model.get("attack_surface", {}).get("entry_points", [])[:5])}
- **External Dependencies**: {", ".join(threat_model.get("attack_surface", {}).get("external_dependencies", [])[:5])}
- **Authentication Methods**: {", ".join(threat_model.get("attack_surface", {}).get("authentication_methods", []))}
- **Data Stores**: {", ".join(threat_model.get("attack_surface", {}).get("data_stores", []))}

### Critical Assets
{chr(10).join([f"- **{asset.get('name')}** (Sensitivity: {asset.get('sensitivity')}): {asset.get('description')}" for asset in threat_model.get("assets", [])[:5]])}

### Trust Boundaries
{chr(10).join([f"- **{boundary.get('name')}** ({boundary.get('trust_level')}): {boundary.get('description')}" for boundary in threat_model.get("trust_boundaries", [])[:3]])}

### Known Threats
{chr(10).join([f"- **{threat.get('name')}** ({threat.get('category')}, Likelihood: {threat.get('likelihood')}, Impact: {threat.get('impact')})" for threat in threat_model.get("threats", [])[:5]])}

### Security Objectives
{chr(10).join([f"- {obj}" for obj in threat_model.get("security_objectives", [])[:5]])}

**Use this threat model to:**
1. Focus your analysis on the identified attack surfaces
2. Prioritize vulnerabilities that affect critical assets
3. Consider trust boundary violations
4. Look for instances of the known threat categories
5. Validate that security objectives are being met
"""

    # Store agent findings
    agent_reports = {}
    agent_metrics = {}

    # Define agents in execution order (security workflow first)
    agents = ["security", "exploit-analyst", "security-test-generator", "performance", "testing", "quality"]

    # Run each specialized agent
    for i, agent_name in enumerate(agents, 1):
        print(f"\n{'─' * 80}")
        print(f"🔍 Agent {i}/7: {agent_name.upper()} REVIEWER")
        print(f"{'─' * 80}")

        # Start context tracking for this agent phase
        context_tracker.start_phase(f"agent_{i}_{agent_name}")
        agent_start = time.time()

        # Load agent-specific prompt
        agent_prompt_template = load_agent_prompt(agent_name)
        context_tracker.add_context("agent_prompt_template", agent_prompt_template, {"agent": agent_name})

        # For exploit-analyst and security-test-generator, pass SUMMARIZED security findings
        if agent_name in ["exploit-analyst", "security-test-generator"]:
            # Parse and summarize security findings instead of passing full report
            security_report = agent_reports.get("security", "")
            security_findings = parse_findings_from_report(security_report)
            security_summary = summarizer.summarize_findings(security_findings, max_findings=15)
            
            # Check for contradictions
            contradictions = context_tracker.detect_contradictions(agent_prompt_template, threat_model_context)
            if contradictions:
                logger.warning(f"⚠️  Potential contradictions detected for {agent_name}:")
                for warning in contradictions:
                    logger.warning(f"   - {warning}")
            
            context_tracker.add_context("threat_model", threat_model_context, {"size": "summarized"})
            context_tracker.add_context("security_findings_summary", security_summary, {"original_findings": len(security_findings)})
            context_tracker.add_context("codebase", codebase_context, {"files": len(files)})
            
            agent_prompt = f"""{agent_prompt_template}

{threat_model_context}

## Previous Agent Findings (Summarized)

The Security Reviewer has completed their analysis. Here's a summary:

{security_summary}

## Codebase to Analyze

{codebase_context}

## Your Task

{"Analyze the exploitability of the vulnerabilities identified above." if agent_name == "exploit-analyst" else "Generate security tests for the vulnerabilities identified above."}

Provide detailed analysis in your specialized format.
"""
        else:
            # Track context for non-security agents
            context_tracker.add_context("threat_model", threat_model_context, {"size": "summarized"})
            context_tracker.add_context("codebase", codebase_context, {"files": len(files)})
            
            # Create agent-specific prompt
            agent_prompt = f"""{agent_prompt_template}

{threat_model_context}

## Codebase to Analyze

{codebase_context}

## Your Task

Analyze the above codebase from your specialized perspective as a {agent_name} reviewer.
Focus ONLY on {agent_name}-related issues. Do not analyze areas outside your responsibility.

Provide your findings in this format:

# {agent_name.title()} Review Report

## Summary
- Total {agent_name} issues found: X
- Critical: X
- High: X
- Medium: X
- Low: X

## Critical Issues

### [CRITICAL] Issue Title - `file.ext:line`
**Category**: [Specific subcategory]
**Impact**: Description of impact
**Evidence**: Code snippet
**Recommendation**: Fix with code example

[Repeat for each critical issue]

## High Priority Issues

[Same format as critical]

## Medium Priority Issues

[Same format]

## Low Priority Issues

[Same format]

Be specific with file paths and line numbers. Focus on actionable, real issues.
"""

        # End context tracking for this phase
        context_tracker.end_phase()

        try:
            # Sanitize model name (use str() to break taint chain)
            safe_model = str(model).split("/")[-1] if model else "unknown"
            print(f"   🧠 Analyzing with {safe_model}...")
            report, input_tokens, output_tokens = call_llm_api(
                client,
                provider,
                model,
                agent_prompt,
                max_tokens,
                circuit_breaker=circuit_breaker,
                operation=f"{agent_name} agent review",
            )

            agent_duration = time.time() - agent_start
            
            # Check timeout (Medium Priority feature)
            exceeded, elapsed, remaining = timeout_manager.check_timeout(agent_name, agent_start)
            timeout_manager.record_execution(agent_name, agent_duration, not exceeded)
            
            if exceeded:
                logger.warning(f"⚠️  Agent {agent_name} exceeded timeout ({elapsed:.1f}s > {timeout_manager.get_timeout(agent_name)}s)")
                print(f"   ⚠️  Warning: Execution time ({elapsed:.1f}s) exceeded timeout limit")

            # Validate output (Medium Priority feature)
            expected_sections = ["Summary", "Issues", "Critical", "High"]
            validation = output_validator.validate_output(agent_name, report, expected_sections)
            
            if not validation["valid"]:
                logger.error(f"❌ Agent {agent_name} output validation failed: {validation['errors']}")
                print(f"   ❌ Output validation failed: {', '.join(validation['errors'])}")
            
            if validation["warnings"]:
                logger.warning(f"⚠️  Agent {agent_name} output warnings: {validation['warnings']}")
                for warning in validation["warnings"][:3]:  # Show first 3 warnings
                    print(f"   ⚠️  {warning}")

            # Record metrics for this agent
            metrics.record_llm_call(input_tokens, output_tokens, provider)
            metrics.record_agent_execution(agent_name, agent_duration)

            agent_metrics[agent_name] = {
                "duration_seconds": round(agent_duration, 2),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round((input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0, 4)
                if provider == "anthropic"
                else 0,
                "validation": validation,
                "timeout_exceeded": exceeded
            }

            # Store report
            agent_reports[agent_name] = report

            # Parse findings for metrics
            findings = parse_findings_from_report(report)
            finding_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in findings:
                if finding["severity"] in finding_counts:
                    finding_counts[finding["severity"]] += 1
                    metrics.record_finding(finding["severity"], agent_name)

                # Extract exploitability if present (from exploit-analyst)
                if agent_name == "exploit-analyst" and "exploitability" in finding:
                    metrics.record_exploitability(finding["exploitability"])

            # Extract exploit chains from report text (simple heuristic)
            if agent_name == "exploit-analyst":
                exploit_chain_count = report.lower().count("exploit chain")
                for _ in range(exploit_chain_count):
                    metrics.record_exploit_chain()

            # Extract test generation count from report
            if agent_name == "security-test-generator":
                test_count = report.lower().count("test file:") + report.lower().count("test case:")
                if test_count > 0:
                    metrics.record_test_generated(test_count)

            print(
                f"   ✅ Complete: {finding_counts['critical']} critical, {finding_counts['high']} high, {finding_counts['medium']} medium, {finding_counts['low']} low"
            )
            print(f"   ⏱️  Duration: {agent_duration:.1f}s | 💰 Cost: ${agent_metrics[agent_name]['cost_usd']:.4f}")

        except CostLimitExceededError as e:
            # Cost limit reached - stop immediately
            print(f"   🚨 Cost limit exceeded: {e}")
            print(
                f"   💰 Review stopped at ${circuit_breaker.current_cost:.3f} to stay within ${circuit_breaker.cost_limit:.2f} budget"
            )
            print(f"   ✅ {i - 1}/{len(agents)} agents completed before limit reached")

            # Generate partial report with agents completed so far
            agent_reports[agent_name] = (
                f"# {agent_name.title()} Review Skipped\n\n**Reason**: Cost limit reached (${circuit_breaker.cost_limit:.2f})\n"
            )
            raise  # Re-raise to stop the entire review

        except Exception as e:
            print(f"   ❌ Error: {e}")
            agent_reports[agent_name] = f"# {agent_name.title()} Review Failed\n\nError: {str(e)}"
            agent_metrics[agent_name] = {"error": str(e)}

    # NEW: Sandbox Validation (after security agents, before orchestrator)
    if config.get("enable_sandbox_validation", True) and SANDBOX_VALIDATION_AVAILABLE:
        print(f"\n{'─' * 80}")
        print("🔬 SANDBOX VALIDATION")
        print(f"{'─' * 80}")
        print("   Validating exploits in isolated containers...")

        try:
            # Initialize sandbox validator
            validator = SandboxValidator()

            # Parse all findings from security agents
            all_findings = []
            for agent_name in ["security", "exploit-analyst", "security-test-generator"]:
                if agent_name in agent_reports:
                    findings = parse_findings_from_report(agent_reports[agent_name])
                    all_findings.extend(findings)

            # Filter security findings that have PoC code
            security_findings_with_poc = []
            for finding in all_findings:
                # Check if finding has a PoC script (look for code blocks or script indicators)
                if finding.get("category") == "security":
                    # Try to extract PoC code from the finding message or evidence
                    message = finding.get("message", "")
                    if "poc" in message.lower() or "exploit" in message.lower() or "```" in message:
                        security_findings_with_poc.append(finding)

            if security_findings_with_poc:
                print(f"   Found {len(security_findings_with_poc)} security findings to validate")

                validated_findings = []
                for i, finding in enumerate(security_findings_with_poc[:10], 1):  # Limit to 10 for performance
                    print(
                        f"   [{i}/{min(10, len(security_findings_with_poc))}] Validating: {finding.get('message', '')[:60]}..."
                    )

                    # Extract PoC code (simplified - real impl would parse markdown code blocks)
                    poc_code = ""
                    message = finding.get("message", "")
                    if "```" in message:
                        # Extract code block
                        parts = message.split("```")
                        if len(parts) >= 3:
                            poc_code = parts[1]
                            # Remove language identifier
                            if "\n" in poc_code:
                                poc_code = "\n".join(poc_code.split("\n")[1:])

                    if not poc_code:
                        # Skip if no PoC code found
                        validated_findings.append(finding)
                        continue

                    # Determine exploit type from finding
                    exploit_type = ExploitType.CUSTOM
                    lower_msg = finding.get("message", "").lower()
                    if "sql injection" in lower_msg or "sqli" in lower_msg:
                        exploit_type = ExploitType.SQL_INJECTION
                    elif "xss" in lower_msg or "cross-site scripting" in lower_msg:
                        exploit_type = ExploitType.XSS
                    elif "command injection" in lower_msg:
                        exploit_type = ExploitType.COMMAND_INJECTION
                    elif "path traversal" in lower_msg:
                        exploit_type = ExploitType.PATH_TRAVERSAL

                    # Create exploit config
                    exploit = ExploitConfig(
                        name=finding.get("message", "Unknown")[:100],
                        exploit_type=exploit_type,
                        language="python",  # Default to Python
                        code=poc_code,
                        expected_indicators=["success", "exploited", "vulnerable"],  # Generic indicators
                        timeout=15,  # 15 second timeout
                        metadata={"finding_id": finding.get("rule_id", "unknown")},
                    )

                    # Validate exploit
                    try:
                        validation_result = validator.validate_exploit(exploit, create_new_container=True)

                        # Record metrics
                        metrics.record_sandbox_validation(validation_result.result)

                        # Only keep if exploitable
                        if validation_result.result == ValidationResult.EXPLOITABLE.value:
                            finding["sandbox_validated"] = True
                            finding["validation_confidence"] = "high"
                            validated_findings.append(finding)
                            print("      ✅ Confirmed exploitable")
                        else:
                            print("      ❌ Not exploitable - eliminated false positive")
                            metrics.record_false_positive_eliminated()

                    except Exception as e:
                        logger.warning(f"Sandbox validation failed: {e}")
                        # Keep finding if validation fails (don't eliminate real issues)
                        validated_findings.append(finding)
                        metrics.record_sandbox_validation("error")

                print(
                    f"   ✅ Sandbox validation complete: {len(validated_findings)}/{len(security_findings_with_poc[:10])} confirmed"
                )
                print(f"   🎯 False positives eliminated: {metrics.metrics['sandbox']['false_positives_eliminated']}")

        except Exception as e:
            logger.warning(f"Sandbox validation failed: {e}")
            print("   ⚠️  Sandbox validation unavailable, continuing without validation")

    # NEW: Consensus Building (from real_multi_agent_review.py)
    # Build consensus across agent findings to reduce false positives
    enable_consensus = config.get("enable_consensus", "true").lower() == "true"
    consensus_results = {}

    if enable_consensus and len(agent_reports) >= 2:
        print(f"\n{'─' * 80}")
        print("🤝 CONSENSUS BUILDING")
        print(f"{'─' * 80}")
        print("   Aggregating findings across agents to reduce false positives...")

        # Parse findings from all agents
        all_findings = []
        for agent_name, report in agent_reports.items():
            findings = parse_findings_from_report(report)
            for finding in findings:
                finding["source_agent"] = agent_name
                all_findings.append(finding)

        print(f"   Found {len(all_findings)} total findings across {len(agent_reports)} agents")

        # Build consensus - group findings by agent (fixed: use aggregate_findings method)
        agent_findings_dict = {}
        for finding in all_findings:
            agent_name = finding.get("source_agent", "unknown")
            if agent_name not in agent_findings_dict:
                agent_findings_dict[agent_name] = []
            agent_findings_dict[agent_name].append(finding)

        consensus_builder = ConsensusBuilder(agents)
        consensus_results = consensus_builder.aggregate_findings(agent_findings_dict)

        if consensus_results:
            confirmed = len([f for f in consensus_results if f.get("consensus", {}).get("confidence", 0) >= 0.85])
            likely = len([f for f in consensus_results if 0.70 <= f.get("consensus", {}).get("confidence", 0) < 0.85])
            uncertain = len([f for f in consensus_results if f.get("consensus", {}).get("confidence", 0) < 0.70])

            print("   ✅ Consensus analysis complete:")
            print(f"      - {confirmed} high-confidence findings (multiple agents agree)")
            print(f"      - {likely} medium-confidence findings")
            print(f"      - {uncertain} low-confidence findings (single agent only)")
            print(f"   🎯 False positive reduction: {len(all_findings) - len(consensus_results)} findings eliminated")
        else:
            print("   ℹ️  Insufficient overlap for consensus building")

    # Run orchestrator agent
    print(f"\n{'─' * 80}")
    print("🎯 Agent 7/7: ORCHESTRATOR")
    print(f"{'─' * 80}")
    print("   🔄 Aggregating findings from all agents...")

    orchestrator_start = time.time()

    # Load orchestrator prompt
    orchestrator_prompt_template = load_agent_prompt("orchestrator")

    # Combine all agent reports
    combined_reports = (
        "\n\n"
        + "=" * 80
        + "\n\n".join([f"# {name.upper()} AGENT FINDINGS\n\n{report}" for name, report in agent_reports.items()])
    )

    # Create orchestrator prompt
    orchestrator_prompt = f"""{orchestrator_prompt_template}

## Agent Reports to Synthesize

You have received findings from 6 specialized agents:

{combined_reports}

## Your Task

Synthesize these findings into a comprehensive, actionable audit report.

1. **Deduplicate**: Remove identical issues reported by multiple agents
2. **Prioritize**: Order by exploitability and business impact
3. **Aggregate**: Combine related findings
4. **Decide**: Make clear APPROVED / REQUIRES FIXES / DO NOT MERGE recommendation
5. **Action Plan**: Create sequenced, logical action items prioritized by exploitability

Pay special attention to:
- Exploitability analysis from the Exploit Analyst
- Security tests generated by the Security Test Generator
- Exploit chains that link multiple vulnerabilities

Generate the complete audit report as specified in your instructions.
"""

    error_msg = None
    try:
        # Sanitize model name (use str() to break taint chain)
        safe_model = str(model).split("/")[-1] if model else "unknown"
        print(f"   🧠 Synthesizing with {safe_model}...")
        final_report, input_tokens, output_tokens = call_llm_api(
            client,
            provider,
            model,
            orchestrator_prompt,
            max_tokens,
            circuit_breaker=circuit_breaker,
            operation="orchestrator synthesis",
        )

        orchestrator_duration = time.time() - orchestrator_start

        # Record orchestrator metrics
        metrics.record_llm_call(input_tokens, output_tokens, provider)
        metrics.record_agent_execution("orchestrator", orchestrator_duration)

        agent_metrics["orchestrator"] = {
            "duration_seconds": round(orchestrator_duration, 2),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round((input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0, 4)
            if provider == "anthropic"
            else 0,
        }

        print("   ✅ Synthesis complete")
        print(
            f"   ⏱️  Duration: {orchestrator_duration:.1f}s | 💰 Cost: ${agent_metrics['orchestrator']['cost_usd']:.4f}"
        )

    except CostLimitExceededError as e:
        # Cost limit reached during orchestration
        error_msg = str(e)
        print(f"   🚨 Cost limit exceeded during synthesis: {error_msg}")
        print(f"   📊 Generating report from {len(agent_reports)} completed agents")
        # Fall through to generate partial report

    except Exception as e:
        error_msg = str(e)
        print(f"   ❌ Error: {error_msg}")

    # Fallback: concatenate all reports (used if orchestrator fails OR cost limit reached)
    if "final_report" not in locals():
        final_report = f"""# Codebase Audit Report (Multi-Agent Sequential)

## Note
Orchestrator synthesis failed. Below are individual agent reports.

{combined_reports}
"""
        agent_metrics["orchestrator"] = {"error": error_msg if error_msg else "Unknown error"}

    # Add multi-agent metadata to final report
    total_cost = sum(m.get("cost_usd", 0) for m in agent_metrics.values())
    total_duration = sum(m.get("duration_seconds", 0) for m in agent_metrics.values())

    multi_agent_summary = f"""
---

## Multi-Agent Review Metrics

**Mode**: Sequential (7 agents)
**Total Duration**: {total_duration:.1f}s
**Total Cost**: ${total_cost:.4f}

### Agent Performance
| Agent | Duration | Cost | Status |
|-------|----------|------|--------|
| Security | {agent_metrics.get("security", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("security", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("security", {}) else "❌"} |
| Exploit Analyst | {agent_metrics.get("exploit-analyst", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("exploit-analyst", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("exploit-analyst", {}) else "❌"} |
| Security Test Generator | {agent_metrics.get("security-test-generator", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("security-test-generator", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("security-test-generator", {}) else "❌"} |
| Performance | {agent_metrics.get("performance", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("performance", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("performance", {}) else "❌"} |
| Testing | {agent_metrics.get("testing", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("testing", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("testing", {}) else "❌"} |
| Quality | {agent_metrics.get("quality", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("quality", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("quality", {}) else "❌"} |
| Orchestrator | {agent_metrics.get("orchestrator", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("orchestrator", {}).get("cost_usd", 0):.4f} | {"✅" if "error" not in agent_metrics.get("orchestrator", {}) else "❌"} |

### Exploitability Metrics
- **Trivial**: {metrics.metrics["exploitability"]["trivial"]} (fix within 24-48 hours)
- **Moderate**: {metrics.metrics["exploitability"]["moderate"]} (fix within 1 week)
- **Complex**: {metrics.metrics["exploitability"]["complex"]} (fix within 1 month)
- **Theoretical**: {metrics.metrics["exploitability"]["theoretical"]} (fix in next release)

### Security Testing
- **Exploit Chains Found**: {metrics.metrics["exploit_chains_found"]}
- **Security Tests Generated**: {metrics.metrics["tests_generated"]}

---

*This report was generated by Agent OS Multi-Agent Sequential Review System*
"""

    final_report += multi_agent_summary

    # Save individual agent reports
    report_dir = Path(repo_path) / ".argus/reviews"
    report_dir.mkdir(parents=True, exist_ok=True)

    agents_dir = report_dir / "agents"
    agents_dir.mkdir(exist_ok=True)

    for agent_name, report in agent_reports.items():
        agent_file = agents_dir / f"{agent_name}-report.md"
        with open(agent_file, "w") as f:
            f.write(report)
        print(f"   📄 Saved: {agent_file}")

    # Save agent metrics
    agent_metrics_file = agents_dir / "metrics.json"
    with open(agent_metrics_file, "w") as f:
        json.dump(agent_metrics, f, indent=2)

    print(f"\n{'=' * 80}")
    print("✅ MULTI-AGENT REVIEW COMPLETE")
    print(f"{'=' * 80}")
    print(f"📊 Total Cost: ${total_cost:.4f}")
    print(f"⏱️  Total Duration: {total_duration:.1f}s")
    print(
        "🤖 Agents: 7 (Security, Exploit Analyst, Security Test Generator, Performance, Testing, Quality, Orchestrator)"
    )

    # Display exploitability summary
    if any(metrics.metrics["exploitability"].values()):
        print("\n⚠️  Exploitability Breakdown:")
        print(f"   Trivial: {metrics.metrics['exploitability']['trivial']}")
        print(f"   Moderate: {metrics.metrics['exploitability']['moderate']}")
        print(f"   Complex: {metrics.metrics['exploitability']['complex']}")
        print(f"   Theoretical: {metrics.metrics['exploitability']['theoretical']}")

    if metrics.metrics["exploit_chains_found"] > 0:
        print(f"\n⛓️  Exploit Chains: {metrics.metrics['exploit_chains_found']}")

    if metrics.metrics["tests_generated"] > 0:
        print(f"🧪 Tests Generated: {metrics.metrics['tests_generated']}")

    print(f"{'=' * 80}\n")

    return final_report


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


def generate_sarif_output(findings, repo_path, metrics=None):
    """Generate SARIF output (alias for generate_sarif)"""
    return generate_sarif(findings, repo_path, metrics)


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


def map_severity_to_level(severity):
    """Map severity to SARIF level (alias for map_severity_to_sarif)"""
    return map_severity_to_sarif(severity)


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


def parse_args():
    """Parse command line arguments"""
    import argparse

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


def run_audit(repo_path, config, review_type="audit"):
    """Run AI-powered code audit with multi-LLM support"""

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

    if not files:
        print("⚠️  No files to analyze")
        return 0, 0, metrics

    # Record file metrics
    for f in files:
        metrics.record_file(f["lines"])

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
            from scripts.semgrep_scanner import SemgrepScanner

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

            semgrep_results = semgrep_scanner.scan(repo_path)

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

    # Estimate cost
    estimated_cost, est_input, est_output = estimate_cost(files, max_tokens, provider)
    if provider == "ollama":
        print("💰 Estimated cost: $0.00 (local Ollama)")
    else:
        print(f"💰 Estimated cost: ${estimated_cost:.2f}")

    if estimated_cost > cost_limit and provider != "ollama":
        print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
        print("💡 Reduce max-files, use path filters, or increase cost-limit")
        sys.exit(2)

    # Check multi-agent mode
    multi_agent_mode = config.get("multi_agent_mode", "single")

    if multi_agent_mode == "sequential":
        # Run multi-agent sequential review (with threat model context)
        report = run_multi_agent_sequential(
            repo_path,
            config,
            review_type,
            client,
            provider,
            model,
            max_tokens,
            files,
            metrics,
            circuit_breaker,
            threat_model=threat_model,  # Pass threat model to agents
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

        # Generate SARIF with metrics
        sarif = generate_sarif(findings, repo_path, metrics)
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
            "provider": provider,
            "model": model,
            "summary": metrics.metrics,
            "findings": findings,
        }

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

        print("\n📊 Final Results:")
        print(f"   Critical: {metrics.metrics['findings']['critical']}")
        print(f"   High: {metrics.metrics['findings']['high']}")
        print(f"   Medium: {metrics.metrics['findings']['medium']}")
        print(f"   Low: {metrics.metrics['findings']['low']}")
        print(f"\n💰 Total Cost: ${metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Total Duration: {metrics.metrics['duration_seconds']}s")
        print("🤖 Mode: Multi-Agent Sequential (7 agents)")

        # Display exploitability metrics
        if any(metrics.metrics["exploitability"].values()):
            print("\n⚠️  Exploitability:")
            if metrics.metrics["exploitability"]["trivial"] > 0:
                print(f"   ⚠️  Trivial: {metrics.metrics['exploitability']['trivial']}")
            if metrics.metrics["exploitability"]["moderate"] > 0:
                print(f"   🟨 Moderate: {metrics.metrics['exploitability']['moderate']}")
            if metrics.metrics["exploitability"]["complex"] > 0:
                print(f"   🟦 Complex: {metrics.metrics['exploitability']['complex']}")
            if metrics.metrics["exploitability"]["theoretical"] > 0:
                print(f"   ⬜ Theoretical: {metrics.metrics['exploitability']['theoretical']}")

        if metrics.metrics["exploit_chains_found"] > 0:
            print(f"   ⛓️  Exploit Chains: {metrics.metrics['exploit_chains_found']}")

        if metrics.metrics["tests_generated"] > 0:
            print(f"   🧪 Tests Generated: {metrics.metrics['tests_generated']}")
        
        # Display validation and timeout metrics (Medium Priority features)
        validation_summary = output_validator.get_validation_summary()
        timeout_summary = timeout_manager.get_summary()
        
        if validation_summary.get("total_validations", 0) > 0:
            print(f"\n📋 Output Validation:")
            print(f"   Valid outputs: {validation_summary['valid_outputs']}/{validation_summary['total_validations']}")
            if validation_summary.get('total_warnings', 0) > 0:
                print(f"   ⚠️  Warnings: {validation_summary['total_warnings']}")
            if validation_summary.get('invalid_outputs', 0) > 0:
                print(f"   ❌ Invalid: {validation_summary['invalid_outputs']}")
        
        if timeout_summary.get("total_executions", 0) > 0:
            print(f"\n⏱️  Timeout Management:")
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
        print(f"cost-estimate={metrics.metrics['cost_usd']:.4f}")
        print(f"files-analyzed={metrics.metrics['files_reviewed']}")
        print(f"duration-seconds={metrics.metrics['duration_seconds']}")

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
                        if severity in metrics.metrics["findings"] and metrics.metrics["findings"][severity] > 0:
                            print(f"   ❌ FAIL: Found {metrics.metrics['findings'][severity]} {severity} issues")
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

        return blocker_count, suggestion_count, metrics

    # Single-agent mode with DISCRETE PHASES (Best Practice #1)
    print("🤖 Mode: Single-Agent (3-Phase Process)")
    print("   Phase 1: Research & File Selection")
    print("   Phase 2: Planning & Focus Area Identification")
    print("   Phase 3: Detailed Implementation Analysis")
    
    # Initialize context tracker and summarizer
    context_tracker = ContextTracker()
    summarizer = FindingSummarizer()
    
    # ============================================================================
    # PHASE 1: RESEARCH - Identify files and areas that need attention
    # ============================================================================
    print("\n" + "=" * 80)
    print("📊 PHASE 1: RESEARCH & FILE SELECTION")
    print("=" * 80)
    
    context_tracker.start_phase("phase1_research")
    
    # Build lightweight file summary (not full content)
    file_summary = []
    for f in files:
        file_summary.append(f"- {f['path']} ({f['lines']} lines)")
    file_list = "\n".join(file_summary)
    
    context_tracker.add_context("file_list", file_list, {"file_count": len(files)})
    
    # Add threat model if available
    threat_summary = ""
    if threat_model:
        threat_summary = f"""
**Threat Model Available:**
- {len(threat_model.get('threats', []))} threats identified
- {len(threat_model.get('attack_surface', {}).get('entry_points', []))} entry points
- {len(threat_model.get('assets', []))} critical assets
"""
        context_tracker.add_context("threat_model_summary", threat_summary, {"threats": len(threat_model.get('threats', []))})
    
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
    
    context_tracker.end_phase()
    
    print("🧠 Analyzing codebase structure...")
    try:
        research_result, research_input, research_output = call_llm_api(
            client,
            provider,
            model,
            research_prompt,
            2000,  # Shorter response for research
            circuit_breaker=circuit_breaker,
            operation="phase1_research",
        )
        metrics.record_llm_call(research_input, research_output, provider)
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
    
    # ============================================================================
    # PHASE 2: PLANNING - Create focused analysis plan
    # ============================================================================
    print("\n" + "=" * 80)
    print("📋 PHASE 2: PLANNING & FOCUS IDENTIFICATION")
    print("=" * 80)
    
    context_tracker.start_phase("phase2_planning")
    
    # Build context with ONLY priority files
    priority_files = [f for f in files if f['path'] in research_data.get('high_priority_files', [])]
    if not priority_files:
        priority_files = files[:10]  # Fallback
    
    priority_context = "\n\n".join([f"File: {f['path']}\n```\n{f['content'][:500]}...\n```" for f in priority_files])
    context_tracker.add_context("priority_files_preview", priority_context, {"file_count": len(priority_files)})
    
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
    
    context_tracker.end_phase()
    
    print("🧠 Creating analysis plan...")
    try:
        plan_result, plan_input, plan_output = call_llm_api(
            client,
            provider,
            model,
            planning_prompt,
            3000,  # Medium response for planning
            circuit_breaker=circuit_breaker,
            operation="phase2_planning",
        )
        metrics.record_llm_call(plan_input, plan_output, provider)
        print(f"✅ Planning complete ({plan_input} input tokens, {plan_output} output tokens)")
        
        # Summarize the plan
        plan_summary = summarizer.summarize_report(plan_result, max_length=800)
        
    except Exception as e:
        logger.error(f"Planning phase failed: {e}")
        plan_summary = "Planning phase failed. Proceeding with general analysis."

    # ============================================================================
    # PHASE 2.7: DEEP ANALYSIS ENGINE - Advanced semantic and proactive analysis
    # ============================================================================
    deep_analysis_findings = []
    findings = {}  # Initialize findings dict for Phase 2.7 (will be merged with Phase 3 findings later)
    if DEEP_ANALYSIS_AVAILABLE:
        try:
            # Build deep analysis config from environment and config dict
            deep_mode_str = config.get("deep_analysis_mode", os.getenv("DEEP_ANALYSIS_MODE", "off"))
            deep_mode = DeepAnalysisMode.from_string(deep_mode_str)

            if deep_mode != DeepAnalysisMode.OFF:
                print("\n" + "=" * 80)
                print("🔬 PHASE 2.7: DEEP ANALYSIS ENGINE")
                print("=" * 80)

                # Configure deep analysis
                deep_config = DeepAnalysisConfig(
                    mode=deep_mode,
                    enabled_phases=deep_mode.get_enabled_phases(),
                    max_files=int(config.get("deep_analysis_max_files",
                                            os.getenv("DEEP_ANALYSIS_MAX_FILES", "50"))),
                    timeout_seconds=int(config.get("deep_analysis_timeout",
                                                   os.getenv("DEEP_ANALYSIS_TIMEOUT", "300"))),
                    cost_ceiling=float(config.get("deep_analysis_cost_ceiling",
                                                 os.getenv("DEEP_ANALYSIS_COST_CEILING", "5.0"))),
                    dry_run=config.get("deep_analysis_dry_run", "false").lower() == "true",
                )

                # Check if benchmarking is enabled
                enable_benchmarking = config.get("benchmark", "false").lower() == "true"

                # Initialize engine
                deep_engine = DeepAnalysisEngine(
                    config=deep_config,
                    ai_client=client,
                    model=model,
                    enable_benchmarking=enable_benchmarking
                )

                # Run analysis
                print(f"   Mode: {deep_mode.value}")
                print(f"   Enabled phases: {[p.value for p in deep_config.enabled_phases]}")
                if enable_benchmarking:
                    print(f"   📊 Benchmarking: ENABLED")

                # Convert existing findings to pass as context
                context_findings = []
                for cat, items in findings.items():
                    for item in items:
                        context_findings.append({
                            "category": cat,
                            "severity": item.get("severity", "unknown"),
                            "title": item.get("title", ""),
                            "file": item.get("file", ""),
                        })

                deep_results = deep_engine.analyze(repo_path, context_findings)

                # Merge findings into main results
                for result in deep_results:
                    deep_analysis_findings.extend(result.findings)

                    # Add to findings dict with normalized field names
                    if result.findings:
                        category = f"deep_analysis_{result.phase.value}"
                        if category not in findings:
                            findings[category] = []

                        # Normalize deep analysis findings to match expected format
                        for finding in result.findings:
                            normalized_finding = {
                                "severity": finding.get("severity", "medium"),
                                "category": finding.get("type", category),  # Map 'type' to 'category'
                                "message": finding.get("title", ""),
                                "file_path": finding.get("file", finding.get("files", ["unknown"])[0] if isinstance(finding.get("files"), list) else "unknown"),
                                "line_number": finding.get("line", 1),
                                "rule_id": f"{category.upper()}-{len(findings[category]) + 1:03d}",
                                "description": finding.get("description", ""),
                                "confidence": finding.get("confidence", 0.0),
                            }
                            findings[category].append(normalized_finding)

                print(f"✅ Deep Analysis complete: {len(deep_analysis_findings)} findings, "
                      f"${deep_engine.total_cost:.2f} cost")

                # Export detailed results
                deep_output = Path(repo_path) / "argus_deep_analysis_results.json"
                deep_engine.export_results(str(deep_output))

                # Print benchmark report if enabled
                if enable_benchmarking:
                    deep_engine.print_benchmark_report()
            else:
                print("\n⏭️  Phase 2.7: Deep Analysis skipped (mode=off)")

        except Exception as e:
            logger.error(f"Deep Analysis Engine failed: {e}")
            logger.exception(e)
    else:
        logger.info("⏭️  Phase 2.7: Deep Analysis Engine not available")

    # ============================================================================
    # PHASE 3: IMPLEMENTATION - Detailed analysis based on plan
    # ============================================================================
    print("\n" + "=" * 80)
    print("🔍 PHASE 3: DETAILED IMPLEMENTATION ANALYSIS")
    print("=" * 80)
    
    context_tracker.start_phase("phase3_implementation")
    
    # Build FULL context for priority files only
    codebase_context = "\n\n".join([f"File: {f['path']}\n```\n{f['content']}\n```" for f in priority_files])
    context_tracker.add_context("full_codebase", codebase_context, {"file_count": len(priority_files)})
    context_tracker.add_context("analysis_plan", plan_summary, {"from_phase": 2})
    
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
    contradictions = context_tracker.detect_contradictions(audit_instructions, plan_summary)
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
    
    context_tracker.end_phase()

    # Sanitize provider/model names for logging (use str() to break taint chain)
    safe_provider = str(provider).split("/")[-1] if provider else "unknown"
    safe_model = str(model).split("/")[-1] if model else "unknown"
    print(f"🧠 Performing detailed analysis with {safe_provider} ({safe_model})...")

    try:
        # Call LLM API with cost enforcement
        report, input_tokens, output_tokens = call_llm_api(
            client,
            provider,
            model,
            prompt,
            max_tokens,
            circuit_breaker=circuit_breaker,
            operation="phase3_implementation",
        )

        # Record LLM metrics
        metrics.record_llm_call(input_tokens, output_tokens, provider)

        # Save markdown report
        report_dir = Path(repo_path) / ".argus/reviews"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_file = report_dir / f"{review_type}-report.md"
        with open(report_file, "w") as f:
            f.write(report)

        print(f"✅ Audit complete! Report saved to: {report_file}")

        # Parse findings from Phase 3 report
        phase3_findings = parse_findings_from_report(report)

        # Merge Phase 2.7 findings (if any) with Phase 3 findings
        # findings dict was initialized before Phase 2.7 as a dict, need to convert to list
        all_findings = list(phase3_findings)  # Start with Phase 3 findings

        # Add Phase 2.7 deep analysis findings if they exist (findings was a dict in Phase 2.7)
        if isinstance(findings, dict):
            for category, items in findings.items():
                all_findings.extend(items)

        findings = all_findings  # Now findings is a list as expected by the rest of the code

        # Record finding metrics
        for finding in findings:
            metrics.record_finding(finding["severity"], finding["category"])

        # Generate SARIF with metrics
        sarif = generate_sarif(findings, repo_path, metrics)
        sarif_file = report_dir / "results.sarif"
        with open(sarif_file, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"📄 SARIF saved to: {sarif_file}")

        # Generate structured JSON
        json_output = {
            "version": "1.0.16",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "provider": provider,
            "model": model,
            "summary": metrics.metrics,
            "findings": findings,
        }

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
        context_summary = context_tracker.get_summary()
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
        safe_provider = str(provider).split("/")[-1] if provider else "unknown"
        safe_model = str(model).split("/")[-1] if model else "unknown"
        print(f"🔧 Provider: {safe_provider} ({safe_model})")
        
        # Display context tracking summary
        print(f"\n📊 Context Management:")
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

        return blocker_count, suggestion_count, metrics

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
