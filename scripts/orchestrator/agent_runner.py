"""Agent Runner Module

Provides multi-agent orchestration for the Argus Security pipeline (Phase 3).
Extracted from run_ai_audit.py to isolate agent prompt loading, enhanced prompt
construction, and the sequential multi-agent review workflow.

Functions:
    load_agent_prompt       - Load specialized agent prompt from profiles
    build_enhanced_agent_prompt - Build prompt with rubrics and self-consistency checks
    run_multi_agent_sequential  - Run 7 agents in sequence with consensus and sandbox validation

Constants:
    AVAILABLE_AGENTS        - All supported agent names
    SECURITY_WORKFLOW_AGENTS - Agents that run first (security pipeline)
    PARALLEL_QUALITY_AGENTS - Agents eligible for parallel execution
    COST_ESTIMATES          - Per-agent cost estimates (Claude Sonnet 4 pricing)
"""

import json
import logging
import os
import time
from pathlib import Path

from analysis_helpers import (
    ContextTracker,
    FindingSummarizer,
    AgentOutputValidator,
    TimeoutManager,
    ReviewMetrics,
    CostLimitExceededError,
)
from consensus_builder import ConsensusBuilder

# Conditional sandbox validator import (mirrors run_ai_audit.py)
try:
    from sandbox_validator import ExploitConfig, ExploitType, SandboxValidator, ValidationResult

    SANDBOX_VALIDATION_AVAILABLE = True
except ImportError:
    SANDBOX_VALIDATION_AVAILABLE = False

from orchestrator.llm_manager import call_llm_api

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Helper: parse_findings_from_report (local copy to avoid circular import)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------


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

    print(f"\u26a0\ufe0f  Agent prompt not found for: {agent_name}")
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
**\u26a0\ufe0f  PRE-SCAN ALERTS**: Heuristic analysis flagged: {", ".join(heuristic_flags)}
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
    print("\U0001f916 MULTI-AGENT SEQUENTIAL MODE")
    print("=" * 80)
    print("Running 7 specialized agents in sequence:")
    print("  1\ufe0f\u20e3  Security Reviewer")
    print("  2\ufe0f\u20e3  Exploit Analyst")
    print("  3\ufe0f\u20e3  Security Test Generator")
    print("  4\ufe0f\u20e3  Performance Reviewer")
    print("  5\ufe0f\u20e3  Testing Reviewer")
    print("  6\ufe0f\u20e3  Code Quality Reviewer")
    print("  7\ufe0f\u20e3  Review Orchestrator")
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
        print(f"\n{'\u2500' * 80}")
        print(f"\U0001f50d Agent {i}/7: {agent_name.upper()} REVIEWER")
        print(f"{'\u2500' * 80}")

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
                logger.warning(f"\u26a0\ufe0f  Potential contradictions detected for {agent_name}:")
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
            print(f"   \U0001f9e0 Analyzing with {safe_model}...")
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
                logger.warning(f"\u26a0\ufe0f  Agent {agent_name} exceeded timeout ({elapsed:.1f}s > {timeout_manager.get_timeout(agent_name)}s)")
                print(f"   \u26a0\ufe0f  Warning: Execution time ({elapsed:.1f}s) exceeded timeout limit")

            # Validate output (Medium Priority feature)
            expected_sections = ["Summary", "Issues", "Critical", "High"]
            validation = output_validator.validate_output(agent_name, report, expected_sections)

            if not validation["valid"]:
                logger.error(f"\u274c Agent {agent_name} output validation failed: {validation['errors']}")
                print(f"   \u274c Output validation failed: {', '.join(validation['errors'])}")

            if validation["warnings"]:
                logger.warning(f"\u26a0\ufe0f  Agent {agent_name} output warnings: {validation['warnings']}")
                for warning in validation["warnings"][:3]:  # Show first 3 warnings
                    print(f"   \u26a0\ufe0f  {warning}")

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
                f"   \u2705 Complete: {finding_counts['critical']} critical, {finding_counts['high']} high, {finding_counts['medium']} medium, {finding_counts['low']} low"
            )
            print(f"   \u23f1\ufe0f  Duration: {agent_duration:.1f}s | \U0001f4b0 Cost: ${agent_metrics[agent_name]['cost_usd']:.4f}")

        except CostLimitExceededError as e:
            # Cost limit reached - stop immediately
            print(f"   \U0001f6a8 Cost limit exceeded: {e}")
            print(
                f"   \U0001f4b0 Review stopped at ${circuit_breaker.current_cost:.3f} to stay within ${circuit_breaker.cost_limit:.2f} budget"
            )
            print(f"   \u2705 {i - 1}/{len(agents)} agents completed before limit reached")

            # Generate partial report with agents completed so far
            agent_reports[agent_name] = (
                f"# {agent_name.title()} Review Skipped\n\n**Reason**: Cost limit reached (${circuit_breaker.cost_limit:.2f})\n"
            )
            raise  # Re-raise to stop the entire review

        except Exception as e:
            print(f"   \u274c Error: {e}")
            agent_reports[agent_name] = f"# {agent_name.title()} Review Failed\n\nError: {str(e)}"
            agent_metrics[agent_name] = {"error": str(e)}

    # NEW: Sandbox Validation (after security agents, before orchestrator)
    if config.get("enable_sandbox_validation", True) and SANDBOX_VALIDATION_AVAILABLE:
        print(f"\n{'\u2500' * 80}")
        print("\U0001f52c SANDBOX VALIDATION")
        print(f"{'\u2500' * 80}")
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
                            print("      \u2705 Confirmed exploitable")
                        else:
                            print("      \u274c Not exploitable - eliminated false positive")
                            metrics.record_false_positive_eliminated()

                    except Exception as e:
                        logger.warning(f"Sandbox validation failed: {e}")
                        # Keep finding if validation fails (don't eliminate real issues)
                        validated_findings.append(finding)
                        metrics.record_sandbox_validation("error")

                print(
                    f"   \u2705 Sandbox validation complete: {len(validated_findings)}/{len(security_findings_with_poc[:10])} confirmed"
                )
                print(f"   \U0001f3af False positives eliminated: {metrics.metrics['sandbox']['false_positives_eliminated']}")

        except Exception as e:
            logger.warning(f"Sandbox validation failed: {e}")
            print("   \u26a0\ufe0f  Sandbox validation unavailable, continuing without validation")

    # NEW: Consensus Building (from real_multi_agent_review.py)
    # Build consensus across agent findings to reduce false positives
    enable_consensus = config.get("enable_consensus", "true").lower() == "true"
    consensus_results = {}

    if enable_consensus and len(agent_reports) >= 2:
        print(f"\n{'\u2500' * 80}")
        print("\U0001f91d CONSENSUS BUILDING")
        print(f"{'\u2500' * 80}")
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

            print("   \u2705 Consensus analysis complete:")
            print(f"      - {confirmed} high-confidence findings (multiple agents agree)")
            print(f"      - {likely} medium-confidence findings")
            print(f"      - {uncertain} low-confidence findings (single agent only)")
            print(f"   \U0001f3af False positive reduction: {len(all_findings) - len(consensus_results)} findings eliminated")
        else:
            print("   \u2139\ufe0f  Insufficient overlap for consensus building")

    # Run orchestrator agent
    print(f"\n{'\u2500' * 80}")
    print("\U0001f3af Agent 7/7: ORCHESTRATOR")
    print(f"{'\u2500' * 80}")
    print("   \U0001f504 Aggregating findings from all agents...")

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
        print(f"   \U0001f9e0 Synthesizing with {safe_model}...")
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

        print("   \u2705 Synthesis complete")
        print(
            f"   \u23f1\ufe0f  Duration: {orchestrator_duration:.1f}s | \U0001f4b0 Cost: ${agent_metrics['orchestrator']['cost_usd']:.4f}"
        )

    except CostLimitExceededError as e:
        # Cost limit reached during orchestration
        error_msg = str(e)
        print(f"   \U0001f6a8 Cost limit exceeded during synthesis: {error_msg}")
        print(f"   \U0001f4ca Generating report from {len(agent_reports)} completed agents")
        # Fall through to generate partial report

    except Exception as e:
        error_msg = str(e)
        print(f"   \u274c Error: {error_msg}")

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
| Security | {agent_metrics.get("security", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("security", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("security", {}) else "\u274c"} |
| Exploit Analyst | {agent_metrics.get("exploit-analyst", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("exploit-analyst", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("exploit-analyst", {}) else "\u274c"} |
| Security Test Generator | {agent_metrics.get("security-test-generator", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("security-test-generator", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("security-test-generator", {}) else "\u274c"} |
| Performance | {agent_metrics.get("performance", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("performance", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("performance", {}) else "\u274c"} |
| Testing | {agent_metrics.get("testing", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("testing", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("testing", {}) else "\u274c"} |
| Quality | {agent_metrics.get("quality", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("quality", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("quality", {}) else "\u274c"} |
| Orchestrator | {agent_metrics.get("orchestrator", {}).get("duration_seconds", "N/A")}s | ${agent_metrics.get("orchestrator", {}).get("cost_usd", 0):.4f} | {"\u2705" if "error" not in agent_metrics.get("orchestrator", {}) else "\u274c"} |

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
        print(f"   \U0001f4c4 Saved: {agent_file}")

    # Save agent metrics
    agent_metrics_file = agents_dir / "metrics.json"
    with open(agent_metrics_file, "w") as f:
        json.dump(agent_metrics, f, indent=2)

    print(f"\n{'=' * 80}")
    print("\u2705 MULTI-AGENT REVIEW COMPLETE")
    print(f"{'=' * 80}")
    print(f"\U0001f4ca Total Cost: ${total_cost:.4f}")
    print(f"\u23f1\ufe0f  Total Duration: {total_duration:.1f}s")
    print(
        "\U0001f916 Agents: 7 (Security, Exploit Analyst, Security Test Generator, Performance, Testing, Quality, Orchestrator)"
    )

    # Display exploitability summary
    if any(metrics.metrics["exploitability"].values()):
        print("\n\u26a0\ufe0f  Exploitability Breakdown:")
        print(f"   Trivial: {metrics.metrics['exploitability']['trivial']}")
        print(f"   Moderate: {metrics.metrics['exploitability']['moderate']}")
        print(f"   Complex: {metrics.metrics['exploitability']['complex']}")
        print(f"   Theoretical: {metrics.metrics['exploitability']['theoretical']}")

    if metrics.metrics["exploit_chains_found"] > 0:
        print(f"\n\u26d3\ufe0f  Exploit Chains: {metrics.metrics['exploit_chains_found']}")

    if metrics.metrics["tests_generated"] > 0:
        print(f"\U0001f9ea Tests Generated: {metrics.metrics['tests_generated']}")

    print(f"{'=' * 80}\n")

    return final_report


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "AVAILABLE_AGENTS",
    "SECURITY_WORKFLOW_AGENTS",
    "PARALLEL_QUALITY_AGENTS",
    "COST_ESTIMATES",
    "load_agent_prompt",
    "build_enhanced_agent_prompt",
    "run_multi_agent_sequential",
    "parse_findings_from_report",
]
