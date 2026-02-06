"""
AI Enrichment Module for Hybrid Security Analysis.

This module contains AI-powered enrichment functions that enhance security findings
with LLM analysis, CWE mapping, exploitability assessment, and IRIS semantic analysis.

Functions:
    enrich_with_ai: Enrich findings with Claude/OpenAI analysis
    enrich_with_iris: Enrich findings with IRIS semantic analysis
    analyze_xss_output_destination: Determine XSS output context
    build_enrichment_prompt: Build AI analysis prompt with project context
    parse_ai_response: Parse AI response JSON

Extracted from hybrid_analyzer.py for better modularity.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from hybrid.models import HybridFinding

# IRIS analyzer imports (optional)
try:
    from iris_analyzer import IRISAnalyzer, IRISFinding, load_code_context
    IRIS_AVAILABLE = True
except ImportError:
    IRIS_AVAILABLE = False
    IRISAnalyzer = None  # type: ignore
    IRISFinding = None  # type: ignore
    load_code_context = None  # type: ignore

# Project context imports (optional)
try:
    from project_context_detector import ProjectContext
    PROJECT_CONTEXT_AVAILABLE = True
except ImportError:
    PROJECT_CONTEXT_AVAILABLE = False
    ProjectContext = None  # type: ignore


logger = logging.getLogger(__name__)


def enrich_with_ai(
    ai_client: Any,
    findings: list[HybridFinding],
    project_context: Optional[Any],
    logger: logging.Logger
) -> list[HybridFinding]:
    """
    Enrich findings with AI analysis (Claude/OpenAI)

    For each finding:
    - Map to CWE (if not already mapped)
    - Assess exploitability (trivial/moderate/complex/theoretical)
    - Generate remediation recommendations
    - Adjust severity based on context

    Args:
        ai_client: AI client instance (with call_llm_api method)
        findings: List of findings to enrich
        project_context: Optional project context for context-aware analysis
        logger: Logger instance

    Returns:
        List of enriched findings
    """
    if not ai_client:
        logger.warning("⚠️  AI client not available, skipping enrichment")
        return findings

    enriched = []
    enriched_count = 0

    logger.info(f"   🤖 Enriching {len(findings)} findings with AI analysis...")

    for finding in findings:
        # Skip if already enriched
        if finding.llm_enriched:
            enriched.append(finding)
            continue

        try:
            # Build prompt for AI analysis
            prompt = build_enrichment_prompt(finding, project_context, finding.file_path, logger)

            # Call AI model
            response, _input_tokens, _output_tokens = ai_client.call_llm_api(
                prompt=prompt,
                max_tokens=1000,
                operation=f"Enrich finding {finding.finding_id}"
            )

            # Parse AI response
            analysis = parse_ai_response(response, logger)

            # Update finding with AI insights
            if analysis:
                if analysis.get("cwe_id") and not finding.cwe_id:
                    finding.cwe_id = analysis["cwe_id"]

                if analysis.get("exploitability"):
                    finding.exploitability = analysis["exploitability"]

                if analysis.get("severity_assessment"):
                    # AI can upgrade/downgrade severity based on context
                    original_severity = finding.severity
                    finding.severity = analysis["severity_assessment"]
                    if original_severity != finding.severity:
                        logger.debug(f"   Severity adjusted: {original_severity} → {finding.severity}")

                if analysis.get("recommendation"):
                    finding.recommendation = analysis["recommendation"]

                if analysis.get("references"):
                    finding.references.extend(analysis["references"])

                finding.llm_enriched = True
                enriched_count += 1
                logger.debug(
                    f"   ✅ Enriched {finding.finding_id}: CWE={finding.cwe_id}, exploitability={finding.exploitability}"
                )

            enriched.append(finding)

        except Exception as e:
            logger.warning(f"⚠️  AI enrichment failed for {finding.finding_id}: {e}")
            enriched.append(finding)

    if enriched_count > 0:
        logger.info(f"   ✅ AI enriched {enriched_count}/{len(findings)} findings")
    else:
        logger.info("   ℹ️  No findings were AI-enriched")

    return enriched


def enrich_with_iris(
    iris_analyzer: Any,
    findings: list[HybridFinding],
    target_path: str,
    project_context: Optional[Any],
    logger: logging.Logger
) -> list[HybridFinding]:
    """
    Enrich findings with IRIS semantic analysis

    IRIS (arXiv 2405.17238) provides multi-step LLM reasoning:
    1. Data flow analysis
    2. Vulnerability assessment
    3. Impact analysis
    4. Confidence scoring

    Only analyzes CRITICAL/HIGH severity findings to manage cost.

    Args:
        iris_analyzer: IRIS analyzer instance
        findings: List of findings to analyze
        target_path: Repository root path for loading code context
        project_context: Optional project context
        logger: Logger instance

    Returns:
        Findings with IRIS analysis results
    """
    if not iris_analyzer:
        logger.warning("⚠️  IRIS analyzer not available")
        return findings

    enriched = []
    analyzed_count = 0

    # Focus on high-severity findings
    high_severity_findings = [
        f for f in findings
        if f.severity.lower() in ['critical', 'high']
    ]

    logger.info(f"   🎯 Analyzing {len(high_severity_findings)}/{len(findings)} CRITICAL/HIGH severity findings")

    for finding in findings:
        # Skip findings that aren't high severity
        if finding.severity.lower() not in ['critical', 'high']:
            enriched.append(finding)
            continue

        try:
            # Skip if already IRIS verified
            if finding.iris_verified:
                enriched.append(finding)
                continue

            # Build finding dict for IRIS
            finding_dict = {
                'id': finding.finding_id,
                'type': finding.title,
                'severity': finding.severity,
                'cwe_id': finding.cwe_id,
                'description': finding.description,
                'file_path': finding.file_path,
                'line_number': finding.line_number or 1,
            }

            # Load code context
            code_context = ""
            if finding.file_path and Path(finding.file_path).exists():
                # Make path absolute if relative to target
                file_path = finding.file_path
                if not Path(file_path).is_absolute():
                    file_path = str(Path(target_path) / file_path)

                code_context = load_code_context(
                    file_path=file_path,
                    line_number=finding.line_number or 1,
                    lines_before=20,
                    lines_after=20
                )
            else:
                logger.debug(f"   ⚠️  Skipping IRIS for {finding.finding_id}: file not found")
                enriched.append(finding)
                continue

            # Repository context (frameworks, etc.)
            repo_context = {}
            if project_context:
                repo_context = {
                    'frameworks': [project_context.framework] if project_context.framework else [],
                    'type': project_context.type,
                    'runtime': project_context.runtime,
                }

            # Run IRIS analysis
            logger.debug(f"   🔬 IRIS analyzing {finding.finding_id}...")
            iris_finding = iris_analyzer.analyze_finding(
                finding=finding_dict,
                code_context=code_context,
                repo_context=repo_context
            )

            # Update finding with IRIS results
            if iris_finding.iris_verified:
                finding.iris_verified = True
                finding.iris_confidence = iris_finding.iris_analysis.confidence
                finding.iris_verdict = iris_finding.iris_analysis.verdict.value

                # Update exploitability if IRIS has higher confidence
                if iris_finding.iris_analysis.exploitation_complexity != "UNKNOWN":
                    complexity_map = {
                        "LOW": "trivial",
                        "MEDIUM": "moderate",
                        "HIGH": "complex"
                    }
                    finding.exploitability = complexity_map.get(
                        iris_finding.iris_analysis.exploitation_complexity,
                        finding.exploitability
                    )

                # Add IRIS attack vector to description if available
                if iris_finding.iris_analysis.attack_vector:
                    finding.description += f"\n\n**IRIS Attack Vector:** {iris_finding.iris_analysis.attack_vector}"

                analyzed_count += 1
                logger.debug(
                    f"   ✅ IRIS: {finding.finding_id} - {iris_finding.iris_verdict} "
                    f"(confidence: {iris_finding.iris_confidence:.2f})"
                )
            else:
                logger.debug(f"   ℹ️  IRIS: {finding.finding_id} - not verified")

            enriched.append(finding)

        except Exception as e:
            logger.warning(f"⚠️  IRIS analysis failed for {finding.finding_id}: {e}")
            enriched.append(finding)

    if analyzed_count > 0:
        logger.info(f"   ✅ IRIS verified {analyzed_count}/{len(high_severity_findings)} high-severity findings")
    else:
        logger.info("   ℹ️  No findings were IRIS-verified")

    return enriched


def analyze_xss_output_destination(finding: HybridFinding, target_path: str, logger: logging.Logger) -> Optional[str]:
    """
    Analyze XSS finding to determine output destination (browser vs. terminal)

    Args:
        finding: XSS finding to analyze
        target_path: Repository root path (unused, kept for API compatibility)
        logger: Logger instance

    Returns:
        Output destination: 'browser', 'terminal', 'console', or None if unclear
    """
    if not finding.file_path or not Path(finding.file_path).exists():
        return None

    try:
        # Read file content around the finding
        with open(finding.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Browser/HTML output patterns
        browser_patterns = [
            ".innerHTML",
            ".appendChild",
            "document.write",
            "render_template",
            "res.send(",
            "res.render(",
            "HttpResponse(",
            "response.write",
            "<script>",
            "dangerouslySetInnerHTML",
        ]

        # Terminal/console output patterns
        terminal_patterns = [
            "console.log(",
            "print(",
            "println(",
            "fmt.Println(",
            "puts ",
            "echo ",
            "logger.",
            "logging.",
            "System.out.println",
        ]

        # Count matches
        browser_matches = sum(1 for pattern in browser_patterns if pattern in content)
        terminal_matches = sum(1 for pattern in terminal_patterns if pattern in content)

        # Determine destination based on patterns
        if browser_matches > terminal_matches:
            return "browser"
        elif terminal_matches > browser_matches:
            return "terminal"
        elif terminal_matches > 0:
            return "console"

        return None

    except Exception as e:
        logger.debug(f"Error analyzing XSS output destination for {finding.file_path}: {e}")
        return None


def build_enrichment_prompt(
    finding: HybridFinding,
    project_context: Optional[Any],
    target_path: str,
    logger: logging.Logger
) -> str:
    """
    Build prompt for AI to analyze a finding with project context

    Args:
        finding: Finding to analyze
        project_context: Optional project context for context-aware analysis
        target_path: Repository root path for XSS analysis
        logger: Logger instance

    Returns:
        Formatted prompt string for AI analysis
    """

    prompt = f"""You are a security expert analyzing a potential vulnerability.

**Finding Details:**
- ID: {finding.finding_id}
- Source Tool: {finding.source_tool}
- Current Severity: {finding.severity}
- Category: {finding.category}
- Title: {finding.title}
- Description: {finding.description}
- File: {finding.file_path}
- Line: {finding.line_number or "N/A"}
"""

    if finding.cve_id:
        prompt += f"- CVE: {finding.cve_id}\n"
    if finding.cvss_score:
        prompt += f"- CVSS Score: {finding.cvss_score}\n"

    # Add project context if available
    if project_context:
        prompt += f"""
**Project Context:**
- Type: {project_context.type}
- Runtime: {project_context.runtime}
- Output Destinations: {', '.join(project_context.output_destinations)}
- Framework: {project_context.framework or 'Unknown'}
"""

    # Add context-aware rules
    if project_context:
        prompt += """
**Context-Aware Rules:**
"""
        # CLI tool specific rules
        if project_context.is_cli_tool or 'terminal' in project_context.output_destinations:
            prompt += """- CLI Tools: XSS in console.log/print() is FALSE POSITIVE (terminal output, not browser-rendered HTML)
- CLI Tools: CSRF findings are FALSE POSITIVE (no browser sessions)
- Terminal output is not HTML-rendered, so XSS attacks do not apply
"""

        # Web app specific rules
        if project_context.is_web_app or 'browser' in project_context.output_destinations:
            prompt += """- Web Apps: XSS in HTML rendering (innerHTML, res.send, render_template) is TRUE POSITIVE
- Web Apps: CSRF protection should be evaluated for state-changing operations
- Browser-rendered content requires strict output encoding
"""

        # Library specific rules
        if project_context.is_library:
            prompt += """- Libraries: Consider how consuming applications might misuse the API
- Libraries: Security burden may be shared with consumers
"""

        # Special handling for XSS findings
        if (finding.title and "xss" in finding.title.lower()) or (finding.description and "cross-site" in finding.description.lower()):
            output_dest = analyze_xss_output_destination(finding, target_path, logger)
            if output_dest == "terminal" or output_dest == "console":
                prompt += f"""
**⚠️  IMPORTANT XSS ANALYSIS:**
- Code analysis shows output goes to TERMINAL/CONSOLE (e.g., console.log, print)
- Terminal output is NOT browser-rendered HTML
- This XSS finding is likely a FALSE POSITIVE for CLI tools
- Downgrade severity to LOW or mark as false positive unless output reaches browser
"""

    prompt += """
**Your Task:**
Analyze this security finding and provide:

1. **CWE Mapping**: Map to the most specific CWE ID (e.g., CWE-89 for SQL Injection)
2. **Exploitability**: Assess how easy it is to exploit (trivial/moderate/complex/theoretical)
3. **Severity Assessment**: Confirm or adjust severity (critical/high/medium/low) based on:
   - Real-world exploitability in THIS PROJECT CONTEXT
   - Potential impact
   - Attack complexity
   - Required privileges
   - Whether the vulnerability actually applies to this project type
4. **Remediation**: Provide specific, actionable fix recommendation
5. **References**: Include relevant CWE/OWASP/security reference URLs

**Response Format (JSON only, no markdown):**
{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Brief CWE name",
  "exploitability": "trivial|moderate|complex|theoretical",
  "exploitability_reason": "Brief explanation considering project context",
  "severity_assessment": "critical|high|medium|low",
  "severity_reason": "Why this severity (considering project context)",
  "recommendation": "Specific fix (code snippet if applicable)",
  "references": ["https://cwe.mitre.org/...", "https://owasp.org/..."]
}

Respond with JSON only:"""

    return prompt


def parse_ai_response(response: str, logger: logging.Logger) -> Optional[dict[str, Any]]:
    """
    Parse AI response JSON

    Args:
        response: Raw AI response text
        logger: Logger instance

    Returns:
        Parsed analysis dict or None if parsing fails
    """
    try:
        # Try to extract JSON from response
        # Sometimes models add extra text, so find the JSON part

        # Look for JSON object
        json_match = re.search(r"\{.*\}", response, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            analysis = json.loads(json_str)

            # Validate required fields
            if "cwe_id" in analysis or "exploitability" in analysis:
                return analysis
            else:
                logger.warning("AI response missing required fields")
                return None
        else:
            logger.warning("Could not find JSON in AI response")
            return None

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI response as JSON: {e}")
        logger.debug(f"Response was: {response[:200]}")
        return None
    except Exception as e:
        logger.warning(f"Error parsing AI response: {e}")
        return None


__all__ = [
    "enrich_with_ai",
    "enrich_with_iris",
    "analyze_xss_output_destination",
    "build_enrichment_prompt",
    "parse_ai_response",
]
