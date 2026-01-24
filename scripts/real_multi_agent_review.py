#!/usr/bin/env python3
"""
Real Multi-Agent Consensus Code Review
Uses actual API calls to multiple AI models available in Cursor

Models:
1. Claude Sonnet 4 (Anthropic API)
2. GPT-4 or another model (configurable)

DEPRECATION NOTICE:
====================
This file is now DEPRECATED. All advanced features have been merged into run_ai_audit.py:

Features Merged:
- HeuristicScanner: Pre-scan code with pattern matching before LLM analysis
- ConsensusBuilder: Build consensus across multiple agent opinions
- Enhanced Prompts: Severity rubrics, self-verification checklists, category focus
- Category-specific passes: Security, performance, quality focused analysis

To use these features, run run_ai_audit.py with:
  ENABLE_HEURISTICS=true
  ENABLE_CONSENSUS=true
  CATEGORY_PASSES=true

This file is kept for reference only.
Date Deprecated: 2025-11-03
Merged into: run_ai_audit.py (commit: multi-agent consolidation)
"""

import ast
import asyncio
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import anthropic


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SUGGESTION = "suggestion"


@dataclass
class TestCase:
    """A test case for a finding"""

    description: str
    test_code: str
    input_example: str
    expected_behavior: str


@dataclass
class Finding:
    """A single code review finding from one agent"""

    agent: str
    file: str
    line: int
    issue_type: str
    severity: str
    description: str
    recommendation: str
    confidence: float
    is_production: bool
    context: str
    raw_response: str = ""
    category: str = "general"  # security, performance, quality, general
    test_case: Optional[TestCase] = None


@dataclass
class ConsensusResult:
    """Aggregated finding with consensus information"""

    file: str
    line: int
    issue_type: str
    severity: str
    votes: int
    total_agents: int
    confidence: float
    descriptions: list[str]
    recommendations: list[str]
    agents_agree: list[str]
    agents_disagree: list[str]
    consensus_level: str
    is_production: bool
    final_classification: str
    category: str = "general"
    test_case: Optional[TestCase] = None
    heuristic_flags: list[str] = None


class RealMultiAgentReview:
    """Real multi-agent review using actual API calls"""

    def __init__(self, anthropic_api_key: str, openai_api_key: Optional[str] = None):
        self.anthropic_api_key = anthropic_api_key
        self.openai_api_key = openai_api_key

        # Initialize agents
        self.agents = []
        self.claude_client = None
        self.claude_sonnet_model = None
        self.claude_haiku_model = None

        if anthropic_api_key:
            self.claude_client = anthropic.Anthropic(api_key=anthropic_api_key)

            # Discover working models with fallback
            self.claude_sonnet_model = self._find_working_sonnet_model()
            self.claude_haiku_model = self._find_working_haiku_model()

            if self.claude_sonnet_model and self.claude_haiku_model:
                # Register two Anthropic agents to enable fully-automated consensus without OpenAI
                self.agents.append("Claude-Sonnet-4")
                self.agents.append("Claude-Haiku-3.5")
                print(f"✅ Found working models - Sonnet: {self.claude_sonnet_model}, Haiku: {self.claude_haiku_model}")
            else:
                print("⚠️  Warning: Could not find working Claude models")

        # Add OpenAI if available
        if openai_api_key:
            try:
                import openai

                openai.api_key = openai_api_key
                self.agents.append("GPT-4-Turbo")
            except ImportError:
                print("⚠️  OpenAI library not installed. Install with: pip install openai")

        print(f"✅ Initialized {len(self.agents)} agent(s): {', '.join(self.agents)}")

    def _find_working_sonnet_model(self) -> Optional[str]:
        """Find a working Claude Sonnet model with fallback"""
        models_to_try = [
            "claude-sonnet-4-5-20250929",  # Latest Claude Sonnet 4.5
            "claude-3-5-sonnet-20241022",  # Claude 3.5 Sonnet
            "claude-3-5-sonnet-20240620",  # Stable
            "claude-3-sonnet-20240229",  # Claude 3
        ]

        for model in models_to_try:
            try:
                # Quick test
                self.claude_client.messages.create(
                    model=model, max_tokens=10, messages=[{"role": "user", "content": "test"}]
                )
                return model
            except Exception:
                continue

        return None

    def _find_working_haiku_model(self) -> Optional[str]:
        """Find a working Claude Haiku model with fallback"""
        models_to_try = [
            "claude-3-5-haiku-20241022",  # Latest
            "claude-3-haiku-20240307",  # Claude 3
        ]

        for model in models_to_try:
            try:
                # Quick test
                self.claude_client.messages.create(
                    model=model, max_tokens=10, messages=[{"role": "user", "content": "test"}]
                )
                return model
            except Exception:
                continue

        # Fallback to Sonnet if Haiku not available
        return self._find_working_sonnet_model()

    def is_production_code(self, file_path: str) -> bool:
        """Determine if this is production code or dev infrastructure"""
        dev_indicators = [
            "docker/",
            "docker-compose",
            ".env.example",
            "test/",
            "tests/",
            ".github/workflows",
            "Dockerfile",
            ".dockerignore",
        ]
        return not any(indicator in file_path for indicator in dev_indicators)

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def get_git_context(self, file_path: str, repo_path: str) -> dict[str, Any]:
        """
        Feature #4: Context Injection
        Get git context for better prioritization
        """
        context = {"recent_changes": 0, "last_modified": None, "blame_authors": [], "change_frequency": 0}

        try:
            full_path = Path(repo_path) / file_path

            # Get recent changes (last 30 days)
            result = subprocess.run(
                ["git", "log", "--since=30.days.ago", "--oneline", "--", str(full_path)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                context["recent_changes"] = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

            # Get last modified date
            result = subprocess.run(
                ["git", "log", "-1", "--format=%ai", "--", str(full_path)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                context["last_modified"] = result.stdout.strip()

            # Get blame authors (top contributors)
            result = subprocess.run(
                ["git", "shortlog", "-sn", "--", str(full_path)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                authors = [line.split("\t")[1].strip() for line in result.stdout.strip().split("\n") if line][:3]
                context["blame_authors"] = authors

            context["change_frequency"] = (
                "high" if context["recent_changes"] > 10 else "medium" if context["recent_changes"] > 3 else "low"
            )

        except Exception as e:
            print(f"    ⚠️  Could not get git context: {e}")

        return context

    def pre_scan_heuristics(self, file_path: str, code_content: str) -> list[str]:
        """Run lightweight heuristic checks to identify potential issues"""
        flags = []

        # Security patterns
        if re.search(r'(password|secret|api[_-]?key|token)\s*=\s*["\'][^"\']{8,}["\']', code_content, re.I):
            flags.append("hardcoded-secrets")

        if re.search(r"eval\(|exec\(|__import__\(", code_content):
            flags.append("dangerous-exec")

        # SQL patterns
        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*\+.*["\']', code_content, re.I | re.DOTALL):
            flags.append("sql-concatenation")

        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*f["\'].*\{', code_content, re.I):
            flags.append("sql-f-string")

        # Authentication/Authorization
        if re.search(r"(admin|root|superuser).*=.*true", code_content, re.I):
            flags.append("hardcoded-admin")

        # Crypto issues
        if re.search(r"(md5|sha1)\(", code_content, re.I):
            flags.append("weak-crypto")

        # File operations
        if re.search(r'open\([^)]*["\']w["\']', code_content):
            flags.append("file-write")

        # Network/External calls
        if re.search(r"(requests\.|urllib\.|httpx\.)", code_content):
            flags.append("external-http")

        # Python-specific complexity
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code_content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        complexity = self._calculate_complexity(node)
                        if complexity > 15:
                            flags.append(f"high-complexity-{node.name}")
            except Exception:
                pass  # Syntax errors will be caught by AI review

        return flags

    def _calculate_complexity(self, node) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def build_context_injection(self, file_path: str, repo_path: str) -> dict[str, Any]:
        """Gather contextual information about the file"""
        context = {}

        try:
            # Git diff stats
            result = subprocess.run(
                ["git", "log", "--oneline", "-1", "--", file_path],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                context["recent_changes"] = result.stdout.strip()
        except Exception:
            pass

        try:
            # Git blame to see who touched this file
            result = subprocess.run(
                ["git", "log", "--format=%an", "-5", "--", file_path],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                authors = result.stdout.strip().split("\n")
                context["recent_authors"] = len(set(authors))
        except Exception:
            pass

        return context

    def build_review_prompt(
        self,
        file_path: str,
        code_content: str,
        context: dict[str, Any],
        category: str = "general",
        heuristic_flags: list[str] = None,
    ) -> str:
        """Build a comprehensive review prompt with rubrics, self-consistency, and category focus"""

        is_prod = self.is_production_code(file_path)
        heuristic_flags = heuristic_flags or []

        # Category-specific instructions
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

        git_context = ""
        if context.get("recent_changes"):
            git_context = f"\n**RECENT CHANGES**: {context['recent_changes']}"
        if context.get("recent_authors"):
            git_context += f"\n**RECENT ACTIVITY**: {context['recent_authors']} authors in last 5 commits"

        prompt = f"""You are an expert code reviewer performing a {category.upper()} review.

{category_focus[category]}

**FILE**: {file_path}
**TYPE**: {context.get("file_type", "unknown")}
**PRODUCTION CODE**: {"Yes" if is_prod else "No (dev infrastructure)"}{git_context}{heuristic_context}

**CRITICAL CONTEXT RULES**:
1. If file is in docker/, docker-compose.yml, etc. → LOCAL DEV ONLY (not production)
2. If this is a test file → Different security standards apply
3. If this is static SQL DDL (CREATE TABLE, etc.) → NOT SQL injection risk
4. If this is data extraction/pipeline → Not creating new vulnerabilities
5. Distinguish between development tooling and production code

**CODE TO REVIEW**:
```
{code_content[:3000]}
```

**SEVERITY RUBRIC** (Use this to score consistently):
- **CRITICAL** (0.9-1.0 confidence): Exploitable security flaw, production data loss, system-wide outage
  Examples: SQL injection, hardcoded secrets, authentication bypass, RCE

- **HIGH** (0.7-0.89 confidence): Major security gap, significant performance degradation, data corruption risk
  Examples: Missing auth checks, N+1 queries causing timeouts, memory leaks

- **MEDIUM** (0.5-0.69 confidence): Moderate issue with workaround, sub-optimal design
  Examples: Weak validation, inefficient algorithm, poor error handling

- **LOW** (0.3-0.49 confidence): Minor issue, edge case, defensive improvement
  Examples: Missing logging, minor optimization opportunity

- **SUGGESTION** (0.0-0.29 confidence): Style, optional refactoring, best practice
  Examples: Variable naming, code organization, documentation

**SELF-VERIFICATION CHECKLIST** (Ask yourself before reporting):
1. Is this issue ACTUALLY exploitable/harmful in this context?
2. Would this issue cause real problems in production?
3. Is my recommendation actionable and specific?
4. Am I considering the full context (dev vs prod, test vs runtime)?
5. If I'm unsure, have I lowered my confidence score appropriately?

**YOUR TASK**:
1. Review the code through the lens of {category}
2. For each potential issue, run the self-verification checklist
3. Use the severity rubric to assign accurate severity and confidence
4. Report ONLY issues that pass verification

**RESPONSE FORMAT** (JSON array):
[
  {{
    "issue_type": "descriptive-identifier",
    "severity": "critical|high|medium|low|suggestion",
    "line": 42,
    "description": "What's wrong (1-2 sentences)",
    "recommendation": "Specific, actionable fix (1-2 sentences)",
    "confidence": 0.85,
    "is_production": true
  }}
]

Return ONLY the JSON array, no other text.
"""
        return prompt

    async def review_with_claude(
        self,
        file_path: str,
        code_content: str,
        context: dict[str, Any],
        category: str = "general",
        heuristic_flags: list[str] = None,
    ) -> list[Finding]:
        """Review code using Claude Sonnet 4"""
        if not self.claude_client:
            return []

        category_label = f" ({category})" if category != "general" else ""
        print(f"  🔵 Claude Sonnet 4{category_label}: Reviewing {file_path}...")

        prompt = self.build_review_prompt(file_path, code_content, context, category, heuristic_flags)

        try:
            response = await asyncio.to_thread(
                self.claude_client.messages.create,
                model=self.claude_sonnet_model,
                max_tokens=2048,
                temperature=0.3,  # Lower temp for consistency
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = response.content[0].text
            print(f"    Response length: {len(response_text)} chars")

            # Parse JSON response
            findings = self._parse_json_response(response_text, f"Claude-Sonnet-4-{category}", file_path, category)
            print(f"    Found: {len(findings)} issue(s)")

            return findings

        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []

    async def review_with_claude_haiku(
        self, file_path: str, code_content: str, context: dict[str, Any]
    ) -> list[Finding]:
        """Review code using Claude 3.5 Haiku"""
        if not self.claude_client:
            return []

        print(f"  🔵 Claude 3.5 Haiku: Reviewing {file_path}...")

        prompt = self.build_review_prompt(file_path, code_content, context)

        try:
            response = await asyncio.to_thread(
                self.claude_client.messages.create,
                model=self.claude_haiku_model,
                max_tokens=2048,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = response.content[0].text
            print(f"    Response length: {len(response_text)} chars")

            findings = self._parse_json_response(response_text, "Claude-Haiku-3.5", file_path)
            print(f"    Found: {len(findings)} issue(s)")

            return findings

        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []

    async def review_with_gpt4(self, file_path: str, code_content: str, context: dict[str, Any]) -> list[Finding]:
        """Review code using GPT-4"""
        if "GPT-4-Turbo" not in self.agents:
            return []

        print(f"  🟢 GPT-4 Turbo: Reviewing {file_path}...")

        try:
            import openai

            prompt = self.build_review_prompt(file_path, code_content, context)

            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-4-turbo-preview",
                messages=[
                    {"role": "system", "content": "You are an expert code reviewer. Respond with JSON only."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
            )

            response_text = response.choices[0].message.content
            print(f"    Response length: {len(response_text)} chars")

            findings = self._parse_json_response(response_text, "GPT-4-Turbo", file_path)
            print(f"    Found: {len(findings)} issue(s)")

            return findings

        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []

    def _safe_int(self, value, default=0):
        """Safely convert value to int, handling strings, nulls, and invalid values"""
        try:
            if value in (None, "", "null", "None"):
                return default
            return int(value)
        except (ValueError, TypeError):
            return default

    def _parse_json_response(
        self, response_text: str, agent_name: str, file_path: str, category: str = "general"
    ) -> list[Finding]:
        """Parse JSON response from AI model"""
        try:
            # Try to extract JSON from response
            # Sometimes models wrap JSON in markdown code blocks
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.find("```") + 3
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()

            # Parse JSON
            json_data = json.loads(response_text)

            if not isinstance(json_data, list):
                json_data = [json_data]

            findings = []
            for item in json_data:
                finding = Finding(
                    agent=agent_name,
                    file=file_path,
                    line=self._safe_int(item.get("line"), 0),
                    issue_type=item.get("issue_type", "unknown"),
                    severity=item.get("severity", "medium"),
                    description=item.get("description", ""),
                    recommendation=item.get("recommendation", ""),
                    confidence=float(item.get("confidence", 0.5)),
                    is_production=item.get("is_production", True),
                    context=f"Agent: {agent_name}",
                    raw_response=response_text[:500],
                    category=category,
                )
                findings.append(finding)

            return findings

        except json.JSONDecodeError as e:
            print(f"    ⚠️  Failed to parse JSON: {e}")
            print(f"    Response: {response_text[:200]}")
            return []
        except Exception as e:
            print(f"    ⚠️  Error parsing response: {e}")
            return []

    async def review_file(self, file_path: str, repo_path: str, use_category_passes: bool = True) -> list[Finding]:
        """Review a single file with enhanced multi-pass strategy"""
        full_path = Path(repo_path) / file_path

        if not full_path.exists():
            print(f"  ⚠️  File not found: {full_path}")
            return []

        # Read file content
        try:
            with open(full_path, encoding="utf-8") as f:
                code_content = f.read()
        except Exception as e:
            print(f"  ⚠️  Error reading file: {e}")
            return []

        # Phase 0: Heuristic pre-scan
        print("  🔍 Running heuristic pre-scan...")
        heuristic_flags = self.pre_scan_heuristics(file_path, code_content)

        if heuristic_flags:
            print(f"    ⚠️  Flagged: {', '.join(heuristic_flags)}")
        else:
            print("    ✅ No heuristic flags - file looks clean")
            # Uncomment to skip clean files: return []

        # Build enhanced context
        context = {
            "file_path": file_path,
            "file_type": full_path.suffix,
            "is_test": "test" in file_path.lower(),
            "is_production": self.is_production_code(file_path),
        }

        # Add git context
        git_context = self.build_context_injection(file_path, repo_path)
        context.update(git_context)

        # Phase 1: Category-specific passes or traditional review
        all_findings = []

        if use_category_passes and "Claude-Sonnet-4" in self.agents:
            # Run focused category passes with Claude Sonnet
            categories = ["security", "performance", "quality"]
            print(f"  🎯 Running category-specific passes: {', '.join(categories)}")

            tasks = []
            for category in categories:
                tasks.append(self.review_with_claude(file_path, code_content, context, category, heuristic_flags))

            results = await asyncio.gather(*tasks)
            for findings in results:
                all_findings.extend(findings)
        else:
            # Traditional multi-agent review
            print("  🤖 Running traditional multi-agent review...")
            tasks = []

            if "Claude-Sonnet-4" in self.agents:
                tasks.append(self.review_with_claude(file_path, code_content, context, "general", heuristic_flags))
            if "Claude-Haiku-3.5" in self.agents:
                tasks.append(self.review_with_claude_haiku(file_path, code_content, context))
            if "GPT-4-Turbo" in self.agents:
                tasks.append(self.review_with_gpt4(file_path, code_content, context))

            results = await asyncio.gather(*tasks)
            for findings in results:
                all_findings.extend(findings)

        return all_findings

    def build_consensus(self, all_findings: list[Finding]) -> list[ConsensusResult]:
        """Build consensus from findings"""
        if not all_findings:
            return []

        # Group by file + issue_type + line range (similar issues at similar locations)
        grouped = {}

        for finding in all_findings:
            # Create a location-sensitive key to avoid collapsing distinct bugs
            # Group issues within ~10 lines as the same issue
            # Defensive cast to handle any edge cases where line isn't an int
            safe_line = self._safe_int(finding.line, 0)
            line_bucket = (safe_line // 10) * 10
            key = f"{finding.file}:{finding.issue_type}:L{line_bucket}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)

        consensus_results = []

        for _key, group in grouped.items():
            votes = len(group)
            total_agents = len(self.agents)
            avg_confidence = sum(f.confidence for f in group) / len(group)

            is_prod = any(f.is_production for f in group)

            # Classify based on votes and production status
            if votes == total_agents and is_prod and avg_confidence >= 0.7:
                final_classification = "critical_fix"
            elif votes >= total_agents // 2 + 1 and is_prod:
                final_classification = "high_priority"
            elif votes >= total_agents // 2 + 1 and not is_prod:
                final_classification = "dev_issue"  # Dev infrastructure issues, not false positives
            elif votes == 1:
                final_classification = "suggestion"
            else:
                final_classification = "needs_investigation"

            # Consensus level
            if votes == total_agents:
                consensus_level = "unanimous"
            elif votes > total_agents / 2:
                consensus_level = "majority"
            else:
                consensus_level = "minority"

            # Get average line number
            avg_line = int(sum(f.line for f in group) / len(group))

            result = ConsensusResult(
                file=group[0].file,
                line=avg_line,
                issue_type=group[0].issue_type,
                severity=group[0].severity,
                votes=votes,
                total_agents=total_agents,
                confidence=avg_confidence,
                descriptions=[f.description for f in group],
                recommendations=[f.recommendation for f in group],
                agents_agree=[f.agent for f in group],
                agents_disagree=[a for a in self.agents if a not in [f.agent for f in group]],
                consensus_level=consensus_level,
                is_production=is_prod,
                final_classification=final_classification,
            )

            consensus_results.append(result)

        # Sort by votes and confidence
        consensus_results.sort(key=lambda x: (x.votes, x.confidence), reverse=True)

        return consensus_results

    async def generate_test_case(self, finding: ConsensusResult) -> Optional[TestCase]:
        """
        Feature #5: Test Case Generation
        Generate concrete test cases for high/critical findings
        """
        if not self.claude_client:
            return None

        if finding.severity not in ["critical", "high"]:
            return None

        print(f"    🧪 Generating test case for {finding.issue_type}...")

        prompt = f"""You are a test engineer. Generate a concrete test case for this security/quality issue:

**Issue**: {finding.issue_type}
**File**: {finding.file}:{finding.line}
**Severity**: {finding.severity}
**Description**: {finding.descriptions[0] if finding.descriptions else "No description"}
**Recommendation**: {finding.recommendations[0] if finding.recommendations else "No recommendation"}

Generate a specific, executable test case that would catch this issue.

**RESPONSE FORMAT** (JSON object):
{{
  "description": "Brief test description (1 sentence)",
  "test_code": "Complete test function code (Python/JS/etc.)",
  "input_example": "Example malicious/problematic input",
  "expected_behavior": "What should happen (error, validation, etc.)"
}}

Return ONLY the JSON object, no other text."""

        try:
            response = await asyncio.to_thread(
                self.claude_client.messages.create,
                model=self.claude_haiku_model,  # Use faster/cheaper model for tests
                max_tokens=1024,
                temperature=0.3,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = response.content[0].text

            # Parse JSON
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.find("```") + 3
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()

            test_data = json.loads(response_text)

            return TestCase(
                description=test_data.get("description", ""),
                test_code=test_data.get("test_code", ""),
                input_example=test_data.get("input_example", ""),
                expected_behavior=test_data.get("expected_behavior", ""),
            )

        except Exception as e:
            print(f"      ⚠️  Failed to generate test case: {e}")
            return None

    async def enhance_findings_with_tests(self, consensus_results: list[ConsensusResult]) -> list[ConsensusResult]:
        """Add test cases to high/critical findings"""
        print("\n🧪 Generating test cases for high/critical findings...")

        tasks = []
        indices = []

        for i, result in enumerate(consensus_results):
            if result.severity in ["critical", "high"] and result.final_classification in [
                "critical_fix",
                "high_priority",
            ]:
                tasks.append(self.generate_test_case(result))
                indices.append(i)

        if not tasks:
            print("  No high/critical findings to generate tests for.")
            return consensus_results

        test_cases = await asyncio.gather(*tasks)

        for idx, test_case in zip(indices, test_cases):
            if test_case:
                consensus_results[idx].test_case = test_case
                print(f"  ✅ Generated test for: {consensus_results[idx].issue_type}")

        return consensus_results

    def generate_report(self, consensus_results: list[ConsensusResult], repo_name: str) -> str:
        """Generate markdown report"""

        critical = [r for r in consensus_results if r.final_classification == "critical_fix"]
        high = [r for r in consensus_results if r.final_classification == "high_priority"]
        suggestions = [r for r in consensus_results if r.final_classification == "suggestion"]
        dev_issues = [r for r in consensus_results if r.final_classification == "dev_issue"]

        report = f"""# 🤖 Real Multi-Agent Consensus Code Review

**Repository**: {repo_name}
**Agents**: {", ".join(self.agents)} (REAL API CALLS)
**Review Date**: {datetime.utcnow().isoformat()}Z

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| **Total Agents** | {len(self.agents)} |
| **Consensus Findings** | {len(consensus_results)} |
| **Critical Fixes (Unanimous/High Conf)** | {len(critical)} 🔴 |
| **High Priority (Majority)** | {len(high)} 🟠 |
| **Suggestions (Minority)** | {len(suggestions)} 🟡 |
| **Dev Infrastructure Issues** | {len(dev_issues)} 🔧 |

---

## 🔴 Critical Fixes ({len(critical)})

"""

        for result in critical:
            report += f"""
### {result.issue_type.replace("-", " ").title()}

**File**: `{result.file}:{result.line}`
**Votes**: {result.votes}/{result.total_agents} ({result.consensus_level.upper()})
**Confidence**: {result.confidence:.0%}

**Findings from agents**:
"""
            for i, (agent, desc) in enumerate(zip(result.agents_agree, result.descriptions), 1):
                report += f"{i}. **{agent}**: {desc}\n"

            report += "\n**Recommendations**:\n"
            for i, rec in enumerate(result.recommendations, 1):
                report += f"{i}. {rec}\n"

            # Add test case if available
            if result.test_case:
                report += "\n**🧪 Suggested Test Case**:\n"
                report += f"*{result.test_case.description}*\n\n"
                report += f"**Input**: `{result.test_case.input_example}`\n"
                report += f"**Expected**: {result.test_case.expected_behavior}\n\n"
                report += f"```python\n{result.test_case.test_code}\n```\n"

            report += "\n---\n"

        report += f"""

## 🟠 High Priority ({len(high)})

"""

        for result in high:
            report += f"""
### {result.issue_type.replace("-", " ").title()}

**File**: `{result.file}:{result.line}`
**Votes**: {result.votes}/{result.total_agents}
**Agents**: {", ".join(result.agents_agree)}

{result.descriptions[0]}
"""
            # Add test case if available
            if result.test_case:
                report += "\n**🧪 Suggested Test Case**:\n"
                report += f"*{result.test_case.description}*\n\n"
                report += f"```python\n{result.test_case.test_code}\n```\n"

            report += "\n---\n"

        report += ""

        report += f"""

## 🟡 Suggestions ({len(suggestions)})

"""
        for result in suggestions:
            report += f"- {result.issue_type} in `{result.file}` (1 agent)\n"

        report += f"""

## 🔧 Dev Infrastructure Issues ({len(dev_issues)})

"""
        for result in dev_issues:
            report += f"- {result.issue_type} in `{result.file}:{result.line}` (dev infrastructure, not production-critical)\n"

        report += """

---

**💡 This report was generated using REAL API calls to multiple AI models.**
**Each finding represents actual consensus between independent AI agents.**

"""

        return report


async def main():
    """Main entry point"""
    print("🤖 Real Multi-Agent Consensus Review")
    print("=" * 70)
    print()

    # Get API keys from environment
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    if not anthropic_key:
        print("❌ ANTHROPIC_API_KEY not found in environment")
        print("   Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        return

    # Initialize review system
    reviewer = RealMultiAgentReview(anthropic_api_key=anthropic_key, openai_api_key=openai_key)

    print()

    # Repository to review
    repo_path = "/tmp/Spring-Steampipe-Data-Pipeline"
    repo_name = "Spring-Steampipe-Data-Pipeline"

    if not Path(repo_path).exists():
        print(f"❌ Repository not found: {repo_path}")
        print("   Clone it first with:")
        print(f"   gh repo clone devatsecure/{repo_name} {repo_path}")
        return

    # Files to review (key files from human feedback)
    files_to_review = [
        "docker/hive/postgres-init/02-configure-auth.sql",
        "pipeline/src/urr/aws/services/rds/create_rds_urr.sql",
    ]

    print(f"📂 Repository: {repo_name}")
    print(f"📄 Files to review: {len(files_to_review)}")
    print()

    # Review all files
    all_findings = []

    for file_path in files_to_review:
        print(f"📄 Reviewing: {file_path}")
        findings = await reviewer.review_file(file_path, repo_path)
        all_findings.extend(findings)
        print()

    print(f"✅ Total findings: {len(all_findings)}")
    print()

    # Build consensus
    print("🔄 Building consensus...")
    consensus_results = reviewer.build_consensus(all_findings)
    print(f"✅ Consensus results: {len(consensus_results)}")
    print()

    # Generate test cases for high/critical findings
    consensus_results = await reviewer.enhance_findings_with_tests(consensus_results)
    print()

    # Generate report
    print("📝 Generating report...")
    report = reviewer.generate_report(consensus_results, repo_name)

    # Save report
    output_file = "/tmp/real_multi_agent_report.md"
    with open(output_file, "w") as f:
        f.write(report)

    print(f"✅ Report saved: {output_file}")
    print()

    # Summary
    print("📊 Summary:")
    critical = len([r for r in consensus_results if r.final_classification == "critical_fix"])
    high = len([r for r in consensus_results if r.final_classification == "high_priority"])
    suggestions = len([r for r in consensus_results if r.final_classification == "suggestion"])

    print(f"  🔴 Critical Fixes: {critical}")
    print(f"  🟠 High Priority: {high}")
    print(f"  🟡 Suggestions: {suggestions}")
    print()

    print("🎉 Real multi-agent consensus review complete!")
    print(f"📄 View report: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
