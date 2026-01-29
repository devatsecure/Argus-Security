#!/usr/bin/env python3
"""
Zero-Day Vulnerability Hypothesis Generator

This module implements novel vulnerability hypothesis generation using LLM reasoning.
Unlike traditional scanners that match known patterns (CWE-based), this module thinks
like an attacker: identifying assumptions in code and hypothesizing what could go wrong
when those assumptions are violated.

Key Features:
- Hypothesis-driven security analysis (not pattern matching)
- Explores uncommon vulnerability categories (type confusion, race conditions, etc.)
- Multi-step LLM reasoning to identify implicit assumptions
- Attack scenario generation with exploitation likelihood scoring
- High-confidence filtering (>0.75) to minimize noise

Discovery Categories:
- Type Confusion: Mixed type operations, implicit conversions
- Integer Issues: Overflow, underflow, signedness errors
- Race Conditions: TOCTOU, concurrent access without synchronization
- Logic Flaws: State machine errors, missing edge case handling
- Crypto Misuse: Custom crypto, weak randomness, timing attacks
- Resource Exhaustion: Unbounded loops, memory allocation bombs
- Format String: User data in format specifiers
- Prototype Pollution: Object property injection (JavaScript)

Integration:
- Uses ZeroDayHypothesis dataclass for structured output
- Integrates with any AI provider (Anthropic, OpenAI, Ollama)
- Returns high-confidence hypotheses (>0.75) for manual review
- Provides suggested tests for hypothesis validation
"""

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class HypothesisCategory(Enum):
    """Categories of zero-day vulnerability hypotheses"""
    TYPE_CONFUSION = "type_confusion"
    INTEGER_ISSUES = "integer_issues"
    RACE_CONDITIONS = "race_conditions"
    LOGIC_FLAWS = "logic_flaws"
    CRYPTO_MISUSE = "crypto_misuse"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    FORMAT_STRING = "format_string"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    MEMORY_SAFETY = "memory_safety"
    DESERIALIZATION = "deserialization"
    UNKNOWN = "unknown"


@dataclass
class CodeLocation:
    """Represents a location in code where a vulnerability might exist"""
    file_path: str
    line_number: int
    snippet: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "context_before": self.context_before,
            "context_after": self.context_after
        }


@dataclass
class ZeroDayHypothesis:
    """
    A hypothesis about a potential zero-day vulnerability

    This represents an educated guess about what could go wrong in code,
    based on LLM analysis of implicit assumptions and edge cases.
    """
    # Core hypothesis details
    hypothesis: str  # What could go wrong
    category: HypothesisCategory
    affected_code: CodeLocation

    # Assumption analysis
    assumption_violated: str  # What assumption fails
    implicit_assumptions: List[str]  # All identified assumptions

    # Attack scenario
    attack_scenario: str  # How an attacker could exploit this
    attack_prerequisites: List[str]  # What attacker needs

    # Scoring (0.0 - 1.0)
    likelihood: float  # How likely is the assumption to be violated?
    impact: float  # What's the damage if exploited?
    novelty: float  # Is this a known pattern or something new?
    confidence: float  # Overall confidence in this hypothesis

    # Validation
    suggested_test: str  # How to validate this hypothesis
    test_payload: Optional[str] = None  # Example exploit payload

    # Metadata
    hypothesis_id: str = ""
    cwe_approximation: Optional[str] = None  # Closest CWE if any
    reasoning_chain: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        """Generate hypothesis ID if not provided"""
        if not self.hypothesis_id:
            key = f"{self.hypothesis}:{self.affected_code.file_path}:{self.affected_code.line_number}"
            self.hypothesis_id = hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis": self.hypothesis,
            "category": self.category.value,
            "affected_code": self.affected_code.to_dict(),
            "assumption_violated": self.assumption_violated,
            "implicit_assumptions": self.implicit_assumptions,
            "attack_scenario": self.attack_scenario,
            "attack_prerequisites": self.attack_prerequisites,
            "scores": {
                "likelihood": self.likelihood,
                "impact": self.impact,
                "novelty": self.novelty,
                "confidence": self.confidence
            },
            "suggested_test": self.suggested_test,
            "test_payload": self.test_payload,
            "cwe_approximation": self.cwe_approximation,
            "reasoning_chain": self.reasoning_chain,
            "created_at": self.created_at
        }


class ZeroDayHypothesizer:
    """
    Zero-Day Vulnerability Hypothesis Generator

    Uses LLM reasoning to identify potential vulnerabilities that don't match
    known patterns. Thinks like an attacker: finds assumptions and hypothesizes
    how to violate them.

    Usage:
        hypothesizer = ZeroDayHypothesizer(ai_provider)
        hypotheses = hypothesizer.hypothesize(files, language="python")

        for h in hypotheses:
            if h.confidence > 0.75:
                print(f"High-confidence: {h.hypothesis}")
    """

    # Patterns to identify code segments worth analyzing
    INTERESTING_PATTERNS = {
        "python": {
            "type_operations": r"(?:int|str|float|bool)\s*\(",
            "arithmetic": r"[\+\-\*\/\%]\s*=|[\+\-\*\/\%]{1,2}",
            "file_operations": r"open\s*\(|read\s*\(|write\s*\(",
            "network": r"socket|request|urllib|http",
            "serialization": r"pickle|json\.loads|yaml\.load|marshal",
            "eval_exec": r"eval\s*\(|exec\s*\(|compile\s*\(",
            "crypto": r"random|hashlib|cryptography|hmac",
            "concurrency": r"thread|async|await|lock|semaphore",
            "format": r"format\s*\(|%\s*[sdfr]|\{.*\}\.format",
        },
        "javascript": {
            "type_operations": r"parseInt|parseFloat|Number\(|String\(",
            "object_access": r"\[\s*\w+\s*\]|Object\.assign|\.prototype",
            "eval_function": r"eval\s*\(|Function\s*\(|new\s+Function",
            "serialization": r"JSON\.parse|deserialize",
            "dom_manipulation": r"innerHTML|outerHTML|document\.write",
            "crypto": r"Math\.random|crypto\.random",
            "concurrency": r"Promise|async|await|setTimeout|setInterval",
            "template": r"\$\{.*\}|`.*`",
        },
        "go": {
            "type_conversion": r"int\(|string\(|float64\(|byte\(",
            "unsafe": r"unsafe\.Pointer|reflect",
            "concurrency": r"go\s+\w+|chan\s+|select\s*\{|sync\.",
            "file_io": r"os\.Open|ioutil\.|bufio\.",
            "serialization": r"json\.Unmarshal|gob\.Decode|xml\.Unmarshal",
            "network": r"net\.Listen|http\.Handle",
        },
        "java": {
            "type_casting": r"\(\s*\w+\s*\)\s*\w+",
            "serialization": r"ObjectInputStream|readObject|XMLDecoder",
            "reflection": r"Class\.forName|getMethod|invoke",
            "concurrency": r"synchronized|Thread|Executor|volatile",
            "crypto": r"SecureRandom|MessageDigest|Cipher",
            "file_io": r"FileInputStream|BufferedReader|Scanner",
        }
    }

    # CWE approximations for hypothesis categories
    CWE_APPROXIMATIONS = {
        HypothesisCategory.TYPE_CONFUSION: "CWE-843",  # Type Confusion
        HypothesisCategory.INTEGER_ISSUES: "CWE-190",  # Integer Overflow
        HypothesisCategory.RACE_CONDITIONS: "CWE-362",  # TOCTOU
        HypothesisCategory.LOGIC_FLAWS: "CWE-840",  # Business Logic Errors
        HypothesisCategory.CRYPTO_MISUSE: "CWE-327",  # Broken Crypto
        HypothesisCategory.RESOURCE_EXHAUSTION: "CWE-400",  # Uncontrolled Resource Consumption
        HypothesisCategory.FORMAT_STRING: "CWE-134",  # Format String
        HypothesisCategory.PROTOTYPE_POLLUTION: "CWE-1321",  # Prototype Pollution
        HypothesisCategory.MEMORY_SAFETY: "CWE-119",  # Buffer Errors
        HypothesisCategory.DESERIALIZATION: "CWE-502",  # Insecure Deserialization
    }

    def __init__(
        self,
        ai_provider: Optional[Any] = None,
        confidence_threshold: float = 0.75,
        max_hypotheses_per_file: int = 5
    ):
        """
        Initialize the Zero-Day Hypothesizer

        Args:
            ai_provider: AI provider instance (AnthropicProvider, OpenAIProvider, etc.)
            confidence_threshold: Minimum confidence to report (default: 0.75)
            max_hypotheses_per_file: Maximum hypotheses to generate per file (default: 5)
        """
        self.ai_provider = ai_provider
        self.confidence_threshold = confidence_threshold
        self.max_hypotheses_per_file = max_hypotheses_per_file

        # Statistics tracking
        self.total_files_analyzed = 0
        self.total_hypotheses_generated = 0
        self.high_confidence_hypotheses = 0
        self.total_cost = 0.0

        logger.info(
            f"ZeroDayHypothesizer initialized "
            f"(confidence threshold: {confidence_threshold})"
        )

    def hypothesize(
        self,
        files: List[str],
        language: str = "auto",
        focus_categories: Optional[List[HypothesisCategory]] = None,
        max_files: int = 30
    ) -> List[ZeroDayHypothesis]:
        """
        Generate zero-day vulnerability hypotheses for the given files

        Args:
            files: List of file paths to analyze
            language: Programming language (auto-detect if not specified)
            focus_categories: Categories to focus on (all if None)
            max_files: Maximum number of files to analyze

        Returns:
            List of ZeroDayHypothesis objects with confidence > threshold
        """
        logger.info(f"Starting zero-day hypothesis generation for {len(files)} files")

        all_hypotheses = []
        files_to_analyze = files[:max_files] if len(files) > max_files else files

        if len(files) > max_files:
            logger.warning(f"Limiting analysis to {max_files} files for performance")

        for file_path in files_to_analyze:
            try:
                # Detect language if auto
                detected_language = self._detect_language(file_path) if language == "auto" else language

                if detected_language not in self.INTERESTING_PATTERNS:
                    logger.debug(f"Skipping {file_path} - unsupported language: {detected_language}")
                    continue

                # Analyze file and generate hypotheses
                file_hypotheses = self._analyze_file(
                    file_path,
                    detected_language,
                    focus_categories
                )

                all_hypotheses.extend(file_hypotheses)
                self.total_files_analyzed += 1

            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
                continue

        # Filter to high-confidence hypotheses
        high_confidence = [
            h for h in all_hypotheses
            if h.confidence >= self.confidence_threshold
        ]

        self.high_confidence_hypotheses = len(high_confidence)
        self.total_hypotheses_generated = len(all_hypotheses)

        logger.info(
            f"Hypothesis generation complete: "
            f"{len(high_confidence)}/{len(all_hypotheses)} high-confidence hypotheses"
        )

        return high_confidence

    def _analyze_file(
        self,
        file_path: str,
        language: str,
        focus_categories: Optional[List[HypothesisCategory]]
    ) -> List[ZeroDayHypothesis]:
        """
        Analyze a single file and generate hypotheses

        Args:
            file_path: Path to the file
            language: Programming language
            focus_categories: Categories to focus on

        Returns:
            List of hypotheses for this file
        """
        logger.debug(f"Analyzing {file_path} ({language})")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return []

        hypotheses = []
        patterns = self.INTERESTING_PATTERNS.get(language, {})

        # Find interesting code segments
        interesting_segments = self._find_interesting_segments(
            content, lines, patterns, file_path
        )

        # Limit segments per file
        segments_to_analyze = interesting_segments[:self.max_hypotheses_per_file * 2]

        for segment in segments_to_analyze:
            # Determine which categories apply to this segment
            applicable_categories = self._determine_categories(segment, language)

            if focus_categories:
                applicable_categories = [
                    c for c in applicable_categories
                    if c in focus_categories
                ]

            if not applicable_categories:
                continue

            # Generate hypothesis using LLM
            hypothesis = self._generate_hypothesis(
                segment,
                language,
                applicable_categories
            )

            if hypothesis:
                hypotheses.append(hypothesis)

                if len(hypotheses) >= self.max_hypotheses_per_file:
                    break

        return hypotheses

    def _find_interesting_segments(
        self,
        content: str,
        lines: List[str],
        patterns: Dict[str, str],
        file_path: str
    ) -> List[CodeLocation]:
        """
        Find code segments worth analyzing for potential vulnerabilities

        Args:
            content: Full file content
            lines: List of lines
            patterns: Regex patterns for interesting code
            file_path: Path to the file

        Returns:
            List of CodeLocation objects for interesting segments
        """
        segments = []
        found_lines = set()  # Avoid duplicates

        for pattern_name, pattern in patterns.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Find the line number
                    line_start = content[:match.start()].count("\n")

                    if line_start in found_lines:
                        continue
                    found_lines.add(line_start)

                    # Get context
                    context_start = max(0, line_start - 5)
                    context_end = min(len(lines), line_start + 6)

                    segment = CodeLocation(
                        file_path=file_path,
                        line_number=line_start + 1,  # 1-indexed
                        snippet=lines[line_start] if line_start < len(lines) else "",
                        context_before=lines[context_start:line_start],
                        context_after=lines[line_start + 1:context_end]
                    )
                    segments.append(segment)

            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_name}': {e}")
                continue

        return segments

    def _determine_categories(
        self,
        segment: CodeLocation,
        language: str
    ) -> List[HypothesisCategory]:
        """
        Determine which vulnerability categories apply to a code segment

        Args:
            segment: The code segment
            language: Programming language

        Returns:
            List of applicable HypothesisCategory values
        """
        categories = []
        snippet_lower = segment.snippet.lower()
        context = "\n".join(segment.context_before + [segment.snippet] + segment.context_after).lower()

        # Type confusion indicators
        if any(x in context for x in ["int(", "str(", "float(", "parseint", "parsefloat", "number(", "string("]):
            categories.append(HypothesisCategory.TYPE_CONFUSION)

        # Integer issues
        if any(x in context for x in ["+", "-", "*", "/", "%", "<<", ">>"]) and any(c.isdigit() for c in context):
            categories.append(HypothesisCategory.INTEGER_ISSUES)

        # Race conditions
        if any(x in context for x in ["thread", "async", "await", "lock", "mutex", "go ", "chan ", "promise"]):
            categories.append(HypothesisCategory.RACE_CONDITIONS)

        # Logic flaws (state-related keywords)
        if any(x in context for x in ["state", "status", "if ", "else", "switch", "case", "while", "for "]):
            categories.append(HypothesisCategory.LOGIC_FLAWS)

        # Crypto misuse
        if any(x in context for x in ["random", "hash", "encrypt", "decrypt", "cipher", "hmac", "md5", "sha"]):
            categories.append(HypothesisCategory.CRYPTO_MISUSE)

        # Resource exhaustion
        if any(x in context for x in ["while", "for ", "loop", "recursion", "append", "push", "malloc", "alloc"]):
            categories.append(HypothesisCategory.RESOURCE_EXHAUSTION)

        # Format string
        if any(x in context for x in ["format", "printf", "sprintf", "%s", "%d", "f'"]):
            categories.append(HypothesisCategory.FORMAT_STRING)

        # Prototype pollution (JavaScript specific)
        if language == "javascript" and any(x in context for x in ["prototype", "__proto__", "constructor", "object.assign"]):
            categories.append(HypothesisCategory.PROTOTYPE_POLLUTION)

        # Deserialization
        if any(x in context for x in ["pickle", "marshal", "json.load", "yaml.load", "deserialize", "unmarshal", "readobject"]):
            categories.append(HypothesisCategory.DESERIALIZATION)

        return categories

    def _generate_hypothesis(
        self,
        segment: CodeLocation,
        language: str,
        categories: List[HypothesisCategory]
    ) -> Optional[ZeroDayHypothesis]:
        """
        Generate a hypothesis for a code segment using LLM reasoning

        Args:
            segment: The code segment to analyze
            language: Programming language
            categories: Applicable vulnerability categories

        Returns:
            ZeroDayHypothesis if a valid hypothesis is generated, None otherwise
        """
        if not self.ai_provider:
            # Use heuristic-based hypothesis when no LLM available
            return self._generate_heuristic_hypothesis(segment, language, categories)

        try:
            # Build the LLM prompt
            prompt = self._build_hypothesis_prompt(segment, language, categories)

            # Call the LLM
            response = self.ai_provider.analyze(prompt)

            # Parse the response
            hypothesis = self._parse_llm_hypothesis(response, segment, categories)

            # Track cost
            if hasattr(response, 'usage'):
                self.total_cost += self._calculate_cost(response)

            return hypothesis

        except Exception as e:
            logger.error(f"LLM hypothesis generation failed: {e}")
            return self._generate_heuristic_hypothesis(segment, language, categories)

    def _build_hypothesis_prompt(
        self,
        segment: CodeLocation,
        language: str,
        categories: List[HypothesisCategory]
    ) -> str:
        """
        Build the LLM prompt for hypothesis generation

        Args:
            segment: Code segment to analyze
            language: Programming language
            categories: Categories to consider

        Returns:
            Formatted prompt string
        """
        context_code = "\n".join(
            segment.context_before +
            [f">>> {segment.snippet}  # LINE {segment.line_number}"] +
            segment.context_after
        )

        category_names = ", ".join([c.value for c in categories])

        prompt = f"""You are an elite security researcher looking for NOVEL vulnerabilities in code.
Your job is NOT to find standard vulnerabilities (SQL injection, XSS, etc.) but to think like an
advanced attacker looking for UNCOMMON issues that scanners would miss.

LANGUAGE: {language}
FILE: {segment.file_path}
CATEGORIES TO CONSIDER: {category_names}

CODE SEGMENT:
```{language}
{context_code}
```

Think like an attacker and answer these questions:

## STEP 1: ASSUMPTION IDENTIFICATION
List ALL implicit assumptions this code is making:
- What data types/ranges are expected?
- What state is assumed to exist?
- What order of operations is assumed?
- What resource availability is assumed?
- What concurrent access patterns are assumed?

## STEP 2: ASSUMPTION VIOLATION ANALYSIS
For each assumption, how could an attacker VIOLATE it?
- What unexpected input could break assumptions?
- What timing/ordering could cause issues?
- What resource exhaustion could occur?

## STEP 3: ATTACK SCENARIO
If an assumption is violated, what's the WORST case?
- Can it lead to code execution?
- Can it cause data corruption/leakage?
- Can it cause denial of service?
- Can it bypass security controls?

## STEP 4: NOVELTY ASSESSMENT
Is this a NOVEL vulnerability or a standard pattern?
- Is this something traditional scanners would catch?
- Is this an edge case specific to this code?
- Rate novelty from 0.0 (standard issue) to 1.0 (highly novel)

## STEP 5: VALIDATION TEST
How would you TEST this hypothesis?
- What input would trigger the issue?
- What observable behavior would confirm the vulnerability?

OUTPUT FORMAT (JSON):
{{
  "hypothesis": "Description of what could go wrong",
  "assumption_violated": "The key assumption that fails",
  "implicit_assumptions": ["assumption1", "assumption2", ...],
  "attack_scenario": "Step-by-step attack description",
  "attack_prerequisites": ["prerequisite1", "prerequisite2"],
  "likelihood": 0.0-1.0,
  "impact": 0.0-1.0,
  "novelty": 0.0-1.0,
  "suggested_test": "How to validate this hypothesis",
  "test_payload": "Example exploit input (if applicable)",
  "reasoning_chain": ["step1", "step2", "step3"]
}}

If no valid hypothesis exists, return: {{"hypothesis": null}}

Respond with ONLY the JSON object."""

        return prompt

    def _parse_llm_hypothesis(
        self,
        response: Any,
        segment: CodeLocation,
        categories: List[HypothesisCategory]
    ) -> Optional[ZeroDayHypothesis]:
        """
        Parse LLM response into a ZeroDayHypothesis

        Args:
            response: LLM response object
            segment: Original code segment
            categories: Applicable categories

        Returns:
            ZeroDayHypothesis or None if parsing fails
        """
        try:
            # Extract content from response
            if hasattr(response, 'content'):
                content = response.content[0].text if isinstance(response.content, list) else response.content
            elif hasattr(response, 'choices'):
                content = response.choices[0].message.content
            else:
                content = str(response)

            # Handle markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            data = json.loads(content)

            # Check for null hypothesis
            if data.get("hypothesis") is None:
                logger.debug(f"No valid hypothesis for {segment.file_path}:{segment.line_number}")
                return None

            # Calculate confidence from component scores
            likelihood = float(data.get("likelihood", 0.5))
            impact = float(data.get("impact", 0.5))
            novelty = float(data.get("novelty", 0.5))

            # Weighted confidence calculation
            confidence = (likelihood * 0.35) + (impact * 0.35) + (novelty * 0.30)

            # Select primary category based on hypothesis content
            primary_category = categories[0] if categories else HypothesisCategory.UNKNOWN

            hypothesis = ZeroDayHypothesis(
                hypothesis=data.get("hypothesis", "Unknown hypothesis"),
                category=primary_category,
                affected_code=segment,
                assumption_violated=data.get("assumption_violated", "Unknown"),
                implicit_assumptions=data.get("implicit_assumptions", []),
                attack_scenario=data.get("attack_scenario", "Unknown"),
                attack_prerequisites=data.get("attack_prerequisites", []),
                likelihood=likelihood,
                impact=impact,
                novelty=novelty,
                confidence=confidence,
                suggested_test=data.get("suggested_test", "Manual review required"),
                test_payload=data.get("test_payload"),
                cwe_approximation=self.CWE_APPROXIMATIONS.get(primary_category),
                reasoning_chain=data.get("reasoning_chain", [])
            )

            return hypothesis

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing hypothesis: {e}")
            return None

    def _generate_heuristic_hypothesis(
        self,
        segment: CodeLocation,
        language: str,
        categories: List[HypothesisCategory]
    ) -> Optional[ZeroDayHypothesis]:
        """
        Generate a hypothesis using heuristics when LLM is unavailable

        Args:
            segment: Code segment to analyze
            language: Programming language
            categories: Applicable categories

        Returns:
            ZeroDayHypothesis based on pattern matching
        """
        if not categories:
            return None

        primary_category = categories[0]
        snippet = segment.snippet
        context = "\n".join(segment.context_before + [snippet] + segment.context_after)

        # Generate hypothesis based on category and patterns
        hypothesis_templates = {
            HypothesisCategory.TYPE_CONFUSION: {
                "hypothesis": f"Type confusion may occur at line {segment.line_number} if input type differs from expected",
                "assumption_violated": "Input is of the expected type",
                "attack_scenario": "Provide input of unexpected type to trigger type coercion errors or unexpected behavior",
                "suggested_test": "Pass values of different types (string, int, array, object, null) and observe behavior",
            },
            HypothesisCategory.INTEGER_ISSUES: {
                "hypothesis": f"Integer overflow/underflow possible at line {segment.line_number} with large or negative values",
                "assumption_violated": "Numeric values stay within expected bounds",
                "attack_scenario": "Provide extremely large numbers, negative numbers, or boundary values to cause overflow",
                "suggested_test": "Test with INT_MAX, INT_MIN, 0, -1, and boundary values",
            },
            HypothesisCategory.RACE_CONDITIONS: {
                "hypothesis": f"Race condition possible at line {segment.line_number} between check and use",
                "assumption_violated": "State remains consistent between check and operation",
                "attack_scenario": "Make concurrent requests to trigger TOCTOU or state corruption",
                "suggested_test": "Send rapid concurrent requests and monitor for inconsistent state",
            },
            HypothesisCategory.LOGIC_FLAWS: {
                "hypothesis": f"Logic flaw may exist at line {segment.line_number} due to missing edge case handling",
                "assumption_violated": "All possible states and transitions are handled",
                "attack_scenario": "Reach an unexpected state by violating assumed invariants",
                "suggested_test": "Map state machine and try to reach invalid states",
            },
            HypothesisCategory.CRYPTO_MISUSE: {
                "hypothesis": f"Potential cryptographic weakness at line {segment.line_number}",
                "assumption_violated": "Cryptographic operations are correctly implemented",
                "attack_scenario": "Exploit weak randomness, timing side-channels, or algorithm misuse",
                "suggested_test": "Analyze randomness quality, measure timing variations, verify algorithm parameters",
            },
            HypothesisCategory.RESOURCE_EXHAUSTION: {
                "hypothesis": f"Resource exhaustion possible at line {segment.line_number} with unbounded input",
                "assumption_violated": "Input size and iterations are bounded",
                "attack_scenario": "Provide very large input or trigger unbounded loops to exhaust memory/CPU",
                "suggested_test": "Send increasingly large payloads and monitor resource usage",
            },
            HypothesisCategory.FORMAT_STRING: {
                "hypothesis": f"Format string vulnerability possible at line {segment.line_number} if user input reaches format specifier",
                "assumption_violated": "Format strings are static and trusted",
                "attack_scenario": "Inject format specifiers (%s, %x, %n) to leak memory or cause crashes",
                "suggested_test": "Include format specifiers in user-controlled input",
            },
            HypothesisCategory.PROTOTYPE_POLLUTION: {
                "hypothesis": f"Prototype pollution possible at line {segment.line_number} via object property injection",
                "assumption_violated": "Object properties are trusted and sanitized",
                "attack_scenario": "Inject __proto__ or constructor.prototype to pollute object prototype chain",
                "suggested_test": "Send JSON with __proto__ or constructor.prototype keys",
            },
            HypothesisCategory.DESERIALIZATION: {
                "hypothesis": f"Insecure deserialization at line {segment.line_number} may allow code execution",
                "assumption_violated": "Serialized data is trusted and safe",
                "attack_scenario": "Craft malicious serialized payload to execute arbitrary code during deserialization",
                "suggested_test": "Provide crafted serialized objects with dangerous classes/methods",
            },
        }

        template = hypothesis_templates.get(primary_category, {
            "hypothesis": f"Potential vulnerability at line {segment.line_number}",
            "assumption_violated": "Unknown assumption",
            "attack_scenario": "Manual analysis required",
            "suggested_test": "Review code manually",
        })

        # Calculate heuristic confidence (lower than LLM-based)
        base_confidence = 0.55

        # Boost confidence based on pattern strength
        if re.search(r"(user|input|request|param)", context, re.IGNORECASE):
            base_confidence += 0.1
        if re.search(r"(admin|root|system|exec|eval)", context, re.IGNORECASE):
            base_confidence += 0.1

        return ZeroDayHypothesis(
            hypothesis=template["hypothesis"],
            category=primary_category,
            affected_code=segment,
            assumption_violated=template["assumption_violated"],
            implicit_assumptions=["Heuristic analysis - manual verification required"],
            attack_scenario=template["attack_scenario"],
            attack_prerequisites=["Access to the affected endpoint"],
            likelihood=0.5,
            impact=0.6,
            novelty=0.4,
            confidence=min(base_confidence, 0.75),
            suggested_test=template["suggested_test"],
            cwe_approximation=self.CWE_APPROXIMATIONS.get(primary_category),
            reasoning_chain=["Heuristic pattern matching", "No LLM analysis available"]
        )

    def _detect_language(self, file_path: str) -> str:
        """
        Detect programming language from file extension

        Args:
            file_path: Path to the file

        Returns:
            Language identifier string
        """
        ext_to_language = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",
            ".jsx": "javascript",
            ".tsx": "javascript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
        }

        ext = Path(file_path).suffix.lower()
        return ext_to_language.get(ext, "unknown")

    def _calculate_cost(self, response: Any) -> float:
        """
        Calculate cost of LLM API call

        Args:
            response: LLM response with usage data

        Returns:
            Cost in USD
        """
        if not hasattr(response, 'usage'):
            return 0.0

        usage = response.usage
        input_tokens = getattr(usage, 'input_tokens', 0)
        output_tokens = getattr(usage, 'output_tokens', 0)

        # Approximate pricing (Claude Sonnet)
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0

        return input_cost + output_cost

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get hypothesizer statistics

        Returns:
            Dictionary with analysis statistics
        """
        return {
            "total_files_analyzed": self.total_files_analyzed,
            "total_hypotheses_generated": self.total_hypotheses_generated,
            "high_confidence_hypotheses": self.high_confidence_hypotheses,
            "confidence_threshold": self.confidence_threshold,
            "high_confidence_rate": round(
                self.high_confidence_hypotheses / max(self.total_hypotheses_generated, 1),
                2
            ),
            "total_cost_usd": round(self.total_cost, 4)
        }

    def hypothesize_single(
        self,
        code: str,
        file_name: str = "snippet.py",
        language: str = "python",
        line_number: int = 1
    ) -> List[ZeroDayHypothesis]:
        """
        Generate hypotheses for a single code snippet (useful for testing)

        Args:
            code: Code snippet to analyze
            file_name: Virtual file name
            language: Programming language
            line_number: Starting line number

        Returns:
            List of hypotheses
        """
        # Create a temporary segment
        lines = code.split("\n")

        hypotheses = []
        patterns = self.INTERESTING_PATTERNS.get(language, {})

        segments = self._find_interesting_segments(code, lines, patterns, file_name)

        for segment in segments[:self.max_hypotheses_per_file]:
            categories = self._determine_categories(segment, language)
            if categories:
                hypothesis = self._generate_hypothesis(segment, language, categories)
                if hypothesis and hypothesis.confidence >= self.confidence_threshold:
                    hypotheses.append(hypothesis)

        return hypotheses


def main():
    """CLI entry point for zero-day hypothesis generation"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Zero-Day Vulnerability Hypothesis Generator - Find novel security issues"
    )
    parser.add_argument("path", help="Path to analyze (file or directory)")
    parser.add_argument("--language", default="auto", help="Programming language (auto, python, javascript, go, java)")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--max-files", type=int, default=30, help="Max files to analyze")
    parser.add_argument("--confidence", type=float, default=0.75, help="Minimum confidence threshold")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--category",
        action="append",
        choices=[c.value for c in HypothesisCategory],
        help="Focus on specific category (can be repeated)"
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Gather files
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path {args.path} does not exist")
        sys.exit(1)

    files = []
    if target_path.is_file():
        files = [str(target_path)]
    else:
        extensions = ["*.py", "*.js", "*.ts", "*.go", "*.java", "*.rb", "*.php"]
        for ext in extensions:
            files.extend([str(f) for f in target_path.rglob(ext)])

    if not files:
        print("No supported files found to analyze")
        sys.exit(1)

    print(f"Found {len(files)} files to analyze")
    print(f"Confidence threshold: {args.confidence}")

    # Parse categories if specified
    focus_categories = None
    if args.category:
        focus_categories = [HypothesisCategory(c) for c in args.category]
        print(f"Focusing on categories: {[c.value for c in focus_categories]}")

    # Initialize hypothesizer (without LLM for CLI usage)
    hypothesizer = ZeroDayHypothesizer(
        ai_provider=None,  # Use heuristic mode
        confidence_threshold=args.confidence
    )

    # Generate hypotheses
    print("\nGenerating hypotheses...")
    hypotheses = hypothesizer.hypothesize(
        files=files,
        language=args.language,
        focus_categories=focus_categories,
        max_files=args.max_files
    )

    # Output results
    if args.output:
        output_data = {
            "statistics": hypothesizer.get_statistics(),
            "hypotheses": [h.to_dict() for h in hypotheses]
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults written to {args.output}")
    else:
        stats = hypothesizer.get_statistics()
        print(f"\n{'='*60}")
        print("ZERO-DAY HYPOTHESIS GENERATION RESULTS")
        print(f"{'='*60}")
        print(f"Files analyzed: {stats['total_files_analyzed']}")
        print(f"Total hypotheses: {stats['total_hypotheses_generated']}")
        print(f"High-confidence: {stats['high_confidence_hypotheses']}")
        print(f"{'='*60}\n")

        if hypotheses:
            for i, h in enumerate(hypotheses, 1):
                print(f"{i}. [{h.category.value.upper()}] {h.hypothesis}")
                print(f"   File: {h.affected_code.file_path}:{h.affected_code.line_number}")
                print(f"   Confidence: {h.confidence:.0%} (L:{h.likelihood:.0%} I:{h.impact:.0%} N:{h.novelty:.0%})")
                print(f"   Assumption: {h.assumption_violated}")
                print(f"   Test: {h.suggested_test}")
                if h.cwe_approximation:
                    print(f"   CWE: {h.cwe_approximation}")
                print()
        else:
            print("No high-confidence hypotheses generated.")
            print("Try lowering the confidence threshold with --confidence 0.5")

    return 0


if __name__ == "__main__":
    exit(main())
