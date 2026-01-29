#!/usr/bin/env python3
"""
Proactive AI Scanner - VulnHuntr-Style Autonomous Vulnerability Discovery

This module implements autonomous vulnerability discovery using LLM reasoning,
inspired by VulnHuntr's approach to finding security issues without relying on
traditional pattern-based scanner rules.

Key Features:
- Autonomous scanning without pattern-based rules
- Call chain analysis from entry points to sensitive sinks
- LLM-powered reasoning about security assumptions and exploitation
- High confidence threshold (>0.7) to minimize false positives
- Comprehensive vulnerability type coverage

Vulnerability Types Covered:
- Injection (SQL, command, code, template)
- Authentication/authorization bypasses
- Business logic flaws
- Race conditions
- Insecure deserialization
- SSRF, path traversal

Integration:
- Uses LLMManager for AI provider abstraction
- Outputs ProactiveFinding dataclass for unified reporting
- Integrates with existing Argus pipeline

Based on research: VulnHuntr autonomous vulnerability detection patterns
"""

import ast
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Classification of vulnerability types for proactive scanning"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    TEMPLATE_INJECTION = "template_injection"
    AUTH_BYPASS = "authentication_bypass"
    AUTHZ_BYPASS = "authorization_bypass"
    BUSINESS_LOGIC = "business_logic_flaw"
    RACE_CONDITION = "race_condition"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "cross_site_scripting"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "insecure_direct_object_reference"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CallChainNode:
    """
    Represents a single node in a call chain from source to sink.

    Tracks file location, function/method name, line number, and
    a snippet of the relevant code for context.
    """
    file_path: str
    function_name: str
    line_number: int
    code_snippet: str = ""
    node_type: str = "call"  # "source", "transform", "call", "sink"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "file": self.file_path,
            "function": self.function_name,
            "line": self.line_number,
            "snippet": self.code_snippet,
            "type": self.node_type
        }


@dataclass
class CallChain:
    """
    Represents a complete call chain from an entry point to a sensitive sink.

    A call chain traces how untrusted input flows through the application
    from a source (HTTP handler, CLI arg, file read) to a sink (database
    query, command execution, file write).
    """
    source: CallChainNode
    sink: CallChainNode
    intermediate_nodes: List[CallChainNode] = field(default_factory=list)
    data_transformations: List[str] = field(default_factory=list)
    sanitization_present: bool = False
    validation_present: bool = False

    def get_full_path(self) -> List[CallChainNode]:
        """Get the complete path from source to sink"""
        return [self.source] + self.intermediate_nodes + [self.sink]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "intermediate_nodes": [n.to_dict() for n in self.intermediate_nodes],
            "data_transformations": self.data_transformations,
            "sanitization_present": self.sanitization_present,
            "validation_present": self.validation_present,
            "chain_length": len(self.get_full_path())
        }


@dataclass
class ProactiveFinding:
    """
    Represents a vulnerability discovered through proactive AI scanning.

    Contains comprehensive information about the vulnerability including
    the call chain, LLM reasoning steps, and exploitation scenario.
    """
    vulnerability_type: VulnerabilityType
    description: str
    confidence: float  # 0.0-1.0, only report if >0.7
    call_chain: CallChain
    reasoning_steps: List[str]  # How the LLM reached the conclusion
    exploit_scenario: str  # Potential attack description
    cwe_id: str
    severity: Severity

    # Additional metadata
    finding_id: str = ""
    affected_files: List[str] = field(default_factory=list)
    security_assumptions: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Token usage tracking
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def __post_init__(self):
        """Generate finding ID if not provided"""
        if not self.finding_id:
            self.finding_id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate unique finding ID based on characteristics"""
        key = (
            f"{self.vulnerability_type.value}:"
            f"{self.call_chain.source.file_path}:"
            f"{self.call_chain.sink.function_name}:"
            f"{self.call_chain.sink.line_number}"
        )
        return f"proactive-{hashlib.sha256(key.encode()).hexdigest()[:12]}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "finding_id": self.finding_id,
            "vulnerability_type": self.vulnerability_type.value,
            "description": self.description,
            "confidence": self.confidence,
            "call_chain": self.call_chain.to_dict(),
            "reasoning_steps": self.reasoning_steps,
            "exploit_scenario": self.exploit_scenario,
            "cwe_id": self.cwe_id,
            "severity": self.severity.value,
            "affected_files": self.affected_files,
            "security_assumptions": self.security_assumptions,
            "preconditions": self.preconditions,
            "remediation": self.remediation,
            "references": self.references,
            "token_usage": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "cost_usd": self.cost_usd
            }
        }


class ProactiveAIScanner:
    """
    VulnHuntr-Style Autonomous Vulnerability Discovery Scanner

    This scanner analyzes code without relying on traditional pattern-based
    rules. Instead, it uses LLM reasoning to:

    1. Identify entry points (HTTP handlers, CLI args, file reads)
    2. Trace data flow through function calls
    3. Reason about security assumptions and potential exploitation
    4. Identify dangerous sinks (SQL queries, command execution, etc.)

    Key Principles:
    - Autonomous: Does not rely on predefined vulnerability patterns
    - Reasoning-based: Uses LLM to understand code semantics
    - Call-chain focused: Traces data from source to sink
    - High precision: Only reports findings with >0.7 confidence

    Usage:
        scanner = ProactiveAIScanner(llm_manager)
        findings = scanner.scan(file_paths, project_context)
    """

    # CWE mappings for vulnerability types
    CWE_MAPPINGS = {
        VulnerabilityType.SQL_INJECTION: "CWE-89",
        VulnerabilityType.COMMAND_INJECTION: "CWE-78",
        VulnerabilityType.CODE_INJECTION: "CWE-94",
        VulnerabilityType.TEMPLATE_INJECTION: "CWE-1336",
        VulnerabilityType.AUTH_BYPASS: "CWE-287",
        VulnerabilityType.AUTHZ_BYPASS: "CWE-863",
        VulnerabilityType.BUSINESS_LOGIC: "CWE-840",
        VulnerabilityType.RACE_CONDITION: "CWE-362",
        VulnerabilityType.INSECURE_DESERIALIZATION: "CWE-502",
        VulnerabilityType.SSRF: "CWE-918",
        VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
        VulnerabilityType.XSS: "CWE-79",
        VulnerabilityType.OPEN_REDIRECT: "CWE-601",
        VulnerabilityType.IDOR: "CWE-639",
        VulnerabilityType.SENSITIVE_DATA_EXPOSURE: "CWE-200",
        VulnerabilityType.UNKNOWN: "CWE-1000"
    }

    # Entry point patterns by language
    ENTRY_POINT_PATTERNS = {
        "python": [
            r"@app\.route\s*\(",
            r"@router\.(get|post|put|delete|patch)\s*\(",
            r"def\s+(get|post|put|delete|patch)\s*\(",
            r"class\s+\w+View\s*\(",
            r"def\s+handle\s*\(",
            r"argparse\.ArgumentParser",
            r"sys\.argv",
            r"click\.command",
            r"typer\.Typer",
        ],
        "javascript": [
            r"app\.(get|post|put|delete|patch)\s*\(",
            r"router\.(get|post|put|delete|patch)\s*\(",
            r"express\(\)",
            r"process\.argv",
            r"req\.body",
            r"req\.query",
            r"req\.params",
        ],
        "go": [
            r"func\s+\w+Handler\s*\(",
            r"http\.HandleFunc\s*\(",
            r"r\.HandleFunc\s*\(",
            r"flag\.(String|Int|Bool)",
            r"os\.Args",
        ],
        "java": [
            r"@(Get|Post|Put|Delete|Patch)Mapping",
            r"@RequestMapping",
            r"doGet|doPost|doPut|doDelete",
            r"public\s+\w+\s+main\s*\(",
        ]
    }

    # Dangerous sink patterns by category
    DANGEROUS_SINKS = {
        "sql": [
            r"execute\s*\(",
            r"cursor\.\s*execute",
            r"raw\s*\(",
            r"rawQuery\s*\(",
            r"query\s*\(",
            r"SELECT.*FROM",
            r"INSERT\s+INTO",
            r"UPDATE.*SET",
            r"DELETE\s+FROM",
        ],
        "command": [
            r"subprocess\.(run|call|Popen|check_output)",
            r"os\.(system|popen|exec)",
            r"eval\s*\(",
            r"exec\s*\(",
            r"child_process\.(exec|spawn)",
            r"Runtime\.getRuntime\(\)\.exec",
        ],
        "file": [
            r"open\s*\(",
            r"fopen\s*\(",
            r"readFile\s*\(",
            r"writeFile\s*\(",
            r"Path\s*\(",
            r"file_get_contents",
        ],
        "network": [
            r"requests\.(get|post|put|delete)",
            r"urllib\.request",
            r"http\.request",
            r"fetch\s*\(",
            r"axios\.(get|post)",
            r"HttpClient",
        ],
        "deserialization": [
            r"pickle\.load",
            r"yaml\.load",
            r"json\.loads",
            r"unserialize\s*\(",
            r"ObjectInputStream",
            r"Marshal\.load",
        ],
        "template": [
            r"render_template_string",
            r"Template\s*\(",
            r"Jinja2\s*\(",
            r"eval\s*\(",
            r"\$\{.*\}",
        ]
    }

    def __init__(
        self,
        llm_manager: Optional[Any] = None,
        confidence_threshold: float = 0.7,
        max_chain_depth: int = 10,
        max_files_per_scan: int = 100
    ):
        """
        Initialize the Proactive AI Scanner.

        Args:
            llm_manager: LLMManager instance for AI-powered analysis
            confidence_threshold: Minimum confidence for reporting (default: 0.7)
            max_chain_depth: Maximum call chain depth to trace (default: 10)
            max_files_per_scan: Maximum files to analyze per scan (default: 100)
        """
        self.llm_manager = llm_manager
        self.confidence_threshold = confidence_threshold
        self.max_chain_depth = max_chain_depth
        self.max_files_per_scan = max_files_per_scan

        # Statistics tracking
        self.total_files_scanned = 0
        self.total_entry_points_found = 0
        self.total_chains_analyzed = 0
        self.total_findings = 0
        self.total_cost = 0.0

        # Cache for parsed files and function mappings
        self._file_cache: Dict[str, str] = {}
        self._function_map: Dict[str, Dict[str, int]] = {}  # file -> {func_name: line_num}

        if not llm_manager:
            logger.warning(
                "No LLM manager provided - proactive scanning will be limited. "
                "Provide an initialized LLMManager for full functionality."
            )

        logger.info(
            f"ProactiveAIScanner initialized "
            f"(confidence_threshold={confidence_threshold}, "
            f"max_chain_depth={max_chain_depth})"
        )

    def scan(
        self,
        file_paths: List[str],
        project_context: Optional[Dict[str, Any]] = None,
        target_vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> List[ProactiveFinding]:
        """
        Main entry point - scan files for vulnerabilities autonomously.

        This method orchestrates the entire scanning process:
        1. Identify entry points in the code
        2. Build call chains from entry points to sinks
        3. Analyze each chain using LLM reasoning
        4. Filter to high-confidence findings

        Args:
            file_paths: List of file paths to scan
            project_context: Optional context about the project (frameworks, etc.)
            target_vuln_types: Optional list of vulnerability types to focus on

        Returns:
            List of ProactiveFinding objects with confidence > threshold
        """
        logger.info(f"Starting proactive AI scan on {len(file_paths)} files")

        all_findings: List[ProactiveFinding] = []

        # Limit files for performance
        files_to_scan = file_paths[:self.max_files_per_scan]
        if len(file_paths) > self.max_files_per_scan:
            logger.warning(
                f"Limiting scan to {self.max_files_per_scan} files "
                f"(total: {len(file_paths)})"
            )

        # Phase 1: Identify entry points
        logger.info("Phase 1: Identifying entry points...")
        entry_points = self._identify_entry_points(files_to_scan)
        self.total_entry_points_found = len(entry_points)
        logger.info(f"Found {len(entry_points)} potential entry points")

        if not entry_points:
            logger.info("No entry points found - completing scan")
            return []

        # Phase 2: Build call chains from entry points
        logger.info("Phase 2: Building call chains...")
        call_chains = self._build_call_chains(entry_points, files_to_scan)
        logger.info(f"Built {len(call_chains)} call chains to analyze")

        # Phase 3: Analyze each call chain for vulnerabilities
        logger.info("Phase 3: Analyzing call chains with LLM reasoning...")
        for i, chain in enumerate(call_chains):
            logger.debug(
                f"Analyzing chain {i+1}/{len(call_chains)}: "
                f"{chain.source.function_name} -> {chain.sink.function_name}"
            )

            finding = self._analyze_call_chain(chain, project_context, target_vuln_types)
            self.total_chains_analyzed += 1

            if finding and finding.confidence >= self.confidence_threshold:
                all_findings.append(finding)
                self.total_findings += 1
                logger.info(
                    f"Found vulnerability: {finding.vulnerability_type.value} "
                    f"(confidence: {finding.confidence:.2f})"
                )

        # Phase 4: Deduplicate and sort findings
        logger.info("Phase 4: Post-processing findings...")
        deduplicated_findings = self._deduplicate_findings(all_findings)
        sorted_findings = sorted(
            deduplicated_findings,
            key=lambda f: (
                -f.confidence,
                ["critical", "high", "medium", "low", "info"].index(f.severity.value)
            )
        )

        logger.info(
            f"Proactive scan complete: {len(sorted_findings)} high-confidence findings "
            f"(analyzed {self.total_chains_analyzed} chains)"
        )

        self.total_files_scanned = len(files_to_scan)
        return sorted_findings

    def _identify_entry_points(
        self,
        file_paths: List[str]
    ) -> List[CallChainNode]:
        """
        Identify entry points in the codebase.

        Entry points are locations where untrusted input enters the application:
        - HTTP route handlers
        - CLI argument parsers
        - File readers
        - Message queue consumers
        - WebSocket handlers

        Args:
            file_paths: List of files to scan

        Returns:
            List of CallChainNode objects representing entry points
        """
        entry_points: List[CallChainNode] = []

        for file_path in file_paths:
            content = self._read_file(file_path)
            if not content:
                continue

            # Detect language
            language = self._detect_language(file_path)
            patterns = self.ENTRY_POINT_PATTERNS.get(language, [])

            # Add generic patterns
            patterns.extend([
                r"def\s+\w+\s*\([^)]*request",
                r"function\s+\w+\s*\([^)]*req\b",
            ])

            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extract function/handler name
                        func_name = self._extract_function_name(line, lines, line_num - 1)
                        if func_name:
                            entry_points.append(CallChainNode(
                                file_path=file_path,
                                function_name=func_name,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                node_type="source"
                            ))
                        break

        return entry_points

    def _build_call_chains(
        self,
        entry_points: List[CallChainNode],
        file_paths: List[str]
    ) -> List[CallChain]:
        """
        Build call chains from entry points to dangerous sinks.

        Traces data flow from each entry point through function calls
        until reaching a potentially dangerous operation (sink).

        Args:
            entry_points: List of entry point nodes
            file_paths: List of files to search for sinks

        Returns:
            List of CallChain objects from sources to sinks
        """
        call_chains: List[CallChain] = []

        # First, identify all dangerous sinks in the codebase
        sinks = self._identify_dangerous_sinks(file_paths)

        if not sinks:
            logger.debug("No dangerous sinks identified")
            return []

        # Build function call graph for tracing
        self._build_function_map(file_paths)

        # For each entry point, try to find paths to sinks
        for entry_point in entry_points:
            for sink_category, sink_nodes in sinks.items():
                for sink in sink_nodes:
                    # Check if there's a potential path from entry to sink
                    intermediate = self._find_intermediate_calls(
                        entry_point,
                        sink,
                        file_paths
                    )

                    # Create call chain
                    chain = CallChain(
                        source=entry_point,
                        sink=sink,
                        intermediate_nodes=intermediate,
                        data_transformations=self._detect_transformations(
                            entry_point, sink, intermediate
                        ),
                        sanitization_present=self._check_sanitization(
                            entry_point, sink, intermediate
                        ),
                        validation_present=self._check_validation(
                            entry_point, sink, intermediate
                        )
                    )

                    # Only add chains that seem connected
                    if self._chains_appear_connected(entry_point, sink, intermediate):
                        call_chains.append(chain)

        return call_chains

    def _identify_dangerous_sinks(
        self,
        file_paths: List[str]
    ) -> Dict[str, List[CallChainNode]]:
        """
        Identify dangerous sinks in the codebase.

        Sinks are locations where untrusted data could cause harm:
        - SQL query execution
        - Command execution
        - File operations
        - Network requests (SSRF)
        - Deserialization

        Args:
            file_paths: List of files to scan

        Returns:
            Dictionary mapping sink category to list of sink nodes
        """
        sinks: Dict[str, List[CallChainNode]] = {}

        for file_path in file_paths:
            content = self._read_file(file_path)
            if not content:
                continue

            lines = content.split('\n')

            for category, patterns in self.DANGEROUS_SINKS.items():
                for line_num, line in enumerate(lines, 1):
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            if category not in sinks:
                                sinks[category] = []

                            func_name = self._extract_sink_function(line, pattern)
                            sinks[category].append(CallChainNode(
                                file_path=file_path,
                                function_name=func_name,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                node_type="sink"
                            ))
                            break

        return sinks

    def _analyze_call_chain(
        self,
        chain: CallChain,
        project_context: Optional[Dict[str, Any]],
        target_vuln_types: Optional[List[VulnerabilityType]]
    ) -> Optional[ProactiveFinding]:
        """
        Analyze a call chain using LLM reasoning to identify vulnerabilities.

        This is the core of the autonomous scanning - it uses the LLM to:
        1. Understand what security assumptions the code makes
        2. Reason about what could go wrong with malicious input
        3. Determine the worst-case exploitation scenario
        4. Assign a confidence score

        Args:
            chain: CallChain to analyze
            project_context: Optional project context
            target_vuln_types: Optional filter for vulnerability types

        Returns:
            ProactiveFinding if vulnerability found, None otherwise
        """
        if not self.llm_manager:
            # Fall back to heuristic analysis without LLM
            return self._heuristic_analysis(chain)

        try:
            # Load code context for the chain
            code_context = self._load_chain_code_context(chain)

            # Build the reasoning prompt
            prompt = self._build_reasoning_prompt(chain, code_context, project_context)

            # Call LLM for analysis
            response_text, input_tokens, output_tokens = self.llm_manager.call_llm_api(
                prompt=prompt,
                max_tokens=2000,
                operation="proactive_vulnerability_analysis"
            )

            # Parse LLM response
            finding = self._parse_analysis_response(
                response_text,
                chain,
                input_tokens,
                output_tokens
            )

            # Calculate cost
            if finding:
                finding.input_tokens = input_tokens
                finding.output_tokens = output_tokens
                finding.cost_usd = self._calculate_cost(input_tokens, output_tokens)
                self.total_cost += finding.cost_usd

            return finding

        except Exception as e:
            logger.error(f"Error analyzing call chain: {e}")
            return None

    def _build_reasoning_prompt(
        self,
        chain: CallChain,
        code_context: str,
        project_context: Optional[Dict[str, Any]]
    ) -> str:
        """
        Build the LLM prompt for vulnerability reasoning.

        The prompt guides the LLM through a structured analysis:
        1. Understand the data flow
        2. Identify security assumptions
        3. Reason about exploitation
        4. Assess impact and confidence

        Args:
            chain: The call chain being analyzed
            code_context: Source code context
            project_context: Optional project metadata

        Returns:
            Formatted prompt string
        """
        # Extract framework info if available
        frameworks = []
        if project_context:
            frameworks = project_context.get('frameworks', [])
        frameworks_str = ", ".join(frameworks) if frameworks else "Not detected"

        # Build chain description
        chain_desc = self._format_chain_for_prompt(chain)

        prompt = f"""You are an expert security researcher performing autonomous vulnerability discovery.
Analyze the following code path for security vulnerabilities WITHOUT relying on pattern matching.
Instead, reason deeply about what could go wrong.

## CODE FLOW ANALYSIS

**Entry Point (Source):**
File: {chain.source.file_path}
Function: {chain.source.function_name}
Line: {chain.source.line_number}
Code: `{chain.source.code_snippet}`

**Dangerous Operation (Sink):**
File: {chain.sink.file_path}
Function: {chain.sink.function_name}
Line: {chain.sink.line_number}
Code: `{chain.sink.code_snippet}`

**Call Chain Path:**
{chain_desc}

**Sanitization Detected:** {chain.sanitization_present}
**Validation Detected:** {chain.validation_present}

**Project Context:**
Frameworks: {frameworks_str}

## SOURCE CODE CONTEXT

```
{code_context}
```

## ANALYSIS INSTRUCTIONS

Perform VulnHuntr-style autonomous vulnerability reasoning:

### STEP 1: DATA FLOW UNDERSTANDING
- Where does user/external data enter the application?
- How does it flow through the code to reach the sink?
- Is there any transformation, encoding, or processing along the way?

### STEP 2: SECURITY ASSUMPTIONS
- What security assumptions is this code making?
- Are these assumptions explicitly validated or implicitly trusted?
- Could an attacker violate these assumptions?

### STEP 3: EXPLOITATION REASONING
- If an attacker controls the input, what malicious values could they provide?
- What is the worst-case scenario if exploitation succeeds?
- Are there any bypass techniques for existing protections?

### STEP 4: CONFIDENCE ASSESSMENT
Rate your confidence that this is an exploitable vulnerability:
- 0.9-1.0: Clear vulnerability with obvious exploit path
- 0.7-0.9: Likely vulnerable, minor uncertainties remain
- 0.5-0.7: Possible vulnerability, needs more context
- 0.3-0.5: Probably not vulnerable, weak evidence
- 0.0-0.3: Not vulnerable or false positive

## OUTPUT FORMAT (JSON)

Respond with ONLY valid JSON in this exact format:
{{
    "vulnerability_type": "sql_injection|command_injection|code_injection|template_injection|authentication_bypass|authorization_bypass|business_logic_flaw|race_condition|insecure_deserialization|ssrf|path_traversal|cross_site_scripting|open_redirect|insecure_direct_object_reference|sensitive_data_exposure|none",
    "description": "Clear description of the vulnerability and its impact",
    "confidence": 0.0,
    "severity": "critical|high|medium|low|info",
    "reasoning_steps": [
        "Step 1: Analyzed data flow and found...",
        "Step 2: Identified security assumption that...",
        "Step 3: Exploitation possible because...",
        "Step 4: Confidence assessment based on..."
    ],
    "security_assumptions": ["assumption1", "assumption2"],
    "exploit_scenario": "Detailed description of how an attacker would exploit this",
    "preconditions": ["precondition1", "precondition2"],
    "remediation": "Specific remediation guidance",
    "cwe_id": "CWE-XXX"
}}

If no vulnerability is found, set vulnerability_type to "none" and confidence to 0.0."""

        return prompt

    def _parse_analysis_response(
        self,
        response_text: str,
        chain: CallChain,
        input_tokens: int,
        output_tokens: int
    ) -> Optional[ProactiveFinding]:
        """
        Parse the LLM response into a ProactiveFinding.

        Args:
            response_text: Raw LLM response text
            chain: The analyzed call chain
            input_tokens: Tokens used for input
            output_tokens: Tokens used for output

        Returns:
            ProactiveFinding if vulnerability found, None otherwise
        """
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_text = response_text
            if "```json" in response_text:
                json_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_text = response_text.split("```")[1].split("```")[0].strip()

            data = json.loads(json_text)

            # Check if a vulnerability was found
            vuln_type_str = data.get("vulnerability_type", "none")
            if vuln_type_str == "none" or data.get("confidence", 0) < 0.3:
                return None

            # Map string to enum
            vuln_type = self._map_vulnerability_type(vuln_type_str)
            severity = self._map_severity(data.get("severity", "medium"))

            # Get CWE (use from response or lookup)
            cwe_id = data.get("cwe_id", self.CWE_MAPPINGS.get(vuln_type, "CWE-1000"))

            # Build finding
            finding = ProactiveFinding(
                vulnerability_type=vuln_type,
                description=data.get("description", "Potential vulnerability identified"),
                confidence=float(data.get("confidence", 0.5)),
                call_chain=chain,
                reasoning_steps=data.get("reasoning_steps", []),
                exploit_scenario=data.get("exploit_scenario", ""),
                cwe_id=cwe_id,
                severity=severity,
                affected_files=list(set([
                    chain.source.file_path,
                    chain.sink.file_path
                ] + [n.file_path for n in chain.intermediate_nodes])),
                security_assumptions=data.get("security_assumptions", []),
                preconditions=data.get("preconditions", []),
                remediation=data.get("remediation", ""),
                references=self._get_references_for_vuln_type(vuln_type),
                input_tokens=input_tokens,
                output_tokens=output_tokens
            )

            return finding

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Response text: {response_text[:500]}...")
            return None
        except Exception as e:
            logger.error(f"Error parsing analysis response: {e}")
            return None

    def _heuristic_analysis(self, chain: CallChain) -> Optional[ProactiveFinding]:
        """
        Perform heuristic-based analysis when LLM is not available.

        This is a fallback that uses simpler pattern-based logic.

        Args:
            chain: The call chain to analyze

        Returns:
            ProactiveFinding if suspicious pattern found, None otherwise
        """
        # Check for direct concatenation to SQL
        sink_code = chain.sink.code_snippet.lower()

        vuln_type = None
        confidence = 0.5
        description = ""

        # SQL injection heuristics
        if any(sql in sink_code for sql in ["execute", "query", "select", "insert"]):
            if not chain.sanitization_present and ("%" in sink_code or "+" in sink_code):
                vuln_type = VulnerabilityType.SQL_INJECTION
                confidence = 0.72
                description = (
                    "Potential SQL injection: user input may flow to database query "
                    "without proper parameterization."
                )

        # Command injection heuristics
        if any(cmd in sink_code for cmd in ["subprocess", "os.system", "exec", "popen"]):
            if not chain.sanitization_present:
                vuln_type = VulnerabilityType.COMMAND_INJECTION
                confidence = 0.75
                description = (
                    "Potential command injection: user input may reach command execution "
                    "without proper sanitization."
                )

        # Path traversal heuristics
        if any(fp in sink_code for fp in ["open(", "readfile", "fopen"]):
            if not chain.validation_present:
                vuln_type = VulnerabilityType.PATH_TRAVERSAL
                confidence = 0.68
                description = (
                    "Potential path traversal: file path may be constructed from user input "
                    "without path validation."
                )

        # SSRF heuristics
        if any(net in sink_code for net in ["requests.", "urllib", "http.request", "fetch"]):
            if not chain.validation_present:
                vuln_type = VulnerabilityType.SSRF
                confidence = 0.65
                description = (
                    "Potential SSRF: URL may be constructed from user input, "
                    "allowing requests to internal services."
                )

        if not vuln_type:
            return None

        return ProactiveFinding(
            vulnerability_type=vuln_type,
            description=description,
            confidence=confidence,
            call_chain=chain,
            reasoning_steps=[
                "Heuristic analysis (LLM not available)",
                f"Identified {vuln_type.value} pattern in sink",
                f"Sanitization present: {chain.sanitization_present}",
                f"Validation present: {chain.validation_present}"
            ],
            exploit_scenario="Analysis requires LLM for detailed exploit scenario",
            cwe_id=self.CWE_MAPPINGS.get(vuln_type, "CWE-1000"),
            severity=Severity.MEDIUM,
            remediation="Review the code path and apply appropriate input validation and sanitization."
        )

    # ==================== Helper Methods ====================

    def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content with caching"""
        if file_path in self._file_cache:
            return self._file_cache[file_path]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self._file_cache[file_path] = content
                return content
        except Exception as e:
            logger.debug(f"Could not read file {file_path}: {e}")
            return None

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.go': 'go',
            '.java': 'java',
            '.rb': 'ruby',
            '.php': 'php',
            '.rs': 'rust'
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, 'unknown')

    def _extract_function_name(
        self,
        line: str,
        all_lines: List[str],
        line_idx: int
    ) -> Optional[str]:
        """Extract function or handler name from code line"""
        # Try common patterns
        patterns = [
            r"def\s+(\w+)\s*\(",
            r"function\s+(\w+)\s*\(",
            r"const\s+(\w+)\s*=",
            r"func\s+(\w+)\s*\(",
            r"public\s+\w+\s+(\w+)\s*\(",
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        # For decorators, check the next line
        if line.strip().startswith('@') and line_idx + 1 < len(all_lines):
            next_line = all_lines[line_idx + 1]
            return self._extract_function_name(next_line, all_lines, line_idx + 1)

        return "unknown_handler"

    def _extract_sink_function(self, line: str, pattern: str) -> str:
        """Extract the sink function/operation name"""
        match = re.search(r'(\w+(?:\.\w+)*)\s*\(', line)
        if match:
            return match.group(1)
        return "unknown_sink"

    def _build_function_map(self, file_paths: List[str]) -> None:
        """Build a map of functions to their locations"""
        for file_path in file_paths:
            content = self._read_file(file_path)
            if not content:
                continue

            self._function_map[file_path] = {}
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                # Match function definitions
                match = re.search(r'def\s+(\w+)\s*\(', line)
                if match:
                    self._function_map[file_path][match.group(1)] = line_num

    def _find_intermediate_calls(
        self,
        source: CallChainNode,
        sink: CallChainNode,
        file_paths: List[str]
    ) -> List[CallChainNode]:
        """Find intermediate function calls between source and sink"""
        # Simplified: look for function calls in the source file
        intermediate: List[CallChainNode] = []

        source_content = self._read_file(source.file_path)
        if not source_content:
            return intermediate

        # Look for function calls between source and sink
        lines = source_content.split('\n')
        start_line = source.line_number
        end_line = len(lines) if source.file_path != sink.file_path else sink.line_number

        for line_num in range(start_line, min(end_line, start_line + self.max_chain_depth)):
            if line_num <= len(lines):
                line = lines[line_num - 1]
                # Find function calls
                calls = re.findall(r'(\w+)\s*\(', line)
                for call in calls:
                    if call not in ['if', 'for', 'while', 'def', 'class', 'return']:
                        intermediate.append(CallChainNode(
                            file_path=source.file_path,
                            function_name=call,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            node_type="call"
                        ))

        return intermediate[:self.max_chain_depth]

    def _detect_transformations(
        self,
        source: CallChainNode,
        sink: CallChainNode,
        intermediate: List[CallChainNode]
    ) -> List[str]:
        """Detect data transformations in the call chain"""
        transformations = []

        transform_patterns = [
            (r'encode|decode', 'encoding'),
            (r'str\(|int\(|float\(', 'type_conversion'),
            (r'\.lower\(\)|\.upper\(\)', 'case_change'),
            (r'\.strip\(\)|\.trim\(\)', 'whitespace_trim'),
            (r'\.replace\(', 'string_replace'),
            (r'base64|b64', 'base64_transform'),
            (r'json\.(loads|dumps)', 'json_transform'),
        ]

        for node in [source, sink] + intermediate:
            for pattern, transform_name in transform_patterns:
                if re.search(pattern, node.code_snippet, re.IGNORECASE):
                    if transform_name not in transformations:
                        transformations.append(transform_name)

        return transformations

    def _check_sanitization(
        self,
        source: CallChainNode,
        sink: CallChainNode,
        intermediate: List[CallChainNode]
    ) -> bool:
        """Check if sanitization is present in the chain"""
        sanitization_patterns = [
            r'escape', r'sanitize', r'clean', r'bleach',
            r'html\.escape', r'quote', r'parameterize',
            r'prepared_statement', r'bind_param'
        ]

        for node in [source, sink] + intermediate:
            for pattern in sanitization_patterns:
                if re.search(pattern, node.code_snippet, re.IGNORECASE):
                    return True

        return False

    def _check_validation(
        self,
        source: CallChainNode,
        sink: CallChainNode,
        intermediate: List[CallChainNode]
    ) -> bool:
        """Check if input validation is present in the chain"""
        validation_patterns = [
            r'validate', r'validator', r'is_valid', r'check_',
            r'assert', r'schema', r'pydantic', r'cerberus',
            r'wtforms', r'marshmallow'
        ]

        for node in [source, sink] + intermediate:
            for pattern in validation_patterns:
                if re.search(pattern, node.code_snippet, re.IGNORECASE):
                    return True

        return False

    def _chains_appear_connected(
        self,
        source: CallChainNode,
        sink: CallChainNode,
        intermediate: List[CallChainNode]
    ) -> bool:
        """Determine if a chain appears to be connected (heuristic)"""
        # Same file is a strong indicator
        if source.file_path == sink.file_path:
            return True

        # Check for imports between files
        source_content = self._read_file(source.file_path)
        if source_content:
            sink_module = Path(sink.file_path).stem
            if re.search(rf'import.*{sink_module}|from.*{sink_module}', source_content):
                return True

        # If we have intermediate calls, assume connected
        if intermediate:
            return True

        return False

    def _load_chain_code_context(self, chain: CallChain) -> str:
        """Load code context for the entire call chain"""
        context_parts = []

        # Add source context
        source_context = self._get_code_context(
            chain.source.file_path,
            chain.source.line_number,
            lines_before=10,
            lines_after=10
        )
        context_parts.append(f"# Source: {chain.source.file_path}\n{source_context}")

        # Add sink context if different file
        if chain.sink.file_path != chain.source.file_path:
            sink_context = self._get_code_context(
                chain.sink.file_path,
                chain.sink.line_number,
                lines_before=10,
                lines_after=10
            )
            context_parts.append(f"\n# Sink: {chain.sink.file_path}\n{sink_context}")

        return "\n".join(context_parts)

    def _get_code_context(
        self,
        file_path: str,
        line_number: int,
        lines_before: int = 10,
        lines_after: int = 10
    ) -> str:
        """Get code context around a specific line"""
        content = self._read_file(file_path)
        if not content:
            return f"# Could not read {file_path}"

        lines = content.split('\n')
        start = max(0, line_number - lines_before - 1)
        end = min(len(lines), line_number + lines_after)

        context_lines = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == line_number else "    "
            context_lines.append(f"{marker}{line_num:4d} | {lines[i]}")

        return "\n".join(context_lines)

    def _format_chain_for_prompt(self, chain: CallChain) -> str:
        """Format call chain for inclusion in prompt"""
        parts = []

        parts.append(f"1. [SOURCE] {chain.source.function_name} @ {chain.source.file_path}:{chain.source.line_number}")

        for i, node in enumerate(chain.intermediate_nodes[:5], 2):
            parts.append(f"{i}. [CALL] {node.function_name} @ {node.file_path}:{node.line_number}")

        if len(chain.intermediate_nodes) > 5:
            parts.append(f"   ... ({len(chain.intermediate_nodes) - 5} more intermediate calls)")

        parts.append(f"{len(parts)+1}. [SINK] {chain.sink.function_name} @ {chain.sink.file_path}:{chain.sink.line_number}")

        return "\n".join(parts)

    def _map_vulnerability_type(self, vuln_str: str) -> VulnerabilityType:
        """Map string to VulnerabilityType enum"""
        mapping = {
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "command_injection": VulnerabilityType.COMMAND_INJECTION,
            "code_injection": VulnerabilityType.CODE_INJECTION,
            "template_injection": VulnerabilityType.TEMPLATE_INJECTION,
            "authentication_bypass": VulnerabilityType.AUTH_BYPASS,
            "authorization_bypass": VulnerabilityType.AUTHZ_BYPASS,
            "business_logic_flaw": VulnerabilityType.BUSINESS_LOGIC,
            "race_condition": VulnerabilityType.RACE_CONDITION,
            "insecure_deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
            "ssrf": VulnerabilityType.SSRF,
            "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
            "cross_site_scripting": VulnerabilityType.XSS,
            "open_redirect": VulnerabilityType.OPEN_REDIRECT,
            "insecure_direct_object_reference": VulnerabilityType.IDOR,
            "sensitive_data_exposure": VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        }
        return mapping.get(vuln_str.lower(), VulnerabilityType.UNKNOWN)

    def _map_severity(self, severity_str: str) -> Severity:
        """Map string to Severity enum"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)

    def _get_references_for_vuln_type(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get relevant OWASP references for vulnerability type"""
        references = {
            VulnerabilityType.SQL_INJECTION: [
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            ],
            VulnerabilityType.XSS: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                "https://owasp.org/www-community/attacks/Path_Traversal"
            ],
            VulnerabilityType.SSRF: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            VulnerabilityType.INSECURE_DESERIALIZATION: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
            ],
            VulnerabilityType.AUTH_BYPASS: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ],
            VulnerabilityType.AUTHZ_BYPASS: [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
            ],
        }
        return references.get(vuln_type, ["https://owasp.org/www-project-top-ten/"])

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost based on token usage"""
        # Default to Anthropic pricing
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0
        return input_cost + output_cost

    def _deduplicate_findings(
        self,
        findings: List[ProactiveFinding]
    ) -> List[ProactiveFinding]:
        """Remove duplicate findings based on location and type"""
        seen: Set[str] = set()
        unique: List[ProactiveFinding] = []

        for finding in findings:
            key = (
                f"{finding.vulnerability_type.value}:"
                f"{finding.call_chain.sink.file_path}:"
                f"{finding.call_chain.sink.line_number}"
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            "files_scanned": self.total_files_scanned,
            "entry_points_found": self.total_entry_points_found,
            "chains_analyzed": self.total_chains_analyzed,
            "findings_reported": self.total_findings,
            "total_cost_usd": round(self.total_cost, 4),
            "confidence_threshold": self.confidence_threshold
        }


def main():
    """CLI entry point for proactive AI scanner"""
    import argparse
    import sys

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(
        description="Proactive AI Scanner - VulnHuntr-style autonomous vulnerability discovery"
    )
    parser.add_argument("path", help="Path to scan (file or directory)")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--confidence", "-c", type=float, default=0.7,
                       help="Minimum confidence threshold (default: 0.7)")
    parser.add_argument("--max-files", type=int, default=100,
                       help="Maximum files to scan (default: 100)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Gather files to scan
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path {args.path} does not exist")
        sys.exit(1)

    files: List[str] = []
    if target_path.is_file():
        files = [str(target_path)]
    else:
        # Scan for source code files
        extensions = ["*.py", "*.js", "*.ts", "*.go", "*.java", "*.rb", "*.php"]
        for ext in extensions:
            files.extend([str(f) for f in target_path.rglob(ext)])

    print(f"Found {len(files)} files to scan")

    # Initialize scanner (without LLM for CLI demo)
    # In production, pass an initialized LLMManager
    try:
        # Try to initialize LLMManager if API key is available
        from orchestrator.llm_manager import LLMManager

        config = {
            "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY"),
            "openai_api_key": os.environ.get("OPENAI_API_KEY"),
        }

        llm_manager = None
        if config["anthropic_api_key"] or config["openai_api_key"]:
            llm_manager = LLMManager(config)
            if llm_manager.initialize():
                print(f"Initialized LLM: {llm_manager.provider}/{llm_manager.model}")
            else:
                llm_manager = None
                print("LLM initialization failed - using heuristic analysis")
        else:
            print("No API key found - using heuristic analysis")

    except ImportError:
        llm_manager = None
        print("LLMManager not available - using heuristic analysis")

    scanner = ProactiveAIScanner(
        llm_manager=llm_manager,
        confidence_threshold=args.confidence,
        max_files_per_scan=args.max_files
    )

    # Run scan
    print("\nStarting proactive vulnerability scan...")
    print("=" * 60)

    findings = scanner.scan(files)

    # Display results
    print("\n" + "=" * 60)
    print(f"SCAN RESULTS: {len(findings)} vulnerabilities found")
    print("=" * 60)

    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. [{finding.severity.value.upper()}] {finding.vulnerability_type.value}")
        print(f"   Confidence: {finding.confidence:.0%}")
        print(f"   CWE: {finding.cwe_id}")
        print(f"   Location: {finding.call_chain.sink.file_path}:{finding.call_chain.sink.line_number}")
        print(f"   Description: {finding.description[:200]}...")
        if finding.reasoning_steps:
            print(f"   Reasoning: {finding.reasoning_steps[0][:100]}...")

    # Output to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "findings": [f.to_dict() for f in findings],
                "statistics": scanner.get_statistics()
            }, f, indent=2)
        print(f"\nResults written to {args.output}")

    # Print statistics
    stats = scanner.get_statistics()
    print(f"\nStatistics:")
    print(f"  Files scanned: {stats['files_scanned']}")
    print(f"  Entry points found: {stats['entry_points_found']}")
    print(f"  Call chains analyzed: {stats['chains_analyzed']}")
    print(f"  Findings reported: {stats['findings_reported']}")
    if stats['total_cost_usd'] > 0:
        print(f"  Total cost: ${stats['total_cost_usd']:.4f}")


if __name__ == "__main__":
    main()
