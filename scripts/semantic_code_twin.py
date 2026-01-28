#!/usr/bin/env python3
"""
Semantic Code Twin - AISLE-like Semantic Code Understanding

Based on AISLE (AI Security Language Engine) research for deep code semantic analysis.
This module creates a semantic "twin" of code that captures its intended behavior,
actual behavior, data flows, and security-relevant operations.

Key Features:
- AST-based code parsing (tree-sitter with Python ast fallback)
- Semantic extraction: function signatures, data flows, trust boundaries
- Security operation detection: DB queries, file ops, network calls, crypto
- LLM-powered intent inference for missing documentation
- Intent vs behavior mismatch detection for vulnerability discovery

CodeTwin Structure:
- intent: What the code SHOULD do (from docstrings, comments, function names)
- actual_behavior: What it MIGHT do (inferred from code analysis)
- data_flows: Source -> transformations -> sink paths
- trust_boundaries: Map of trusted vs untrusted data
- security_operations: Security-sensitive operations found
- semantic_hash: Unique identifier for semantic meaning

Integration:
- Works with IRISAnalyzer for enhanced vulnerability detection
- Provides structured context for LLM security analysis
- Returns normalized dataclasses for unified reporting
"""

import ast
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Trust level classification for data"""
    UNTRUSTED = "untrusted"      # User input, network data, file contents
    SANITIZED = "sanitized"      # Data that has been validated/sanitized
    INTERNAL = "internal"        # Internal application data
    TRUSTED = "trusted"          # Hardcoded/config values, trusted sources


class SecurityOpType(Enum):
    """Types of security-relevant operations"""
    DATABASE_QUERY = "database_query"
    FILE_OPERATION = "file_operation"
    NETWORK_CALL = "network_call"
    CRYPTO_OPERATION = "crypto_operation"
    COMMAND_EXECUTION = "command_execution"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SERIALIZATION = "serialization"
    LOGGING = "logging"
    INPUT_VALIDATION = "input_validation"


@dataclass
class DataFlow:
    """
    Represents a data flow path through code

    Tracks how data moves from sources (inputs) through
    transformations to sinks (outputs/side effects).
    """
    source: str                                 # Where data originates
    source_type: TrustLevel                     # Trust level of source
    transformations: List[str] = field(default_factory=list)  # Operations applied
    sink: Optional[str] = None                  # Final destination
    sink_type: Optional[str] = None             # Type of sink (db, file, network, etc.)
    is_sanitized: bool = False                  # Whether sanitization was applied
    taint_propagation: List[str] = field(default_factory=list)  # Variables carrying taint

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "source": self.source,
            "source_type": self.source_type.value,
            "transformations": self.transformations,
            "sink": self.sink,
            "sink_type": self.sink_type,
            "is_sanitized": self.is_sanitized,
            "taint_propagation": self.taint_propagation
        }


@dataclass
class SecurityOperation:
    """
    Represents a security-sensitive operation in code

    Captures operations that could have security implications
    such as database queries, file operations, or crypto usage.
    """
    operation_type: SecurityOpType
    location: str                               # file:line
    code_snippet: str                           # The actual code
    function_name: Optional[str] = None         # Enclosing function
    parameters: List[str] = field(default_factory=list)  # Parameters involved
    risk_indicators: List[str] = field(default_factory=list)  # Potential risks
    data_sources: List[str] = field(default_factory=list)  # Data feeding this op

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "operation_type": self.operation_type.value,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "function_name": self.function_name,
            "parameters": self.parameters,
            "risk_indicators": self.risk_indicators,
            "data_sources": self.data_sources
        }


@dataclass
class FunctionSignature:
    """
    Represents a function/method signature with semantic information
    """
    name: str
    parameters: List[Tuple[str, Optional[str]]]  # (name, type_hint)
    return_type: Optional[str] = None
    docstring: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    class_name: Optional[str] = None            # If method, enclosing class
    inferred_purpose: Optional[str] = None      # LLM-inferred purpose

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "name": self.name,
            "parameters": [{"name": p[0], "type": p[1]} for p in self.parameters],
            "return_type": self.return_type,
            "docstring": self.docstring,
            "decorators": self.decorators,
            "is_async": self.is_async,
            "class_name": self.class_name,
            "inferred_purpose": self.inferred_purpose
        }


@dataclass
class CodeTwin:
    """
    Semantic twin of a code unit

    Captures the complete semantic understanding of code including
    its intent, actual behavior, data flows, and security properties.
    This enables comparison between what code should do vs what it
    actually does - a key technique for vulnerability detection.
    """
    # Identity (required fields first)
    file_path: str
    language: str
    semantic_hash: str                          # Hash of semantic meaning

    # Intent (what it SHOULD do)
    intent: str                                 # Overall intended purpose

    # Actual behavior (what it MIGHT do)
    actual_behavior: str                        # Inferred actual behavior

    # Optional fields with defaults below
    stated_preconditions: List[str] = field(default_factory=list)
    stated_postconditions: List[str] = field(default_factory=list)
    behavior_summary: str = ""                  # Brief behavior description

    # Structural analysis
    functions: List[FunctionSignature] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)

    # Data flow analysis
    data_flows: List[DataFlow] = field(default_factory=list)

    # Trust boundary analysis
    trust_boundaries: Dict[str, TrustLevel] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)  # External entry points
    exit_points: List[str] = field(default_factory=list)   # External exit points

    # Security analysis
    security_operations: List[SecurityOperation] = field(default_factory=list)
    potential_vulnerabilities: List[str] = field(default_factory=list)

    # Mismatch detection
    intent_behavior_mismatches: List[str] = field(default_factory=list)

    # Metadata
    lines_of_code: int = 0
    complexity_score: float = 0.0               # Cyclomatic complexity estimate

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "file_path": self.file_path,
            "language": self.language,
            "semantic_hash": self.semantic_hash,
            "intent": self.intent,
            "stated_preconditions": self.stated_preconditions,
            "stated_postconditions": self.stated_postconditions,
            "actual_behavior": self.actual_behavior,
            "behavior_summary": self.behavior_summary,
            "functions": [f.to_dict() for f in self.functions],
            "classes": self.classes,
            "imports": self.imports,
            "data_flows": [df.to_dict() for df in self.data_flows],
            "trust_boundaries": {k: v.value for k, v in self.trust_boundaries.items()},
            "entry_points": self.entry_points,
            "exit_points": self.exit_points,
            "security_operations": [op.to_dict() for op in self.security_operations],
            "potential_vulnerabilities": self.potential_vulnerabilities,
            "intent_behavior_mismatches": self.intent_behavior_mismatches,
            "lines_of_code": self.lines_of_code,
            "complexity_score": self.complexity_score
        }


class SemanticCodeTwin:
    """
    AISLE-like Semantic Code Understanding Engine

    Creates semantic "twins" of code that capture both intended and actual
    behavior. By comparing these, we can detect subtle vulnerabilities where
    code doesn't do what developers think it does.

    Analysis Pipeline:
    1. Parse code into AST (tree-sitter or Python ast)
    2. Extract structural information (functions, classes, imports)
    3. Analyze data flows (sources, transformations, sinks)
    4. Identify trust boundaries (user input vs internal data)
    5. Detect security-relevant operations
    6. Infer intent from documentation and naming
    7. Compare intent vs behavior to find mismatches

    Usage:
        analyzer = SemanticCodeTwin(llm_provider)
        twin = analyzer.analyze_file("path/to/code.py")
        mismatches = twin.intent_behavior_mismatches
    """

    # Patterns for identifying security-relevant operations
    SECURITY_PATTERNS = {
        "database": [
            r"\.execute\s*\(",
            r"\.query\s*\(",
            r"cursor\.",
            r"SELECT\s+.*\s+FROM",
            r"INSERT\s+INTO",
            r"UPDATE\s+.*\s+SET",
            r"DELETE\s+FROM",
            r"\.find\s*\(",
            r"\.aggregate\s*\(",
        ],
        "file": [
            r"open\s*\(",
            r"\.read\s*\(",
            r"\.write\s*\(",
            r"os\.path",
            r"pathlib\.",
            r"shutil\.",
            r"with\s+open",
        ],
        "network": [
            r"requests\.",
            r"urllib",
            r"httpx\.",
            r"aiohttp",
            r"socket\.",
            r"\.fetch\s*\(",
            r"axios\.",
        ],
        "crypto": [
            r"hashlib\.",
            r"hmac\.",
            r"cryptography\.",
            r"Crypto\.",
            r"bcrypt",
            r"\.encrypt\s*\(",
            r"\.decrypt\s*\(",
            r"\.hash\s*\(",
        ],
        "command": [
            r"subprocess\.",
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"exec\s*\(",
            r"eval\s*\(",
            r"shell=True",
            r"child_process",
        ],
        "auth": [
            r"authenticate",
            r"login",
            r"logout",
            r"verify_password",
            r"check_password",
            r"jwt\.",
            r"token",
        ],
        "serialization": [
            r"pickle\.",
            r"yaml\.load",
            r"json\.loads",
            r"deserialize",
            r"unmarshal",
            r"\.parse\s*\(",
        ],
    }

    # Patterns for identifying untrusted input sources
    UNTRUSTED_SOURCES = [
        r"request\.",
        r"req\.",
        r"params\[",
        r"query\[",
        r"body\[",
        r"headers\[",
        r"\.GET\[",
        r"\.POST\[",
        r"form\[",
        r"args\[",
        r"input\s*\(",
        r"sys\.argv",
        r"os\.environ",
        r"\.read\s*\(",
    ]

    # Patterns for sanitization functions
    SANITIZATION_PATTERNS = [
        r"escape",
        r"sanitize",
        r"validate",
        r"clean",
        r"strip",
        r"encode",
        r"quote",
        r"parameterize",
        r"prepared_statement",
    ]

    def __init__(self, llm_provider: Optional[Any] = None, use_tree_sitter: bool = True):
        """
        Initialize Semantic Code Twin analyzer

        Args:
            llm_provider: AI provider for intent inference (Claude, OpenAI, etc.)
            use_tree_sitter: Whether to try tree-sitter first (falls back to ast)
        """
        self.llm_provider = llm_provider
        self.use_tree_sitter = use_tree_sitter
        self._tree_sitter_available = False

        # Try to initialize tree-sitter
        if use_tree_sitter:
            self._tree_sitter_available = self._init_tree_sitter()

        # Statistics tracking
        self.files_analyzed = 0
        self.total_functions = 0
        self.total_security_ops = 0
        self.total_mismatches = 0

        logger.info(
            f"SemanticCodeTwin initialized "
            f"(tree-sitter: {'enabled' if self._tree_sitter_available else 'disabled'}, "
            f"LLM: {'enabled' if llm_provider else 'disabled'})"
        )

    def _init_tree_sitter(self) -> bool:
        """
        Initialize tree-sitter parser if available

        Returns:
            True if tree-sitter is available, False otherwise
        """
        try:
            # Attempt to import tree-sitter
            # Note: Requires tree-sitter and language-specific parsers
            import tree_sitter
            logger.debug("tree-sitter available")
            return True
        except ImportError:
            logger.debug("tree-sitter not available, will use Python ast module")
            return False

    def analyze_file(self, file_path: str, content: Optional[str] = None) -> CodeTwin:
        """
        Analyze a file and create its semantic twin

        Args:
            file_path: Path to the source file
            content: Optional file content (if not provided, reads from file_path)

        Returns:
            CodeTwin representing the semantic understanding of the code
        """
        logger.info(f"Analyzing file: {file_path}")
        self.files_analyzed += 1

        # Read file content if not provided
        if content is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return self._create_error_twin(file_path, str(e))

        # Detect language
        language = self._detect_language(file_path)

        # Parse code into AST
        ast_data = self._parse_code(content, language)

        # Extract semantic information
        functions = self._extract_functions(ast_data, content, language)
        classes = self._extract_classes(ast_data, content, language)
        imports = self._extract_imports(ast_data, content, language)

        # Analyze data flows
        data_flows = self._analyze_data_flows(content, ast_data, language)

        # Identify trust boundaries
        trust_boundaries = self._identify_trust_boundaries(content, functions)
        entry_points = self._identify_entry_points(functions, content)
        exit_points = self._identify_exit_points(content)

        # Detect security operations
        security_ops = self._detect_security_operations(content, file_path, functions)
        self.total_security_ops += len(security_ops)

        # Infer intent from documentation and naming
        intent = self._infer_intent(content, functions, file_path)

        # Analyze actual behavior
        actual_behavior = self._analyze_actual_behavior(
            content, functions, data_flows, security_ops
        )

        # Detect intent/behavior mismatches
        mismatches = self._detect_mismatches(intent, actual_behavior, functions, security_ops)
        self.total_mismatches += len(mismatches)

        # Calculate complexity
        complexity = self._calculate_complexity(ast_data, content)

        # Generate semantic hash
        semantic_hash = self._generate_semantic_hash(
            functions, data_flows, security_ops, intent
        )

        # Track function count
        self.total_functions += len(functions)

        # Create CodeTwin
        twin = CodeTwin(
            file_path=file_path,
            language=language,
            semantic_hash=semantic_hash,
            intent=intent,
            actual_behavior=actual_behavior,
            behavior_summary=self._summarize_behavior(actual_behavior),
            functions=functions,
            classes=classes,
            imports=imports,
            data_flows=data_flows,
            trust_boundaries=trust_boundaries,
            entry_points=entry_points,
            exit_points=exit_points,
            security_operations=security_ops,
            potential_vulnerabilities=self._identify_potential_vulns(data_flows, security_ops),
            intent_behavior_mismatches=mismatches,
            lines_of_code=len(content.splitlines()),
            complexity_score=complexity
        )

        logger.info(
            f"Analysis complete: {len(functions)} functions, "
            f"{len(security_ops)} security ops, {len(mismatches)} mismatches"
        )

        return twin

    def analyze_code_snippet(
        self,
        code: str,
        language: str = "python",
        context: Optional[str] = None
    ) -> CodeTwin:
        """
        Analyze a code snippet without file context

        Args:
            code: Source code to analyze
            language: Programming language
            context: Optional surrounding context

        Returns:
            CodeTwin for the snippet
        """
        return self.analyze_file(
            file_path="<snippet>",
            content=code
        )

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
        }
        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, "unknown")

    def _parse_code(self, content: str, language: str) -> Optional[Any]:
        """
        Parse code into AST

        Uses tree-sitter if available, falls back to Python ast module for Python.
        """
        if language == "python":
            try:
                return ast.parse(content)
            except SyntaxError as e:
                logger.warning(f"Failed to parse Python code: {e}")
                return None
        else:
            # For non-Python, return None and rely on regex-based analysis
            # In production, would use tree-sitter for other languages
            logger.debug(f"AST parsing not implemented for {language}, using regex analysis")
            return None

    def _extract_functions(
        self,
        ast_data: Optional[Any],
        content: str,
        language: str
    ) -> List[FunctionSignature]:
        """Extract function signatures from code"""
        functions = []

        if language == "python" and ast_data:
            functions = self._extract_python_functions(ast_data)
        else:
            # Regex fallback for other languages
            functions = self._extract_functions_regex(content, language)

        return functions

    def _extract_python_functions(self, tree: ast.AST) -> List[FunctionSignature]:
        """Extract functions from Python AST"""
        functions = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Extract parameters
                params = []
                for arg in node.args.args:
                    type_hint = None
                    if arg.annotation:
                        type_hint = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else str(arg.annotation)
                    params.append((arg.arg, type_hint))

                # Extract return type
                return_type = None
                if node.returns:
                    return_type = ast.unparse(node.returns) if hasattr(ast, 'unparse') else str(node.returns)

                # Extract docstring
                docstring = ast.get_docstring(node)

                # Extract decorators
                decorators = []
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(f"{dec.value.id}.{dec.attr}" if isinstance(dec.value, ast.Name) else dec.attr)
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            decorators.append(dec.func.id)

                # Determine enclosing class
                class_name = None
                for parent in ast.walk(tree):
                    if isinstance(parent, ast.ClassDef):
                        for child in ast.iter_child_nodes(parent):
                            if child is node:
                                class_name = parent.name
                                break

                func_sig = FunctionSignature(
                    name=node.name,
                    parameters=params,
                    return_type=return_type,
                    docstring=docstring,
                    decorators=decorators,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    class_name=class_name
                )
                functions.append(func_sig)

        return functions

    def _extract_functions_regex(self, content: str, language: str) -> List[FunctionSignature]:
        """Extract functions using regex for non-Python languages"""
        functions = []

        # Language-specific patterns
        patterns = {
            "javascript": r"(?:async\s+)?function\s+(\w+)\s*\((.*?)\)",
            "typescript": r"(?:async\s+)?function\s+(\w+)\s*\((.*?)\)",
            "go": r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\((.*?)\)",
            "java": r"(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\((.*?)\)",
            "ruby": r"def\s+(\w+)(?:\((.*?)\))?",
        }

        pattern = patterns.get(language)
        if pattern:
            for match in re.finditer(pattern, content, re.MULTILINE):
                name = match.group(1)
                params_str = match.group(2) if len(match.groups()) > 1 else ""
                params = [(p.strip(), None) for p in params_str.split(",") if p.strip()]

                functions.append(FunctionSignature(
                    name=name,
                    parameters=params,
                    is_async="async" in match.group(0)
                ))

        return functions

    def _extract_classes(
        self,
        ast_data: Optional[Any],
        content: str,
        language: str
    ) -> List[str]:
        """Extract class names from code"""
        classes = []

        if language == "python" and ast_data:
            for node in ast.walk(ast_data):
                if isinstance(node, ast.ClassDef):
                    classes.append(node.name)
        else:
            # Regex fallback
            class_pattern = r"class\s+(\w+)"
            for match in re.finditer(class_pattern, content):
                classes.append(match.group(1))

        return classes

    def _extract_imports(
        self,
        ast_data: Optional[Any],
        content: str,
        language: str
    ) -> List[str]:
        """Extract import statements from code"""
        imports = []

        if language == "python" and ast_data:
            for node in ast.walk(ast_data):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
        else:
            # Regex for common import patterns
            import_patterns = [
                r"import\s+(.+?)(?:;|\n)",
                r"from\s+(.+?)\s+import",
                r"require\s*\(\s*['\"](.+?)['\"]\s*\)",
            ]
            for pattern in import_patterns:
                for match in re.finditer(pattern, content):
                    imports.append(match.group(1).strip())

        return imports

    def _analyze_data_flows(
        self,
        content: str,
        ast_data: Optional[Any],
        language: str
    ) -> List[DataFlow]:
        """
        Analyze data flow patterns in code

        Identifies sources of untrusted data and tracks how they flow
        through the code to potential sinks.
        """
        data_flows = []

        # Find untrusted input sources
        for pattern in self.UNTRUSTED_SOURCES:
            for match in re.finditer(pattern, content):
                source = match.group(0)
                line_num = content[:match.start()].count('\n') + 1

                # Look for subsequent operations on this data
                context = content[match.start():match.start() + 500]

                # Check if sanitization is applied
                is_sanitized = any(
                    re.search(san_pattern, context, re.IGNORECASE)
                    for san_pattern in self.SANITIZATION_PATTERNS
                )

                # Find potential sinks
                sink = None
                sink_type = None

                for op_type, op_patterns in self.SECURITY_PATTERNS.items():
                    for op_pattern in op_patterns:
                        if re.search(op_pattern, context, re.IGNORECASE):
                            sink = op_pattern
                            sink_type = op_type
                            break
                    if sink:
                        break

                data_flow = DataFlow(
                    source=f"{source} (line {line_num})",
                    source_type=TrustLevel.UNTRUSTED,
                    transformations=self._find_transformations(context),
                    sink=sink,
                    sink_type=sink_type,
                    is_sanitized=is_sanitized
                )
                data_flows.append(data_flow)

        return data_flows

    def _find_transformations(self, context: str) -> List[str]:
        """Find data transformations in code context"""
        transformations = []

        transform_patterns = [
            (r"\.strip\(\)", "strip whitespace"),
            (r"\.lower\(\)", "lowercase conversion"),
            (r"\.upper\(\)", "uppercase conversion"),
            (r"\.encode\(", "encoding"),
            (r"\.decode\(", "decoding"),
            (r"int\(", "integer conversion"),
            (r"str\(", "string conversion"),
            (r"json\.loads", "JSON parsing"),
            (r"json\.dumps", "JSON serialization"),
        ]

        for pattern, description in transform_patterns:
            if re.search(pattern, context):
                transformations.append(description)

        return transformations

    def _identify_trust_boundaries(
        self,
        content: str,
        functions: List[FunctionSignature]
    ) -> Dict[str, TrustLevel]:
        """
        Identify trust boundaries in code

        Maps variable/parameter names to their trust levels based on
        source analysis and naming conventions.
        """
        boundaries = {}

        # Parameters from request handlers are untrusted
        for func in functions:
            if any(x in func.name.lower() for x in ["handler", "view", "endpoint", "route"]):
                for param_name, _ in func.parameters:
                    if param_name not in ["self", "cls"]:
                        boundaries[param_name] = TrustLevel.UNTRUSTED

        # Look for explicitly untrusted variable names
        untrusted_names = ["user_input", "request", "req", "params", "query", "body"]
        for name in untrusted_names:
            if name in content:
                boundaries[name] = TrustLevel.UNTRUSTED

        # Look for validated/sanitized data
        for pattern in self.SANITIZATION_PATTERNS:
            matches = re.findall(rf"(\w+)\s*=\s*{pattern}", content)
            for var_name in matches:
                boundaries[var_name] = TrustLevel.SANITIZED

        return boundaries

    def _identify_entry_points(
        self,
        functions: List[FunctionSignature],
        content: str
    ) -> List[str]:
        """Identify external entry points into the code"""
        entry_points = []

        # Look for route/endpoint decorators
        endpoint_decorators = ["route", "get", "post", "put", "delete", "api", "endpoint"]
        for func in functions:
            if any(dec.lower() in endpoint_decorators for dec in func.decorators):
                entry_points.append(func.name)

        # Look for main entry points
        if "__main__" in content or "if __name__" in content:
            entry_points.append("__main__")

        # Look for handler functions
        handler_patterns = ["handler", "callback", "listener", "on_"]
        for func in functions:
            if any(pattern in func.name.lower() for pattern in handler_patterns):
                entry_points.append(func.name)

        return entry_points

    def _identify_exit_points(self, content: str) -> List[str]:
        """Identify external exit points from the code"""
        exit_points = []

        # Database operations
        if re.search(r"\.execute\(|\.query\(|cursor\.", content):
            exit_points.append("database")

        # File operations
        if re.search(r"open\(|\.write\(|\.read\(", content):
            exit_points.append("filesystem")

        # Network operations
        if re.search(r"requests\.|urllib|httpx\.|socket\.", content):
            exit_points.append("network")

        # Logging
        if re.search(r"logger\.|logging\.|print\(|console\.", content):
            exit_points.append("logging")

        return exit_points

    def _detect_security_operations(
        self,
        content: str,
        file_path: str,
        functions: List[FunctionSignature]
    ) -> List[SecurityOperation]:
        """Detect security-relevant operations in code"""
        operations = []
        lines = content.splitlines()

        # Map operation patterns to types
        op_type_map = {
            "database": SecurityOpType.DATABASE_QUERY,
            "file": SecurityOpType.FILE_OPERATION,
            "network": SecurityOpType.NETWORK_CALL,
            "crypto": SecurityOpType.CRYPTO_OPERATION,
            "command": SecurityOpType.COMMAND_EXECUTION,
            "auth": SecurityOpType.AUTHENTICATION,
            "serialization": SecurityOpType.SERIALIZATION,
        }

        for category, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Find enclosing function
                    enclosing_func = None
                    for func in functions:
                        # Simple heuristic - could be improved with AST
                        if func.name in content[:match.start()]:
                            enclosing_func = func.name

                    # Identify risk indicators
                    risk_indicators = self._identify_risks(line_content, category)

                    op = SecurityOperation(
                        operation_type=op_type_map.get(category, SecurityOpType.LOGGING),
                        location=f"{file_path}:{line_num}",
                        code_snippet=line_content.strip(),
                        function_name=enclosing_func,
                        risk_indicators=risk_indicators
                    )
                    operations.append(op)

        return operations

    def _identify_risks(self, code_line: str, category: str) -> List[str]:
        """Identify potential risk indicators in a line of code"""
        risks = []

        # Check for string concatenation in SQL (SQL injection risk)
        if category == "database":
            if "+" in code_line or "%" in code_line or "f'" in code_line or 'f"' in code_line:
                risks.append("Possible SQL injection - string concatenation in query")

        # Check for shell=True (command injection risk)
        if category == "command":
            if "shell=True" in code_line:
                risks.append("Command injection risk - shell=True")

        # Check for eval/exec with user input
        if "eval(" in code_line or "exec(" in code_line:
            risks.append("Code injection risk - dynamic code execution")

        # Check for pickle (deserialization risk)
        if "pickle" in code_line.lower():
            risks.append("Deserialization risk - pickle usage")

        return risks

    def _infer_intent(
        self,
        content: str,
        functions: List[FunctionSignature],
        file_path: str
    ) -> str:
        """
        Infer the intent of the code

        Combines docstrings, comments, and function names to understand
        what the code is supposed to do. Uses LLM if available and
        documentation is missing.
        """
        intent_parts = []

        # Extract module-level docstring
        module_doc_match = re.match(r'^[\'\"]{3}(.*?)[\'\"]{3}', content, re.DOTALL)
        if module_doc_match:
            intent_parts.append(f"Module purpose: {module_doc_match.group(1).strip()[:200]}")

        # Collect function intents
        for func in functions:
            if func.docstring:
                intent_parts.append(f"{func.name}: {func.docstring[:100]}")
            else:
                # Infer from function name
                inferred = self._infer_from_name(func.name)
                if inferred:
                    intent_parts.append(f"{func.name}: {inferred}")

        # If no documentation found and LLM available, use it
        if not intent_parts and self.llm_provider:
            intent_parts.append(self._llm_infer_intent(content, file_path))

        if intent_parts:
            return " | ".join(intent_parts)
        else:
            return "Intent unclear - no documentation or naming patterns detected"

    def _infer_from_name(self, name: str) -> Optional[str]:
        """Infer purpose from function/variable name"""
        # Common naming patterns
        patterns = {
            "get_": "retrieves",
            "set_": "sets/updates",
            "create_": "creates",
            "delete_": "deletes",
            "update_": "updates",
            "validate_": "validates",
            "check_": "checks/verifies",
            "is_": "checks boolean condition",
            "has_": "checks existence",
            "handle_": "handles/processes",
            "process_": "processes",
            "parse_": "parses",
            "save_": "saves/persists",
            "load_": "loads",
            "init_": "initializes",
            "auth": "authentication/authorization",
        }

        for pattern, meaning in patterns.items():
            if name.lower().startswith(pattern) or pattern in name.lower():
                return f"{meaning} {name.replace('_', ' ')}"

        return None

    def _llm_infer_intent(self, content: str, file_path: str) -> str:
        """Use LLM to infer code intent when documentation is missing"""
        if not self.llm_provider:
            return "LLM not available for intent inference"

        prompt = f"""Analyze this code and describe its intended purpose in 1-2 sentences.
Focus on WHAT it should do, not HOW it does it.

File: {file_path}

Code (first 1000 chars):
```
{content[:1000]}
```

Intent:"""

        try:
            response = self.llm_provider.analyze(prompt)
            if hasattr(response, 'content'):
                text = response.content[0].text if isinstance(response.content, list) else response.content
                return text.strip()[:200]
            return str(response)[:200]
        except Exception as e:
            logger.warning(f"LLM intent inference failed: {e}")
            return "Intent inference failed"

    def _analyze_actual_behavior(
        self,
        content: str,
        functions: List[FunctionSignature],
        data_flows: List[DataFlow],
        security_ops: List[SecurityOperation]
    ) -> str:
        """
        Analyze what the code actually does

        Infers actual behavior from code patterns, data flows, and
        security operations - independent of documentation.
        """
        behaviors = []

        # Analyze data flow behavior
        untrusted_to_sink = [df for df in data_flows if df.sink and not df.is_sanitized]
        if untrusted_to_sink:
            behaviors.append(
                f"Passes untrusted data to {len(untrusted_to_sink)} sinks without sanitization"
            )

        # Analyze security operation behavior
        db_ops = [op for op in security_ops if op.operation_type == SecurityOpType.DATABASE_QUERY]
        if db_ops:
            risky_db = [op for op in db_ops if op.risk_indicators]
            if risky_db:
                behaviors.append(f"Performs {len(risky_db)} potentially unsafe database operations")
            else:
                behaviors.append(f"Performs {len(db_ops)} database operations")

        cmd_ops = [op for op in security_ops if op.operation_type == SecurityOpType.COMMAND_EXECUTION]
        if cmd_ops:
            behaviors.append(f"Executes {len(cmd_ops)} system commands")

        # Analyze function patterns
        async_funcs = [f for f in functions if f.is_async]
        if async_funcs:
            behaviors.append(f"Uses async/await pattern ({len(async_funcs)} async functions)")

        # Check for authentication
        auth_ops = [op for op in security_ops if op.operation_type == SecurityOpType.AUTHENTICATION]
        if auth_ops:
            behaviors.append("Handles authentication")

        if behaviors:
            return " | ".join(behaviors)
        else:
            return "Standard code execution without notable security-relevant patterns"

    def _detect_mismatches(
        self,
        intent: str,
        actual_behavior: str,
        functions: List[FunctionSignature],
        security_ops: List[SecurityOperation]
    ) -> List[str]:
        """
        Detect mismatches between stated intent and actual behavior

        This is the core AISLE technique - finding places where code
        doesn't do what developers think/say it does.
        """
        mismatches = []

        # Check for validation functions that don't validate
        for func in functions:
            if "validate" in func.name.lower() or "sanitize" in func.name.lower():
                if func.docstring and "returns" in func.docstring.lower():
                    # Check if function actually validates or just returns
                    if "input" in func.docstring.lower() and "safe" not in func.docstring.lower():
                        mismatches.append(
                            f"Function '{func.name}' claims to validate but may not ensure safety"
                        )

        # Check for auth decorators without actual auth checks
        for func in functions:
            has_auth_decorator = any("auth" in dec.lower() for dec in func.decorators)
            if has_auth_decorator:
                # Would need deeper analysis to verify auth is actually enforced
                pass

        # Check for "safe" claims with risky operations
        if "safe" in intent.lower() or "secure" in intent.lower():
            risky_ops = [op for op in security_ops if op.risk_indicators]
            if risky_ops:
                mismatches.append(
                    f"Code claims to be safe/secure but contains {len(risky_ops)} risky operations"
                )

        # Check for unsanitized data in actual behavior vs validation claims in intent
        if "validate" in intent.lower() and "without sanitization" in actual_behavior:
            mismatches.append(
                "Intent mentions validation but untrusted data reaches sinks without sanitization"
            )

        return mismatches

    def _summarize_behavior(self, actual_behavior: str) -> str:
        """Create a brief summary of actual behavior"""
        if len(actual_behavior) <= 100:
            return actual_behavior
        return actual_behavior[:97] + "..."

    def _identify_potential_vulns(
        self,
        data_flows: List[DataFlow],
        security_ops: List[SecurityOperation]
    ) -> List[str]:
        """Identify potential vulnerabilities based on analysis"""
        vulns = []

        # Unsanitized data flows to sensitive sinks
        for flow in data_flows:
            if flow.sink and not flow.is_sanitized:
                if flow.sink_type == "database":
                    vulns.append(f"Potential SQL injection: {flow.source} -> database")
                elif flow.sink_type == "command":
                    vulns.append(f"Potential command injection: {flow.source} -> command execution")
                elif flow.sink_type == "file":
                    vulns.append(f"Potential path traversal: {flow.source} -> file operation")

        # Risky security operations
        for op in security_ops:
            for risk in op.risk_indicators:
                vulns.append(f"{op.operation_type.value}: {risk}")

        return vulns

    def _calculate_complexity(self, ast_data: Optional[Any], content: str) -> float:
        """Calculate approximate cyclomatic complexity"""
        complexity = 1.0  # Base complexity

        # Count control flow statements
        control_patterns = [
            r"\bif\b",
            r"\belif\b",
            r"\belse\b",
            r"\bfor\b",
            r"\bwhile\b",
            r"\btry\b",
            r"\bexcept\b",
            r"\bcase\b",
            r"\bcatch\b",
        ]

        for pattern in control_patterns:
            complexity += len(re.findall(pattern, content))

        # Normalize by lines of code
        loc = max(len(content.splitlines()), 1)
        normalized = complexity / (loc / 100)

        return round(min(normalized, 100.0), 2)

    def _generate_semantic_hash(
        self,
        functions: List[FunctionSignature],
        data_flows: List[DataFlow],
        security_ops: List[SecurityOperation],
        intent: str
    ) -> str:
        """Generate a hash representing the semantic meaning of the code"""
        # Combine key semantic elements
        elements = [
            ",".join(f.name for f in functions),
            ",".join(df.source for df in data_flows),
            ",".join(op.operation_type.value for op in security_ops),
            intent[:100]
        ]

        combined = "|".join(elements)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    def _create_error_twin(self, file_path: str, error: str) -> CodeTwin:
        """Create an error CodeTwin when analysis fails"""
        return CodeTwin(
            file_path=file_path,
            language="unknown",
            semantic_hash="error",
            intent=f"Analysis failed: {error}",
            actual_behavior="Unable to analyze"
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get analyzer statistics

        Returns:
            Dictionary with analysis statistics
        """
        return {
            "files_analyzed": self.files_analyzed,
            "total_functions": self.total_functions,
            "total_security_operations": self.total_security_ops,
            "total_mismatches_detected": self.total_mismatches,
            "average_functions_per_file": round(
                self.total_functions / max(self.files_analyzed, 1), 2
            ),
            "tree_sitter_enabled": self._tree_sitter_available,
            "llm_enabled": self.llm_provider is not None
        }


def main():
    """CLI entry point and example usage"""
    import argparse
    import sys

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    parser = argparse.ArgumentParser(
        description="Semantic Code Twin - AISLE-like Code Understanding"
    )
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument("--output", "-o", help="Output file (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize analyzer (without LLM for CLI demo)
    analyzer = SemanticCodeTwin(llm_provider=None)

    target = args.path
    twins = []

    if os.path.isfile(target):
        # Single file
        twin = analyzer.analyze_file(target)
        twins.append(twin)
    elif os.path.isdir(target):
        # Directory - analyze Python files
        from pathlib import Path
        for py_file in Path(target).rglob("*.py"):
            if "test" not in str(py_file) and "__pycache__" not in str(py_file):
                try:
                    twin = analyzer.analyze_file(str(py_file))
                    twins.append(twin)
                except Exception as e:
                    logger.error(f"Failed to analyze {py_file}: {e}")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)

    # Output results
    print("\n" + "=" * 70)
    print("SEMANTIC CODE TWIN ANALYSIS")
    print("=" * 70)

    for twin in twins:
        print(f"\nFile: {twin.file_path}")
        print(f"Language: {twin.language}")
        print(f"Lines of Code: {twin.lines_of_code}")
        print(f"Complexity: {twin.complexity_score}")
        print(f"\nIntent: {twin.intent[:200]}...")
        print(f"Actual Behavior: {twin.actual_behavior[:200]}...")

        if twin.functions:
            print(f"\nFunctions ({len(twin.functions)}):")
            for func in twin.functions[:5]:
                print(f"  - {func.name}({len(func.parameters)} params)")

        if twin.security_operations:
            print(f"\nSecurity Operations ({len(twin.security_operations)}):")
            for op in twin.security_operations[:5]:
                print(f"  - {op.operation_type.value}: {op.code_snippet[:50]}...")

        if twin.potential_vulnerabilities:
            print(f"\nPotential Vulnerabilities ({len(twin.potential_vulnerabilities)}):")
            for vuln in twin.potential_vulnerabilities[:5]:
                print(f"  - {vuln}")

        if twin.intent_behavior_mismatches:
            print(f"\nIntent/Behavior Mismatches ({len(twin.intent_behavior_mismatches)}):")
            for mismatch in twin.intent_behavior_mismatches:
                print(f"  - {mismatch}")

        print("-" * 70)

    # Print statistics
    stats = analyzer.get_statistics()
    print("\nAnalysis Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Write JSON output if requested
    if args.output:
        output_data = {
            "twins": [twin.to_dict() for twin in twins],
            "statistics": stats
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
