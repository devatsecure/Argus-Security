#!/usr/bin/env python3
"""
Cross-Function/Inter-Procedural Taint Analysis for Argus

Inspired by Pysa (Facebook's Python Static Analyzer) and Scalpel, this module
implements taint tracking across function boundaries to identify security
vulnerabilities where untrusted input flows to dangerous sinks without
proper sanitization.

Key Features:
- Source/Sink/Sanitizer definitions for common vulnerability patterns
- Call graph construction for inter-procedural analysis
- Taint propagation through assignments, function calls, and returns
- Path finding from sources to sinks with sanitizer detection
- Support for Python (primary) with extensible design for JavaScript

Vulnerability Detection:
- SQL Injection: User input -> database queries
- Command Injection: User input -> system commands
- XSS: User input -> template rendering
- Path Traversal: User input -> file operations
- SSRF: User input -> network requests

Integration:
- Works with Argus pipeline for comprehensive security analysis
- Outputs TaintFlow dataclass for unified reporting
- High confidence scoring based on path complexity and sanitizer presence
"""

import ast
import hashlib
import logging
import os
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


# =============================================================================
# Taint Source, Sink, and Sanitizer Definitions
# =============================================================================

class TaintCategory(Enum):
    """Categories of taint sources and sinks"""
    USER_INPUT = "user_input"
    FILE_INPUT = "file_input"
    NETWORK = "network"
    ENVIRONMENT = "environment"
    DATABASE = "database"
    SQL = "sql"
    COMMAND = "command"
    FILE_WRITE = "file_write"
    TEMPLATE = "template"


# Taint sources - where untrusted data enters the application
TAINT_SOURCES: Dict[str, List[str]] = {
    "user_input": [
        "request.GET", "request.POST", "request.args", "request.form",
        "request.data", "request.json", "request.values", "request.cookies",
        "request.headers", "input()", "sys.argv", "raw_input(",
        "flask.request", "django.request", "params", "query_params"
    ],
    "file_input": [
        "open(", "read()", "readlines()", "readline()",
        "file.read", "Path.read_text", "Path.read_bytes",
        "csv.reader", "json.load(", "yaml.load(", "pickle.load(",
        "configparser"
    ],
    "network": [
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "urllib.request", "urllib.urlopen", "httplib", "http.client",
        "socket.recv", "socket.recvfrom", "aiohttp", "httpx"
    ],
    "environment": [
        "os.environ", "os.getenv", "environ.get", "dotenv",
        "config.get", "settings."
    ]
}

# Taint sinks - where tainted data becomes dangerous
TAINT_SINKS: Dict[str, List[str]] = {
    "sql": [
        "execute(", "cursor.execute", "raw(", "db.query",
        "session.execute", "engine.execute", "connection.execute",
        "executemany(", "executescript(", "mogrify(",
        "text(", "literal_column(", "RawSQL"
    ],
    "command": [
        "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "eval(", "exec(", "compile(", "execfile(",
        "os.popen", "commands.getoutput", "commands.getstatusoutput",
        "pty.spawn", "pexpect"
    ],
    "file": [
        "open(", "write(", "writelines(", "shutil.copy", "shutil.move",
        "os.rename", "os.remove", "os.unlink", "os.mkdir", "os.makedirs",
        "Path.write_text", "Path.write_bytes", "Path.mkdir",
        "tempfile.NamedTemporaryFile"
    ],
    "network": [
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "urllib.request.urlopen", "urllib.urlopen",
        "socket.send", "socket.sendall", "socket.connect",
        "http.client.HTTPConnection", "httpx", "aiohttp.ClientSession"
    ],
    "template": [
        "render(", "render_template(", "render_to_response(",
        "Markup(", "mark_safe(", "SafeString(", "format_html(",
        "jinja2.Template", "Template.render", "render_string("
    ],
    "deserialization": [
        "pickle.loads(", "pickle.load(", "cPickle.loads(",
        "yaml.load(", "yaml.unsafe_load(",
        "marshal.loads(", "shelve.open(",
        "jsonpickle.decode(", "dill.loads("
    ],
    "xpath": [
        "xpath(", "etree.xpath", "lxml.xpath",
        "XPathEvaluator", "selectNodes"
    ],
    "ldap": [
        "ldap.search", "ldap.search_s", "ldap.search_ext",
        "ldap.bind", "ldap.simple_bind"
    ]
}

# Sanitizers - functions that neutralize tainted data
SANITIZERS: List[str] = [
    # Generic sanitization
    "escape(", "html.escape(", "cgi.escape(",
    "quote(", "urllib.parse.quote(", "shlex.quote(",
    "sanitize", "clean(", "validate(", "filter(",

    # Type conversion (safe for SQL injection)
    "int(", "float(", "bool(", "str.isdigit(", "str.isalnum(",

    # Database parameterization indicators
    "parameterize", "%s", "?", ":param", "$1",

    # HTML/XSS sanitization
    "bleach.clean(", "markupsafe.escape(", "django.utils.html.escape(",
    "xss_clean(", "strip_tags(",

    # Path sanitization
    "os.path.basename(", "os.path.normpath(", "secure_filename(",
    "path.resolve(", "realpath(",

    # SQL sanitization
    "sqlalchemy.text(", "paramstyle", "mogrify(",

    # Encoding
    "base64.b64encode(", "json.dumps(", "urlencode("
]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TaintLocation:
    """Represents a location in source code"""
    file: str
    line: int
    column: int = 0
    code_snippet: str = ""

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet
        }


@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    location: TaintLocation
    variable: str
    source_type: str  # Key from TAINT_SOURCES
    source_pattern: str  # The actual pattern matched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "variable": self.variable,
            "source_type": self.source_type,
            "source_pattern": self.source_pattern
        }


@dataclass
class TaintSink:
    """Represents a dangerous sink"""
    location: TaintLocation
    operation: str
    sink_type: str  # Key from TAINT_SINKS
    sink_pattern: str  # The actual pattern matched

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "operation": self.operation,
            "sink_type": self.sink_type,
            "sink_pattern": self.sink_pattern
        }


@dataclass
class TaintPathNode:
    """A node in a taint propagation path"""
    location: TaintLocation
    operation: str  # e.g., "assignment", "function_call", "return"
    variable: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "operation": self.operation,
            "variable": self.variable
        }


@dataclass
class TaintFlow:
    """
    Complete taint flow from source to sink

    This is the primary output of taint analysis, representing a complete
    path where untrusted data flows from a source to a sink.
    """
    source: TaintSource
    sink: TaintSink
    path: List[TaintPathNode]
    sanitized: bool
    confidence: float  # 0.0-1.0
    sanitizers_on_path: List[str] = field(default_factory=list)

    # Vulnerability metadata
    vulnerability_type: str = ""  # e.g., "SQL Injection", "Command Injection"
    cwe_id: Optional[str] = None
    severity: str = "medium"

    def __post_init__(self):
        """Set vulnerability metadata based on sink type"""
        sink_to_vuln = {
            "sql": ("SQL Injection", "CWE-89", "high"),
            "command": ("Command Injection", "CWE-78", "critical"),
            "file": ("Path Traversal", "CWE-22", "high"),
            "template": ("Cross-Site Scripting (XSS)", "CWE-79", "medium"),
            "network": ("Server-Side Request Forgery (SSRF)", "CWE-918", "high"),
            "deserialization": ("Insecure Deserialization", "CWE-502", "critical"),
            "xpath": ("XPath Injection", "CWE-643", "high"),
            "ldap": ("LDAP Injection", "CWE-90", "high")
        }

        if self.sink.sink_type in sink_to_vuln and not self.vulnerability_type:
            vuln_name, cwe, severity = sink_to_vuln[self.sink.sink_type]
            self.vulnerability_type = vuln_name
            self.cwe_id = cwe
            self.severity = severity

    def generate_id(self) -> str:
        """Generate unique ID for this taint flow"""
        key = (
            f"{self.source.location}:{self.source.variable}:"
            f"{self.sink.location}:{self.sink.operation}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.generate_id(),
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "path": [node.to_dict() for node in self.path],
            "sanitized": self.sanitized,
            "confidence": self.confidence,
            "sanitizers_on_path": self.sanitizers_on_path,
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "severity": self.severity
        }


@dataclass
class FunctionInfo:
    """Information about a function for call graph analysis"""
    name: str
    file: str
    line: int
    parameters: List[str]
    calls: List[str]  # Functions this function calls
    returns_tainted: bool = False
    tainted_params: Set[int] = field(default_factory=set)  # Indices of params that propagate taint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "parameters": self.parameters,
            "calls": self.calls,
            "returns_tainted": self.returns_tainted,
            "tainted_params": list(self.tainted_params)
        }


@dataclass
class CallGraph:
    """Represents the call graph of a project"""
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    callers: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    callees: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_function(self, func: FunctionInfo) -> None:
        """Add a function to the call graph"""
        self.functions[func.name] = func
        for callee in func.calls:
            self.callees[func.name].add(callee)
            self.callers[callee].add(func.name)

    def get_callers(self, func_name: str) -> Set[str]:
        """Get all functions that call the given function"""
        return self.callers.get(func_name, set())

    def get_callees(self, func_name: str) -> Set[str]:
        """Get all functions called by the given function"""
        return self.callees.get(func_name, set())


# =============================================================================
# AST Visitors for Python Analysis
# =============================================================================

class PythonFunctionVisitor(ast.NodeVisitor):
    """AST visitor to extract function definitions and calls"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.functions: List[FunctionInfo] = []
        self.current_function: Optional[str] = None
        self.current_calls: List[str] = []
        self.current_params: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition"""
        self.current_function = node.name
        self.current_calls = []
        self.current_params = [arg.arg for arg in node.args.args]

        # Visit function body
        self.generic_visit(node)

        # Record function info
        func_info = FunctionInfo(
            name=node.name,
            file=self.file_path,
            line=node.lineno,
            parameters=self.current_params,
            calls=self.current_calls.copy()
        )
        self.functions.append(func_info)

        self.current_function = None
        self.current_calls = []
        self.current_params = []

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition"""
        # Treat async functions the same as regular functions
        self.visit_FunctionDef(node)  # type: ignore

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call"""
        if self.current_function:
            call_name = self._get_call_name(node)
            if call_name:
                self.current_calls.append(call_name)

        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract the name of a function call"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None


class PythonTaintVisitor(ast.NodeVisitor):
    """AST visitor to find taint sources, sinks, and propagation"""

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.sources: List[TaintSource] = []
        self.sinks: List[TaintSink] = []
        self.assignments: Dict[str, List[TaintLocation]] = defaultdict(list)
        self.tainted_vars: Set[str] = set()
        self.current_function: Optional[str] = None

    def _get_line_snippet(self, lineno: int) -> str:
        """Get the source code at a given line"""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _create_location(self, node: ast.AST) -> TaintLocation:
        """Create a TaintLocation from an AST node"""
        return TaintLocation(
            file=self.file_path,
            line=node.lineno,
            column=getattr(node, 'col_offset', 0),
            code_snippet=self._get_line_snippet(node.lineno)
        )

    def _check_for_source(self, node: ast.AST, code: str) -> Optional[Tuple[str, str]]:
        """Check if code contains a taint source, returns (source_type, pattern)"""
        for source_type, patterns in TAINT_SOURCES.items():
            for pattern in patterns:
                if pattern in code:
                    return (source_type, pattern)
        return None

    def _check_for_sink(self, node: ast.AST, code: str) -> Optional[Tuple[str, str]]:
        """Check if code contains a taint sink, returns (sink_type, pattern)"""
        for sink_type, patterns in TAINT_SINKS.items():
            for pattern in patterns:
                if pattern in code:
                    return (sink_type, pattern)
        return None

    def _check_for_sanitizer(self, code: str) -> Optional[str]:
        """Check if code contains a sanitizer"""
        for sanitizer in SANITIZERS:
            if sanitizer in code:
                return sanitizer
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignment - track potential taint propagation"""
        code = self._get_line_snippet(node.lineno)
        location = self._create_location(node)

        # Check if RHS contains a source
        source_info = self._check_for_source(node, code)
        if source_info:
            source_type, pattern = source_info
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.sources.append(TaintSource(
                        location=location,
                        variable=target.id,
                        source_type=source_type,
                        source_pattern=pattern
                    ))
                    self.tainted_vars.add(target.id)

        # Track assignments for taint propagation
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id].append(location)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call - check for sinks"""
        code = self._get_line_snippet(node.lineno)
        location = self._create_location(node)

        # Check if this is a sink
        sink_info = self._check_for_sink(node, code)
        if sink_info:
            sink_type, pattern = sink_info

            # Get the operation name
            operation = ""
            if isinstance(node.func, ast.Name):
                operation = node.func.id
            elif isinstance(node.func, ast.Attribute):
                operation = node.func.attr

            self.sinks.append(TaintSink(
                location=location,
                operation=operation,
                sink_type=sink_type,
                sink_pattern=pattern
            ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track current function context"""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track current async function context"""
        self.visit_FunctionDef(node)  # type: ignore


# =============================================================================
# Language Parser Interface
# =============================================================================

class LanguageParser(ABC):
    """Abstract base class for language-specific parsers"""

    @abstractmethod
    def parse_file(self, file_path: str) -> Tuple[List[FunctionInfo], List[TaintSource], List[TaintSink]]:
        """Parse a file and extract functions, sources, and sinks"""
        pass

    @abstractmethod
    def supports_extension(self, ext: str) -> bool:
        """Check if this parser supports a file extension"""
        pass


class PythonParser(LanguageParser):
    """Parser for Python source files"""

    SUPPORTED_EXTENSIONS = {".py", ".pyw"}

    def supports_extension(self, ext: str) -> bool:
        return ext.lower() in self.SUPPORTED_EXTENSIONS

    def parse_file(self, file_path: str) -> Tuple[List[FunctionInfo], List[TaintSource], List[TaintSink]]:
        """Parse a Python file"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
                source_lines = source.split("\n")

            tree = ast.parse(source, filename=file_path)

            # Extract functions
            func_visitor = PythonFunctionVisitor(file_path)
            func_visitor.visit(tree)

            # Extract taint information
            taint_visitor = PythonTaintVisitor(file_path, source_lines)
            taint_visitor.visit(tree)

            return (
                func_visitor.functions,
                taint_visitor.sources,
                taint_visitor.sinks
            )

        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {file_path}: {e}")
            return ([], [], [])
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return ([], [], [])


class JavaScriptParser(LanguageParser):
    """
    Parser for JavaScript/TypeScript source files

    Note: This is a simplified regex-based parser. For production use,
    consider integrating with a proper JS parser like esprima or babel.
    """

    SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs"}

    # JavaScript-specific sources
    JS_SOURCES = {
        "user_input": [
            "req.body", "req.query", "req.params", "req.headers",
            "document.location", "window.location", "location.search",
            "document.cookie", "localStorage", "sessionStorage",
            "process.argv", "readline"
        ],
        "network": [
            "fetch(", "axios.", "http.get", "https.get",
            "XMLHttpRequest", "$.ajax", "$.get", "$.post"
        ]
    }

    # JavaScript-specific sinks
    JS_SINKS = {
        "command": ["exec(", "execSync(", "spawn(", "eval(", "Function("],
        "sql": ["query(", "execute(", "raw("],
        "template": ["innerHTML", "outerHTML", "document.write(", "dangerouslySetInnerHTML"],
        "file": ["writeFile", "writeFileSync", "createWriteStream"]
    }

    def supports_extension(self, ext: str) -> bool:
        return ext.lower() in self.SUPPORTED_EXTENSIONS

    def parse_file(self, file_path: str) -> Tuple[List[FunctionInfo], List[TaintSource], List[TaintSink]]:
        """Parse a JavaScript/TypeScript file using regex patterns"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
                source_lines = source.split("\n")

            functions = []
            sources = []
            sinks = []

            # Extract function definitions (simplified)
            func_pattern = r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))"
            for match in re.finditer(func_pattern, source):
                func_name = match.group(1) or match.group(2)
                line_num = source[:match.start()].count("\n") + 1
                functions.append(FunctionInfo(
                    name=func_name,
                    file=file_path,
                    line=line_num,
                    parameters=[],
                    calls=[]
                ))

            # Find sources
            for line_num, line in enumerate(source_lines, 1):
                for source_type, patterns in self.JS_SOURCES.items():
                    for pattern in patterns:
                        if pattern in line:
                            # Try to extract variable name
                            var_match = re.search(r"(?:const|let|var)\s+(\w+)\s*=", line)
                            var_name = var_match.group(1) if var_match else "unknown"

                            sources.append(TaintSource(
                                location=TaintLocation(
                                    file=file_path,
                                    line=line_num,
                                    code_snippet=line.strip()
                                ),
                                variable=var_name,
                                source_type=source_type,
                                source_pattern=pattern
                            ))
                            break

            # Find sinks
            for line_num, line in enumerate(source_lines, 1):
                for sink_type, patterns in self.JS_SINKS.items():
                    for pattern in patterns:
                        if pattern in line:
                            sinks.append(TaintSink(
                                location=TaintLocation(
                                    file=file_path,
                                    line=line_num,
                                    code_snippet=line.strip()
                                ),
                                operation=pattern.rstrip("("),
                                sink_type=sink_type,
                                sink_pattern=pattern
                            ))
                            break

            return (functions, sources, sinks)

        except Exception as e:
            logger.error(f"Error parsing JavaScript file {file_path}: {e}")
            return ([], [], [])


# =============================================================================
# Main Taint Analyzer Class
# =============================================================================

class TaintAnalyzer:
    """
    Cross-Function/Inter-Procedural Taint Analyzer

    Performs taint analysis across function boundaries to identify
    security vulnerabilities where untrusted input flows to dangerous
    sinks without proper sanitization.

    Usage:
        analyzer = TaintAnalyzer()
        flows = analyzer.analyze_project("/path/to/project")

        for flow in flows:
            if not flow.sanitized:
                print(f"Vulnerability: {flow.vulnerability_type}")
                print(f"Source: {flow.source.location}")
                print(f"Sink: {flow.sink.location}")
    """

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        max_path_depth: int = 10,
        include_sanitized: bool = False
    ):
        """
        Initialize taint analyzer

        Args:
            confidence_threshold: Minimum confidence for reporting flows (0.0-1.0)
            max_path_depth: Maximum depth for path exploration
            include_sanitized: Whether to include sanitized flows in results
        """
        self.confidence_threshold = confidence_threshold
        self.max_path_depth = max_path_depth
        self.include_sanitized = include_sanitized

        # Language parsers
        self.parsers: List[LanguageParser] = [
            PythonParser(),
            JavaScriptParser()
        ]

        # Analysis state
        self.call_graph = CallGraph()
        self.all_sources: List[TaintSource] = []
        self.all_sinks: List[TaintSink] = []
        self.file_contents: Dict[str, List[str]] = {}

        # Statistics
        self.files_analyzed = 0
        self.total_sources = 0
        self.total_sinks = 0
        self.total_flows = 0
        self.sanitized_flows = 0

        logger.info(
            f"TaintAnalyzer initialized (confidence: {confidence_threshold}, "
            f"max_depth: {max_path_depth})"
        )

    def analyze_project(
        self,
        project_path: str,
        exclude_patterns: Optional[List[str]] = None
    ) -> List[TaintFlow]:
        """
        Analyze an entire project for taint flows

        Args:
            project_path: Path to project directory
            exclude_patterns: Glob patterns to exclude (e.g., ["**/test/**", "**/node_modules/**"])

        Returns:
            List of TaintFlow objects representing potential vulnerabilities
        """
        logger.info(f"Starting taint analysis of {project_path}")

        # Default exclusions
        if exclude_patterns is None:
            exclude_patterns = [
                "**/test/**", "**/tests/**", "**/__pycache__/**",
                "**/node_modules/**", "**/venv/**", "**/.venv/**",
                "**/dist/**", "**/build/**", "**/.git/**"
            ]

        # Gather files to analyze
        files = self._gather_files(project_path, exclude_patterns)
        logger.info(f"Found {len(files)} files to analyze")

        # Phase 1: Build call graph and extract sources/sinks
        logger.info("Phase 1: Building call graph and extracting taint information...")
        self._build_call_graph(files)

        logger.info(f"  Found {len(self.all_sources)} sources")
        logger.info(f"  Found {len(self.all_sinks)} sinks")
        logger.info(f"  Built call graph with {len(self.call_graph.functions)} functions")

        # Phase 2: Propagate taint and find flows
        logger.info("Phase 2: Propagating taint and finding flows...")
        flows = self._find_taint_flows()

        # Phase 3: Calculate confidence and filter
        logger.info("Phase 3: Calculating confidence scores...")
        scored_flows = self._calculate_confidence(flows)

        # Filter by confidence threshold and sanitization
        filtered_flows = [
            flow for flow in scored_flows
            if flow.confidence >= self.confidence_threshold
            and (self.include_sanitized or not flow.sanitized)
        ]

        # Update statistics
        self.total_flows = len(scored_flows)
        self.sanitized_flows = sum(1 for f in scored_flows if f.sanitized)

        logger.info(f"Analysis complete: {len(filtered_flows)} reportable flows")
        logger.info(f"  Total flows found: {self.total_flows}")
        logger.info(f"  Sanitized flows: {self.sanitized_flows}")
        logger.info(f"  Unsanitized (reportable): {len(filtered_flows)}")

        return filtered_flows

    def analyze_file(self, file_path: str) -> List[TaintFlow]:
        """
        Analyze a single file for taint flows

        Args:
            file_path: Path to source file

        Returns:
            List of TaintFlow objects
        """
        return self.analyze_project(os.path.dirname(file_path), exclude_patterns=["**/*"])

    def _gather_files(
        self,
        project_path: str,
        exclude_patterns: List[str]
    ) -> List[str]:
        """Gather all supported source files in project"""
        files = []
        project_dir = Path(project_path)

        # Get all supported extensions
        supported_exts = set()
        for parser in self.parsers:
            if isinstance(parser, PythonParser):
                supported_exts.update(PythonParser.SUPPORTED_EXTENSIONS)
            elif isinstance(parser, JavaScriptParser):
                supported_exts.update(JavaScriptParser.SUPPORTED_EXTENSIONS)

        # Walk directory
        for ext in supported_exts:
            pattern = f"**/*{ext}"
            for file_path in project_dir.glob(pattern):
                # Check exclusions
                str_path = str(file_path)
                excluded = False
                for exclude in exclude_patterns:
                    if Path(str_path).match(exclude):
                        excluded = True
                        break

                if not excluded:
                    files.append(str_path)

        return files

    def _build_call_graph(self, files: List[str]) -> None:
        """Build call graph and extract sources/sinks from all files"""
        self.call_graph = CallGraph()
        self.all_sources = []
        self.all_sinks = []
        self.file_contents = {}

        for file_path in files:
            # Find appropriate parser
            ext = Path(file_path).suffix
            parser = None
            for p in self.parsers:
                if p.supports_extension(ext):
                    parser = p
                    break

            if not parser:
                continue

            # Parse file
            functions, sources, sinks = parser.parse_file(file_path)

            # Update call graph
            for func in functions:
                self.call_graph.add_function(func)

            # Collect sources and sinks
            self.all_sources.extend(sources)
            self.all_sinks.extend(sinks)

            # Cache file contents for path analysis
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    self.file_contents[file_path] = f.read().split("\n")
            except Exception:
                pass

            self.files_analyzed += 1

        self.total_sources = len(self.all_sources)
        self.total_sinks = len(self.all_sinks)

    def _find_taint_flows(self) -> List[TaintFlow]:
        """Find all taint flows from sources to sinks"""
        flows = []

        # For each source, try to find paths to sinks
        for source in self.all_sources:
            for sink in self.all_sinks:
                # Skip if sink is a "source" type (like file read being used to open file for read)
                if sink.sink_type == "file" and source.source_type == "file_input":
                    continue

                # Try to find a path
                path = self._find_path(source, sink)
                if path:
                    # Check for sanitizers on the path
                    sanitizers = self._find_sanitizers_on_path(path)

                    flow = TaintFlow(
                        source=source,
                        sink=sink,
                        path=path,
                        sanitized=len(sanitizers) > 0,
                        confidence=0.0,  # Will be calculated later
                        sanitizers_on_path=sanitizers
                    )
                    flows.append(flow)

        return flows

    def _find_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        visited: Optional[Set[str]] = None,
        depth: int = 0
    ) -> List[TaintPathNode]:
        """
        Find a path from source to sink through taint propagation

        This is a simplified path finding that looks for:
        1. Direct flow (source and sink in same file/function)
        2. Data flow through assignments
        3. Inter-procedural flow through function calls
        """
        if depth > self.max_path_depth:
            return []

        if visited is None:
            visited = set()

        path: List[TaintPathNode] = []

        # Start node
        path.append(TaintPathNode(
            location=source.location,
            operation="source",
            variable=source.variable
        ))

        # Check for direct flow (same file)
        if source.location.file == sink.location.file:
            # Check if source variable appears near sink
            sink_code = sink.location.code_snippet
            if source.variable in sink_code:
                # Direct flow found
                path.append(TaintPathNode(
                    location=sink.location,
                    operation="sink",
                    variable=source.variable
                ))
                return path

            # Check for intermediate assignments
            intermediate_path = self._find_intermediate_path(
                source.location.file,
                source.variable,
                source.location.line,
                sink.location.line
            )
            if intermediate_path:
                path.extend(intermediate_path)

                # Check if last variable reaches sink
                if intermediate_path:
                    last_var = intermediate_path[-1].variable
                    if last_var in sink_code:
                        path.append(TaintPathNode(
                            location=sink.location,
                            operation="sink",
                            variable=last_var
                        ))
                        return path

        # Check for inter-procedural flow through call graph
        inter_path = self._find_interprocedural_path(source, sink, visited, depth)
        if inter_path:
            path.extend(inter_path)
            return path

        return []

    def _find_intermediate_path(
        self,
        file_path: str,
        start_var: str,
        start_line: int,
        end_line: int
    ) -> List[TaintPathNode]:
        """Find intermediate assignments that propagate taint"""
        path = []

        if file_path not in self.file_contents:
            return path

        lines = self.file_contents[file_path]
        current_var = start_var

        # Scan lines between source and sink
        for line_num in range(start_line, min(end_line + 1, len(lines) + 1)):
            if line_num <= 0 or line_num > len(lines):
                continue

            line = lines[line_num - 1]

            # Look for assignment patterns where current variable is on RHS
            # Simple pattern: var = ... current_var ...
            assign_match = re.search(r"(\w+)\s*=\s*.*" + re.escape(current_var), line)
            if assign_match and assign_match.group(1) != current_var:
                new_var = assign_match.group(1)
                path.append(TaintPathNode(
                    location=TaintLocation(
                        file=file_path,
                        line=line_num,
                        code_snippet=line.strip()
                    ),
                    operation="assignment",
                    variable=new_var
                ))
                current_var = new_var

        return path

    def _find_interprocedural_path(
        self,
        source: TaintSource,
        sink: TaintSink,
        visited: Set[str],
        depth: int
    ) -> List[TaintPathNode]:
        """Find taint flow through function calls"""
        path = []

        # Get functions in source file
        source_funcs = [
            f for f in self.call_graph.functions.values()
            if f.file == source.location.file
        ]

        # Get functions in sink file
        sink_funcs = [
            f for f in self.call_graph.functions.values()
            if f.file == sink.location.file
        ]

        # Look for call relationships
        for src_func in source_funcs:
            if src_func.name in visited:
                continue

            for sink_func in sink_funcs:
                if sink_func.name in self.call_graph.get_callees(src_func.name):
                    # Found a call path
                    path.append(TaintPathNode(
                        location=TaintLocation(
                            file=src_func.file,
                            line=src_func.line,
                            code_snippet=f"def {src_func.name}(...)"
                        ),
                        operation="function_call",
                        variable=f"{src_func.name} -> {sink_func.name}"
                    ))
                    return path

        return path

    def _find_sanitizers_on_path(self, path: List[TaintPathNode]) -> List[str]:
        """Find any sanitizers used along the taint path"""
        sanitizers_found = []

        for node in path:
            code = node.location.code_snippet
            for sanitizer in SANITIZERS:
                if sanitizer in code:
                    sanitizers_found.append(sanitizer)

        return list(set(sanitizers_found))

    def _calculate_confidence(self, flows: List[TaintFlow]) -> List[TaintFlow]:
        """Calculate confidence scores for each taint flow"""
        for flow in flows:
            confidence = 0.5  # Base confidence

            # Increase confidence for direct paths
            if len(flow.path) <= 3:
                confidence += 0.2

            # Increase confidence for same-file flows
            if flow.source.location.file == flow.sink.location.file:
                confidence += 0.15

            # Increase confidence for high-risk sink types
            high_risk_sinks = {"command", "sql", "deserialization"}
            if flow.sink.sink_type in high_risk_sinks:
                confidence += 0.1

            # Increase confidence for user input sources
            if flow.source.source_type == "user_input":
                confidence += 0.1

            # Decrease confidence if sanitized
            if flow.sanitized:
                confidence -= 0.3

            # Decrease confidence for long paths
            if len(flow.path) > 5:
                confidence -= 0.1

            # Clamp to valid range
            flow.confidence = max(0.0, min(1.0, confidence))

        return flows

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return {
            "files_analyzed": self.files_analyzed,
            "total_sources": self.total_sources,
            "total_sinks": self.total_sinks,
            "total_flows": self.total_flows,
            "sanitized_flows": self.sanitized_flows,
            "unsanitized_flows": self.total_flows - self.sanitized_flows,
            "functions_in_call_graph": len(self.call_graph.functions),
            "confidence_threshold": self.confidence_threshold
        }

    def export_call_graph(self) -> Dict[str, Any]:
        """Export the call graph for visualization or further analysis"""
        return {
            "functions": {
                name: func.to_dict()
                for name, func in self.call_graph.functions.items()
            },
            "edges": [
                {"caller": caller, "callee": callee}
                for caller, callees in self.call_graph.callees.items()
                for callee in callees
            ]
        }


# =============================================================================
# Convenience Functions
# =============================================================================

def analyze_for_sqli(project_path: str) -> List[TaintFlow]:
    """
    Convenience function to analyze for SQL injection vulnerabilities

    Args:
        project_path: Path to project directory

    Returns:
        List of SQL injection taint flows
    """
    analyzer = TaintAnalyzer(confidence_threshold=0.6)
    flows = analyzer.analyze_project(project_path)
    return [f for f in flows if f.sink.sink_type == "sql"]


def analyze_for_command_injection(project_path: str) -> List[TaintFlow]:
    """
    Convenience function to analyze for command injection vulnerabilities

    Args:
        project_path: Path to project directory

    Returns:
        List of command injection taint flows
    """
    analyzer = TaintAnalyzer(confidence_threshold=0.6)
    flows = analyzer.analyze_project(project_path)
    return [f for f in flows if f.sink.sink_type == "command"]


def analyze_for_xss(project_path: str) -> List[TaintFlow]:
    """
    Convenience function to analyze for XSS vulnerabilities

    Args:
        project_path: Path to project directory

    Returns:
        List of XSS taint flows
    """
    analyzer = TaintAnalyzer(confidence_threshold=0.6)
    flows = analyzer.analyze_project(project_path)
    return [f for f in flows if f.sink.sink_type == "template"]


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """CLI entry point for taint analysis"""
    import argparse
    import json as json_module
    import sys

    parser = argparse.ArgumentParser(
        description="Cross-Function Taint Analysis - Find data flow vulnerabilities"
    )
    parser.add_argument("path", help="Path to project or file to analyze")
    parser.add_argument(
        "--confidence", "-c",
        type=float,
        default=0.7,
        help="Minimum confidence threshold (0.0-1.0, default: 0.7)"
    )
    parser.add_argument(
        "--include-sanitized",
        action="store_true",
        help="Include sanitized flows in output"
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum path exploration depth (default: 10)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (JSON format)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--call-graph",
        action="store_true",
        help="Export call graph to output"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s"
    )

    # Validate path
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    # Run analysis
    print("=" * 70)
    print("Argus Taint Analyzer - Cross-Function Data Flow Analysis")
    print("=" * 70)
    print()

    analyzer = TaintAnalyzer(
        confidence_threshold=args.confidence,
        max_path_depth=args.max_depth,
        include_sanitized=args.include_sanitized
    )

    flows = analyzer.analyze_project(str(target_path))

    # Get statistics
    stats = analyzer.get_statistics()

    print()
    print("Analysis Statistics:")
    print(f"  Files analyzed: {stats['files_analyzed']}")
    print(f"  Taint sources found: {stats['total_sources']}")
    print(f"  Taint sinks found: {stats['total_sinks']}")
    print(f"  Total flows: {stats['total_flows']}")
    print(f"  Sanitized flows: {stats['sanitized_flows']}")
    print(f"  Reportable flows: {len(flows)}")
    print()

    # Output results
    if args.output:
        output_data = {
            "statistics": stats,
            "flows": [flow.to_dict() for flow in flows]
        }

        if args.call_graph:
            output_data["call_graph"] = analyzer.export_call_graph()

        with open(args.output, "w") as f:
            json_module.dump(output_data, f, indent=2)

        print(f"Results written to {args.output}")
    else:
        # Print findings to console
        if not flows:
            print("No taint flows found above confidence threshold.")
        else:
            print(f"Found {len(flows)} potential vulnerabilities:")
            print()

            for i, flow in enumerate(flows, 1):
                severity_colors = {
                    "critical": "\033[91m",  # Red
                    "high": "\033[93m",      # Yellow
                    "medium": "\033[94m",    # Blue
                    "low": "\033[92m"        # Green
                }
                reset = "\033[0m"
                color = severity_colors.get(flow.severity, "")

                print(f"{i}. [{color}{flow.severity.upper()}{reset}] {flow.vulnerability_type}")
                print(f"   CWE: {flow.cwe_id}")
                print(f"   Confidence: {flow.confidence:.0%}")
                print(f"   Source: {flow.source.location} ({flow.source.source_type})")
                print(f"   Sink: {flow.sink.location} ({flow.sink.sink_type})")

                if flow.sanitizers_on_path:
                    print(f"   Sanitizers: {', '.join(flow.sanitizers_on_path)}")

                print(f"   Path length: {len(flow.path)} nodes")
                print()

    # Exit with error if vulnerabilities found
    unsanitized = [f for f in flows if not f.sanitized]
    if unsanitized:
        print(f"Found {len(unsanitized)} unsanitized taint flows")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
