#!/usr/bin/env python3
"""
Comprehensive tests for Intelligent Fuzzing Engine
Tests AI-powered fuzzing capabilities, crash detection, and payload generation.
"""

import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest


# =============================================================================
# Mock dataclasses and enums (these will be in fuzzing_engine.py)
# =============================================================================


class FuzzTarget(Enum):
    """Types of fuzzing targets"""

    API_ENDPOINT = "api_endpoint"
    FUNCTION = "function"
    FILE_PARSER = "file_parser"


@dataclass
class FuzzConfig:
    """Configuration for a fuzzing run"""

    target: FuzzTarget
    target_path: str  # API endpoint URL, function path, or file parser path
    duration_seconds: int = 300  # 5 minutes default
    use_ai_generation: bool = True
    max_iterations: int = 10000
    corpus_dir: Optional[Path] = None
    timeout_per_test: float = 1.0  # seconds
    fail_on_crash: bool = True
    seed: Optional[int] = None
    coverage_tracking: bool = True
    authentication: Optional[dict] = None  # For API fuzzing


@dataclass
class Crash:
    """Represents a crash or vulnerability found during fuzzing"""

    crash_id: str
    input_data: Any
    stack_trace: str
    crash_type: str  # "exception", "timeout", "crash", "assertion"
    reproducible: bool
    severity: str  # "critical", "high", "medium", "low"
    cwe: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    coverage_data: Optional[dict] = None


@dataclass
class FuzzResult:
    """Results from a fuzzing run"""

    target: FuzzTarget
    target_path: str
    total_iterations: int
    unique_crashes: int
    crashes: list[Crash]
    duration_seconds: float
    coverage_percentage: float
    test_cases_generated: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class MockLLMManager:
    """Mock LLM manager for testing"""

    def __init__(self):
        self.call_count = 0

    def call_llm(self, prompt: str, **kwargs) -> str:
        """Mock LLM call"""
        self.call_count += 1
        # Check XSS first since the prompt template always includes "SQL injection"
        # in the Focus line, but context-specific keywords should take priority
        if "XSS vulnerable" in prompt:
            return json.dumps(
                [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                ]
            )
        elif "SQL injection vulnerable" in prompt:
            return json.dumps(
                [
                    "' OR '1'='1",
                    "1; DROP TABLE users--",
                    "admin'--",
                    "' UNION SELECT NULL, NULL--",
                ]
            )
        else:
            return json.dumps(["test1", "test2", "test3"])


# Mock FuzzingEngine class structure
class FuzzingEngine:
    """Intelligent Fuzzing Engine with AI-powered test generation"""

    # Injection payload templates
    INJECTION_PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "admin'--",
            "' UNION SELECT NULL, NULL--",
            "1' AND '1'='1",
            "'; EXEC xp_cmdshell('dir')--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(cat /etc/shadow)",
            "&& id",
            "|| uname -a",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        "buffer_overflow": [
            "A" * 1000,
            "A" * 10000,
            "\x00" * 500,
            "\xff" * 500,
        ],
        "dos": [
            "{'a': " + "{'b': " * 1000 + "'c'" + "}" * 1000 + "}",  # JSON bomb
            "<a>" * 10000 + "</a>" * 10000,  # XML bomb
            "0" * 1000000,  # Large number string
        ],
    }

    def __init__(self, llm_manager=None, config: Optional[dict] = None):
        """Initialize fuzzing engine"""
        self.llm_manager = llm_manager
        self.config = config or {}
        self.crashes: list[Crash] = []
        self.test_cases_run = 0
        self.coverage_data = {}

    def fuzz(self, fuzz_config: FuzzConfig) -> FuzzResult:
        """Execute fuzzing run"""
        start_time = datetime.now()

        if fuzz_config.target == FuzzTarget.API_ENDPOINT:
            crashes = self._fuzz_api(fuzz_config)
        elif fuzz_config.target == FuzzTarget.FUNCTION:
            crashes = self._fuzz_function(fuzz_config)
        elif fuzz_config.target == FuzzTarget.FILE_PARSER:
            crashes = self._fuzz_file_parser(fuzz_config)
        else:
            raise ValueError(f"Unknown target type: {fuzz_config.target}")

        # Deduplicate crashes
        unique_crashes = self._deduplicate_crashes(crashes)

        duration = (datetime.now() - start_time).total_seconds()

        return FuzzResult(
            target=fuzz_config.target,
            target_path=fuzz_config.target_path,
            total_iterations=self.test_cases_run,
            unique_crashes=len(unique_crashes),
            crashes=unique_crashes,
            duration_seconds=duration,
            coverage_percentage=self._calculate_coverage(),
            test_cases_generated=len(self._generate_template_test_cases()),
        )

    def _fuzz_api(self, config: FuzzConfig) -> list[Crash]:
        """Fuzz API endpoint"""
        crashes = []
        test_cases = self._generate_test_cases_for_api(config)

        for test_case in test_cases[: config.max_iterations]:
            self.test_cases_run += 1
            crash = self._execute_api_test(config.target_path, test_case, config)
            if crash:
                crashes.append(crash)

        return crashes

    def _fuzz_function(self, config: FuzzConfig) -> list[Crash]:
        """Fuzz a specific function"""
        crashes = []
        test_cases = self._generate_template_test_cases()

        for test_case in test_cases[: config.max_iterations]:
            self.test_cases_run += 1
            crash = self._execute_function_test(config.target_path, test_case, config)
            if crash:
                crashes.append(crash)

        return crashes

    def _fuzz_file_parser(self, config: FuzzConfig) -> list[Crash]:
        """Fuzz file parser"""
        crashes = []
        test_files = self._generate_malformed_files(config)

        for test_file in test_files[: config.max_iterations]:
            self.test_cases_run += 1
            crash = self._execute_parser_test(config.target_path, test_file, config)
            if crash:
                crashes.append(crash)

        return crashes

    def _generate_template_test_cases(self) -> list[str]:
        """Generate test cases from templates"""
        test_cases = []
        for payload_type, payloads in self.INJECTION_PAYLOADS.items():
            test_cases.extend(payloads)
        return test_cases

    def _generate_ai_test_cases(self, target_type: str, context: str) -> list[str]:
        """Generate test cases using AI"""
        if not self.llm_manager:
            return []

        prompt = f"""Generate 20 malicious test inputs for {target_type} fuzzing.
Context: {context}
Focus on: SQL injection, XSS, command injection, path traversal, buffer overflow.
Return JSON array of strings."""

        response = self.llm_manager.call_llm(prompt)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return []

    def _generate_test_cases_for_api(self, config: FuzzConfig) -> list[dict]:
        """Generate test cases for API fuzzing"""
        test_cases = []

        # Template-based
        for payload in self._generate_template_test_cases():
            test_cases.append({"method": "POST", "data": payload})

        # AI-based (if enabled)
        if config.use_ai_generation and self.llm_manager:
            ai_payloads = self._generate_ai_test_cases("API", config.target_path)
            for payload in ai_payloads:
                test_cases.append({"method": "POST", "data": payload})

        return test_cases

    def _generate_malformed_files(self, config: FuzzConfig) -> list[bytes]:
        """Generate malformed files for parser fuzzing"""
        files = []

        # Null bytes
        files.append(b"\x00" * 100)

        # Large files
        files.append(b"A" * 10000)

        # Invalid UTF-8
        files.append(b"\xff\xfe\xfd")

        # Truncated data
        files.append(b"Valid data...")

        return files

    def _execute_api_test(
        self, endpoint: str, test_case: dict, config: FuzzConfig
    ) -> Optional[Crash]:
        """Execute single API test"""
        # Mock implementation - would make actual HTTP request
        return None

    def _execute_function_test(
        self, function_path: str, test_input: str, config: FuzzConfig
    ) -> Optional[Crash]:
        """Execute single function test"""
        # Mock implementation - would call actual function
        return None

    def _execute_parser_test(
        self, parser_path: str, test_file: bytes, config: FuzzConfig
    ) -> Optional[Crash]:
        """Execute single parser test"""
        # Mock implementation - would call parser
        return None

    def _deduplicate_crashes(self, crashes: list[Crash]) -> list[Crash]:
        """Deduplicate crashes by stack trace hash"""
        seen_traces = set()
        unique = []

        for crash in crashes:
            trace_hash = hash(crash.stack_trace)
            if trace_hash not in seen_traces:
                seen_traces.add(trace_hash)
                unique.append(crash)

        return unique

    def _calculate_coverage(self) -> float:
        """Calculate code coverage percentage"""
        if not self.coverage_data:
            return 0.0
        return 75.5  # Mock value


# =============================================================================
# Test Suite
# =============================================================================


class TestFuzzingEngineInitialization:
    """Test fuzzing engine initialization"""

    def test_engine_initialization_no_llm(self):
        """Test engine initialization without LLM"""
        engine = FuzzingEngine(llm_manager=None)

        assert engine.llm_manager is None
        assert engine.crashes == []
        assert engine.test_cases_run == 0
        assert engine.coverage_data == {}

    def test_engine_initialization_with_llm(self):
        """Test engine initialization with LLM manager"""
        llm_manager = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm_manager)

        assert engine.llm_manager is not None
        assert isinstance(engine.llm_manager, MockLLMManager)

    def test_engine_initialization_with_config(self):
        """Test engine initialization with custom config"""
        config = {"debug": True, "verbose": True}
        engine = FuzzingEngine(llm_manager=None, config=config)

        assert engine.config == config
        assert engine.config["debug"] is True


class TestFuzzConfig:
    """Test fuzzing configuration"""

    def test_fuzz_config_creation(self):
        """Test fuzzing configuration creation"""
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT, target_path="/api/users", duration_seconds=300
        )

        assert config.target == FuzzTarget.API_ENDPOINT
        assert config.target_path == "/api/users"
        assert config.duration_seconds == 300
        assert config.use_ai_generation is True
        assert config.max_iterations == 10000

    def test_fuzz_config_defaults(self):
        """Test fuzzing configuration default values"""
        config = FuzzConfig(target=FuzzTarget.FUNCTION, target_path="parse_input")

        assert config.duration_seconds == 300
        assert config.use_ai_generation is True
        assert config.max_iterations == 10000
        assert config.timeout_per_test == 1.0
        assert config.fail_on_crash is True
        assert config.seed is None
        assert config.coverage_tracking is True

    def test_fuzz_config_with_authentication(self):
        """Test API fuzzing config with authentication"""
        auth = {"type": "bearer", "token": "secret123"}
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/admin",
            authentication=auth,
        )

        assert config.authentication == auth
        assert config.authentication["type"] == "bearer"

    def test_fuzz_config_with_corpus(self):
        """Test fuzzing config with corpus directory"""
        corpus_path = Path("/tmp/corpus")
        config = FuzzConfig(
            target=FuzzTarget.FILE_PARSER,
            target_path="parse_xml",
            corpus_dir=corpus_path,
        )

        assert config.corpus_dir == corpus_path


class TestCrashDataclass:
    """Test crash data structure"""

    def test_crash_creation(self):
        """Test crash report creation"""
        crash = Crash(
            crash_id="abc123",
            input_data="malicious payload",
            stack_trace="Traceback...",
            crash_type="exception",
            reproducible=True,
            severity="critical",
            cwe="CWE-120",
        )

        assert crash.crash_id == "abc123"
        assert crash.input_data == "malicious payload"
        assert crash.severity == "critical"
        assert crash.cwe == "CWE-120"
        assert crash.reproducible is True

    def test_crash_with_timestamp(self):
        """Test crash includes timestamp"""
        crash = Crash(
            crash_id="test1",
            input_data="test",
            stack_trace="trace",
            crash_type="crash",
            reproducible=True,
            severity="high",
        )

        assert crash.timestamp is not None
        assert isinstance(crash.timestamp, str)

    def test_crash_with_coverage_data(self):
        """Test crash with coverage information"""
        coverage = {"lines_hit": 150, "branches_hit": 45}
        crash = Crash(
            crash_id="test2",
            input_data="test",
            stack_trace="trace",
            crash_type="timeout",
            reproducible=False,
            severity="medium",
            coverage_data=coverage,
        )

        assert crash.coverage_data == coverage
        assert crash.coverage_data["lines_hit"] == 150


class TestSQLInjectionPayloads:
    """Test SQL injection payload generation"""

    def test_sql_injection_payloads_exist(self):
        """Test SQL injection payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["sql_injection"]

        assert len(payloads) > 0
        assert isinstance(payloads, list)

    def test_sql_injection_or_payload(self):
        """Test SQL OR injection payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["sql_injection"]

        assert "' OR '1'='1" in payloads

    def test_sql_injection_drop_table_payload(self):
        """Test SQL DROP TABLE payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["sql_injection"]

        assert "1; DROP TABLE users--" in payloads

    def test_sql_injection_union_payload(self):
        """Test SQL UNION injection payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["sql_injection"]

        assert any("UNION" in p for p in payloads)

    def test_sql_injection_comment_payload(self):
        """Test SQL comment-based injection"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["sql_injection"]

        assert any("--" in p for p in payloads)


class TestXSSPayloads:
    """Test XSS payload generation"""

    def test_xss_payloads_exist(self):
        """Test XSS payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["xss"]

        assert len(payloads) > 0

    def test_xss_script_tag_payload(self):
        """Test XSS script tag payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["xss"]

        assert "<script>alert(1)</script>" in payloads

    def test_xss_img_onerror_payload(self):
        """Test XSS img onerror payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["xss"]

        assert any("onerror" in p for p in payloads)

    def test_xss_javascript_protocol_payload(self):
        """Test XSS javascript: protocol payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["xss"]

        assert any("javascript:" in p for p in payloads)

    def test_xss_svg_payload(self):
        """Test XSS SVG-based payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["xss"]

        assert any("<svg" in p for p in payloads)


class TestCommandInjectionPayloads:
    """Test command injection payload generation"""

    def test_command_injection_payloads_exist(self):
        """Test command injection payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert len(payloads) > 0

    def test_command_injection_semicolon(self):
        """Test command injection with semicolon"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert any(";" in p for p in payloads)

    def test_command_injection_pipe(self):
        """Test command injection with pipe"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert any("|" in p for p in payloads)

    def test_command_injection_backtick(self):
        """Test command injection with backticks"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert any("`" in p for p in payloads)

    def test_command_injection_dollar_paren(self):
        """Test command injection with $()"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert any("$(" in p for p in payloads)

    def test_command_injection_ampersand(self):
        """Test command injection with &&"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["command_injection"]

        assert any("&&" in p for p in payloads)


class TestPathTraversalPayloads:
    """Test path traversal payload generation"""

    def test_path_traversal_payloads_exist(self):
        """Test path traversal payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["path_traversal"]

        assert len(payloads) > 0

    def test_path_traversal_unix_style(self):
        """Test Unix-style path traversal"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["path_traversal"]

        assert any("../../../etc/passwd" in p for p in payloads)

    def test_path_traversal_windows_style(self):
        """Test Windows-style path traversal"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["path_traversal"]

        # Check that at least one payload contains a backslash (Windows-style separator)
        assert any("\\" in p for p in payloads)

    def test_path_traversal_url_encoded(self):
        """Test URL-encoded path traversal"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["path_traversal"]

        assert any("%2e%2e%2f" in p.lower() for p in payloads)


class TestBufferOverflowPayloads:
    """Test buffer overflow payload generation"""

    def test_buffer_overflow_payloads_exist(self):
        """Test buffer overflow payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["buffer_overflow"]

        assert len(payloads) > 0

    def test_buffer_overflow_large_string(self):
        """Test large string buffer overflow payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["buffer_overflow"]

        assert any(len(p) >= 1000 for p in payloads)

    def test_buffer_overflow_null_bytes(self):
        """Test null byte buffer overflow payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["buffer_overflow"]

        assert any("\x00" in p for p in payloads)


class TestCrashDeduplication:
    """Test crash deduplication logic"""

    def test_crash_deduplication_identical(self):
        """Test crash deduplication with identical crashes"""
        engine = FuzzingEngine()
        crashes = [
            Crash(
                crash_id="1",
                input_data="test",
                stack_trace="Error at line 42",
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
            Crash(
                crash_id="2",
                input_data="test2",
                stack_trace="Error at line 42",  # Same stack trace
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
        ]

        unique = engine._deduplicate_crashes(crashes)
        assert len(unique) == 1

    def test_crash_deduplication_different(self):
        """Test crash deduplication with different crashes"""
        engine = FuzzingEngine()
        crashes = [
            Crash(
                crash_id="1",
                input_data="test",
                stack_trace="Error at line 42",
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
            Crash(
                crash_id="2",
                input_data="test2",
                stack_trace="Error at line 100",  # Different
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
        ]

        unique = engine._deduplicate_crashes(crashes)
        assert len(unique) == 2

    def test_crash_deduplication_empty_list(self):
        """Test crash deduplication with empty list"""
        engine = FuzzingEngine()
        unique = engine._deduplicate_crashes([])

        assert len(unique) == 0
        assert unique == []

    def test_crash_deduplication_preserves_first(self):
        """Test deduplication preserves first crash of duplicate set"""
        engine = FuzzingEngine()
        crashes = [
            Crash(
                crash_id="first",
                input_data="input1",
                stack_trace="Same trace",
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
            Crash(
                crash_id="second",
                input_data="input2",
                stack_trace="Same trace",
                crash_type="crash",
                reproducible=True,
                severity="high",
            ),
        ]

        unique = engine._deduplicate_crashes(crashes)
        assert len(unique) == 1
        assert unique[0].crash_id == "first"


class TestTemplateTestCaseGeneration:
    """Test template-based test case generation"""

    def test_template_test_case_generation(self):
        """Test template-based test case generation"""
        engine = FuzzingEngine(llm_manager=None)
        test_cases = engine._generate_template_test_cases()

        assert len(test_cases) > 0
        assert isinstance(test_cases, list)

    def test_template_includes_sql_injection(self):
        """Test template includes SQL injection payloads"""
        engine = FuzzingEngine(llm_manager=None)
        test_cases = engine._generate_template_test_cases()

        assert any("' OR '1'='1" in str(tc) for tc in test_cases)

    def test_template_includes_xss(self):
        """Test template includes XSS payloads"""
        engine = FuzzingEngine(llm_manager=None)
        test_cases = engine._generate_template_test_cases()

        assert any("<script>" in str(tc) for tc in test_cases)

    def test_template_includes_command_injection(self):
        """Test template includes command injection payloads"""
        engine = FuzzingEngine(llm_manager=None)
        test_cases = engine._generate_template_test_cases()

        assert any(";" in str(tc) or "|" in str(tc) for tc in test_cases)


class TestAITestCaseGeneration:
    """Test AI-powered test case generation"""

    def test_ai_generation_without_llm(self):
        """Test AI generation fails gracefully without LLM"""
        engine = FuzzingEngine(llm_manager=None)
        test_cases = engine._generate_ai_test_cases("API", "/api/users")

        assert test_cases == []

    def test_ai_generation_with_llm(self):
        """Test AI generation with LLM manager"""
        llm = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm)

        test_cases = engine._generate_ai_test_cases("API", "/api/login")

        assert len(test_cases) > 0
        assert llm.call_count == 1

    def test_ai_generation_sql_context(self):
        """Test AI generation for SQL injection context"""
        llm = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm)

        test_cases = engine._generate_ai_test_cases("API", "SQL injection vulnerable")

        assert len(test_cases) > 0
        assert any("DROP TABLE" in str(tc) for tc in test_cases)

    def test_ai_generation_xss_context(self):
        """Test AI generation for XSS context"""
        llm = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm)

        test_cases = engine._generate_ai_test_cases("API", "XSS vulnerable endpoint")

        assert len(test_cases) > 0
        assert any("<script>" in str(tc) for tc in test_cases)

    def test_ai_generation_handles_invalid_json(self):
        """Test AI generation handles invalid JSON response"""

        class BadLLM:
            def call_llm(self, prompt, **kwargs):
                return "Not valid JSON!"

        engine = FuzzingEngine(llm_manager=BadLLM())
        test_cases = engine._generate_ai_test_cases("API", "/test")

        assert test_cases == []


class TestAPIFuzzing:
    """Test API endpoint fuzzing"""

    def test_api_test_case_generation(self):
        """Test API test case generation"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/users",
            use_ai_generation=False,
        )

        test_cases = engine._generate_test_cases_for_api(config)

        assert len(test_cases) > 0
        assert all("method" in tc for tc in test_cases)
        assert all("data" in tc for tc in test_cases)

    def test_api_test_case_with_ai(self):
        """Test API test case generation with AI"""
        llm = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm)
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/users",
            use_ai_generation=True,
        )

        test_cases = engine._generate_test_cases_for_api(config)

        assert len(test_cases) > 0
        assert llm.call_count > 0

    def test_api_fuzzing_respects_max_iterations(self):
        """Test API fuzzing respects max_iterations config"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/test",
            max_iterations=5,
            use_ai_generation=False,
        )

        crashes = engine._fuzz_api(config)

        assert engine.test_cases_run <= 5


class TestFunctionFuzzing:
    """Test function fuzzing"""

    def test_function_fuzzing_generates_tests(self):
        """Test function fuzzing generates test cases"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.FUNCTION,
            target_path="module.parse_input",
            max_iterations=10,
        )

        crashes = engine._fuzz_function(config)

        assert engine.test_cases_run > 0
        assert isinstance(crashes, list)

    def test_function_fuzzing_uses_templates(self):
        """Test function fuzzing uses template payloads"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.FUNCTION, target_path="parse", max_iterations=5
        )

        # Should generate template test cases
        test_cases = engine._generate_template_test_cases()
        assert len(test_cases) > 0


class TestFileParserFuzzing:
    """Test file parser fuzzing"""

    def test_malformed_file_generation(self):
        """Test malformed file generation"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(target=FuzzTarget.FILE_PARSER, target_path="parse_xml")

        files = engine._generate_malformed_files(config)

        assert len(files) > 0
        assert all(isinstance(f, bytes) for f in files)

    def test_malformed_files_include_null_bytes(self):
        """Test malformed files include null bytes"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(target=FuzzTarget.FILE_PARSER, target_path="parse")

        files = engine._generate_malformed_files(config)

        assert any(b"\x00" in f for f in files)

    def test_malformed_files_include_large_data(self):
        """Test malformed files include large data"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(target=FuzzTarget.FILE_PARSER, target_path="parse")

        files = engine._generate_malformed_files(config)

        assert any(len(f) > 1000 for f in files)

    def test_file_parser_fuzzing_respects_max_iterations(self):
        """Test file parser fuzzing respects max_iterations"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.FILE_PARSER, target_path="parse_json", max_iterations=3
        )

        crashes = engine._fuzz_file_parser(config)

        assert engine.test_cases_run <= 3


class TestFuzzResult:
    """Test fuzzing result data structure"""

    def test_fuzz_result_creation(self):
        """Test fuzz result creation"""
        crashes = [
            Crash(
                crash_id="1",
                input_data="bad input",
                stack_trace="trace",
                crash_type="exception",
                reproducible=True,
                severity="high",
            )
        ]

        result = FuzzResult(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/test",
            total_iterations=100,
            unique_crashes=1,
            crashes=crashes,
            duration_seconds=30.5,
            coverage_percentage=75.5,
            test_cases_generated=50,
        )

        assert result.total_iterations == 100
        assert result.unique_crashes == 1
        assert len(result.crashes) == 1
        assert result.coverage_percentage == 75.5

    def test_fuzz_result_includes_timestamp(self):
        """Test fuzz result includes timestamp"""
        result = FuzzResult(
            target=FuzzTarget.FUNCTION,
            target_path="test_func",
            total_iterations=10,
            unique_crashes=0,
            crashes=[],
            duration_seconds=5.0,
            coverage_percentage=50.0,
            test_cases_generated=10,
        )

        assert result.timestamp is not None
        assert isinstance(result.timestamp, str)


class TestFuzzingOrchestration:
    """Test end-to-end fuzzing orchestration"""

    def test_fuzz_api_endpoint(self):
        """Test fuzzing API endpoint end-to-end"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/users",
            duration_seconds=5,
            max_iterations=10,
            use_ai_generation=False,
        )

        result = engine.fuzz(config)

        assert isinstance(result, FuzzResult)
        assert result.target == FuzzTarget.API_ENDPOINT
        assert result.total_iterations > 0

    def test_fuzz_function(self):
        """Test fuzzing function end-to-end"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.FUNCTION,
            target_path="module.parse",
            duration_seconds=5,
            max_iterations=10,
        )

        result = engine.fuzz(config)

        assert isinstance(result, FuzzResult)
        assert result.target == FuzzTarget.FUNCTION

    def test_fuzz_file_parser(self):
        """Test fuzzing file parser end-to-end"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.FILE_PARSER,
            target_path="parse_xml",
            duration_seconds=5,
            max_iterations=10,
        )

        result = engine.fuzz(config)

        assert isinstance(result, FuzzResult)
        assert result.target == FuzzTarget.FILE_PARSER

    def test_fuzz_invalid_target_raises_error(self):
        """Test fuzzing with invalid target raises error"""
        engine = FuzzingEngine(llm_manager=None)

        # Create config with invalid target by hacking
        config = FuzzConfig(target=FuzzTarget.API_ENDPOINT, target_path="/test")
        config.target = "INVALID_TARGET"

        with pytest.raises(ValueError, match="Unknown target type"):
            engine.fuzz(config)


class TestCoverageTracking:
    """Test code coverage tracking"""

    def test_coverage_calculation(self):
        """Test coverage percentage calculation"""
        engine = FuzzingEngine(llm_manager=None)
        coverage = engine._calculate_coverage()

        assert isinstance(coverage, float)
        assert 0.0 <= coverage <= 100.0

    def test_coverage_without_data(self):
        """Test coverage calculation without data"""
        engine = FuzzingEngine(llm_manager=None)
        engine.coverage_data = {}

        coverage = engine._calculate_coverage()
        assert coverage == 0.0


class TestDOSPayloads:
    """Test Denial of Service payload generation"""

    def test_dos_payloads_exist(self):
        """Test DoS payloads are defined"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["dos"]

        assert len(payloads) > 0

    def test_dos_json_bomb(self):
        """Test DoS JSON bomb payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["dos"]

        # Should contain deeply nested structures
        assert any(len(p) > 1000 for p in payloads)

    def test_dos_xml_bomb(self):
        """Test DoS XML bomb payload"""
        engine = FuzzingEngine()
        payloads = engine.INJECTION_PAYLOADS["dos"]

        assert any("<a>" in p for p in payloads)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling"""

    def test_empty_payload_list(self):
        """Test handling of empty payload list"""
        engine = FuzzingEngine()
        engine.INJECTION_PAYLOADS = {"sql_injection": []}

        test_cases = engine._generate_template_test_cases()
        assert test_cases == []

    def test_fuzz_with_zero_max_iterations(self):
        """Test fuzzing with max_iterations=0"""
        engine = FuzzingEngine(llm_manager=None)
        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/test",
            max_iterations=0,
        )

        crashes = engine._fuzz_api(config)
        assert engine.test_cases_run == 0

    def test_crash_with_empty_stack_trace(self):
        """Test crash with empty stack trace"""
        crash = Crash(
            crash_id="test",
            input_data="input",
            stack_trace="",
            crash_type="timeout",
            reproducible=False,
            severity="low",
        )

        assert crash.stack_trace == ""
        assert crash.crash_type == "timeout"


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for complete fuzzing workflows"""

    def test_complete_api_fuzzing_workflow(self):
        """Test complete API fuzzing workflow"""
        llm = MockLLMManager()
        engine = FuzzingEngine(llm_manager=llm)

        config = FuzzConfig(
            target=FuzzTarget.API_ENDPOINT,
            target_path="/api/users",
            duration_seconds=10,
            max_iterations=20,
            use_ai_generation=True,
        )

        result = engine.fuzz(config)

        assert result.total_iterations > 0
        assert result.test_cases_generated > 0
        assert llm.call_count > 0

    def test_fuzzing_without_ai_still_works(self):
        """Test fuzzing works without AI"""
        engine = FuzzingEngine(llm_manager=None)

        config = FuzzConfig(
            target=FuzzTarget.FUNCTION,
            target_path="parse",
            use_ai_generation=False,
            max_iterations=5,
        )

        result = engine.fuzz(config)

        assert result.total_iterations > 0
        assert result.test_cases_generated > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
