#!/usr/bin/env python3
"""
Tests for Argus Deep Analysis Engine and its sub-modules

Tests cover:
- DeepAnalysisEngine orchestration
- SemanticCodeTwin code understanding
- ProactiveAIScanner vulnerability detection
- TaintAnalyzer cross-function data flow
- ZeroDayHypothesizer novel vulnerability discovery
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from argus_deep_analysis import (
    DeepAnalysisEngine as AISLEEngine,
    DeepAnalysisFinding as AISLEFinding,
    DeepAnalysisResult as AISLEAnalysisResult,
    DeepAnalysisPhase as AISLEPhase,
    FindingSeverity,
    run_deep_analysis as run_aisle_analysis,
)


# ==================== Test Fixtures ====================

@pytest.fixture
def sample_python_code():
    """Sample vulnerable Python code for testing"""
    return '''
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    """Search for users by name"""
    query = request.args.get("q")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()

@app.route("/run")
def run_command():
    """Run a system command"""
    cmd = request.args.get("cmd")
    # Command injection vulnerability
    result = os.system(cmd)
    return str(result)

def process_file(filename):
    """Process a file from user input"""
    # Path traversal vulnerability
    with open(f"/data/{filename}") as f:
        return f.read()
'''


@pytest.fixture
def sample_js_code():
    """Sample vulnerable JavaScript code for testing"""
    return '''
const express = require('express');
const app = express();

app.get('/api/user', (req, res) => {
    const userId = req.query.id;
    // XSS vulnerability
    res.send(`<h1>User: ${userId}</h1>`);
});

app.post('/api/eval', (req, res) => {
    const code = req.body.code;
    // Code injection
    const result = eval(code);
    res.json({ result });
});
'''


@pytest.fixture
def temp_project(sample_python_code, sample_js_code):
    """Create a temporary project with sample files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create Python file
        py_file = Path(tmpdir) / "app.py"
        py_file.write_text(sample_python_code)

        # Create JS file
        js_file = Path(tmpdir) / "server.js"
        js_file.write_text(sample_js_code)

        yield tmpdir


@pytest.fixture
def mock_llm_provider():
    """Mock LLM provider for testing"""
    provider = MagicMock()
    provider.analyze.return_value = MagicMock(
        content=[MagicMock(text='{"confidence": 0.85, "reasoning": ["Step 1", "Step 2"]}')]
    )
    return provider


# ==================== AISLEFinding Tests ====================

class TestAISLEFinding:
    """Tests for AISLEFinding dataclass"""

    def test_finding_creation(self):
        """Test creating an AISLE finding"""
        finding = AISLEFinding(
            id="test123",
            source="proactive-scanner",
            title="SQL Injection",
            description="User input used in SQL query",
            severity=FindingSeverity.CRITICAL,
            confidence=0.9,
            file_path="/app/views.py",
            line_number=42,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            reasoning_chain=["Found user input", "Traced to SQL query", "No sanitization"],
            cwe_id="CWE-89"
        )

        assert finding.id == "test123"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.confidence == 0.9
        assert "CWE-89" in finding.cwe_id

    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = AISLEFinding(
            id="test456",
            source="taint-analyzer",
            title="Command Injection",
            description="Tainted data flows to os.system",
            severity=FindingSeverity.HIGH,
            confidence=0.85,
            file_path="/app/utils.py",
            line_number=100,
            code_snippet="os.system(cmd)",
            reasoning_chain=["Source: request.args", "Sink: os.system"],
            attack_scenario="Attacker can execute arbitrary commands"
        )

        result = finding.to_dict()

        assert result["id"] == "test456"
        assert result["severity"] == "high"
        assert result["location"]["file"] == "/app/utils.py"
        assert result["location"]["line"] == 100
        assert len(result["reasoning_chain"]) == 2

    def test_finding_to_unified_format(self):
        """Test converting to Argus unified finding format"""
        finding = AISLEFinding(
            id="test789",
            source="zero-day-hypothesizer",
            title="Race Condition",
            description="TOCTOU vulnerability in file operations",
            severity=FindingSeverity.MEDIUM,
            confidence=0.75,
            file_path="/app/file_handler.py",
            line_number=50,
            code_snippet="if os.path.exists(path): open(path)",
            reasoning_chain=["Check and use not atomic"],
            cwe_id="CWE-367"
        )

        unified = finding.to_unified_finding(
            repo="test/repo",
            commit_sha="abc123",
            branch="main"
        )

        assert unified["origin"] == "deep-analysis-zero-day-hypothesizer"
        assert unified["repo"] == "test/repo"
        assert unified["cwe"] == "CWE-367"
        assert unified["llm_enriched"] is True


# ==================== AISLEEngine Tests ====================

class TestAISLEEngine:
    """Tests for AISLEEngine orchestrator"""

    def test_engine_initialization(self):
        """Test engine initialization"""
        engine = AISLEEngine()

        assert engine.confidence_threshold == 0.70
        assert engine.enable_verification is True
        assert engine.max_workers == 4

    def test_engine_with_custom_threshold(self):
        """Test engine with custom confidence threshold"""
        engine = AISLEEngine(confidence_threshold=0.85)

        assert engine.confidence_threshold == 0.85

    def test_engine_lazy_loading(self):
        """Test that modules are lazy loaded"""
        engine = AISLEEngine()

        # Modules should be None until accessed
        assert engine._semantic_twin is None
        assert engine._proactive_scanner is None
        assert engine._taint_analyzer is None
        assert engine._zero_day_hypothesizer is None

    def test_generate_id(self):
        """Test finding ID generation"""
        engine = AISLEEngine()

        id1 = engine._generate_id("test", {"file": "a.py", "line": 10})
        id2 = engine._generate_id("test", {"file": "a.py", "line": 10})
        id3 = engine._generate_id("test", {"file": "b.py", "line": 10})

        assert id1 == id2  # Same input = same ID
        assert id1 != id3  # Different input = different ID
        assert len(id1) == 16  # 16 character hash

    def test_taint_severity_mapping(self):
        """Test taint flow severity mapping"""
        engine = AISLEEngine()

        assert engine._taint_severity({"sink_type": "sql"}) == FindingSeverity.CRITICAL
        assert engine._taint_severity({"sink_type": "command"}) == FindingSeverity.CRITICAL
        assert engine._taint_severity({"sink_type": "file"}) == FindingSeverity.HIGH
        assert engine._taint_severity({"sink_type": "log"}) == FindingSeverity.MEDIUM
        assert engine._taint_severity({"sink_type": "unknown"}) == FindingSeverity.LOW

    def test_taint_to_cwe_mapping(self):
        """Test taint sink to CWE mapping"""
        engine = AISLEEngine()

        assert engine._taint_to_cwe({"sink_type": "sql"}) == "CWE-89"
        assert engine._taint_to_cwe({"sink_type": "command"}) == "CWE-78"
        assert engine._taint_to_cwe({"sink_type": "eval"}) == "CWE-94"
        assert engine._taint_to_cwe({"sink_type": "file"}) == "CWE-22"
        assert engine._taint_to_cwe({"sink_type": "xss"}) == "CWE-79"

    def test_deduplication(self):
        """Test finding deduplication"""
        engine = AISLEEngine()

        findings = [
            AISLEFinding(
                id="f1", source="test", title="Finding 1",
                description="Desc", severity=FindingSeverity.HIGH,
                confidence=0.9, file_path="/app/a.py",
                line_number=10, code_snippet="code",
                reasoning_chain=[], cwe_id="CWE-89"
            ),
            AISLEFinding(
                id="f2", source="test", title="Finding 2",
                description="Desc", severity=FindingSeverity.MEDIUM,
                confidence=0.8, file_path="/app/b.py",
                line_number=20, code_snippet="code",
                reasoning_chain=[], cwe_id="CWE-78"
            ),
        ]

        existing = [
            {"path": "/app/a.py", "line_number": 10, "cwe": "CWE-89"}
        ]

        unique = engine._deduplicate(findings, existing)

        assert len(unique) == 1
        assert unique[0].id == "f2"


# ==================== AISLEAnalysisResult Tests ====================

class TestAISLEAnalysisResult:
    """Tests for AISLEAnalysisResult"""

    def test_result_creation(self):
        """Test creating analysis result"""
        result = AISLEAnalysisResult(
            findings=[],
            files_analyzed=10,
            functions_analyzed=50,
            total_time_seconds=5.5,
            proactive_findings=3,
            taint_flows_detected=2
        )

        assert result.files_analyzed == 10
        assert result.total_time_seconds == 5.5
        assert result.proactive_findings == 3

    def test_result_to_dict(self):
        """Test converting result to dictionary"""
        finding = AISLEFinding(
            id="test", source="test", title="Test",
            description="Desc", severity=FindingSeverity.LOW,
            confidence=0.7, file_path="/a.py",
            line_number=1, code_snippet="",
            reasoning_chain=[]
        )

        result = AISLEAnalysisResult(
            findings=[finding],
            files_analyzed=5,
            functions_analyzed=25,
            total_time_seconds=2.0
        )

        d = result.to_dict()

        assert d["summary"]["total_findings"] == 1
        assert d["summary"]["files_analyzed"] == 5
        assert len(d["findings"]) == 1


# ==================== Integration Tests ====================

class TestAISLEIntegration:
    """Integration tests for AISLE Engine"""

    def test_analyze_empty_files(self):
        """Test analyzing empty file list"""
        engine = AISLEEngine(enable_verification=False)
        result = engine.analyze(files=[], project_type="backend-api")

        assert result.files_analyzed == 0
        assert len(result.findings) == 0

    def test_analyze_with_temp_project(self, temp_project):
        """Test analyzing a temporary project"""
        files = [
            str(Path(temp_project) / "app.py"),
            str(Path(temp_project) / "server.js")
        ]

        engine = AISLEEngine(enable_verification=False)
        # Run without LLM modules (they won't be available in test)
        result = engine.analyze(
            files=files,
            project_type="backend-api",
            phases=[]  # Empty phases to skip actual analysis
        )

        assert result.files_analyzed == 2

    def test_run_aisle_analysis_function(self, temp_project):
        """Test the convenience function"""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            result = run_aisle_analysis(
                target_path=temp_project,
                project_type="backend-api",
                output_file=output_path
            )

            assert result is not None
            assert Path(output_path).exists()

            with open(output_path) as f:
                data = json.load(f)
                assert "summary" in data
                assert "findings" in data

        finally:
            if Path(output_path).exists():
                os.unlink(output_path)


# ==================== Module Import Tests ====================

class TestModuleImports:
    """Test that all AISLE modules can be imported"""

    def test_aisle_engine_import(self):
        """Test importing Deep Analysis engine"""
        from argus_deep_analysis import DeepAnalysisEngine
        assert DeepAnalysisEngine is not None

    def test_semantic_twin_import(self):
        """Test importing Semantic Code Twin module"""
        try:
            from semantic_code_twin import SemanticCodeTwin
            assert SemanticCodeTwin is not None
        except ImportError:
            pytest.skip("SemanticCodeTwin not yet available")

    def test_proactive_scanner_import(self):
        """Test importing Proactive AI Scanner module"""
        try:
            from proactive_ai_scanner import ProactiveAIScanner
            assert ProactiveAIScanner is not None
        except ImportError:
            pytest.skip("ProactiveAIScanner not yet available")

    def test_taint_analyzer_import(self):
        """Test importing Taint Analyzer module"""
        try:
            from taint_analyzer import TaintAnalyzer
            assert TaintAnalyzer is not None
        except ImportError:
            pytest.skip("TaintAnalyzer not yet available")

    def test_zero_day_hypothesizer_import(self):
        """Test importing Zero-Day Hypothesizer module"""
        try:
            from zero_day_hypothesizer import ZeroDayHypothesizer
            assert ZeroDayHypothesizer is not None
        except ImportError:
            pytest.skip("ZeroDayHypothesizer not yet available")


# ==================== Severity Tests ====================

class TestFindingSeverity:
    """Tests for FindingSeverity enum"""

    def test_severity_values(self):
        """Test all severity values exist"""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"


# ==================== Phase Tests ====================

class TestAISLEPhase:
    """Tests for AISLEPhase enum"""

    def test_phase_values(self):
        """Test all phase values exist"""
        assert AISLEPhase.SEMANTIC_ANALYSIS.value == "semantic_analysis"
        assert AISLEPhase.PROACTIVE_SCAN.value == "proactive_scan"
        assert AISLEPhase.TAINT_ANALYSIS.value == "taint_analysis"
        assert AISLEPhase.ZERO_DAY_HYPOTHESIS.value == "zero_day_hypothesis"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
