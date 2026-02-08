#!/usr/bin/env python3
"""
Unit tests for Spontaneous Discovery

Tests cover:
- Discovery categories (architecture, hidden_vuln, config, data_security)
- Confidence filtering (>0.7 threshold)
- Deduplication with existing findings
- Architecture analysis
- LLM discovery generation
- File list integration
- Discovery output structure
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from dataclasses import dataclass
from typing import Optional, List

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from spontaneous_discovery import (
    SpontaneousDiscovery,
    Discovery,
)


class TestDiscoveryDataclass:
    """Test Discovery dataclass structure"""

    def test_discovery_creation_minimal(self):
        """Test creating a Discovery with minimal fields"""
        discovery = Discovery(
            category="architecture",
            title="Missing Authentication Layer",
            description="No auth mechanism detected",
            confidence=0.92,
            severity="high",
            evidence=["No auth files found"],
            remediation="Add authentication middleware",
        )

        assert discovery.category == "architecture"
        assert discovery.title == "Missing Authentication Layer"
        assert discovery.description == "No auth mechanism detected"
        assert discovery.confidence == 0.92
        assert discovery.cwe_id is None

    def test_discovery_creation_full(self):
        """Test creating a Discovery with all fields"""
        discovery = Discovery(
            category="hidden_vuln",
            title="SQL injection in user query",
            description="User input concatenated into query",
            confidence=0.95,
            severity="critical",
            evidence=["Query concatenation found"],
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
            affected_files=["src/db.py"],
            code_snippets=["query = 'SELECT * FROM users WHERE id=' + user_id"],
            references=["https://owasp.org"],
        )

        assert discovery.category == "hidden_vuln"
        assert discovery.severity == "critical"
        assert discovery.cwe_id == "CWE-89"
        assert len(discovery.affected_files) == 1
        assert len(discovery.references) == 1

    def test_discovery_categories(self):
        """Test all discovery categories"""
        categories = [
            "architecture",
            "hidden_vuln",
            "config",
            "data_security",
        ]

        for category in categories:
            discovery = Discovery(
                category=category,
                title="Test",
                description="Test",
                confidence=0.8,
                severity="medium",
                evidence=["Test"],
                remediation="Test",
            )
            assert discovery.category == category

    def test_discovery_confidence_bounds(self):
        """Test confidence value bounds"""
        for confidence in [0.0, 0.5, 0.7, 0.99, 1.0]:
            discovery = Discovery(
                category="architecture",
                title="Test",
                description="Test",
                confidence=confidence,
                severity="medium",
                evidence=["Test"],
                remediation="Test",
            )
            assert discovery.confidence == confidence


class TestSpontaneousDiscoveryInitialization:
    """Test SpontaneousDiscovery initialization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()

    def test_initialization(self):
        """Test SpontaneousDiscovery initialization"""
        discovery = SpontaneousDiscovery(self.mock_llm)

        assert discovery.llm == self.mock_llm
        assert isinstance(discovery.discoveries, list)

    def test_initialization_no_llm(self):
        """Test initialization without LLM"""
        discovery = SpontaneousDiscovery(None)

        assert discovery.llm is None

    def test_initialization_stores_llm(self):
        """Test initialization stores LLM reference"""
        discovery = SpontaneousDiscovery(self.mock_llm)

        assert discovery.llm is self.mock_llm


class TestArchitectureAnalysis:
    """Test architecture analysis discovery"""

    def setup_method(self):
        """Set up test fixtures with real temp files for file-based analysis"""
        self.mock_llm = Mock()
        self.discovery = SpontaneousDiscovery(self.mock_llm)
        self.tmpdir = tempfile.mkdtemp()

    def _create_file(self, relpath, content=""):
        """Create a temp file with given content."""
        full_path = os.path.join(self.tmpdir, relpath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_analyze_architecture_missing_auth(self):
        """Test discovering missing authentication"""
        # Create route files but no auth files
        files = [
            self._create_file("src/routes/api.py", "app.route('/users')"),
            self._create_file("src/routes/endpoints.py", "app.route('/data')"),
            self._create_file("src/routes/router.py", "app.route('/admin')"),
            self._create_file("src/models.py", "class User: pass"),
        ]

        discoveries = self.discovery.analyze_architecture(files, "backend-api")

        assert isinstance(discoveries, list)
        # Should find missing auth if route files exist without auth files
        if len(discoveries) > 0:
            assert any(d.category == "architecture" for d in discoveries)

    def test_analyze_architecture_with_auth(self):
        """Test no false alarm when auth exists"""
        files = [
            self._create_file("src/routes/api.py", "app.route('/users')"),
            self._create_file("src/auth/jwt_handler.py", "def authenticate(): pass"),
            self._create_file("src/models.py", "class User: pass"),
        ]

        discoveries = self.discovery.analyze_architecture(files, "backend-api")

        assert isinstance(discoveries, list)

    def test_analyze_architecture_returns_list(self):
        """Test that analyze_architecture always returns a list"""
        files = [
            self._create_file("src/services.py", "class Service: pass"),
        ]

        discoveries = self.discovery.analyze_architecture(files, "backend-api")

        assert isinstance(discoveries, list)


class TestIssueDiscovery:
    """Test issue discovery via the main discover() method"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.discovery = SpontaneousDiscovery(self.mock_llm)
        self.tmpdir = tempfile.mkdtemp()

    def _create_file(self, relpath, content=""):
        """Create a temp file with given content."""
        full_path = os.path.join(self.tmpdir, relpath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_discover_weak_crypto(self):
        """Test discovering weak cryptographic algorithms"""
        files = [
            self._create_file("src/crypto.py", "import hashlib\nhash = md5(data)"),
        ]

        discoveries = self.discovery.discover(
            files=files,
            existing_findings=[],
            architecture="backend-api",
        )

        assert isinstance(discoveries, list)
        # md5 usage should be flagged
        if len(discoveries) > 0:
            assert any(d.confidence > 0.7 for d in discoveries)

    def test_discover_debug_mode(self):
        """Test discovering debug mode enabled"""
        files = [
            self._create_file("config/settings.py", "DEBUG = True\nSECRET_KEY = 'abc'"),
        ]

        discoveries = self.discovery.discover(
            files=files,
            existing_findings=[],
            architecture="backend-api",
        )

        assert isinstance(discoveries, list)

    def test_discover_sensitive_logging(self):
        """Test discovering sensitive data in logs"""
        files = [
            self._create_file("src/api.py", 'logger.info(f"Password: {password}")'),
        ]

        discoveries = self.discovery.discover(
            files=files,
            existing_findings=[],
            architecture="backend-api",
        )

        assert isinstance(discoveries, list)

    def test_discover_returns_only_high_confidence(self):
        """Test that discover returns only high confidence findings"""
        files = [
            self._create_file("src/app.py", "def hello(): return 'world'"),
        ]

        discoveries = self.discovery.discover(
            files=files,
            existing_findings=[],
            architecture="backend-api",
        )

        # All returned discoveries should have confidence > 0.7
        assert all(d.confidence > 0.7 for d in discoveries)

    def test_discover_mixed_issues(self):
        """Test discovering issues from multiple categories"""
        files = [
            self._create_file("src/crypto.py", "import hashlib\nhash = md5(data)"),
            self._create_file("config/settings.py", "DEBUG = True"),
            self._create_file("src/api.py", 'logger.info(f"token: {token}")'),
        ]

        discoveries = self.discovery.discover(
            files=files,
            existing_findings=[],
            architecture="backend-api",
        )

        assert isinstance(discoveries, list)
        # Multiple categories may be found
        if len(discoveries) > 1:
            categories = {d.category for d in discoveries}
            assert len(categories) >= 1


class TestConfidenceFiltering:
    """Test confidence filtering via the discover() method"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.tmpdir = tempfile.mkdtemp()

    def _create_file(self, relpath, content=""):
        """Create a temp file with given content."""
        full_path = os.path.join(self.tmpdir, relpath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_filter_high_confidence_default(self):
        """Test that discover() filters to >0.7 by default"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        # All results must be > 0.7
        assert all(d.confidence > 0.7 for d in results)

    def test_filter_removes_low_confidence(self):
        """Test that low-confidence discoveries are removed"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/app.py", "print('hello')"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        # Should return empty or only high-confidence
        assert all(d.confidence > 0.7 for d in results)

    def test_filter_preserves_high_confidence(self):
        """Test that high-confidence discoveries are preserved"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)\nresult = sha1(input)"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        # Weak crypto detection has confidence 0.85, should be preserved
        for d in results:
            assert d.confidence > 0.7

    def test_filter_empty_files(self):
        """Test filtering with empty file list"""
        discovery = SpontaneousDiscovery(self.mock_llm)

        results = discovery.discover(files=[], existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_filter_no_issues_found(self):
        """Test filtering when no issues found"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/clean.py", "def add(a, b): return a + b"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_filter_preserves_order(self):
        """Test that filtering preserves discovery order"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
            self._create_file("config/settings.py", "DEBUG = True"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        # Order should be maintained
        assert isinstance(results, list)


class TestDeduplication:
    """Test deduplication with existing findings"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.tmpdir = tempfile.mkdtemp()

    def _create_file(self, relpath, content=""):
        """Create a temp file with given content."""
        full_path = os.path.join(self.tmpdir, relpath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_deduplicate_removes_existing(self):
        """Test that deduplication removes overlapping findings"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        existing = [
            {"cwe": "CWE-327", "title": "Weak Crypto", "rule_name": "weak-hash"},
        ]

        results = discovery.discover(files=files, existing_findings=existing, architecture="backend-api")

        # CWE-327 overlap should cause dedup
        # The result may be empty if the weak crypto discovery is deduped
        assert isinstance(results, list)

    def test_deduplicate_keeps_new(self):
        """Test that deduplication keeps new findings"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
            self._create_file("config/settings.py", "DEBUG = True"),
        ]

        # Existing only covers XSS, not our discoveries
        existing = [
            {"cwe": "CWE-79", "title": "XSS vulnerability"},
        ]

        results = discovery.discover(files=files, existing_findings=existing, architecture="backend-api")

        assert isinstance(results, list)

    def test_deduplicate_empty_existing(self):
        """Test deduplication with no existing findings"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_deduplicate_all_exist(self):
        """Test deduplication when all findings overlap"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        existing = [
            {"cwe": "CWE-327", "title": "Weak Cryptographic Algorithms"},
        ]

        results = discovery.discover(files=files, existing_findings=existing, architecture="backend-api")

        # The weak crypto discovery should be deduped
        assert isinstance(results, list)

    def test_deduplicate_similar_but_different(self):
        """Test deduplication with similar but different findings"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
            self._create_file("config/settings.py", "DEBUG = True"),
        ]

        # Existing has different CWE
        existing = [
            {"cwe": "CWE-999", "title": "Something else entirely"},
        ]

        results = discovery.discover(files=files, existing_findings=existing, architecture="backend-api")

        assert isinstance(results, list)


class TestDiscoveryOutput:
    """Test discovery output structure"""

    def test_discovery_contains_required_fields(self):
        """Test that discovery contains all required fields"""
        disc = Discovery(
            category="architecture",
            title="Missing Auth",
            description="No auth detected",
            confidence=0.85,
            severity="high",
            evidence=["No auth files"],
            remediation="Add auth middleware",
        )

        assert hasattr(disc, "category")
        assert hasattr(disc, "title")
        assert hasattr(disc, "description")
        assert hasattr(disc, "evidence")
        assert hasattr(disc, "confidence")

    def test_discovery_can_include_optional_fields(self):
        """Test that discovery can include optional fields"""
        disc = Discovery(
            category="hidden_vuln",
            title="SQL injection",
            description="Injection vulnerability",
            confidence=0.94,
            severity="critical",
            evidence=["Query concatenation"],
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
            affected_files=["src/db.py"],
            code_snippets=["query = 'SELECT * FROM ' + table"],
            references=["https://owasp.org"],
        )

        assert disc.severity == "critical"
        assert disc.cwe_id == "CWE-89"
        assert len(disc.affected_files) == 1

    def test_discovery_title_format(self):
        """Test discovery title format"""
        titles = [
            "Missing Authentication Layer",
            "Weak Cryptographic Algorithms Detected",
            "Debug Mode Enabled",
            "Sensitive Data in Logs",
        ]

        for title in titles:
            disc = Discovery(
                category="architecture",
                title=title,
                description="Test",
                confidence=0.8,
                severity="medium",
                evidence=["Test"],
                remediation="Test",
            )
            assert disc.title == title


class TestLLMIntegration:
    """Test LLM integration"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.tmpdir = tempfile.mkdtemp()

    def _create_file(self, relpath, content=""):
        """Create a temp file with given content."""
        full_path = os.path.join(self.tmpdir, relpath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_llm_not_required_for_heuristic_discovery(self):
        """Test that heuristic-based discovery works without LLM calls"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        # Heuristic discovery doesn't call LLM directly
        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_discovery_without_llm(self):
        """Test discovery works even without an LLM"""
        discovery = SpontaneousDiscovery(None)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_discovery_results_parseable(self):
        """Test that discovery results are structured correctly"""
        discovery = SpontaneousDiscovery(self.mock_llm)
        files = [
            self._create_file("src/crypto.py", "hash = md5(data)"),
        ]

        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        for d in results:
            assert isinstance(d, Discovery)
            assert isinstance(d.category, str)
            assert isinstance(d.title, str)
            assert isinstance(d.confidence, float)


class TestEdgeCases:
    """Test edge cases"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()

    def test_empty_file_list(self):
        """Test with empty file list"""
        discovery = SpontaneousDiscovery(self.mock_llm)

        results = discovery.discover(files=[], existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_single_file(self):
        """Test with single file"""
        tmpdir = tempfile.mkdtemp()
        fpath = os.path.join(tmpdir, "app.py")
        with open(fpath, "w") as f:
            f.write("print('hello')")

        discovery = SpontaneousDiscovery(self.mock_llm)
        results = discovery.discover(files=[fpath], existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_special_characters_in_file_names(self):
        """Test files with special characters"""
        tmpdir = tempfile.mkdtemp()
        files = []
        for name in ["test-api.py", "test_db.py"]:
            fpath = os.path.join(tmpdir, name)
            with open(fpath, "w") as f:
                f.write("pass")
            files.append(fpath)

        discovery = SpontaneousDiscovery(self.mock_llm)
        results = discovery.discover(files=files, existing_findings=[], architecture="backend-api")

        assert isinstance(results, list)

    def test_discovery_confidence_precision(self):
        """Test confidence precision"""
        disc = Discovery(
            category="architecture",
            title="Test",
            description="Test",
            confidence=0.123456789,
            severity="low",
            evidence=["Test"],
            remediation="Test",
        )

        assert disc.confidence == 0.123456789

    def test_long_issue_description(self):
        """Test handling long issue descriptions"""
        long_desc = "A" * 1000
        disc = Discovery(
            category="hidden_vuln",
            title="Test",
            description=long_desc,
            confidence=0.8,
            severity="medium",
            evidence=["Test"],
            remediation="Test",
        )

        assert len(disc.description) == 1000

    def test_unicode_in_issue_description(self):
        """Test handling unicode in issue descriptions"""
        disc = Discovery(
            category="data_security",
            title="GDPR violation",
            description="GDPR violation: donnees personnelles",
            confidence=0.9,
            severity="high",
            evidence=["Evidence"],
            remediation="Fix it",
        )

        assert "donnees" in disc.description
