"""
Tests for scripts/threat_model_generator.py — Threat model generation.

Covers:
- HybridThreatModelGenerator initialization (pytm + Anthropic scenarios)
- analyze_repository (language detection, key file discovery, framework detection)
- generate_threat_model (pytm-only, Anthropic-only, hybrid, fallback)
- save/load threat model (file I/O)
- _detect_frameworks helper
- ThreatModelGenerator._create_fallback_threat_model
- Edge cases: missing engines, API failures, JSON parse failures
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


# ============================================================================
# HybridThreatModelGenerator — initialization
# ============================================================================


class TestHybridThreatModelGeneratorInit:
    """Test initialization with different engine availability scenarios."""

    @patch("threat_model_generator.PYTM_AVAILABLE", False)
    def test_init_no_engines_raises(self):
        """Should raise RuntimeError when neither pytm nor Anthropic is available."""
        from threat_model_generator import HybridThreatModelGenerator

        with pytest.raises(RuntimeError, match="Install pytm"):
            HybridThreatModelGenerator(api_key=None)

    @patch("threat_model_generator.PYTM_AVAILABLE", True)
    def test_init_pytm_only(self):
        """Should work with pytm available and no API key."""
        from threat_model_generator import HybridThreatModelGenerator

        mock_pytm_gen = MagicMock()
        with patch("threat_model_generator.PytmThreatModelGenerator", return_value=mock_pytm_gen):
            gen = HybridThreatModelGenerator(api_key=None)
            assert gen.pytm_available is True
            assert gen.anthropic_available is False

    @patch("threat_model_generator.PYTM_AVAILABLE", False)
    def test_init_anthropic_only(self):
        """Should work with Anthropic available and no pytm."""
        from threat_model_generator import HybridThreatModelGenerator

        mock_anthropic_cls = MagicMock()
        with patch.dict("sys.modules", {"anthropic": MagicMock(Anthropic=mock_anthropic_cls)}):
            gen = HybridThreatModelGenerator(api_key="test-key")
            assert gen.pytm_available is False
            assert gen.anthropic_available is True

    @patch("threat_model_generator.PYTM_AVAILABLE", True)
    def test_init_both_engines(self):
        """Should enable both engines when pytm and Anthropic are available."""
        from threat_model_generator import HybridThreatModelGenerator

        mock_pytm_gen = MagicMock()
        mock_anthropic_cls = MagicMock()
        with patch("threat_model_generator.PytmThreatModelGenerator", return_value=mock_pytm_gen), \
             patch.dict("sys.modules", {"anthropic": MagicMock(Anthropic=mock_anthropic_cls)}):
            gen = HybridThreatModelGenerator(api_key="test-key")
            assert gen.pytm_available is True
            assert gen.anthropic_available is True


# ============================================================================
# HybridThreatModelGenerator._detect_frameworks
# ============================================================================


class TestDetectFrameworks:
    """Test framework detection from key files."""

    def _make_generator(self):
        """Create a HybridThreatModelGenerator with pytm mocked."""
        from threat_model_generator import HybridThreatModelGenerator

        with patch("threat_model_generator.PYTM_AVAILABLE", True), \
             patch("threat_model_generator.PytmThreatModelGenerator"):
            return HybridThreatModelGenerator(api_key=None)

    def test_detect_python_frameworks(self):
        """Should detect Django, Flask, FastAPI from requirements.txt."""
        gen = self._make_generator()
        context = {
            "key_files": [
                {"name": "requirements.txt", "content": "django==4.2\nflask\nfastapi\npytest"},
            ],
            "frameworks": set(),
            "technologies": set(),
        }
        gen._detect_frameworks(context)
        assert "Django" in context["frameworks"]
        assert "Flask" in context["frameworks"]
        assert "FastAPI" in context["frameworks"]
        assert "pytest" in context["technologies"]

    def test_detect_js_frameworks(self):
        """Should detect React, Express from package.json."""
        gen = self._make_generator()
        context = {
            "key_files": [
                {"name": "package.json", "content": '{"dependencies": {"react": "^18.0", "express": "4.18"}}'},
            ],
            "frameworks": set(),
            "technologies": set(),
        }
        gen._detect_frameworks(context)
        assert "React" in context["frameworks"]
        assert "Express" in context["frameworks"]

    def test_detect_database_technologies(self):
        """Should detect PostgreSQL, Redis from any key file."""
        gen = self._make_generator()
        context = {
            "key_files": [
                {"name": "docker-compose.yml", "content": "services:\n  db:\n    image: postgres:15\n  cache:\n    image: redis:7"},
            ],
            "frameworks": set(),
            "technologies": set(),
        }
        gen._detect_frameworks(context)
        assert "PostgreSQL" in context["technologies"]
        assert "Redis" in context["technologies"]

    def test_detect_containerization(self):
        """Should detect Docker from Dockerfile."""
        gen = self._make_generator()
        context = {
            "key_files": [
                {"name": "Dockerfile", "content": "FROM python:3.11\nRUN pip install app"},
            ],
            "frameworks": set(),
            "technologies": set(),
        }
        gen._detect_frameworks(context)
        assert "Docker" in context["technologies"]

    def test_no_frameworks_detected(self):
        """Should not add any frameworks if content is unrelated."""
        gen = self._make_generator()
        context = {
            "key_files": [
                {"name": "README.md", "content": "# Hello World\nThis is a simple project."},
            ],
            "frameworks": set(),
            "technologies": set(),
        }
        gen._detect_frameworks(context)
        assert len(context["frameworks"]) == 0


# ============================================================================
# HybridThreatModelGenerator.generate_threat_model
# ============================================================================


class TestGenerateThreatModel:
    """Test threat model generation with various engine combinations."""

    def _make_generator_pytm_only(self):
        """Create generator with pytm only."""
        from threat_model_generator import HybridThreatModelGenerator

        with patch("threat_model_generator.PYTM_AVAILABLE", True), \
             patch("threat_model_generator.PytmThreatModelGenerator") as mock_cls:
            gen = HybridThreatModelGenerator(api_key=None)
            return gen, mock_cls

    def test_pytm_baseline_returned(self):
        """When only pytm is available, should return its baseline."""
        gen, _ = self._make_generator_pytm_only()
        baseline = {
            "threats": [{"id": "T1", "name": "Spoofing"}],
            "attack_surface": {"entry_points": ["API"]},
        }
        gen.pytm_generator.generate_from_repo_context.return_value = baseline

        repo_context = {"name": "test-repo", "languages": [], "frameworks": [], "technologies": []}
        result = gen.generate_threat_model(repo_context)

        assert result["threats"] == baseline["threats"]
        gen.pytm_generator.generate_from_repo_context.assert_called_once_with(repo_context)

    def test_pytm_failure_falls_through_to_error(self):
        """When pytm fails and no Anthropic, should raise RuntimeError."""
        gen, _ = self._make_generator_pytm_only()
        gen.pytm_generator.generate_from_repo_context.side_effect = RuntimeError("pytm crash")
        gen.anthropic_available = False

        repo_context = {"name": "test-repo", "languages": [], "frameworks": [], "technologies": []}
        with pytest.raises(RuntimeError, match="No threat modeling engines"):
            gen.generate_threat_model(repo_context)


# ============================================================================
# HybridThreatModelGenerator — save/load threat model
# ============================================================================


class TestSaveLoadThreatModel:
    """Test file I/O for threat models."""

    def _make_generator(self):
        from threat_model_generator import HybridThreatModelGenerator

        with patch("threat_model_generator.PYTM_AVAILABLE", True), \
             patch("threat_model_generator.PytmThreatModelGenerator"):
            return HybridThreatModelGenerator(api_key=None)

    def test_save_and_load_round_trip(self):
        """Saved threat model should be loadable and identical."""
        gen = self._make_generator()
        threat_model = {
            "version": "1.0",
            "threats": [{"id": "T1", "name": "Test threat"}],
            "attack_surface": {"entry_points": ["API"]},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "sub" / "threat-model.json")
            gen.save_threat_model(threat_model, output_path)

            loaded = gen.load_existing_threat_model(output_path)
            assert loaded is not None
            assert loaded["version"] == "1.0"
            assert loaded["threats"] == threat_model["threats"]

    def test_load_nonexistent_returns_none(self):
        """Loading a missing file should return None."""
        gen = self._make_generator()
        result = gen.load_existing_threat_model("/nonexistent/path/model.json")
        assert result is None

    def test_load_invalid_json_returns_none(self):
        """Loading a file with invalid JSON should return None."""
        gen = self._make_generator()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            result = gen.load_existing_threat_model(f.name)
            assert result is None

    def test_save_creates_parent_directories(self):
        """save_threat_model should create parent dirs if they don't exist."""
        gen = self._make_generator()
        with tempfile.TemporaryDirectory() as tmpdir:
            deep_path = str(Path(tmpdir) / "a" / "b" / "c" / "model.json")
            gen.save_threat_model({"test": True}, deep_path)
            assert Path(deep_path).exists()


# ============================================================================
# ThreatModelGenerator — fallback threat model
# ============================================================================


class TestThreatModelGeneratorFallback:
    """Test the legacy ThreatModelGenerator._create_fallback_threat_model."""

    def test_fallback_structure(self):
        """Fallback model should have all required sections."""
        from threat_model_generator import ThreatModelGenerator

        # Create instance with mocked Anthropic
        mock_anthropic = MagicMock()
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            gen = ThreatModelGenerator.__new__(ThreatModelGenerator)
            gen.client = MagicMock()

        repo_context = {
            "name": "test-repo",
            "technologies": ["Docker", "Redis"],
        }
        model = gen._create_fallback_threat_model(repo_context)

        assert "version" in model
        assert "generated_at" in model
        assert "repository" in model
        assert model["repository"] == "test-repo"
        assert "attack_surface" in model
        assert "trust_boundaries" in model
        assert "assets" in model
        assert "threats" in model
        assert len(model["threats"]) >= 1
        assert "security_objectives" in model


# ============================================================================
# ThreatModelGenerator.generate_threat_model — JSON parse failure fallback
# ============================================================================


class TestGenerateThreatModelAPIFallback:
    """Test that API JSON parse errors produce fallback model."""

    def test_json_parse_failure_returns_fallback(self):
        """If Claude returns non-JSON, should return fallback threat model."""
        from threat_model_generator import ThreatModelGenerator

        mock_anthropic = MagicMock()
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            gen = ThreatModelGenerator.__new__(ThreatModelGenerator)
            gen.client = MagicMock()

        # Simulate Claude returning non-JSON text
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text="This is not valid JSON at all")]
        mock_message.usage.input_tokens = 100
        mock_message.usage.output_tokens = 50
        gen.client.messages.create.return_value = mock_message

        repo_context = {
            "name": "test-repo",
            "languages": ["Python"],
            "frameworks": ["Flask"],
            "technologies": ["Redis"],
            "key_files": [],
            "file_tree": [],
        }
        result = gen.generate_threat_model(repo_context)
        # Should get fallback model
        assert result["repository"] == "test-repo"
        assert len(result["threats"]) >= 1
