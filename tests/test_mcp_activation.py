"""
Tests for MCP server activation in hybrid_analyzer.py (Phase 0).

Covers:
- MCP disabled by default (no startup)
- MCP enabled with successful startup in background thread
- MCP failure during startup is graceful (non-fatal)
"""

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


# ============================================================================
# Helper: build a minimal HybridSecurityAnalyzer with heavy mocking
# ============================================================================


def _build_analyzer(config: dict | None = None, **kwargs):
    """Construct a HybridSecurityAnalyzer with all scanners disabled.

    Only the MCP-related config paths are exercised.  All scanners and AI
    enrichment are turned off so the constructor does not attempt real
    subprocess / network calls.
    """
    # Patch out every optional import that the constructor touches to avoid
    # side-effects (scanner init, AI client, etc.).
    import hybrid_analyzer as mod

    defaults = dict(
        enable_semgrep=False,
        enable_trivy=False,
        enable_checkov=False,
        enable_api_security=False,
        enable_dast=False,
        enable_supply_chain=False,
        enable_fuzzing=False,
        enable_threat_intel=False,
        enable_remediation=False,
        enable_runtime_security=False,
        enable_regression_testing=False,
        enable_ai_enrichment=True,  # at least one feature must be enabled
        enable_argus=False,
        enable_sandbox=False,
        enable_multi_agent=False,
        enable_spontaneous_discovery=False,
        enable_collaborative_reasoning=False,
        enable_trufflehog=False,
        enable_iris=False,
        enable_nuclei_templates=False,
        enable_zap_baseline=False,
        config=config or {},
    )
    defaults.update(kwargs)
    return mod.HybridSecurityAnalyzer(**defaults)


# ============================================================================
# Test 1: MCP disabled (default)
# ============================================================================


class TestMCPDisabled:
    """When enable_mcp_server is False (default), no MCP server starts."""

    @patch("hybrid_analyzer.create_argus_mcp_server", create=True)
    def test_mcp_server_not_started_when_disabled(self, mock_create):
        """With default config, _mcp_started should be False."""
        analyzer = _build_analyzer(config={})
        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None
        assert analyzer._mcp_thread is None
        # Factory should never be called
        mock_create.assert_not_called()

    def test_mcp_disabled_explicitly(self):
        """Explicitly setting enable_mcp_server=False skips MCP."""
        analyzer = _build_analyzer(config={"enable_mcp_server": False})
        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None


# ============================================================================
# Test 2: MCP enabled with successful startup
# ============================================================================


class TestMCPEnabled:
    """When enable_mcp_server is True and MCP is available, server starts."""

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_mcp_server_starts_in_background(self, mock_create):
        """MCP server should be created and thread should start."""
        mock_server = MagicMock()
        # Make run() block briefly to simulate a real server
        mock_server.run = MagicMock()
        mock_create.return_value = mock_server

        analyzer = _build_analyzer(
            config={
                "enable_mcp_server": True,
                "repo_path": "/tmp/test-repo",
            },
        )

        # Server was created
        mock_create.assert_called_once_with("/tmp/test-repo", config=analyzer.config)

        # Thread was started
        assert analyzer._mcp_started is True
        assert analyzer._mcp_thread is not None
        assert analyzer._mcp_thread.daemon is True
        assert analyzer._mcp_thread.name == "argus-mcp-server"
        assert analyzer._mcp_server is mock_server

        # Cleanup
        analyzer.stop_mcp_server()
        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None
        assert analyzer._mcp_thread is None

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_stop_mcp_server_is_idempotent(self, mock_create):
        """Calling stop_mcp_server multiple times should not raise."""
        mock_server = MagicMock()
        mock_server.run = MagicMock()
        mock_create.return_value = mock_server

        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )
        assert analyzer._mcp_started is True

        # Stop twice -- no error
        analyzer.stop_mcp_server()
        analyzer.stop_mcp_server()
        assert analyzer._mcp_started is False

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_mcp_uses_cwd_when_repo_path_missing(self, mock_create):
        """When repo_path is not in config, os.getcwd() is used."""
        mock_server = MagicMock()
        mock_server.run = MagicMock()
        mock_create.return_value = mock_server

        import os

        analyzer = _build_analyzer(
            config={"enable_mcp_server": True},  # no repo_path
        )

        # Should have called create with os.getcwd()
        call_args = mock_create.call_args
        assert call_args[0][0] == os.getcwd()

        analyzer.stop_mcp_server()


# ============================================================================
# Test 3: MCP failure is graceful
# ============================================================================


class TestMCPFailureGraceful:
    """MCP startup failures should be non-fatal -- analyzer still works."""

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_mcp_creation_returns_none(self, mock_create):
        """If create_argus_mcp_server returns None, no thread starts."""
        mock_create.return_value = None

        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )

        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None
        assert analyzer._mcp_thread is None

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_mcp_creation_raises_exception(self, mock_create):
        """If create_argus_mcp_server raises, analyzer still initializes."""
        mock_create.side_effect = RuntimeError("MCP init boom")

        # Should NOT raise
        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )

        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None
        assert analyzer._mcp_thread is None

    @patch("hybrid_analyzer._MCP_LIB_OK", False)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    def test_mcp_library_not_installed(self):
        """If MCP library is not installed, skip gracefully."""
        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )

        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", False)
    def test_mcp_module_not_importable(self):
        """If mcp_server module fails to import, skip gracefully."""
        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )

        assert analyzer._mcp_started is False
        assert analyzer._mcp_server is None

    @patch("hybrid_analyzer._MCP_LIB_OK", True)
    @patch("hybrid_analyzer._MCP_IMPORT_OK", True)
    @patch("hybrid_analyzer.create_argus_mcp_server")
    def test_run_mcp_server_handles_exception_in_thread(self, mock_create):
        """If server.run() raises inside the thread, it logs and recovers."""
        mock_server = MagicMock()
        mock_server.run.side_effect = OSError("bind failed")
        mock_create.return_value = mock_server

        analyzer = _build_analyzer(
            config={"enable_mcp_server": True, "repo_path": "/tmp/test"},
        )

        # Thread was started...
        assert analyzer._mcp_thread is not None

        # Wait for the thread to finish (it should fail quickly)
        analyzer._mcp_thread.join(timeout=5.0)

        # _mcp_started should be False because _run_mcp_server sets it
        # to False in the finally block
        assert analyzer._mcp_started is False

        # Cleanup
        analyzer.stop_mcp_server()
