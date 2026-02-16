"""Tests for DAST agents and orchestrator integration.

Covers:
- NucleiAgent initialization, scan with mocked subprocess
- ZAPAgent initialization, scan with mocked subprocess
- DASTOrchestrator full pipeline with mocked agents
- Graceful degradation when agents/tools not available
- Deduplication, aggregation, severity counting
- Parallel and sequential execution paths
- Result serialization and saving
"""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add scripts directory to path -- must precede local imports (E402 acknowledged)
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from agents.nuclei_agent import NucleiAgent, NucleiConfig  # noqa: E402
from agents.zap_agent import AuthType, ScanProfile, ZAPAgent, ZAPConfig, ZAPFinding  # noqa: E402
from dast_orchestrator import (  # noqa: E402
    DASTOrchestrator,
    DASTScanResult,
    OrchestratorConfig,
)

# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

SAMPLE_NUCLEI_JSONL = json.dumps(
    {
        "template-id": "cve-2023-1234",
        "info": {
            "name": "SQL Injection in login",
            "severity": "critical",
            "tags": ["sqli", "cve"],
            "classification": {"cwe-id": "CWE-89", "cve-id": "CVE-2023-1234"},
            "metadata": {},
        },
        "matched-at": "http://target.local/login",
        "extracted-results": ["admin' OR 1=1--"],
        "curl-command": "curl http://target.local/login",
        "matcher-name": "sqli-error",
        "type": "http",
        "host": "http://target.local",
        "ip": "127.0.0.1",
        "timestamp": "2026-02-16T00:00:00Z",
        "request": "GET /login HTTP/1.1",
        "response": "HTTP/1.1 500",
    }
)

SAMPLE_NUCLEI_JSONL_MULTI = (
    SAMPLE_NUCLEI_JSONL
    + "\n"
    + json.dumps(
        {
            "template-id": "xss-reflected",
            "info": {
                "name": "Reflected XSS",
                "severity": "high",
                "tags": ["xss"],
                "classification": {"cwe-id": "CWE-79"},
                "metadata": {},
            },
            "matched-at": "http://target.local/search?q=<script>",
            "extracted-results": [],
            "curl-command": "",
            "matcher-name": "xss-body",
            "type": "http",
            "host": "http://target.local",
            "ip": "127.0.0.1",
            "timestamp": "2026-02-16T00:00:01Z",
            "request": "GET /search?q=<script> HTTP/1.1",
            "response": "HTTP/1.1 200",
        }
    )
)

SAMPLE_ZAP_OUTPUT = {
    "site": [
        {
            "@name": "http://target.local",
            "alerts": [
                {
                    "alert": "Cross-Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "confidence": "Medium",
                    "desc": "XSS vulnerability found",
                    "solution": "Encode output",
                    "reference": "https://owasp.org/xss",
                    "cweid": 79,
                    "wascid": 8,
                    "pluginid": 40012,
                    "instances": [
                        {
                            "uri": "http://target.local/search",
                            "method": "GET",
                            "param": "q",
                            "attack": "<script>alert(1)</script>",
                            "evidence": "<script>alert(1)</script>",
                        }
                    ],
                },
                {
                    "alert": "Missing CSP Header",
                    "riskdesc": "Low (High)",
                    "confidence": "High",
                    "desc": "Content Security Policy header missing",
                    "solution": "Add CSP header",
                    "reference": "",
                    "cweid": 693,
                    "wascid": 15,
                    "pluginid": 10038,
                    "instances": [
                        {
                            "uri": "http://target.local/",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "",
                        }
                    ],
                },
            ],
        }
    ]
}


@pytest.fixture
def nuclei_config():
    """Default NucleiConfig for tests."""
    return NucleiConfig(
        severity=["critical", "high"],
        rate_limit=100,
        timeout=5,
        retries=1,
        concurrency=10,
        max_duration=60,
    )


@pytest.fixture
def zap_config():
    """Default ZAPConfig for tests."""
    return ZAPConfig(
        profile=ScanProfile.FAST,
        spider_max_duration=30,
        active_max_duration=60,
    )


@pytest.fixture
def orch_config():
    """Default OrchestratorConfig with both agents disabled (for mocking)."""
    return OrchestratorConfig(
        enable_nuclei=False,
        enable_zap=False,
        parallel_agents=False,
    )


# ---------------------------------------------------------------------------
# NucleiAgent Tests
# ---------------------------------------------------------------------------


class TestNucleiAgent:
    """Tests for the NucleiAgent class."""

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_init_finds_binary(self, mock_run):
        """NucleiAgent finds nuclei when binary exists."""
        mock_run.return_value = Mock(returncode=0, stdout="Nuclei v3.0.0", stderr="")
        agent = NucleiAgent()
        assert agent.nuclei_path == "nuclei"

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_init_binary_not_found(self, mock_run):
        """NucleiAgent gracefully handles missing nuclei binary."""
        mock_run.side_effect = FileNotFoundError("nuclei not found")
        agent = NucleiAgent()
        assert agent.nuclei_path is None

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_scan_raises_without_binary(self, mock_run):
        """NucleiAgent.scan raises RuntimeError when nuclei is not installed."""
        mock_run.side_effect = FileNotFoundError()
        agent = NucleiAgent()
        with pytest.raises(RuntimeError, match="Nuclei not installed"):
            agent.scan(["http://target.local"])

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_scan_raises_on_empty_targets(self, mock_run):
        """NucleiAgent.scan raises ValueError when no targets provided."""
        mock_run.return_value = Mock(returncode=0, stdout="v3", stderr="")
        agent = NucleiAgent()
        with pytest.raises(ValueError, match="No targets"):
            agent.scan([])

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_scan_success(self, mock_run):
        """NucleiAgent.scan parses JSONL output and returns structured results."""
        # First call: version check (init)
        # Second call: version check (command build uses it)
        # Third call: the actual scan
        # Fourth call: _get_version in scan result
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),  # _find_nuclei
            Mock(returncode=0, stdout=SAMPLE_NUCLEI_JSONL, stderr=""),  # scan subprocess
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),  # _get_version
        ]
        agent = NucleiAgent()
        result = agent.scan(["http://target.local"])

        assert result["agent"] == "nuclei"
        assert result["total_findings"] == 1
        assert result["findings"][0]["name"] == "SQL Injection in login"
        assert result["findings"][0]["severity"] == "critical"
        assert result["findings"][0]["matched_at"] == "http://target.local/login"
        assert result["severity_counts"]["critical"] == 1

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_scan_multiple_findings(self, mock_run):
        """NucleiAgent.scan correctly parses multiple JSONL lines."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),
            Mock(returncode=0, stdout=SAMPLE_NUCLEI_JSONL_MULTI, stderr=""),
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),
        ]
        agent = NucleiAgent()
        result = agent.scan(["http://target.local"])

        assert result["total_findings"] == 2
        assert result["severity_counts"]["critical"] == 1
        assert result["severity_counts"]["high"] == 1

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_scan_timeout(self, mock_run):
        """NucleiAgent.scan handles subprocess timeout."""
        import subprocess

        mock_run.side_effect = [
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),
            subprocess.TimeoutExpired(cmd="nuclei", timeout=60),
        ]
        agent = NucleiAgent()
        with pytest.raises(RuntimeError, match="Nuclei scan timeout"):
            agent.scan(["http://target.local"])

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_parse_empty_output(self, mock_run):
        """NucleiAgent returns empty findings for empty output."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
            Mock(returncode=0, stdout="Nuclei v3.0.0", stderr=""),
        ]
        agent = NucleiAgent()
        result = agent.scan(["http://target.local"])
        assert result["total_findings"] == 0
        assert result["findings"] == []

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_parse_malformed_json(self, mock_run):
        """NucleiAgent skips malformed JSONL lines gracefully."""
        mock_run.side_effect = [
            Mock(returncode=0, stdout="v3", stderr=""),
            Mock(returncode=0, stdout="not-json\n" + SAMPLE_NUCLEI_JSONL, stderr=""),
            Mock(returncode=0, stdout="v3", stderr=""),
        ]
        agent = NucleiAgent()
        result = agent.scan(["http://target.local"])
        # Should have parsed 1 valid finding, skipped the malformed line
        assert result["total_findings"] == 1

    def test_nuclei_config_defaults(self):
        """NucleiConfig has sensible defaults."""
        config = NucleiConfig()
        assert config.severity == ["critical", "high", "medium"]
        assert config.rate_limit == 150
        assert config.max_duration == 600
        assert config.enable_caching is True

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_build_command(self, mock_run):
        """NucleiAgent builds correct command line."""
        mock_run.return_value = Mock(returncode=0, stdout="v3", stderr="")
        config = NucleiConfig(
            severity=["critical", "high"],
            headers={"Authorization": "Bearer token123"},
        )
        agent = NucleiAgent(config=config)
        cmd = agent._build_command("/tmp/targets.txt", ["cves/", "vulnerabilities/"])
        assert "-list" in cmd
        assert "/tmp/targets.txt" in cmd
        assert "-severity" in cmd
        idx = cmd.index("-severity")
        assert cmd[idx + 1] == "critical,high"
        assert "-header" in cmd
        header_idx = cmd.index("-header")
        assert cmd[header_idx + 1] == "Authorization: Bearer token123"

    def test_nuclei_tech_stack_detection(self):
        """NucleiAgent detects tech stacks from project files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create Django-like project structure
            (Path(tmpdir) / "manage.py").touch()
            (Path(tmpdir) / "settings.py").touch()

            with patch("agents.nuclei_agent.subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout="v3", stderr="")
                agent = NucleiAgent(project_path=tmpdir)
                stack_names = [s.name for s in agent.detected_stack]
                assert "Django" in stack_names


# ---------------------------------------------------------------------------
# ZAPAgent Tests
# ---------------------------------------------------------------------------


class TestZAPAgent:
    """Tests for the ZAPAgent class."""

    @patch("agents.zap_agent.subprocess.run")
    def test_zap_agent_init_no_tool_available(self, mock_run):
        """ZAPAgent gracefully handles missing ZAP."""
        mock_run.side_effect = FileNotFoundError()
        agent = ZAPAgent()
        assert agent.zap_available is False

    @patch("agents.zap_agent.subprocess.run")
    def test_zap_agent_init_cli_available(self, mock_run):
        """ZAPAgent detects zap-cli when available."""
        mock_run.return_value = Mock(returncode=0, stdout="ZAP CLI 2.11", stderr="")
        agent = ZAPAgent()
        assert agent.zap_available is True

    @patch("agents.zap_agent.subprocess.run")
    def test_zap_agent_scan_docker(self, mock_run):
        """ZAPAgent.scan runs Docker-based scan and parses output."""
        # First call: _check_zap (zap-cli check)
        # Second call: docker scan
        # Third call: _get_version

        def run_side_effect(cmd, **kwargs):
            if "zap-cli" in cmd:
                raise FileNotFoundError()
            if "docker" in cmd and "images" in cmd:
                return Mock(returncode=0, stdout="zaproxy stable", stderr="")
            if "docker" in cmd and "run" in cmd:
                # Write fake output file - the scan writes results to a file
                # We need to intercept and write the file
                return Mock(returncode=0, stdout="", stderr="")
            if "zap.sh" in cmd:
                return Mock(returncode=0, stdout="ZAP 2.14", stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        config = ZAPConfig(profile=ScanProfile.FAST)
        agent = ZAPAgent(config=config)

        # Mock _run_docker_scan to return parsed findings directly
        with patch.object(agent, "_run_docker_scan") as mock_docker:
            mock_docker.return_value = [
                {
                    "alert": "Cross-Site Scripting (Reflected)",
                    "severity": "high",
                    "risk": "High",
                    "confidence": "Medium",
                    "url": "http://target.local/search",
                    "method": "GET",
                    "param": "q",
                    "attack": "<script>alert(1)</script>",
                    "evidence": "<script>alert(1)</script>",
                    "description": "XSS vulnerability",
                    "solution": "Encode output",
                    "reference": "",
                    "cwe_id": 79,
                    "wasc_id": 8,
                    "plugin_id": 40012,
                    "other_info": "",
                }
            ]

            result = agent.scan("http://target.local")
            assert result["agent"] == "zap"
            assert result["total_findings"] == 1
            assert result["findings"][0]["alert"] == "Cross-Site Scripting (Reflected)"
            assert result["risk_counts"]["high"] == 1

    def test_zap_config_defaults(self):
        """ZAPConfig has sensible defaults."""
        config = ZAPConfig()
        assert config.profile == ScanProfile.BALANCED
        assert config.spider_max_depth == 3
        assert config.active_scan is True
        assert config.auth_type == AuthType.NONE

    def test_zap_parse_output(self):
        """ZAPAgent parses ZAP JSON output correctly."""
        with patch("agents.zap_agent.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            agent = ZAPAgent()

        findings = agent._parse_zap_output(SAMPLE_ZAP_OUTPUT)
        assert len(findings) == 2
        assert findings[0]["alert"] == "Cross-Site Scripting (Reflected)"
        assert findings[0]["severity"] == "high"
        assert findings[1]["alert"] == "Missing CSP Header"
        assert findings[1]["severity"] == "low"

    def test_zap_parse_empty_output(self):
        """ZAPAgent returns empty findings for empty output."""
        with patch("agents.zap_agent.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            agent = ZAPAgent()

        findings = agent._parse_zap_output({})
        assert findings == []

    def test_zap_count_by_risk(self):
        """ZAPAgent correctly counts findings by risk level."""
        with patch("agents.zap_agent.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            agent = ZAPAgent()

        findings = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
        counts = agent._count_by_risk(findings)
        assert counts == {"high": 2, "medium": 1, "low": 1, "info": 0}

    def test_zap_finding_to_dict(self):
        """ZAPFinding.to_dict returns correct dictionary."""
        finding = ZAPFinding(
            alert="XSS",
            risk="High",
            confidence="Medium",
            url="http://example.com",
            method="GET",
            param="q",
            attack="<script>",
            evidence="<script>",
            description="XSS found",
            solution="Encode",
            reference="https://owasp.org",
            cwe_id=79,
            wasc_id=8,
            plugin_id=40012,
        )
        d = finding.to_dict()
        assert d["alert"] == "XSS"
        assert d["cwe_id"] == 79
        assert d["plugin_id"] == 40012

    def test_zap_scan_profile_values(self):
        """ScanProfile enum has correct values."""
        assert ScanProfile.FAST.value == "fast"
        assert ScanProfile.BALANCED.value == "balanced"
        assert ScanProfile.COMPREHENSIVE.value == "comprehensive"


# ---------------------------------------------------------------------------
# DASTOrchestrator Tests
# ---------------------------------------------------------------------------


class TestDASTOrchestrator:
    """Tests for the DASTOrchestrator class."""

    def test_orchestrator_init_default_config(self):
        """Orchestrator initializes with default config when no agents enabled."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)
        assert orch.nuclei_agent is None
        assert orch.zap_agent is None

    @patch("agents.zap_agent.subprocess.run")
    @patch("agents.nuclei_agent.subprocess.run")
    def test_orchestrator_init_with_agents(self, mock_nuclei_run, mock_zap_run):
        """Orchestrator initializes both agents when enabled and available."""
        mock_nuclei_run.return_value = Mock(returncode=0, stdout="v3", stderr="")
        mock_zap_run.side_effect = FileNotFoundError()

        config = OrchestratorConfig(enable_nuclei=True, enable_zap=True)
        orch = DASTOrchestrator(config=config)
        assert orch.nuclei_agent is not None
        # ZAP agent is still created even if zap_available=False (it logs a warning)
        assert orch.zap_agent is not None

    def test_orchestrator_scan_no_agents(self):
        """Orchestrator scan returns empty results when no agents available."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)
        result = orch.scan("http://target.local")

        assert isinstance(result, DASTScanResult)
        assert result.total_findings == 0
        assert result.agents_run == []
        assert result.agents_succeeded == []
        assert result.agents_failed == []

    def test_orchestrator_scan_sequential_with_mocked_agents(self):
        """Orchestrator sequential scan collects results from both agents."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            parallel_agents=False,
        )
        orch = DASTOrchestrator(config=config)

        # Inject mock agents
        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {
            "findings": [
                {
                    "name": "SQLi",
                    "severity": "critical",
                    "matched_at": "http://target.local/login",
                    "extracted_results": [],
                }
            ],
            "total_findings": 1,
        }

        mock_zap = MagicMock()
        mock_zap.scan.return_value = {
            "findings": [
                {
                    "alert": "XSS",
                    "severity": "high",
                    "url": "http://target.local/search",
                    "description": "XSS found",
                    "evidence": "<script>",
                }
            ],
            "total_findings": 1,
        }

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")

        assert result.total_findings == 2
        assert "nuclei" in result.agents_succeeded
        assert "zap" in result.agents_succeeded
        assert result.severity_counts["critical"] == 1
        assert result.severity_counts["high"] == 1

    def test_orchestrator_scan_parallel_with_mocked_agents(self):
        """Orchestrator parallel scan collects results from both agents."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            parallel_agents=True,
        )
        orch = DASTOrchestrator(config=config)

        # Inject mock agents
        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {
            "findings": [
                {
                    "name": "SQLi",
                    "severity": "critical",
                    "matched_at": "http://target.local/login",
                    "extracted_results": [],
                }
            ],
            "total_findings": 1,
        }

        mock_zap = MagicMock()
        mock_zap.scan.return_value = {
            "findings": [
                {
                    "alert": "XSS",
                    "severity": "high",
                    "url": "http://target.local/search",
                    "description": "XSS found",
                    "evidence": "<script>",
                }
            ],
            "total_findings": 1,
        }

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")

        assert result.total_findings == 2
        assert "nuclei" in result.agents_succeeded
        assert "zap" in result.agents_succeeded

    def test_orchestrator_agent_failure_graceful(self):
        """Orchestrator handles agent failures gracefully in sequential mode."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            parallel_agents=False,
        )
        orch = DASTOrchestrator(config=config)

        # Inject mock agents - nuclei fails
        mock_nuclei = MagicMock()
        mock_nuclei.scan.side_effect = RuntimeError("Nuclei crashed")

        mock_zap = MagicMock()
        mock_zap.scan.return_value = {
            "findings": [
                {
                    "alert": "XSS",
                    "severity": "high",
                    "url": "http://target.local/search",
                    "description": "XSS found",
                    "evidence": "<script>",
                }
            ],
            "total_findings": 1,
        }

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")

        assert "nuclei" in result.agents_failed
        assert "zap" in result.agents_succeeded
        assert result.total_findings == 1

    def test_orchestrator_deduplication(self):
        """Orchestrator deduplicates findings with same name/url/severity."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            enable_deduplication=True,
        )
        orch = DASTOrchestrator(config=config)

        # Both agents find the same XSS
        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {
            "findings": [
                {
                    "name": "XSS",
                    "severity": "high",
                    "matched_at": "http://target.local/search",
                    "extracted_results": [],
                }
            ],
            "total_findings": 1,
        }

        mock_zap = MagicMock()
        mock_zap.scan.return_value = {
            "findings": [
                {
                    "alert": "XSS",
                    "severity": "high",
                    "url": "http://target.local/search",
                    "description": "XSS",
                    "evidence": "",
                }
            ],
            "total_findings": 1,
        }

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")

        # Both findings should be present since they have different URLs
        # Nuclei: matched_at="http://target.local/search" -> url in aggregated
        # ZAP: url="http://target.local/search" -> url in aggregated
        # Same name "XSS", same url, same severity => deduplicated to 1
        assert result.total_findings == 1

    def test_orchestrator_no_deduplication(self):
        """Orchestrator skips deduplication when disabled."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            enable_deduplication=False,
        )
        orch = DASTOrchestrator(config=config)

        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {
            "findings": [
                {
                    "name": "XSS",
                    "severity": "high",
                    "matched_at": "http://target.local/search",
                    "extracted_results": [],
                }
            ],
            "total_findings": 1,
        }

        mock_zap = MagicMock()
        mock_zap.scan.return_value = {
            "findings": [
                {
                    "alert": "XSS",
                    "severity": "high",
                    "url": "http://target.local/search",
                    "description": "XSS",
                    "evidence": "",
                }
            ],
            "total_findings": 1,
        }

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")
        # Without dedup, both findings remain
        assert result.total_findings == 2

    def test_orchestrator_aggregate_findings(self):
        """Orchestrator properly aggregates findings from Nuclei and ZAP."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)

        nuclei_results = {
            "findings": [
                {
                    "name": "SQLi",
                    "severity": "critical",
                    "matched_at": "http://target.local/api",
                    "extracted_results": ["payload"],
                }
            ]
        }
        zap_results = {
            "findings": [
                {
                    "alert": "Missing Headers",
                    "severity": "info",
                    "url": "http://target.local/",
                    "description": "Headers missing",
                    "evidence": "",
                }
            ]
        }

        aggregated = orch._aggregate_findings(nuclei_results, zap_results)
        assert len(aggregated) == 2
        assert aggregated[0]["source"] == "nuclei"
        assert aggregated[0]["name"] == "SQLi"
        assert aggregated[1]["source"] == "zap"
        assert aggregated[1]["name"] == "Missing Headers"

    def test_orchestrator_aggregate_none_results(self):
        """Orchestrator handles None results from agents."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)

        aggregated = orch._aggregate_findings(None, None)
        assert aggregated == []

    def test_orchestrator_count_by_severity(self):
        """Orchestrator counts findings by severity correctly."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)

        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
            {"severity": "info"},
        ]
        counts = orch._count_by_severity(findings)
        assert counts == {"critical": 2, "high": 1, "medium": 1, "low": 1, "info": 2}

    def test_orchestrator_save_results(self):
        """Orchestrator saves results to output directory."""
        config = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch = DASTOrchestrator(config=config)

        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {
            "findings": [{"name": "test", "severity": "high", "matched_at": "http://t", "extracted_results": []}],
            "total_findings": 1,
        }
        orch.nuclei_agent = mock_nuclei

        with tempfile.TemporaryDirectory() as tmpdir:
            orch.scan("http://target.local", output_dir=tmpdir)

            # Check that files were created
            dast_results = Path(tmpdir) / "dast-results.json"
            assert dast_results.exists()

            with open(dast_results) as f:
                saved = json.load(f)
            assert saved["target_url"] == "http://target.local"
            assert saved["total_findings"] == 1

            nuclei_results = Path(tmpdir) / "nuclei-results.json"
            assert nuclei_results.exists()

    def test_dast_scan_result_to_dict(self):
        """DASTScanResult.to_dict returns all fields."""
        result = DASTScanResult(
            timestamp="2026-02-16T00:00:00",
            target_url="http://target.local",
            duration_seconds=10.5,
            agents_run=["nuclei"],
            agents_succeeded=["nuclei"],
            agents_failed=[],
            total_findings=1,
            nuclei_results={"findings": []},
            zap_results=None,
            aggregated_findings=[{"name": "test"}],
            severity_counts={"critical": 1},
            metadata={"key": "value"},
        )
        d = result.to_dict()
        assert d["target_url"] == "http://target.local"
        assert d["total_findings"] == 1
        assert d["metadata"]["key"] == "value"

    def test_orchestrator_additional_targets(self):
        """Orchestrator handles additional targets list."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
        )
        orch = DASTOrchestrator(config=config)

        mock_nuclei = MagicMock()
        mock_nuclei.scan.return_value = {"findings": [], "total_findings": 0}
        orch.nuclei_agent = mock_nuclei

        orch.scan(
            "http://target.local",
            additional_targets=["http://api.target.local", "http://admin.target.local"],
        )

        # nuclei.scan should have been called with all targets
        call_args = mock_nuclei.scan.call_args
        targets_passed = call_args[0][0]
        assert "http://target.local" in targets_passed
        assert "http://api.target.local" in targets_passed
        assert "http://admin.target.local" in targets_passed

    def test_orchestrator_get_enabled_agents(self):
        """Orchestrator reports enabled agents correctly."""
        config = OrchestratorConfig(enable_nuclei=True, enable_zap=False)
        orch = DASTOrchestrator.__new__(DASTOrchestrator)
        orch.config = config
        assert orch._get_enabled_agents() == "Nuclei"

        config2 = OrchestratorConfig(enable_nuclei=True, enable_zap=True)
        orch.config = config2
        assert orch._get_enabled_agents() == "Nuclei, ZAP"

        config3 = OrchestratorConfig(enable_nuclei=False, enable_zap=False)
        orch.config = config3
        assert orch._get_enabled_agents() == "None"

    def test_orchestrator_parallel_agent_failure(self):
        """Orchestrator handles parallel agent failures gracefully."""
        config = OrchestratorConfig(
            enable_nuclei=False,
            enable_zap=False,
            parallel_agents=True,
        )
        orch = DASTOrchestrator(config=config)

        # Both agents fail
        mock_nuclei = MagicMock()
        mock_nuclei.scan.side_effect = RuntimeError("Nuclei crashed")

        mock_zap = MagicMock()
        mock_zap.scan.side_effect = RuntimeError("ZAP crashed")

        orch.nuclei_agent = mock_nuclei
        orch.zap_agent = mock_zap

        result = orch.scan("http://target.local")

        assert "nuclei" in result.agents_failed
        assert "zap" in result.agents_failed
        assert result.total_findings == 0


# ---------------------------------------------------------------------------
# Graceful Degradation Tests
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    """Tests for graceful degradation when tools/agents are unavailable."""

    def test_orchestrator_nuclei_import_missing(self):
        """Orchestrator handles missing NucleiAgent import gracefully."""
        import dast_orchestrator as dast_mod

        original_nuclei = dast_mod.NucleiAgent
        original_config = dast_mod.NucleiConfig
        try:
            dast_mod.NucleiAgent = None
            dast_mod.NucleiConfig = None

            config = OrchestratorConfig(enable_nuclei=True, enable_zap=False)
            orch = dast_mod.DASTOrchestrator(config=config)
            assert orch.nuclei_agent is None

            result = orch.scan("http://target.local")
            assert result.total_findings == 0
        finally:
            dast_mod.NucleiAgent = original_nuclei
            dast_mod.NucleiConfig = original_config

    def test_orchestrator_zap_import_missing(self):
        """Orchestrator handles missing ZAPAgent import gracefully."""
        import dast_orchestrator as dast_mod

        original_zap = dast_mod.ZAPAgent
        original_config = dast_mod.ZAPConfig
        try:
            dast_mod.ZAPAgent = None
            dast_mod.ZAPConfig = None

            config = OrchestratorConfig(enable_nuclei=False, enable_zap=True)
            orch = dast_mod.DASTOrchestrator(config=config)
            assert orch.zap_agent is None

            result = orch.scan("http://target.local")
            assert result.total_findings == 0
        finally:
            dast_mod.ZAPAgent = original_zap
            dast_mod.ZAPConfig = original_config

    def test_orchestrator_both_imports_missing(self):
        """Orchestrator handles both agents missing gracefully."""
        import dast_orchestrator as dast_mod

        orig_nuclei = dast_mod.NucleiAgent
        orig_nuclei_cfg = dast_mod.NucleiConfig
        orig_zap = dast_mod.ZAPAgent
        orig_zap_cfg = dast_mod.ZAPConfig
        try:
            dast_mod.NucleiAgent = None
            dast_mod.NucleiConfig = None
            dast_mod.ZAPAgent = None
            dast_mod.ZAPConfig = None

            config = OrchestratorConfig(enable_nuclei=True, enable_zap=True)
            orch = dast_mod.DASTOrchestrator(config=config)
            assert orch.nuclei_agent is None
            assert orch.zap_agent is None

            result = orch.scan("http://target.local")
            assert isinstance(result, DASTScanResult)
            assert result.total_findings == 0
        finally:
            dast_mod.NucleiAgent = orig_nuclei
            dast_mod.NucleiConfig = orig_nuclei_cfg
            dast_mod.ZAPAgent = orig_zap
            dast_mod.ZAPConfig = orig_zap_cfg

    def test_orchestrator_auth_config_missing(self):
        """Orchestrator handles missing dast_auth_config module."""
        import dast_orchestrator as dast_mod

        orig_loader = dast_mod.load_dast_auth_config
        try:
            dast_mod.load_dast_auth_config = None

            config = OrchestratorConfig(
                enable_nuclei=False,
                enable_zap=False,
                dast_auth_config_path="/fake/path.yml",
            )
            # Should not raise
            orch = dast_mod.DASTOrchestrator(config=config)
            assert orch.dast_auth is None
        finally:
            dast_mod.load_dast_auth_config = orig_loader

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_version_check_fails(self, mock_run):
        """NucleiAgent handles version check failure."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
        agent = NucleiAgent()
        assert agent.nuclei_path is None

    @patch("agents.nuclei_agent.subprocess.run")
    def test_nuclei_agent_timeout_on_version_check(self, mock_run):
        """NucleiAgent handles timeout during version check."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=10)
        agent = NucleiAgent()
        assert agent.nuclei_path is None
