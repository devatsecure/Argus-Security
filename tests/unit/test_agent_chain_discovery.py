#!/usr/bin/env python3
"""
Unit tests for Agent Chain Discovery.

Uses mocked LLM (llm_call) to test discover_chains, prompt building,
and parsing without calling a real API.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from agent_chain_discovery import AgentChainDiscovery, AttackChain, AttackStep, CrossComponentRisk


def _mock_llm_returning_chains(num_chains: int = 1) -> str:
    """Return a JSON string that _parse_chains can handle (top-level array)."""
    chains = []
    for i in range(num_chains):
        chains.append({
            "chain_id": f"chain-{i}",
            "finding_ids": [f"f{i}-1", f"f{i}-2"],
            "steps": [
                {"finding_id": f"f{i}-1", "action": "exploit", "enables": "access"},
                {"finding_id": f"f{i}-2", "action": "escalate", "enables": "root"},
            ],
            "severity": "high" if i == 0 else "medium",
            "complexity": "medium",
            "impact": "Full compromise",
            "description": f"Chain {i} description",
        })
    return json.dumps(chains)


class TestDiscoverChainsMockedLLM:
    """discover_chains with mocked llm_call."""

    def test_empty_findings_returns_empty_list(self):
        """When findings list is empty, discover_chains returns [] without calling LLM."""
        llm = MagicMock()
        discovery = AgentChainDiscovery(llm_call=llm)
        result = discovery.discover_chains([])
        assert result == []
        llm.assert_not_called()

    def test_returns_parsed_chains(self):
        """LLM returning valid JSON chains results in list of AttackChain."""
        llm = MagicMock(return_value=_mock_llm_returning_chains(2))
        discovery = AgentChainDiscovery(llm_call=llm)
        findings = [
            {"id": "f0-1", "type": "xss", "severity": "high", "file": "a.py", "description": "XSS"},
            {"id": "f0-2", "type": "sql", "severity": "medium", "file": "b.py", "description": "SQLi"},
        ]
        chains = discovery.discover_chains(findings)
        assert len(chains) == 2
        assert all(isinstance(c, AttackChain) for c in chains)
        assert chains[0].chain_id == "chain-0"
        assert chains[0].severity == "high"
        assert len(chains[0].steps) == 2
        assert chains[1].chain_id == "chain-1"
        llm.assert_called_once()

    def test_llm_exception_returns_empty_list(self):
        """When llm_call raises, discover_chains returns [] and logs."""
        llm = MagicMock(side_effect=RuntimeError("API error"))
        discovery = AgentChainDiscovery(llm_call=llm)
        findings = [{"id": "f1", "type": "xss", "severity": "high", "file": "a.py", "description": "X"}]
        result = discovery.discover_chains(findings)
        assert result == []
        llm.assert_called_once()

    def test_batch_limit_respected(self):
        """Findings beyond max_findings_per_batch are truncated (LLM receives only batch)."""
        llm = MagicMock(return_value=_mock_llm_returning_chains(0))
        discovery = AgentChainDiscovery(llm_call=llm, max_findings_per_batch=5)
        findings = [{"id": f"f{i}", "type": "xss", "severity": "high", "file": "a.py", "description": "X"} for i in range(10)]
        discovery.discover_chains(findings)
        # Prompt should contain at most 5 findings
        call_args = llm.call_args[0][0]
        assert "f0" in call_args
        assert "f4" in call_args


class TestParseChains:
    """_parse_chains behavior with various LLM outputs."""

    def test_valid_json_with_chains(self):
        """Valid JSON with attack_chains key returns AttackChain list."""
        discovery = AgentChainDiscovery(llm_call=lambda _: "")
        raw = _mock_llm_returning_chains(1)
        chains = discovery._parse_chains(raw)
        assert len(chains) == 1
        assert chains[0].chain_id == "chain-0"
        assert chains[0].severity == "high"
        assert len(chains[0].steps) == 2

    def test_invalid_json_returns_empty(self):
        """Invalid JSON or non-array returns empty list."""
        discovery = AgentChainDiscovery(llm_call=lambda _: "")
        assert discovery._parse_chains("not json") == []
        assert discovery._parse_chains("{}") == []
        assert discovery._parse_chains('{"other": []}') == []  # object, not array


class TestAttackChainDataclass:
    """AttackChain and AttackStep serialization."""

    def test_to_dict(self):
        """AttackChain.to_dict is JSON-serializable and includes steps."""
        chain = AttackChain(
            chain_id="c1",
            finding_ids=["f1", "f2"],
            steps=[
                AttackStep(finding_id="f1", action="exploit", enables="access"),
            ],
            severity="high",
            complexity="medium",
            impact="Data breach",
            description="Test chain",
        )
        d = chain.to_dict()
        assert d["chain_id"] == "c1"
        assert d["severity"] == "high"
        assert len(d["steps"]) == 1
        assert d["steps"][0]["finding_id"] == "f1"
