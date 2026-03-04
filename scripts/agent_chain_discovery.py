#!/usr/bin/env python3
"""
LLM-Powered Vulnerability Chain Discovery for Argus Security

Complements the rule-based vulnerability_chaining_engine.py (14 static rules)
with LLM-powered reasoning to discover novel multi-step attack paths that
static rules cannot anticipate.

Key Features:
- LLM-driven attack chain discovery beyond predefined rule sets
- Cross-component analysis for inter-module vulnerability combinations
- Structured prompt engineering for reliable JSON chain output
- Batch processing with configurable limits to control LLM costs

Integration:
- Accepts a callable ``llm_call`` matching Argus's LLMManager.call_llm_api()
  pattern (takes prompt string, returns response string)
- Returns dataclass-based results with ``to_dict()`` for JSON serialization
- Works alongside VulnerabilityChainer for hybrid static + AI chain detection

Toggle: enable_agent_chain_discovery (not yet wired into config_loader defaults)
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AttackStep:
    """A single step within a multi-step attack chain."""

    finding_id: str
    action: str
    enables: str


@dataclass
class AttackChain:
    """
    A multi-step attack path discovered by LLM analysis.

    Each chain links several security findings into an ordered exploitation
    sequence with an assessed severity, complexity, and final impact.
    """

    chain_id: str
    finding_ids: list[str]
    steps: list[AttackStep]
    severity: str  # critical / high / medium / low
    complexity: str  # trivial / low / medium / high
    impact: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return {
            "chain_id": self.chain_id,
            "finding_ids": self.finding_ids,
            "steps": [asdict(s) for s in self.steps],
            "severity": self.severity,
            "complexity": self.complexity,
            "impact": self.impact,
            "description": self.description,
        }


@dataclass
class CrossComponentRisk:
    """Risk arising from vulnerabilities spanning two application components."""

    component_a: str
    component_b: str
    findings_a: list[str]  # finding IDs
    findings_b: list[str]
    risk_type: str
    severity: str
    description: str


# ---------------------------------------------------------------------------
# AgentChainDiscovery
# ---------------------------------------------------------------------------


class AgentChainDiscovery:
    """LLM-powered vulnerability chain discovery.

    Uses a language model to reason about multi-step attack paths that
    combine discrete security findings from the same application.  This
    discovers chains that rule-based engines cannot anticipate because
    they depend on application-specific context and creative attacker
    thinking.

    Args:
        llm_call: Function that takes a prompt string and returns a
            response string, matching Argus's ``LLMManager.call_llm_api()``
            pattern.
        max_findings_per_batch: Upper limit on findings sent to the LLM
            in a single prompt.  Keeps token usage bounded.
    """

    def __init__(
        self,
        llm_call: Callable[[str], str],
        max_findings_per_batch: int = 30,
    ):
        self.llm_call = llm_call
        self.max_findings_per_batch = max_findings_per_batch

    # -- public API ---------------------------------------------------------

    def discover_chains(
        self,
        findings: list[dict],
        app_context: dict[str, Any] | None = None,
    ) -> list[AttackChain]:
        """Discover multi-step attack chains via LLM reasoning.

        Args:
            findings: Security findings, each a dict with at least
                ``id``, ``type``/``category``, ``severity``, ``file``/``path``,
                and ``description``/``message`` keys.
            app_context: Optional application metadata (e.g. framework,
                auth model, deployment info) to improve LLM reasoning.

        Returns:
            List of :class:`AttackChain` objects sorted by severity
            (critical first).
        """
        if not findings:
            logger.info("No findings provided for chain discovery")
            return []

        # Batch findings to stay within token limits
        batch = findings[: self.max_findings_per_batch]
        if len(findings) > self.max_findings_per_batch:
            logger.warning(
                "Truncating %d findings to batch limit of %d",
                len(findings),
                self.max_findings_per_batch,
            )

        prompt = self._build_discovery_prompt(batch, app_context)

        logger.info(
            "Sending %d findings to LLM for chain discovery", len(batch)
        )

        try:
            response = self.llm_call(prompt)
        except Exception:
            logger.exception("LLM call failed during chain discovery")
            return []

        chains = self._parse_chains(response)

        # Sort: critical > high > medium > low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        chains.sort(key=lambda c: severity_order.get(c.severity.lower(), 4))

        logger.info("LLM discovered %d attack chains", len(chains))
        return chains

    # -- prompt building ----------------------------------------------------

    def _build_discovery_prompt(
        self,
        findings: list[dict],
        app_context: dict[str, Any] | None,
    ) -> str:
        """Build a structured prompt for LLM chain discovery.

        Args:
            findings: Batch of finding dicts.
            app_context: Optional application metadata.

        Returns:
            Complete prompt string.
        """
        # Format findings into a readable list
        formatted_findings: list[str] = []
        for f in findings:
            fid = f.get("id", f.get("rule_id", "unknown"))
            ftype = f.get("type", f.get("category", f.get("check_id", "unknown")))
            severity = f.get("severity", "medium")
            filepath = f.get("file", f.get("path", "unknown"))
            description = f.get("description", f.get("message", ""))
            line = f.get("line", f.get("start_line", ""))
            line_info = f" (line {line})" if line else ""
            formatted_findings.append(
                f"- ID: {fid} | Type: {ftype} | Severity: {severity} "
                f"| File: {filepath}{line_info}\n  Description: {description}"
            )

        findings_block = "\n".join(formatted_findings)

        # Optional app context section
        context_section = ""
        if app_context:
            ctx_lines = [f"- {k}: {v}" for k, v in app_context.items()]
            context_section = (
                "\nApplication Context:\n" + "\n".join(ctx_lines) + "\n"
            )

        prompt = (
            "You are an expert penetration tester analyzing security findings "
            "from the same application.\n"
            "Identify multi-step attack chains that combine these findings.\n"
            "\n"
            "For each chain:\n"
            "1. List the finding IDs in exploitation order\n"
            "2. Describe each step and what it enables\n"
            "3. Rate the overall chain severity (critical/high/medium/low)\n"
            "4. Estimate attack complexity (trivial/low/medium/high)\n"
            "5. Describe the final impact\n"
            "\n"
            f"Findings:\n{findings_block}\n"
            f"{context_section}\n"
            "Return ONLY a JSON array of chain objects with keys: "
            "chain_id, finding_ids, steps (array of {finding_id, action, enables}), "
            "severity, complexity, impact, description"
        )
        return prompt

    # -- response parsing ---------------------------------------------------

    def _parse_chains(self, response: str) -> list[AttackChain]:
        """Parse LLM response into AttackChain objects.

        Handles:
        - Raw JSON arrays
        - JSON wrapped in markdown code blocks (```json ... ```)
        - Graceful fallback to empty list on parse failure

        Args:
            response: Raw LLM response string.

        Returns:
            List of validated :class:`AttackChain` objects.
        """
        if not response or not response.strip():
            logger.warning("Empty LLM response for chain discovery")
            return []

        # Strip markdown code fences if present
        cleaned = response.strip()
        code_block_match = re.search(
            r"```(?:json)?\s*\n?(.*?)```", cleaned, re.DOTALL
        )
        if code_block_match:
            cleaned = code_block_match.group(1).strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse LLM chain response as JSON: %s", exc)
            return []

        if not isinstance(data, list):
            logger.warning(
                "Expected JSON array from LLM, got %s", type(data).__name__
            )
            return []

        chains: list[AttackChain] = []
        for idx, item in enumerate(data):
            try:
                chain = self._validate_chain_item(item, idx)
                if chain is not None:
                    chains.append(chain)
            except Exception:
                logger.warning(
                    "Skipping invalid chain at index %d", idx, exc_info=True
                )

        return chains

    def _validate_chain_item(
        self, item: dict, idx: int
    ) -> Optional[AttackChain]:
        """Validate and convert a single chain dict to an AttackChain.

        Args:
            item: Raw chain dict from LLM JSON.
            idx: Index in the array (for fallback chain_id).

        Returns:
            :class:`AttackChain` or ``None`` if the item is invalid.
        """
        if not isinstance(item, dict):
            logger.warning("Chain item at index %d is not a dict", idx)
            return None

        # Required keys
        finding_ids = item.get("finding_ids")
        if not finding_ids or not isinstance(finding_ids, list):
            logger.warning("Chain at index %d missing valid finding_ids", idx)
            return None

        chain_id = item.get("chain_id", f"llm-chain-{idx}")

        # Parse steps
        raw_steps = item.get("steps", [])
        steps: list[AttackStep] = []
        for raw_step in raw_steps:
            if isinstance(raw_step, dict):
                steps.append(
                    AttackStep(
                        finding_id=str(raw_step.get("finding_id", "")),
                        action=str(raw_step.get("action", "")),
                        enables=str(raw_step.get("enables", "")),
                    )
                )

        severity = str(item.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"

        complexity = str(item.get("complexity", "medium")).lower()
        if complexity not in ("trivial", "low", "medium", "high"):
            complexity = "medium"

        return AttackChain(
            chain_id=str(chain_id),
            finding_ids=[str(fid) for fid in finding_ids],
            steps=steps,
            severity=severity,
            complexity=complexity,
            impact=str(item.get("impact", "")),
            description=str(item.get("description", "")),
        )


# ---------------------------------------------------------------------------
# CrossComponentAnalyzer
# ---------------------------------------------------------------------------


# Component directory patterns used for classification
_COMPONENT_DIRS: dict[str, list[str]] = {
    "api": ["api", "apis", "endpoints", "resources"],
    "auth": ["auth", "authentication", "authorization", "identity", "login"],
    "models": ["models", "entities", "schemas", "orm"],
    "views": ["views", "templates", "pages", "components", "ui"],
    "middleware": ["middleware", "middlewares", "interceptors", "filters"],
    "routes": ["routes", "routing", "urls", "router"],
    "services": ["services", "service", "providers", "adapters"],
    "utils": ["utils", "utilities", "helpers", "lib", "common"],
    "config": ["config", "configuration", "settings", "conf", "env"],
}

# Dangerous cross-component combinations
_DANGEROUS_PAIRS: list[dict[str, str]] = [
    {
        "a": "auth",
        "b": "api",
        "risk_type": "broken_access_control",
        "severity": "critical",
        "description": (
            "Authentication/authorization weaknesses combined with API "
            "vulnerabilities can lead to broken access control, allowing "
            "unauthenticated or low-privilege users to access protected "
            "endpoints and data."
        ),
    },
    {
        "a": "models",
        "b": "api",
        "risk_type": "mass_assignment",
        "severity": "high",
        "description": (
            "Model-layer vulnerabilities combined with API endpoint issues "
            "can enable mass assignment attacks where attackers modify "
            "protected fields (roles, permissions, balances) by including "
            "unexpected parameters in API requests."
        ),
    },
    {
        "a": "auth",
        "b": "config",
        "risk_type": "credential_exposure",
        "severity": "critical",
        "description": (
            "Authentication weaknesses combined with configuration issues "
            "can expose credentials, secrets, or tokens through insecure "
            "defaults, debug modes, or unprotected configuration files."
        ),
    },
    {
        "a": "middleware",
        "b": "routes",
        "risk_type": "security_bypass",
        "severity": "high",
        "description": (
            "Middleware vulnerabilities combined with routing issues can "
            "allow attackers to bypass security controls such as "
            "authentication checks, rate limiting, CSRF protection, or "
            "input validation by crafting requests that skip middleware "
            "processing."
        ),
    },
    {
        "a": "services",
        "b": "api",
        "risk_type": "ssrf_injection",
        "severity": "high",
        "description": (
            "Service-layer vulnerabilities combined with API issues can "
            "enable SSRF or injection attacks where user-controlled input "
            "reaches backend services, internal APIs, or external "
            "integrations without proper validation or sanitization."
        ),
    },
]


class CrossComponentAnalyzer:
    """Analyzes findings across application component boundaries.

    Groups findings by their originating component (classified by
    directory path) and checks for dangerous cross-component
    combinations that amplify risk.

    Args:
        project_path: Root path of the project under analysis.
    """

    def __init__(self, project_path: str):
        self.project_path = project_path

    # -- public API ---------------------------------------------------------

    def analyze(self, findings: list[dict]) -> list[dict]:
        """Analyze findings for dangerous cross-component combinations.

        Args:
            findings: Security findings, each with at least ``id`` and
                ``file``/``path`` keys.

        Returns:
            List of risk dicts, one per dangerous combination detected.
            Each dict contains ``component_a``, ``component_b``,
            ``risk_type``, ``severity``, ``description``,
            ``findings_a``, and ``findings_b``.
        """
        if not findings:
            return []

        # Group findings by component
        component_findings: dict[str, list[dict]] = defaultdict(list)
        for f in findings:
            filepath = f.get("file", f.get("path", ""))
            component = self._classify_component(filepath)
            component_findings[component].append(f)

        components = list(component_findings.keys())
        logger.info(
            "Cross-component analysis: %d findings across %d components (%s)",
            len(findings),
            len(components),
            ", ".join(sorted(components)),
        )

        # Check every pair for dangerous combinations
        risks: list[dict] = []
        for i, comp_a in enumerate(components):
            for comp_b in components[i + 1 :]:
                pair_risks = self._check_dangerous_combinations(
                    component_findings[comp_a],
                    component_findings[comp_b],
                    comp_a,
                    comp_b,
                )
                risks.extend(pair_risks)

        if risks:
            logger.info(
                "Found %d cross-component risks", len(risks)
            )
        else:
            logger.info("No dangerous cross-component combinations detected")

        return risks

    # -- component classification -------------------------------------------

    def _classify_component(self, file_path: str) -> str:
        """Map a file path to a component name based on directory names.

        Scans all path parts for known component directory names.  Falls
        back to ``"other"`` when no match is found.

        Args:
            file_path: Relative or absolute file path.

        Returns:
            Component name string (e.g. ``"api"``, ``"auth"``).
        """
        if not file_path:
            return "other"

        # Normalise to forward-slash parts and lowercase
        parts = Path(file_path).parts
        lower_parts = [p.lower() for p in parts]

        for component, dir_names in _COMPONENT_DIRS.items():
            for dir_name in dir_names:
                if dir_name in lower_parts:
                    return component

        return "other"

    # -- dangerous combination checks ---------------------------------------

    def _check_dangerous_combinations(
        self,
        comp_a_findings: list[dict],
        comp_b_findings: list[dict],
        comp_a: str,
        comp_b: str,
    ) -> list[dict]:
        """Check a component pair for predefined dangerous combinations.

        The check is order-independent: ``(auth, api)`` matches the same
        rule as ``(api, auth)``.

        Args:
            comp_a_findings: Findings from the first component.
            comp_b_findings: Findings from the second component.
            comp_a: Name of the first component.
            comp_b: Name of the second component.

        Returns:
            List of risk dicts with ``component_a``, ``component_b``,
            ``risk_type``, ``severity``, ``description``,
            ``findings_a``, and ``findings_b`` keys.
        """
        risks: list[dict] = []

        def _extract_ids(flist: list[dict]) -> list[str]:
            return [
                str(f.get("id", f.get("rule_id", "unknown")))
                for f in flist
            ]

        for pair in _DANGEROUS_PAIRS:
            pair_set = {pair["a"], pair["b"]}
            query_set = {comp_a, comp_b}

            if pair_set == query_set:
                # Determine which actual component maps to which pair role
                if comp_a == pair["a"]:
                    fa, fb = comp_a_findings, comp_b_findings
                    ca, cb = comp_a, comp_b
                else:
                    fa, fb = comp_b_findings, comp_a_findings
                    ca, cb = comp_b, comp_a

                risk = CrossComponentRisk(
                    component_a=ca,
                    component_b=cb,
                    findings_a=_extract_ids(fa),
                    findings_b=_extract_ids(fb),
                    risk_type=pair["risk_type"],
                    severity=pair["severity"],
                    description=pair["description"],
                )

                risks.append(asdict(risk))

        return risks


# ---------------------------------------------------------------------------
# __main__
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(
        "Argus Security - LLM-Powered Vulnerability Chain Discovery\n"
        "============================================================\n"
        "\n"
        "Usage (AgentChainDiscovery):\n"
        "\n"
        "    from agent_chain_discovery import AgentChainDiscovery\n"
        "\n"
        "    def my_llm_call(prompt: str) -> str:\n"
        '        """Wrapper around your LLM provider."""\n'
        "        return llm_manager.call_llm_api(prompt)\n"
        "\n"
        "    discoverer = AgentChainDiscovery(llm_call=my_llm_call)\n"
        "    chains = discoverer.discover_chains(findings, app_context={\n"
        '        "framework": "Django",\n'
        '        "auth_model": "session-based",\n'
        "    })\n"
        "\n"
        "    for chain in chains:\n"
        "        print(chain.to_dict())\n"
        "\n"
        "Usage (CrossComponentAnalyzer):\n"
        "\n"
        "    from agent_chain_discovery import CrossComponentAnalyzer\n"
        "\n"
        '    analyzer = CrossComponentAnalyzer(project_path="/path/to/project")\n'
        "    risks = analyzer.analyze(findings)\n"
        "\n"
        "    for risk in risks:\n"
        '        print(f"{risk[\'risk_type\']}: {risk[\'component_a\']} + {risk[\'component_b\']}")\n'
        "\n"
        "This module complements vulnerability_chaining_engine.py (14 static\n"
        "rules) with LLM-powered reasoning to discover novel attack paths\n"
        "that static rule sets cannot anticipate.\n"
    )
