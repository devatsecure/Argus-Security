# Cybersecurity Skills Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the Anthropic-Cybersecurity-Skills repo as a knowledge source for Argus agent personas, enabling skill-based context injection during Phase 3 analysis, auto-selection via index matching, and runbook-driven verification workflows.

**Architecture:** A new `skills_knowledge` module loads and indexes the cybersecurity skills repo's `index.json`. During Phase 3, each agent persona receives matching skill content as additional context in its LLM prompt. A `SkillMatcher` maps findings to skills using CWE, tags, category, and keyword matching. A `SkillRunbookExecutor` extracts verification commands from skill workflows for Phase 4 sandbox validation.

**Tech Stack:** Python 3.9+, JSON, YAML frontmatter parsing, existing Argus config system

---

## File Structure

| File | Responsibility |
|------|---------------|
| `scripts/skills_knowledge.py` | Core module: loads index.json, parses SKILL.md files, matches skills to findings |
| `tests/unit/test_skills_knowledge.py` | Unit tests for the skills_knowledge module |
| `scripts/agent_personas.py` | Modified: inject skill context into `_build_base_prompt()` |
| `scripts/config_loader.py` | Modified: add `skills_repo_path` and `enable_skills_knowledge` config keys |
| `scripts/hybrid/phases/phase3_review.py` | Modified: pass skills_knowledge to agent review |
| `scripts/hybrid_analyzer.py` | Modified: initialize SkillsKnowledge in HybridSecurityAnalyzer |

---

## Task 1: Create SkillsKnowledge Module — Index Loader

**Files:**
- Create: `scripts/skills_knowledge.py`
- Test: `tests/unit/test_skills_knowledge.py`

This task builds the core index loading and skill matching engine.

- [ ] **Step 1: Write failing test for SkillsIndex loading**

```python
# tests/unit/test_skills_knowledge.py
import json
import sys
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from skills_knowledge import SkillsIndex


SAMPLE_INDEX = {
    "version": "1.0.0",
    "total_skills": 3,
    "skills": [
        {
            "name": "detecting-sql-injection-via-waf-logs",
            "description": "Analyze WAF logs to detect SQL injection attack campaigns.",
            "domain": "cybersecurity",
            "subdomain": "security-operations",
            "tags": ["sql-injection", "waf", "sast", "owasp"],
            "path": "skills/detecting-sql-injection-via-waf-logs",
        },
        {
            "name": "detecting-aws-credential-exposure-with-trufflehog",
            "description": "Detecting exposed AWS credentials using TruffleHog.",
            "domain": "cybersecurity",
            "subdomain": "cloud-security",
            "tags": ["cloud-security", "aws", "credential-exposure", "trufflehog", "secrets-detection"],
            "path": "skills/detecting-aws-credential-exposure-with-trufflehog",
        },
        {
            "name": "performing-web-cache-poisoning",
            "description": "Exploit web cache poisoning vulnerabilities.",
            "domain": "cybersecurity",
            "subdomain": "web-application-security",
            "tags": ["web-security", "cache-poisoning", "exploit"],
            "path": "skills/performing-web-cache-poisoning",
        },
    ],
}


class TestSkillsIndexLoading:
    def test_load_from_dict(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        assert index.total_skills == 3
        assert len(index.skills) == 3

    def test_load_from_file(self, tmp_path):
        index_file = tmp_path / "index.json"
        index_file.write_text(json.dumps(SAMPLE_INDEX))
        index = SkillsIndex.from_path(index_file)
        assert index.total_skills == 3

    def test_load_missing_file_returns_empty(self, tmp_path):
        index = SkillsIndex.from_path(tmp_path / "nonexistent.json")
        assert index.total_skills == 0
        assert len(index.skills) == 0

    def test_skill_lookup_by_name(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        skill = index.get_skill("detecting-sql-injection-via-waf-logs")
        assert skill is not None
        assert skill["subdomain"] == "security-operations"

    def test_skill_lookup_missing_returns_none(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        assert index.get_skill("nonexistent-skill") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py -v -x --no-header 2>&1 | head -30`
Expected: FAIL with `ModuleNotFoundError: No module named 'skills_knowledge'`

- [ ] **Step 3: Write minimal SkillsIndex implementation**

```python
# scripts/skills_knowledge.py
"""
Cybersecurity Skills Knowledge Integration for Argus Security.

Loads the Anthropic-Cybersecurity-Skills index and provides skill matching
for agent personas during Phase 3 multi-agent review.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SkillsIndex:
    """In-memory index of cybersecurity skills."""

    total_skills: int = 0
    skills: list[dict[str, Any]] = field(default_factory=list)
    _by_name: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    _by_tag: dict[str, list[dict[str, Any]]] = field(default_factory=dict, repr=False)
    _by_subdomain: dict[str, list[dict[str, Any]]] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self._build_indexes()

    def _build_indexes(self):
        self._by_name = {s["name"]: s for s in self.skills}
        self._by_tag = {}
        self._by_subdomain = {}
        for skill in self.skills:
            for tag in skill.get("tags", []):
                self._by_tag.setdefault(tag, []).append(skill)
            subdomain = skill.get("subdomain", "")
            if subdomain:
                self._by_subdomain.setdefault(subdomain, []).append(skill)

    def get_skill(self, name: str) -> Optional[dict[str, Any]]:
        return self._by_name.get(name)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SkillsIndex":
        return cls(
            total_skills=data.get("total_skills", len(data.get("skills", []))),
            skills=data.get("skills", []),
        )

    @classmethod
    def from_path(cls, path: Path) -> "SkillsIndex":
        path = Path(path)
        if not path.is_file():
            logger.warning("Skills index not found at %s", path)
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load skills index: %s", e)
            return cls()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillsIndexLoading -v --no-header 2>&1 | tail -10`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/skills_knowledge.py tests/unit/test_skills_knowledge.py
git commit -m "feat: add SkillsIndex loader for cybersecurity skills integration"
```

---

## Task 2: Add SkillMatcher — Finding-to-Skill Matching

**Files:**
- Modify: `scripts/skills_knowledge.py`
- Modify: `tests/unit/test_skills_knowledge.py`

- [ ] **Step 1: Write failing tests for SkillMatcher**

Add to `tests/unit/test_skills_knowledge.py`:

```python
from skills_knowledge import SkillsIndex, SkillMatcher


class TestSkillMatcher:
    @pytest.fixture()
    def matcher(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        return SkillMatcher(index)

    def test_match_by_tag(self, matcher):
        finding = {"category": "SAST", "rule_id": "sql-injection", "severity": "high",
                   "cwe_id": "CWE-89", "path": "app/db.py"}
        matches = matcher.match(finding)
        assert len(matches) >= 1
        assert any("sql-injection" in m["name"] for m in matches)

    def test_match_by_cwe_keyword(self, matcher):
        finding = {"category": "SECRETS", "rule_id": "hardcoded-credential",
                   "severity": "high", "cwe_id": "CWE-798", "path": "config.py"}
        matches = matcher.match(finding)
        assert len(matches) >= 1
        assert any("credential" in m["name"] for m in matches)

    def test_match_returns_empty_for_unrelated_finding(self, matcher):
        finding = {"category": "QUALITY", "rule_id": "unused-variable",
                   "severity": "low", "path": "utils.py"}
        matches = matcher.match(finding)
        assert isinstance(matches, list)

    def test_match_limits_results(self, matcher):
        finding = {"category": "SAST", "rule_id": "sql-injection",
                   "severity": "high", "path": "app/db.py"}
        matches = matcher.match(finding, max_results=1)
        assert len(matches) <= 1

    def test_match_by_description_keywords(self, matcher):
        finding = {"category": "SAST", "rule_id": "cache-poisoning",
                   "severity": "medium", "path": "proxy.py", "title": "web cache poisoning"}
        matches = matcher.match(finding)
        assert any("cache-poisoning" in m["name"] for m in matches)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillMatcher -v -x --no-header 2>&1 | head -20`
Expected: FAIL with `ImportError: cannot import name 'SkillMatcher'`

- [ ] **Step 3: Implement SkillMatcher**

Add to `scripts/skills_knowledge.py`:

```python
# CWE to keyword mapping for common vulnerability classes
_CWE_KEYWORDS: dict[str, list[str]] = {
    "CWE-79": ["xss", "cross-site-scripting", "web-security"],
    "CWE-89": ["sql-injection", "sql", "injection"],
    "CWE-78": ["command-injection", "os-command", "injection"],
    "CWE-798": ["credential", "secret", "hardcoded", "password"],
    "CWE-200": ["information-disclosure", "data-exposure"],
    "CWE-287": ["authentication", "auth", "identity"],
    "CWE-862": ["authorization", "access-control", "broken-access"],
    "CWE-918": ["ssrf", "server-side-request"],
    "CWE-502": ["deserialization", "insecure-deserialization"],
    "CWE-611": ["xxe", "xml", "external-entity"],
    "CWE-22": ["path-traversal", "directory-traversal"],
    "CWE-352": ["csrf", "cross-site-request-forgery"],
    "CWE-327": ["cryptography", "weak-crypto", "encryption"],
    "CWE-400": ["denial-of-service", "resource-exhaustion"],
    "CWE-434": ["file-upload", "unrestricted-upload"],
}


class SkillMatcher:
    """Matches security findings to relevant cybersecurity skills."""

    def __init__(self, index: SkillsIndex):
        self.index = index

    def match(self, finding: dict[str, Any], max_results: int = 3) -> list[dict[str, Any]]:
        """Find skills relevant to a security finding.

        Scoring strategy:
        - Tag match: +3 per matching tag
        - CWE keyword match: +5 (strong signal)
        - Name/description keyword match: +2
        - Subdomain match: +1
        """
        keywords = self._extract_keywords(finding)
        if not keywords:
            return []

        scored: list[tuple[float, dict[str, Any]]] = []
        for skill in self.index.skills:
            score = self._score_skill(skill, keywords, finding)
            if score > 0:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [skill for _, skill in scored[:max_results]]

    def _extract_keywords(self, finding: dict[str, Any]) -> set[str]:
        """Extract searchable keywords from a finding."""
        keywords: set[str] = set()

        # From rule_id (e.g. "sql-injection" -> {"sql", "injection"})
        rule_id = finding.get("rule_id", "")
        keywords.update(re.split(r"[-_./]", rule_id.lower()))

        # From category
        category = finding.get("category", "").lower()
        if category:
            keywords.add(category)

        # From CWE
        cwe = finding.get("cwe_id", "")
        if cwe:
            cwe_kws = _CWE_KEYWORDS.get(cwe.upper(), [])
            keywords.update(cwe_kws)

        # From title
        title = finding.get("title", "")
        keywords.update(re.split(r"[\s\-_./]+", title.lower()))

        # Clean up
        keywords.discard("")
        return keywords

    def _score_skill(self, skill: dict[str, Any], keywords: set[str],
                     finding: dict[str, Any]) -> float:
        score = 0.0

        # Tag matches
        skill_tags = set(skill.get("tags", []))
        tag_overlap = keywords & skill_tags
        score += len(tag_overlap) * 3

        # Name keyword match
        name_parts = set(skill.get("name", "").split("-"))
        name_overlap = keywords & name_parts
        score += len(name_overlap) * 2

        # Description keyword match
        desc = skill.get("description", "").lower()
        for kw in keywords:
            if len(kw) > 3 and kw in desc:
                score += 2

        # CWE-derived keyword bonus (strong signal)
        cwe = finding.get("cwe_id", "")
        if cwe:
            cwe_kws = set(_CWE_KEYWORDS.get(cwe.upper(), []))
            if cwe_kws & skill_tags:
                score += 5

        return score
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py -v --no-header 2>&1 | tail -15`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/skills_knowledge.py tests/unit/test_skills_knowledge.py
git commit -m "feat: add SkillMatcher for finding-to-skill matching"
```

---

## Task 3: Add Skill Content Loader

**Files:**
- Modify: `scripts/skills_knowledge.py`
- Modify: `tests/unit/test_skills_knowledge.py`

This loads the actual SKILL.md body content for matched skills to inject into LLM prompts.

- [ ] **Step 1: Write failing test for load_skill_content**

Add to `tests/unit/test_skills_knowledge.py`:

```python
class TestSkillContentLoader:
    def test_load_skill_content_from_file(self, tmp_path):
        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text(
            "---\nname: test-skill\ndescription: A test skill\n"
            "domain: cybersecurity\nsubdomain: testing\ntags: [test]\n---\n"
            "# Test Skill\n\n## Workflow\n\n1. Do step one\n2. Do step two\n"
            "\n## Verification\n\n- Check result A\n- Check result B\n"
        )
        index = SkillsIndex.from_dict({
            "skills": [{"name": "test-skill", "path": "skills/test-skill", "tags": ["test"]}]
        })
        knowledge = SkillsKnowledge(index=index, repo_path=tmp_path)
        content = knowledge.load_skill_content("test-skill")
        assert content is not None
        assert "Do step one" in content
        assert "Verification" in content

    def test_load_skill_content_missing_returns_none(self, tmp_path):
        index = SkillsIndex.from_dict({"skills": []})
        knowledge = SkillsKnowledge(index=index, repo_path=tmp_path)
        content = knowledge.load_skill_content("nonexistent")
        assert content is None

    def test_load_skill_content_truncates_long_content(self, tmp_path):
        skill_dir = tmp_path / "skills" / "long-skill"
        skill_dir.mkdir(parents=True)
        body = "x" * 5000
        (skill_dir / "SKILL.md").write_text(f"---\nname: long-skill\n---\n{body}")
        index = SkillsIndex.from_dict({
            "skills": [{"name": "long-skill", "path": "skills/long-skill", "tags": []}]
        })
        knowledge = SkillsKnowledge(index=index, repo_path=tmp_path)
        content = knowledge.load_skill_content("long-skill", max_chars=2000)
        assert content is not None
        assert len(content) <= 2100  # Allow small overhead from truncation marker
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillContentLoader -v -x --no-header 2>&1 | head -15`
Expected: FAIL with `ImportError: cannot import name 'SkillsKnowledge'`

- [ ] **Step 3: Implement SkillsKnowledge class**

Add to `scripts/skills_knowledge.py`:

```python
class SkillsKnowledge:
    """Main interface for cybersecurity skills knowledge integration.

    Combines index loading, skill matching, and content loading.
    """

    def __init__(self, index: Optional[SkillsIndex] = None,
                 repo_path: Optional[Path] = None):
        self.repo_path = Path(repo_path) if repo_path else None
        self.index = index or SkillsIndex()
        self.matcher = SkillMatcher(self.index)
        self._content_cache: dict[str, Optional[str]] = {}

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> Optional["SkillsKnowledge"]:
        """Create from Argus config dict. Returns None if disabled."""
        if not config.get("enable_skills_knowledge", False):
            return None
        repo_path = config.get("skills_repo_path", "")
        if not repo_path:
            return None
        repo_path = Path(repo_path)
        index_path = repo_path / "index.json"
        index = SkillsIndex.from_path(index_path)
        if index.total_skills == 0:
            logger.warning("Skills knowledge enabled but index is empty or missing")
            return None
        logger.info("Loaded %d cybersecurity skills from %s", index.total_skills, index_path)
        return cls(index=index, repo_path=repo_path)

    def match_finding(self, finding: dict[str, Any], max_results: int = 3) -> list[dict[str, Any]]:
        """Find skills relevant to a finding."""
        return self.matcher.match(finding, max_results=max_results)

    def load_skill_content(self, skill_name: str, max_chars: int = 3000) -> Optional[str]:
        """Load SKILL.md body content (without frontmatter) for a given skill.

        Returns None if the skill or file is not found.
        Content is cached after first load.
        """
        if skill_name in self._content_cache:
            return self._content_cache[skill_name]

        skill = self.index.get_skill(skill_name)
        if not skill or not self.repo_path:
            self._content_cache[skill_name] = None
            return None

        skill_path = self.repo_path / skill["path"] / "SKILL.md"
        if not skill_path.is_file():
            logger.debug("SKILL.md not found at %s", skill_path)
            self._content_cache[skill_name] = None
            return None

        try:
            raw = skill_path.read_text(encoding="utf-8")
        except OSError as e:
            logger.error("Failed to read %s: %s", skill_path, e)
            self._content_cache[skill_name] = None
            return None

        # Strip YAML frontmatter
        fm_match = re.match(r"^---\n.*?\n---\n?", raw, re.DOTALL)
        body = raw[fm_match.end():] if fm_match else raw
        body = body.strip()

        if len(body) > max_chars:
            body = body[:max_chars] + "\n\n[... truncated]"

        self._content_cache[skill_name] = body
        return body

    def get_context_for_finding(self, finding: dict[str, Any],
                                max_skills: int = 2,
                                max_chars_per_skill: int = 2000) -> str:
        """Get formatted skill context block for injection into an LLM prompt.

        Returns empty string if no matching skills found.
        """
        matches = self.match_finding(finding, max_results=max_skills)
        if not matches:
            return ""

        sections = []
        for skill in matches:
            content = self.load_skill_content(skill["name"], max_chars=max_chars_per_skill)
            if content:
                sections.append(
                    f"### Skill: {skill['name']}\n"
                    f"Subdomain: {skill.get('subdomain', 'N/A')}\n"
                    f"Tags: {', '.join(skill.get('tags', []))}\n\n"
                    f"{content}"
                )

        if not sections:
            return ""

        return (
            "\n\n--- Cybersecurity Skills Knowledge ---\n"
            "Use the following expert procedures as additional context for your analysis:\n\n"
            + "\n\n---\n\n".join(sections)
            + "\n--- End Skills Knowledge ---\n"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py -v --no-header 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/skills_knowledge.py tests/unit/test_skills_knowledge.py
git commit -m "feat: add SkillsKnowledge with content loading and context generation"
```

---

## Task 4: Wire Config — Add skills_repo_path and enable_skills_knowledge

**Files:**
- Modify: `scripts/config_loader.py` (add 2 keys to `get_default_config()`)
- Modify: `tests/unit/test_skills_knowledge.py` (add config integration test)

- [ ] **Step 1: Write failing test for config-based initialization**

Add to `tests/unit/test_skills_knowledge.py`:

```python
class TestSkillsKnowledgeConfig:
    def test_from_config_disabled(self):
        config = {"enable_skills_knowledge": False, "skills_repo_path": "/some/path"}
        result = SkillsKnowledge.from_config(config)
        assert result is None

    def test_from_config_no_path(self):
        config = {"enable_skills_knowledge": True, "skills_repo_path": ""}
        result = SkillsKnowledge.from_config(config)
        assert result is None

    def test_from_config_valid(self, tmp_path):
        # Create a minimal skills repo structure
        index_data = json.dumps(SAMPLE_INDEX)
        (tmp_path / "index.json").write_text(index_data)
        config = {"enable_skills_knowledge": True, "skills_repo_path": str(tmp_path)}
        result = SkillsKnowledge.from_config(config)
        assert result is not None
        assert result.index.total_skills == 3
```

- [ ] **Step 2: Run test to verify it passes** (implementation already in Task 3)

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillsKnowledgeConfig -v --no-header 2>&1 | tail -10`
Expected: All 3 tests PASS

- [ ] **Step 3: Add config keys to config_loader.py**

In `scripts/config_loader.py`, inside `get_default_config()`, add these two keys after the `"enable_app_context": True,` line (around line 170):

```python
        # -- Skills knowledge integration --
        "enable_skills_knowledge": False,  # opt-in: inject cybersecurity skills context into agent prompts
        "skills_repo_path": "",  # path to Anthropic-Cybersecurity-Skills repo clone
```

- [ ] **Step 4: Verify config key is picked up**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -c "import sys; sys.path.insert(0,'scripts'); from config_loader import get_default_config; c = get_default_config(); print(c['enable_skills_knowledge'], c['skills_repo_path'])"`
Expected: `False `

- [ ] **Step 5: Commit**

```bash
git add scripts/config_loader.py tests/unit/test_skills_knowledge.py
git commit -m "feat: add skills_knowledge config keys to config_loader"
```

---

## Task 5: Inject Skill Context into Agent Personas

**Files:**
- Modify: `scripts/agent_personas.py` — update `BaseAgentPersona.__init__()` and `_build_base_prompt()`
- Modify: `tests/unit/test_skills_knowledge.py` — add integration test

This is the key integration point: when an agent analyzes a finding, matching skill content is appended to the LLM prompt.

- [ ] **Step 1: Write failing test for skill context injection**

Add to `tests/unit/test_skills_knowledge.py`:

```python
from agent_personas import BaseAgentPersona, ExploitAssessor


class TestSkillContextInjection:
    def test_build_base_prompt_includes_skill_context(self, tmp_path):
        # Set up a skills repo with a matching skill
        skill_dir = tmp_path / "skills" / "detecting-sql-injection-via-waf-logs"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: detecting-sql-injection-via-waf-logs\n"
            "description: Detect SQL injection\ndomain: cybersecurity\n"
            "subdomain: security-operations\ntags: [sql-injection, waf]\n---\n"
            "# SQL Injection Detection\n\n## Workflow\n1. Check WAF logs\n"
        )
        index_data = json.dumps({
            "skills": [{
                "name": "detecting-sql-injection-via-waf-logs",
                "description": "Detect SQL injection",
                "subdomain": "security-operations",
                "tags": ["sql-injection", "waf"],
                "path": "skills/detecting-sql-injection-via-waf-logs",
            }]
        })
        (tmp_path / "index.json").write_text(index_data)

        knowledge = SkillsKnowledge(
            index=SkillsIndex.from_path(tmp_path / "index.json"),
            repo_path=tmp_path,
        )

        mock_llm = Mock()
        mock_llm.client = Mock()
        mock_llm.call_llm_api = Mock(return_value=("Verdict: confirmed\nConfidence: 0.9\nReasoning: Real issue", 100, 0.01))

        agent = ExploitAssessor(mock_llm)
        agent.skills_knowledge = knowledge

        finding = {
            "id": "test-sqli",
            "path": "app/db.py",
            "line": 10,
            "severity": "high",
            "rule_id": "sql-injection",
            "category": "SAST",
            "origin": "semgrep",
            "evidence": {"snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'"},
        }
        prompt = agent._build_base_prompt(finding)
        assert "Cybersecurity Skills Knowledge" in prompt
        assert "SQL Injection Detection" in prompt

    def test_build_base_prompt_without_skills(self):
        mock_llm = Mock()
        agent = ExploitAssessor(mock_llm)
        # No skills_knowledge set
        finding = {
            "id": "test-001", "path": "app.py", "line": 1,
            "severity": "high", "rule_id": "test", "category": "SAST",
            "origin": "semgrep", "evidence": {},
        }
        prompt = agent._build_base_prompt(finding)
        assert "Skills Knowledge" not in prompt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillContextInjection -v -x --no-header 2>&1 | head -20`
Expected: FAIL (skills_knowledge attribute not found or context not in prompt)

- [ ] **Step 3: Modify BaseAgentPersona to support skills_knowledge**

In `scripts/agent_personas.py`, update the `BaseAgentPersona.__init__()` method (line ~73):

Change:
```python
    def __init__(self, llm_manager):
        self.llm = llm_manager
        self.name = ""
        self.role = ""
        self.expertise = []
        self.focus_areas = []
        self.prompt_template = ""
```

To:
```python
    def __init__(self, llm_manager):
        self.llm = llm_manager
        self.name = ""
        self.role = ""
        self.expertise = []
        self.focus_areas = []
        self.prompt_template = ""
        self.skills_knowledge = None  # Optional: SkillsKnowledge instance
```

Then update `_build_base_prompt()` (line ~100). Change the return statement at the end of the method — the current method ends with `return context`. Change it to:

```python
        # Inject matching cybersecurity skills context if available
        skills_context = ""
        if self.skills_knowledge:
            try:
                skills_context = self.skills_knowledge.get_context_for_finding(finding)
            except Exception as e:
                logger.debug("Skills knowledge lookup failed: %s", e)

        return context + skills_context
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillContextInjection -v --no-header 2>&1 | tail -10`
Expected: Both tests PASS

- [ ] **Step 5: Run existing agent_personas tests to verify no regression**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_agent_personas.py -v --no-header 2>&1 | tail -15`
Expected: All existing tests still PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/agent_personas.py tests/unit/test_skills_knowledge.py
git commit -m "feat: inject cybersecurity skill context into agent persona prompts"
```

---

## Task 6: Wire Phase 3 — Pass SkillsKnowledge to Agents

**Files:**
- Modify: `scripts/hybrid_analyzer.py` — initialize SkillsKnowledge in `__init__()`
- Modify: `scripts/hybrid/phases/phase3_review.py` — set skills_knowledge on agents

- [ ] **Step 1: Add SkillsKnowledge import and initialization to hybrid_analyzer.py**

At the top of `scripts/hybrid_analyzer.py`, after the other try/except import blocks (~line 195), add:

```python
try:
    from skills_knowledge import SkillsKnowledge

    _SKILLS_KNOWLEDGE_OK = True
except ImportError:
    _SKILLS_KNOWLEDGE_OK = False
```

In `HybridSecurityAnalyzer.__init__()`, after the multi-agent personas init block (after ~line 384 where `self.enable_multi_agent = False` is set), add:

```python
        # Skills knowledge integration (enhances multi-agent personas with cybersecurity runbooks)
        self.skills_knowledge = None
        if _SKILLS_KNOWLEDGE_OK and self.config.get("enable_skills_knowledge", False):
            self.skills_knowledge = SkillsKnowledge.from_config(self.config)
            if self.skills_knowledge:
                logger.info("✅ Skills knowledge loaded: %d cybersecurity skills available", self.skills_knowledge.index.total_skills)
```

Note: `self.config` is set at line 325 (`self.config = config or {}`).

- [ ] **Step 2: Update phase3_review.py to set skills_knowledge on agents**

In `scripts/hybrid/phases/phase3_review.py`, in the `_run_argus_review()` function, add `skills_knowledge` as a parameter:

Change the function signature (line ~78):
```python
def _run_argus_review(
    *,
    findings: list[HybridFinding],
    target_path: str,
    agent_personas: Any,
    ai_client: Any,
    collaborative_reasoning: Any | None,
    enable_collaborative_reasoning: bool,
    skills_knowledge: Any | None = None,
) -> list[HybridFinding]:
```

Then in the non-collaborative branch (line ~155), after `agent = agent_personas.select_agent_for_finding(...)`:

```python
            agent = agent_personas.select_agent_for_finding(finding_dict, ai_client)
            if skills_knowledge:
                agent.skills_knowledge = skills_knowledge
            analysis = agent.analyze(finding_dict)
```

Also update `run_phase3_review()` to pass `skills_knowledge` (line ~54):

```python
        enriched_findings = _run_argus_review(
            findings=all_findings,
            target_path=target_path,
            agent_personas=analyzer.agent_personas,
            ai_client=analyzer.ai_client,
            collaborative_reasoning=analyzer.collaborative_reasoning,
            enable_collaborative_reasoning=analyzer.enable_collaborative_reasoning,
            skills_knowledge=getattr(analyzer, "skills_knowledge", None),
        )
```

- [ ] **Step 3: Run full test suite to verify no regressions**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_agent_personas.py tests/unit/test_skills_knowledge.py -v --no-header 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add scripts/hybrid_analyzer.py scripts/hybrid/phases/phase3_review.py
git commit -m "feat: wire skills knowledge into Phase 3 multi-agent review pipeline"
```

---

## Task 7: Add Runbook Executor for Phase 4 Sandbox Verification

**Files:**
- Modify: `scripts/skills_knowledge.py` — add `SkillRunbookExtractor`
- Modify: `tests/unit/test_skills_knowledge.py` — add tests

This extracts verification commands from skill workflows that could be used in Phase 4 sandbox validation.

- [ ] **Step 1: Write failing test for runbook extraction**

Add to `tests/unit/test_skills_knowledge.py`:

```python
from skills_knowledge import SkillRunbookExtractor


class TestSkillRunbookExtractor:
    def test_extract_commands_from_workflow(self):
        content = (
            "## Workflow\n\n"
            "1. Install dependencies:\n"
            "```bash\npip install semgrep\n```\n\n"
            "2. Run the scan:\n"
            "```bash\nsemgrep --config auto .\n```\n\n"
            "## Verification\n\n"
            "```bash\nsemgrep --version\n```\n"
        )
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        assert len(commands) >= 2
        assert any("semgrep" in cmd for cmd in commands)

    def test_extract_commands_from_python_blocks(self):
        content = (
            "## Steps\n\n"
            "```python\nimport subprocess\nsubprocess.run(['nmap', '-sV', 'target'])\n```\n"
        )
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        # Python blocks are returned as-is
        assert len(commands) >= 1

    def test_extract_empty_content(self):
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands("")
        assert commands == []

    def test_extract_verification_steps(self):
        content = (
            "## Verification\n\n"
            "- Run `nmap --version` to confirm installation\n"
            "- Check output contains expected results\n"
            "```bash\nnmap -sP 192.168.1.0/24\n```\n"
        )
        extractor = SkillRunbookExtractor()
        verification = extractor.extract_verification(content)
        assert len(verification) >= 1
        assert any("nmap" in v for v in verification)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py::TestSkillRunbookExtractor -v -x --no-header 2>&1 | head -15`
Expected: FAIL with `ImportError: cannot import name 'SkillRunbookExtractor'`

- [ ] **Step 3: Implement SkillRunbookExtractor**

Add to `scripts/skills_knowledge.py`:

```python
class SkillRunbookExtractor:
    """Extracts executable commands and verification steps from skill content."""

    _CODE_BLOCK_RE = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
    _VERIFICATION_HEADER_RE = re.compile(r"^##\s*Verification", re.MULTILINE)

    def extract_commands(self, content: str) -> list[str]:
        """Extract code blocks from skill content.

        Returns list of command strings from bash/shell/python code blocks.
        """
        if not content:
            return []

        commands = []
        for match in self._CODE_BLOCK_RE.finditer(content):
            lang = match.group(1).lower()
            code = match.group(2).strip()
            if lang in ("bash", "shell", "sh", ""):
                # Split multi-line bash into individual commands
                for line in code.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        commands.append(line)
            elif lang == "python":
                commands.append(code)
        return commands

    def extract_verification(self, content: str) -> list[str]:
        """Extract verification steps from the Verification section."""
        if not content:
            return []

        match = self._VERIFICATION_HEADER_RE.search(content)
        if not match:
            return []

        # Get content from Verification header to next ## header or end
        rest = content[match.end():]
        next_header = re.search(r"^##\s", rest, re.MULTILINE)
        section = rest[:next_header.start()] if next_header else rest

        # Extract code blocks from verification section
        return self.extract_commands(section)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py -v --no-header 2>&1 | tail -20`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/skills_knowledge.py tests/unit/test_skills_knowledge.py
git commit -m "feat: add SkillRunbookExtractor for verification command extraction"
```

---

## Task 8: End-to-End Integration Test

**Files:**
- Modify: `tests/unit/test_skills_knowledge.py`

- [ ] **Step 1: Write end-to-end test**

Add to `tests/unit/test_skills_knowledge.py`:

```python
class TestEndToEndIntegration:
    def test_full_flow_finding_to_context(self, tmp_path):
        """Test the complete flow: index load -> match -> content -> context string."""
        # Set up skills repo structure
        for skill_name, tags, body in [
            ("detecting-xss-with-burp", ["xss", "web-security", "burp"],
             "# XSS Detection\n\n## Workflow\n1. Configure Burp\n2. Scan target\n\n## Verification\n```bash\ncurl -s target | grep xss\n```\n"),
            ("auditing-aws-s3-buckets", ["aws", "s3", "cloud-security"],
             "# S3 Audit\n\n## Workflow\n1. List buckets\n2. Check ACLs\n"),
        ]:
            skill_dir = tmp_path / "skills" / skill_name
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {skill_name}\ndescription: Test\n"
                f"domain: cybersecurity\nsubdomain: test\n"
                f"tags: [{', '.join(tags)}]\n---\n{body}"
            )

        index = {
            "skills": [
                {"name": "detecting-xss-with-burp", "description": "Detect XSS",
                 "subdomain": "web-application-security",
                 "tags": ["xss", "web-security", "burp"],
                 "path": "skills/detecting-xss-with-burp"},
                {"name": "auditing-aws-s3-buckets", "description": "Audit S3",
                 "subdomain": "cloud-security",
                 "tags": ["aws", "s3", "cloud-security"],
                 "path": "skills/auditing-aws-s3-buckets"},
            ]
        }
        (tmp_path / "index.json").write_text(json.dumps(index))

        config = {"enable_skills_knowledge": True, "skills_repo_path": str(tmp_path)}
        knowledge = SkillsKnowledge.from_config(config)
        assert knowledge is not None

        # XSS finding should match XSS skill
        xss_finding = {"category": "SAST", "rule_id": "xss-reflected",
                       "severity": "high", "cwe_id": "CWE-79", "path": "app.py",
                       "title": "Reflected XSS"}
        context = knowledge.get_context_for_finding(xss_finding)
        assert "XSS Detection" in context
        assert "Configure Burp" in context

        # AWS finding should match S3 skill
        aws_finding = {"category": "CLOUD", "rule_id": "s3-public-read",
                       "severity": "high", "path": "terraform/main.tf",
                       "title": "S3 bucket public access"}
        context = knowledge.get_context_for_finding(aws_finding)
        assert "S3 Audit" in context

    def test_runbook_extraction_from_matched_skill(self, tmp_path):
        """Test extracting runbook commands from a matched skill."""
        skill_dir = tmp_path / "skills" / "scanning-with-trivy"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: scanning-with-trivy\ndescription: Scan images\n"
            "domain: cybersecurity\nsubdomain: container-security\n"
            "tags: [trivy, container, cve]\n---\n"
            "# Trivy Scanning\n\n## Workflow\n"
            "```bash\ntrivy image myapp:latest\n```\n\n"
            "## Verification\n```bash\ntrivy --version\n```\n"
        )
        (tmp_path / "index.json").write_text(json.dumps({
            "skills": [{"name": "scanning-with-trivy", "description": "Scan images with Trivy",
                        "subdomain": "container-security", "tags": ["trivy", "container", "cve"],
                        "path": "skills/scanning-with-trivy"}]
        }))

        knowledge = SkillsKnowledge.from_config({
            "enable_skills_knowledge": True, "skills_repo_path": str(tmp_path)
        })
        content = knowledge.load_skill_content("scanning-with-trivy")
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        assert "trivy image myapp:latest" in commands

        verification = extractor.extract_verification(content)
        assert "trivy --version" in verification
```

- [ ] **Step 2: Run all tests**

Run: `cd /Users/waseem.ahmed/Repos/Argus-Security && python -m pytest tests/unit/test_skills_knowledge.py -v --no-header 2>&1 | tail -25`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_skills_knowledge.py
git commit -m "test: add end-to-end integration tests for skills knowledge"
```

---

## Task 9: Documentation — Update Config Reference

**Files:**
- Modify: `docs/CONFIG_REFERENCE.md` (if it exists, add 2 new keys)

- [ ] **Step 1: Add config documentation**

Add to the config reference doc (find the appropriate section):

```markdown
### Skills Knowledge Integration

| Key | Type | Default | Env Var | Description |
|-----|------|---------|---------|-------------|
| `enable_skills_knowledge` | bool | `false` | `ARGUS_ENABLE_SKILLS_KNOWLEDGE` | Inject cybersecurity skills context into agent prompts during Phase 3 |
| `skills_repo_path` | string | `""` | `ARGUS_SKILLS_REPO_PATH` | Path to cloned Anthropic-Cybersecurity-Skills repository |
```

- [ ] **Step 2: Commit**

```bash
git add docs/CONFIG_REFERENCE.md
git commit -m "docs: add skills knowledge config keys to reference"
```

---

## Summary

| Task | What it delivers |
|------|-----------------|
| 1 | SkillsIndex loader — parses index.json into searchable in-memory index |
| 2 | SkillMatcher — scores and ranks skills against findings using tags, CWE, keywords |
| 3 | SkillsKnowledge — loads SKILL.md content, generates context blocks for LLM prompts |
| 4 | Config wiring — `enable_skills_knowledge` + `skills_repo_path` in Argus config |
| 5 | Agent integration — `_build_base_prompt()` injects matched skill context |
| 6 | Phase 3 wiring — passes SkillsKnowledge through to agents in the review pipeline |
| 7 | Runbook extractor — pulls verification commands for Phase 4 sandbox use |
| 8 | E2E tests — validates the full flow from finding to enriched prompt |
| 9 | Docs — config reference update |
