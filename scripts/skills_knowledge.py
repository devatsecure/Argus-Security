"""
Cybersecurity Skills Knowledge Integration for Argus Security.

Loads the Anthropic-Cybersecurity-Skills index and provides skill matching
for agent personas during Phase 3 multi-agent review.

Usage:
    from skills_knowledge import SkillsKnowledge
    knowledge = SkillsKnowledge.from_config(config)
    context = knowledge.get_context_for_finding(finding)
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

    def get_by_tag(self, tag: str) -> list[dict[str, Any]]:
        return self._by_tag.get(tag, [])

    def get_by_subdomain(self, subdomain: str) -> list[dict[str, Any]]:
        return self._by_subdomain.get(subdomain, [])

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


# ---------------------------------------------------------------------------
# CWE to keyword mapping for common vulnerability classes
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Skill content loader and context generator
# ---------------------------------------------------------------------------


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

    # Common names for the cybersecurity skills repo directory
    _REPO_DIR_NAMES = [
        "Anthropic-Cybersecurity-Skills",
        "anthropic-cybersecurity-skills",
        "cybersecurity-skills",
    ]

    @classmethod
    def _auto_discover_repo(cls) -> Optional[Path]:
        """Try to find the cybersecurity skills repo in common locations.

        Search order:
        1. Sibling directory of Argus project root
        2. ~/Repos/
        3. Home directory
        """
        search_roots = []

        # Sibling of this project
        project_root = Path(__file__).resolve().parent.parent
        search_roots.append(project_root.parent)

        # ~/Repos/
        repos_dir = Path.home() / "Repos"
        if repos_dir.is_dir():
            search_roots.append(repos_dir)

        # Home directory
        search_roots.append(Path.home())

        for root in search_roots:
            for name in cls._REPO_DIR_NAMES:
                candidate = root / name
                if (candidate / "index.json").is_file():
                    logger.debug("Auto-discovered skills repo at %s", candidate)
                    return candidate

        return None

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> Optional["SkillsKnowledge"]:
        """Create from Argus config dict. Returns None if disabled.

        When skills_repo_path is not set, auto-discovers the repo in
        sibling directories, ~/Repos/, or home directory.
        """
        if not config.get("enable_skills_knowledge", True):
            return None

        repo_path = config.get("skills_repo_path", "")
        if repo_path:
            repo_path = Path(repo_path)
        else:
            repo_path = cls._auto_discover_repo()
            if not repo_path:
                logger.debug("Skills repo not found via auto-discovery, skipping")
                return None

        index_path = repo_path / "index.json"
        index = SkillsIndex.from_path(index_path)
        if index.total_skills == 0:
            logger.warning("Skills knowledge enabled but index is empty or missing at %s", index_path)
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


# ---------------------------------------------------------------------------
# Runbook command extraction for Phase 4 sandbox verification
# ---------------------------------------------------------------------------


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
