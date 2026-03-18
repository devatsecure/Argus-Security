"""
Unit tests for Skills Knowledge Integration.

Tests cover:
- SkillsIndex loading (from dict, file, missing file)
- SkillMatcher (tag, CWE, keyword, description matching)
- SkillsKnowledge (content loading, context generation, config init)
- SkillRunbookExtractor (command and verification extraction)
- End-to-end integration (finding -> matched skill -> context in prompt)
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from skills_knowledge import (
    SkillMatcher,
    SkillRunbookExtractor,
    SkillsIndex,
    SkillsKnowledge,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# SkillsIndex tests
# ---------------------------------------------------------------------------


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

    def test_load_corrupt_json_returns_empty(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json")
        index = SkillsIndex.from_path(bad_file)
        assert index.total_skills == 0

    def test_skill_lookup_by_name(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        skill = index.get_skill("detecting-sql-injection-via-waf-logs")
        assert skill is not None
        assert skill["subdomain"] == "security-operations"

    def test_skill_lookup_missing_returns_none(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        assert index.get_skill("nonexistent-skill") is None

    def test_get_by_tag(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        results = index.get_by_tag("aws")
        assert len(results) == 1
        assert results[0]["name"] == "detecting-aws-credential-exposure-with-trufflehog"

    def test_get_by_subdomain(self):
        index = SkillsIndex.from_dict(SAMPLE_INDEX)
        results = index.get_by_subdomain("cloud-security")
        assert len(results) == 1

    def test_empty_index(self):
        index = SkillsIndex()
        assert index.total_skills == 0
        assert index.get_skill("anything") is None
        assert index.get_by_tag("anything") == []


# ---------------------------------------------------------------------------
# SkillMatcher tests
# ---------------------------------------------------------------------------


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

    def test_match_by_title_keywords(self, matcher):
        finding = {"category": "SAST", "rule_id": "cache-poisoning",
                   "severity": "medium", "path": "proxy.py", "title": "web cache poisoning"}
        matches = matcher.match(finding)
        assert any("cache-poisoning" in m["name"] for m in matches)

    def test_match_empty_finding(self, matcher):
        matches = matcher.match({})
        assert matches == []

    def test_match_ordering_best_first(self, matcher):
        """Higher-scoring skills should come first."""
        finding = {"category": "SAST", "rule_id": "sql-injection",
                   "severity": "high", "cwe_id": "CWE-89", "path": "app/db.py",
                   "title": "SQL injection via WAF"}
        matches = matcher.match(finding, max_results=3)
        if len(matches) >= 2:
            # SQL skill should rank higher than unrelated skills
            assert "sql" in matches[0]["name"]


# ---------------------------------------------------------------------------
# Auto-discovery tests
# ---------------------------------------------------------------------------


class TestAutoDiscovery:
    def test_auto_discover_finds_sibling_repo(self, tmp_path, monkeypatch):
        """Finds the repo as a sibling directory of the project root."""
        # Simulate: project_root.parent / Anthropic-Cybersecurity-Skills / index.json
        skills_dir = tmp_path / "Anthropic-Cybersecurity-Skills"
        skills_dir.mkdir()
        (skills_dir / "index.json").write_text(json.dumps(SAMPLE_INDEX))

        # Patch __file__ so project_root.parent == tmp_path
        fake_script = tmp_path / "Argus-Security" / "scripts" / "skills_knowledge.py"
        fake_script.parent.mkdir(parents=True, exist_ok=True)
        fake_script.touch()

        import skills_knowledge as sk_mod
        original_file = sk_mod.__file__
        monkeypatch.setattr(sk_mod, "__file__", str(fake_script))
        try:
            result = SkillsKnowledge._auto_discover_repo()
            assert result is not None
            assert result == skills_dir
        finally:
            monkeypatch.setattr(sk_mod, "__file__", original_file)

    def test_auto_discover_returns_none_when_not_found(self, tmp_path, monkeypatch):
        """Returns None when no skills repo exists anywhere."""
        fake_script = tmp_path / "project" / "scripts" / "sk.py"
        fake_script.parent.mkdir(parents=True, exist_ok=True)
        fake_script.touch()

        import skills_knowledge as sk_mod
        original_file = sk_mod.__file__
        monkeypatch.setattr(sk_mod, "__file__", str(fake_script))
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        (tmp_path / "fakehome").mkdir(exist_ok=True)
        try:
            result = SkillsKnowledge._auto_discover_repo()
            assert result is None
        finally:
            monkeypatch.setattr(sk_mod, "__file__", original_file)


# ---------------------------------------------------------------------------
# SkillsKnowledge tests
# ---------------------------------------------------------------------------


class TestSkillsKnowledgeConfig:
    def test_from_config_disabled(self):
        config = {"enable_skills_knowledge": False, "skills_repo_path": "/some/path"}
        result = SkillsKnowledge.from_config(config)
        assert result is None

    def test_from_config_no_path_no_autodiscover(self, monkeypatch):
        """When no path given and auto-discovery finds nothing, returns None."""
        monkeypatch.setattr(SkillsKnowledge, "_auto_discover_repo", staticmethod(lambda: None))
        config = {"enable_skills_knowledge": True, "skills_repo_path": ""}
        result = SkillsKnowledge.from_config(config)
        assert result is None

    def test_from_config_explicit_path(self, tmp_path):
        (tmp_path / "index.json").write_text(json.dumps(SAMPLE_INDEX))
        config = {"enable_skills_knowledge": True, "skills_repo_path": str(tmp_path)}
        result = SkillsKnowledge.from_config(config)
        assert result is not None
        assert result.index.total_skills == 3

    def test_from_config_auto_discover(self, tmp_path, monkeypatch):
        """When no path given but auto-discovery finds the repo, loads it."""
        (tmp_path / "index.json").write_text(json.dumps(SAMPLE_INDEX))
        monkeypatch.setattr(SkillsKnowledge, "_auto_discover_repo", staticmethod(lambda: tmp_path))
        config = {"enable_skills_knowledge": True, "skills_repo_path": ""}
        result = SkillsKnowledge.from_config(config)
        assert result is not None
        assert result.index.total_skills == 3

    def test_from_config_missing_index(self, tmp_path):
        config = {"enable_skills_knowledge": True, "skills_repo_path": str(tmp_path)}
        result = SkillsKnowledge.from_config(config)
        assert result is None

    def test_from_config_default_enabled(self, tmp_path):
        """enable_skills_knowledge defaults to True when key is absent."""
        (tmp_path / "index.json").write_text(json.dumps(SAMPLE_INDEX))
        config = {"skills_repo_path": str(tmp_path)}
        result = SkillsKnowledge.from_config(config)
        assert result is not None


class TestSkillContentLoader:
    def test_load_skill_content_from_file(self, tmp_path):
        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
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
        # Frontmatter should be stripped
        assert "---" not in content.split("\n")[0]

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
        assert len(content) <= 2100
        assert "[... truncated]" in content

    def test_content_is_cached(self, tmp_path):
        skill_dir = tmp_path / "skills" / "cached-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: cached-skill\n---\nBody content")
        index = SkillsIndex.from_dict({
            "skills": [{"name": "cached-skill", "path": "skills/cached-skill", "tags": []}]
        })
        knowledge = SkillsKnowledge(index=index, repo_path=tmp_path)
        content1 = knowledge.load_skill_content("cached-skill")
        content2 = knowledge.load_skill_content("cached-skill")
        assert content1 == content2
        assert content1 is content2  # Same object from cache

    def test_load_without_repo_path(self):
        index = SkillsIndex.from_dict({
            "skills": [{"name": "some-skill", "path": "skills/some-skill", "tags": []}]
        })
        knowledge = SkillsKnowledge(index=index, repo_path=None)
        assert knowledge.load_skill_content("some-skill") is None


class TestGetContextForFinding:
    def test_returns_empty_for_no_matches(self):
        index = SkillsIndex.from_dict({"skills": []})
        knowledge = SkillsKnowledge(index=index, repo_path=Path("/tmp"))
        context = knowledge.get_context_for_finding({"rule_id": "xyz", "path": "f.py"})
        assert context == ""

    def test_returns_formatted_context(self, tmp_path):
        skill_dir = tmp_path / "skills" / "detecting-xss-reflected"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: detecting-xss-reflected\n---\n"
            "# XSS Detection\n\n## Workflow\n1. Scan for reflected XSS\n"
        )
        index = SkillsIndex.from_dict({
            "skills": [{
                "name": "detecting-xss-reflected",
                "description": "Detect reflected XSS",
                "subdomain": "web-application-security",
                "tags": ["xss", "web-security"],
                "path": "skills/detecting-xss-reflected",
            }]
        })
        knowledge = SkillsKnowledge(index=index, repo_path=tmp_path)
        finding = {"rule_id": "xss-reflected", "category": "SAST",
                   "severity": "high", "path": "app.py", "cwe_id": "CWE-79"}
        context = knowledge.get_context_for_finding(finding)
        assert "Cybersecurity Skills Knowledge" in context
        assert "XSS Detection" in context
        assert "End Skills Knowledge" in context


# ---------------------------------------------------------------------------
# SkillRunbookExtractor tests
# ---------------------------------------------------------------------------


class TestSkillRunbookExtractor:
    def test_extract_commands_from_bash_blocks(self):
        content = (
            "## Workflow\n\n"
            "1. Install dependencies:\n"
            "```bash\npip install semgrep\n```\n\n"
            "2. Run the scan:\n"
            "```bash\nsemgrep --config auto .\n```\n\n"
        )
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        assert len(commands) == 2
        assert "pip install semgrep" in commands
        assert "semgrep --config auto ." in commands

    def test_extract_commands_from_python_blocks(self):
        content = (
            "## Steps\n\n"
            "```python\nimport subprocess\nsubprocess.run(['nmap', '-sV', 'target'])\n```\n"
        )
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        assert len(commands) == 1
        assert "import subprocess" in commands[0]

    def test_extract_empty_content(self):
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands("")
        assert commands == []

    def test_extract_skips_comments(self):
        content = "```bash\n# This is a comment\nactual-command\n```\n"
        extractor = SkillRunbookExtractor()
        commands = extractor.extract_commands(content)
        assert commands == ["actual-command"]

    def test_extract_verification_steps(self):
        content = (
            "## Workflow\n\n```bash\nnmap -sP target\n```\n\n"
            "## Verification\n\n"
            "```bash\nnmap --version\n```\n"
        )
        extractor = SkillRunbookExtractor()
        verification = extractor.extract_verification(content)
        assert len(verification) == 1
        assert "nmap --version" in verification

    def test_extract_verification_empty_when_no_section(self):
        content = "## Workflow\n\n```bash\nls\n```\n"
        extractor = SkillRunbookExtractor()
        assert extractor.extract_verification(content) == []

    def test_extract_verification_stops_at_next_header(self):
        content = (
            "## Verification\n\n```bash\ncheck-cmd\n```\n\n"
            "## Other Section\n\n```bash\nunrelated-cmd\n```\n"
        )
        extractor = SkillRunbookExtractor()
        verification = extractor.extract_verification(content)
        assert "check-cmd" in verification
        assert "unrelated-cmd" not in verification


# ---------------------------------------------------------------------------
# Agent context injection tests
# ---------------------------------------------------------------------------


class TestSkillContextInjection:
    def test_build_base_prompt_includes_skill_context(self, tmp_path):
        skill_dir = tmp_path / "skills" / "detecting-sql-injection-via-waf-logs"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: detecting-sql-injection-via-waf-logs\n"
            "description: Detect SQL injection\ndomain: cybersecurity\n"
            "subdomain: security-operations\ntags: [sql-injection, waf]\n---\n"
            "# SQL Injection Detection\n\n## Workflow\n1. Check WAF logs\n"
        )
        (tmp_path / "index.json").write_text(json.dumps({
            "skills": [{
                "name": "detecting-sql-injection-via-waf-logs",
                "description": "Detect SQL injection",
                "subdomain": "security-operations",
                "tags": ["sql-injection", "waf"],
                "path": "skills/detecting-sql-injection-via-waf-logs",
            }]
        }))

        knowledge = SkillsKnowledge(
            index=SkillsIndex.from_path(tmp_path / "index.json"),
            repo_path=tmp_path,
        )

        mock_llm = Mock()
        mock_llm.client = Mock()
        mock_llm.call_llm_api = Mock(return_value=(
            "Verdict: confirmed\nConfidence: 0.9\nReasoning: Real issue", 100, 0.01
        ))

        from agent_personas import ExploitAssessor

        agent = ExploitAssessor(mock_llm)
        agent.skills_knowledge = knowledge

        finding = {
            "id": "test-sqli", "path": "app/db.py", "line": 10,
            "severity": "high", "rule_id": "sql-injection", "category": "SAST",
            "origin": "semgrep",
            "evidence": {"snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'"},
        }
        prompt = agent._build_base_prompt(finding)
        assert "Cybersecurity Skills Knowledge" in prompt
        assert "SQL Injection Detection" in prompt

    def test_build_base_prompt_without_skills(self):
        mock_llm = Mock()
        from agent_personas import ExploitAssessor

        agent = ExploitAssessor(mock_llm)
        # No skills_knowledge set
        finding = {
            "id": "test-001", "path": "app.py", "line": 1,
            "severity": "high", "rule_id": "test", "category": "SAST",
            "origin": "semgrep", "evidence": {},
        }
        prompt = agent._build_base_prompt(finding)
        assert "Skills Knowledge" not in prompt


# ---------------------------------------------------------------------------
# End-to-end integration tests
# ---------------------------------------------------------------------------


class TestEndToEndIntegration:
    def test_full_flow_finding_to_context(self, tmp_path):
        """Test the complete flow: index load -> match -> content -> context string."""
        for skill_name, tags, body in [
            ("detecting-xss-with-burp", ["xss", "web-security", "burp"],
             "# XSS Detection\n\n## Workflow\n1. Configure Burp\n2. Scan target\n\n"
             "## Verification\n```bash\ncurl -s target | grep xss\n```\n"),
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

        (tmp_path / "index.json").write_text(json.dumps({
            "skills": [
                {"name": "detecting-xss-with-burp", "description": "Detect XSS with Burp Suite",
                 "subdomain": "web-application-security",
                 "tags": ["xss", "web-security", "burp"],
                 "path": "skills/detecting-xss-with-burp"},
                {"name": "auditing-aws-s3-buckets", "description": "Audit S3 bucket security",
                 "subdomain": "cloud-security",
                 "tags": ["aws", "s3", "cloud-security"],
                 "path": "skills/auditing-aws-s3-buckets"},
            ]
        }))

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
