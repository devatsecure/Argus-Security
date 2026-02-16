"""Tests for the Disclosure Generator module.

Covers DisclosureGenerator and DisclosureReport: initialization, repo URL
parsing, path sanitization, finding categorization, report generation,
GitHub discussion creation, and edge cases.

All subprocess and file I/O calls are mocked.
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.disclosure_generator import DisclosureGenerator, DisclosureReport


# ---------------------------------------------------------------------------
# Sample findings
# ---------------------------------------------------------------------------

def _code_finding(severity="high", title="SQL Injection in login", source_tool="semgrep"):
    return {
        "source_tool": source_tool,
        "severity": severity,
        "title": title,
        "file_path": "/Users/dev/project/app/views.py",
        "line_number": 42,
        "description": "User input concatenated into SQL query",
        "cwe_id": "CWE-89",
        "recommendation": "Use parameterized queries",
    }


def _dependency_finding(severity="high", title="CVE-2023-1234 in requests", source_tool="trivy"):
    return {
        "source_tool": source_tool,
        "severity": severity,
        "title": title,
        "file_path": "requirements.txt",
        "cve_id": "CVE-2023-1234",
        "recommendation": "Upgrade to 2.31.0",
    }


@pytest.fixture
def generator():
    return DisclosureGenerator()


@pytest.fixture
def generator_with_repo():
    return DisclosureGenerator(repo_url="https://github.com/acme/webapp")


@pytest.fixture
def sample_findings():
    return [
        _code_finding(),
        _code_finding(severity="medium", title="Missing CSRF token"),
        _dependency_finding(),
        _dependency_finding(severity="medium", title="CVE-2023-5678 in flask"),
    ]


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------

class TestInit:
    def test_default_init(self, generator):
        assert generator.repo_url is None
        assert generator.repo_owner is None
        assert generator.repo_name is None

    def test_init_with_repo_url(self, generator_with_repo):
        assert generator_with_repo.repo_owner == "acme"
        assert generator_with_repo.repo_name == "webapp"

    def test_init_with_ssh_url(self):
        gen = DisclosureGenerator(repo_url="git@github.com:acme/webapp.git")
        assert gen.repo_owner == "acme"
        assert gen.repo_name == "webapp"

    def test_init_with_owner_repo_format(self):
        gen = DisclosureGenerator(repo_url="acme/webapp")
        assert gen.repo_owner == "acme"
        assert gen.repo_name == "webapp"


# ---------------------------------------------------------------------------
# 2. _parse_repo_url
# ---------------------------------------------------------------------------

class TestParseRepoUrl:
    def test_https_url(self, generator):
        generator._parse_repo_url("https://github.com/org/repo")
        assert generator.repo_owner == "org"
        assert generator.repo_name == "repo"

    def test_url_with_git_suffix(self, generator):
        generator._parse_repo_url("https://github.com/org/repo.git")
        assert generator.repo_name == "repo"

    def test_unparseable_url(self, generator):
        generator._parse_repo_url("not-a-url")
        assert generator.repo_owner is None
        assert generator.repo_name is None


# ---------------------------------------------------------------------------
# 3. _sanitize_path
# ---------------------------------------------------------------------------

class TestSanitizePath:
    def test_removes_users_prefix(self, generator):
        result = generator._sanitize_path("/Users/devuser/Projects/app/models.py")
        assert not result.startswith("/Users/devuser/Projects/")
        assert "models.py" in result

    def test_removes_tmp_prefix(self, generator):
        result = generator._sanitize_path("/tmp/scan123/app/views.py")
        assert not result.startswith("/tmp/scan123/")
        assert "views.py" in result

    def test_removes_private_tmp_prefix(self, generator):
        result = generator._sanitize_path("/private/tmp/scan123/app/views.py")
        assert not result.startswith("/private/tmp/")
        assert "views.py" in result

    def test_no_prefix_unchanged(self, generator):
        result = generator._sanitize_path("app/models.py")
        assert result == "app/models.py"


# ---------------------------------------------------------------------------
# 4. _categorize_findings
# ---------------------------------------------------------------------------

class TestCategorizeFindings:
    def test_separates_code_and_dependency(self, generator, sample_findings):
        code, deps = generator._categorize_findings(sample_findings)
        assert len(deps) >= 2  # trivy + lockfile findings
        assert len(code) >= 1

    def test_trivy_source_classified_as_dependency(self, generator):
        findings = [_dependency_finding(source_tool="trivy")]
        code, deps = generator._categorize_findings(findings)
        assert len(deps) == 1
        assert len(code) == 0

    def test_lockfile_path_classified_as_dependency(self, generator):
        finding = _code_finding(source_tool="semgrep")
        finding["file_path"] = "package-lock.json"
        code, deps = generator._categorize_findings([finding])
        assert len(deps) == 1

    def test_empty_findings(self, generator):
        code, deps = generator._categorize_findings([])
        assert code == []
        assert deps == []


# ---------------------------------------------------------------------------
# 5. _get_high_severity_findings
# ---------------------------------------------------------------------------

class TestGetHighSeverity:
    def test_filters_high_and_critical(self, generator):
        findings = [
            _code_finding(severity="critical"),
            _code_finding(severity="high"),
            _code_finding(severity="medium"),
            _code_finding(severity="low"),
        ]
        result = generator._get_high_severity_findings(findings)
        assert len(result) == 2

    def test_empty_list(self, generator):
        assert generator._get_high_severity_findings([]) == []


# ---------------------------------------------------------------------------
# 6. _check_repo_security_options
# ---------------------------------------------------------------------------

class TestCheckRepoSecurityOptions:
    def test_no_repo_returns_defaults(self, generator):
        result = generator._check_repo_security_options()
        assert result["has_security_policy"] is False
        assert result["has_discussions"] is False
        assert result["has_private_reporting"] is False

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_security_policy_found(self, mock_run, generator_with_repo):
        # First call checks SECURITY.md, second checks repo features, third checks private reporting
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout=json.dumps({"has_discussions": True}), stderr=""),
            MagicMock(returncode=0, stdout="enabled", stderr=""),
        ]
        result = generator_with_repo._check_repo_security_options()
        assert result["has_security_policy"] is True
        assert result["has_discussions"] is True
        assert result["has_private_reporting"] is True

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_subprocess_exception_handled(self, mock_run, generator_with_repo):
        mock_run.side_effect = Exception("network error")
        result = generator_with_repo._check_repo_security_options()
        assert result["has_security_policy"] is False


# ---------------------------------------------------------------------------
# 7. _generate_private_report
# ---------------------------------------------------------------------------

class TestGeneratePrivateReport:
    def test_includes_code_findings(self, generator_with_repo):
        code = [_code_finding()]
        report = generator_with_repo._generate_private_report(code, [])
        assert "SQL Injection" in report
        assert "CWE-89" in report
        assert "parameterized queries" in report

    def test_includes_dependency_findings(self, generator_with_repo):
        deps = [_dependency_finding()]
        report = generator_with_repo._generate_private_report([], deps)
        assert "CVE-2023-1234" in report

    def test_no_findings_message(self, generator_with_repo):
        report = generator_with_repo._generate_private_report([], [])
        assert "No code vulnerabilities found" in report

    def test_sanitizes_paths(self, generator_with_repo):
        finding = _code_finding()
        finding["file_path"] = "/Users/dev/project/app/views.py"
        report = generator_with_repo._generate_private_report([finding], [])
        assert "/Users/dev/project/" not in report

    def test_truncates_long_descriptions(self, generator_with_repo):
        finding = _code_finding()
        finding["description"] = "A" * 600
        report = generator_with_repo._generate_private_report([finding], [])
        assert "..." in report

    def test_disclosure_timeline_present(self, generator_with_repo):
        report = generator_with_repo._generate_private_report([], [])
        assert "Disclosure Timeline" in report
        assert "Initial private report" in report


# ---------------------------------------------------------------------------
# 8. _generate_public_safe_report
# ---------------------------------------------------------------------------

class TestGeneratePublicSafeReport:
    def test_no_exploit_details(self, generator_with_repo):
        code = [_code_finding()]
        deps = [_dependency_finding()]
        report = generator_with_repo._generate_public_safe_report(code, deps)
        # Should NOT contain specific exploit details
        assert "CWE-89" not in report
        assert "SQL Injection in login" not in report

    def test_mentions_packages(self, generator_with_repo):
        deps = [_dependency_finding(title="CVE-2023-1234 in requests")]
        report = generator_with_repo._generate_public_safe_report([], deps)
        assert "requests" in report

    def test_empty_findings(self, generator_with_repo):
        report = generator_with_repo._generate_public_safe_report([], [])
        assert "Security" in report  # Still generates a valid report


# ---------------------------------------------------------------------------
# 9. generate (main entry point)
# ---------------------------------------------------------------------------

class TestGenerate:
    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_returns_disclosure_report(self, mock_check, generator_with_repo, sample_findings):
        mock_check.return_value = {
            "has_security_policy": True,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        result = generator_with_repo.generate(sample_findings)
        assert isinstance(result, DisclosureReport)
        assert result.repo_owner == "acme"
        assert result.repo_name == "webapp"
        assert result.has_security_policy is True
        assert len(result.private_report) > 0
        assert len(result.public_safe_report) > 0

    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_saves_to_output_dir(self, mock_check, generator_with_repo, sample_findings, tmp_path):
        mock_check.return_value = {
            "has_security_policy": False,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        out = str(tmp_path / "disclosure")
        result = generator_with_repo.generate(sample_findings, output_dir=out)
        assert (Path(out) / "DISCLOSURE_PRIVATE.md").exists()
        assert (Path(out) / "ISSUE_PUBLIC_SAFE.md").exists()

    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_timeline_has_correct_keys(self, mock_check, generator_with_repo, sample_findings):
        mock_check.return_value = {
            "has_security_policy": False,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        result = generator_with_repo.generate(sample_findings)
        assert "reported" in result.disclosure_timeline
        assert "followup" in result.disclosure_timeline
        assert "public_disclosure" in result.disclosure_timeline


# ---------------------------------------------------------------------------
# 10. create_github_discussion
# ---------------------------------------------------------------------------

class TestCreateGithubDiscussion:
    def test_no_repo_returns_none(self, generator):
        assert generator.create_github_discussion() is None

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_success(self, mock_run, generator_with_repo):
        # First call: get repo ID + categories
        mock_run.side_effect = [
            MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "data": {
                        "repository": {
                            "id": "R_123",
                            "discussionCategories": {
                                "nodes": [
                                    {"id": "DC_1", "name": "General", "slug": "general"},
                                ]
                            },
                        }
                    }
                }),
            ),
            # Second call: create discussion
            MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "data": {
                        "createDiscussion": {
                            "discussion": {"url": "https://github.com/acme/webapp/discussions/1", "number": 1}
                        }
                    }
                }),
            ),
        ]
        url = generator_with_repo.create_github_discussion()
        assert url == "https://github.com/acme/webapp/discussions/1"

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_no_category_returns_none(self, mock_run, generator_with_repo):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "data": {
                    "repository": {
                        "id": "R_123",
                        "discussionCategories": {"nodes": [{"id": "DC_1", "name": "Announcements", "slug": "announcements"}]},
                    }
                }
            }),
        )
        assert generator_with_repo.create_github_discussion() is None

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_api_failure_returns_none(self, mock_run, generator_with_repo):
        mock_run.return_value = MagicMock(returncode=1, stderr="auth required")
        assert generator_with_repo.create_github_discussion() is None

    @patch("scripts.disclosure_generator.subprocess.run")
    def test_exception_returns_none(self, mock_run, generator_with_repo):
        mock_run.side_effect = Exception("network timeout")
        assert generator_with_repo.create_github_discussion() is None


# ---------------------------------------------------------------------------
# 11. DisclosureReport dataclass
# ---------------------------------------------------------------------------

class TestDisclosureReport:
    def test_dataclass_fields(self):
        report = DisclosureReport(
            private_report="private",
            public_safe_report="public",
            repo_owner="owner",
            repo_name="repo",
            has_security_policy=True,
            has_discussions=False,
            has_private_reporting=False,
            high_findings=[],
            dependency_findings=[],
            disclosure_timeline={"reported": "2026-01-01"},
        )
        assert report.private_report == "private"
        assert report.has_security_policy is True
        assert report.disclosure_timeline["reported"] == "2026-01-01"
