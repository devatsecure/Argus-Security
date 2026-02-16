#!/usr/bin/env python3
"""
Unit Tests for Disclosure Generator

Tests cover:
- DisclosureReport dataclass
- DisclosureGenerator initialization and URL parsing
- Path sanitization
- Finding categorization (code vs dependency)
- High severity filtering
- Private report generation
- Public-safe report generation
- generate() orchestration
- GitHub security options check (mocked)
- Edge cases (empty findings, no repo URL, missing fields)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from disclosure_generator import DisclosureGenerator, DisclosureReport

# ---------------------------------------------------------------------------
# DisclosureReport
# ---------------------------------------------------------------------------


class TestDisclosureReport:
    """Test DisclosureReport dataclass"""

    def test_creation(self):
        report = DisclosureReport(
            private_report="private content",
            public_safe_report="public content",
            repo_owner="owner",
            repo_name="repo",
            has_security_policy=True,
            has_discussions=False,
            has_private_reporting=True,
            high_findings=[{"id": "f1"}],
            dependency_findings=[{"id": "f2"}],
            disclosure_timeline={"reported": "2026-01-01"},
        )
        assert report.repo_owner == "owner"
        assert report.has_security_policy is True
        assert len(report.high_findings) == 1


# ---------------------------------------------------------------------------
# Initialization and URL Parsing
# ---------------------------------------------------------------------------


class TestInitialization:
    """Test DisclosureGenerator initialization"""

    def test_no_repo_url(self):
        gen = DisclosureGenerator()
        assert gen.repo_owner is None
        assert gen.repo_name is None

    def test_https_url(self):
        gen = DisclosureGenerator("https://github.com/devatsecure/Argus-Security")
        assert gen.repo_owner == "devatsecure"
        assert gen.repo_name == "Argus-Security"

    def test_ssh_url(self):
        gen = DisclosureGenerator("git@github.com:devatsecure/Argus-Security.git")
        assert gen.repo_owner == "devatsecure"
        assert gen.repo_name == "Argus-Security"

    def test_owner_repo_format(self):
        gen = DisclosureGenerator("devatsecure/Argus-Security")
        assert gen.repo_owner == "devatsecure"
        assert gen.repo_name == "Argus-Security"

    def test_dot_git_stripped(self):
        gen = DisclosureGenerator("https://github.com/owner/repo.git")
        assert gen.repo_name == "repo"

    def test_unparseable_url(self):
        gen = DisclosureGenerator("not-a-valid-url")
        # Should not crash
        assert gen.repo_url == "not-a-valid-url"


# ---------------------------------------------------------------------------
# Path Sanitization
# ---------------------------------------------------------------------------


class TestPathSanitization:
    """Test _sanitize_path"""

    def test_remove_private_tmp(self):
        gen = DisclosureGenerator()
        result = gen._sanitize_path("/private/tmp/abc123/src/api.py")
        assert result == "src/api.py"

    def test_remove_tmp(self):
        gen = DisclosureGenerator()
        result = gen._sanitize_path("/tmp/scan_123/src/api.py")
        assert result == "src/api.py"

    def test_remove_users_path(self):
        gen = DisclosureGenerator()
        result = gen._sanitize_path("/Users/johndoe/projects/src/api.py")
        assert result == "src/api.py"

    def test_no_sanitization_needed(self):
        gen = DisclosureGenerator()
        result = gen._sanitize_path("src/api/users.py")
        assert result == "src/api/users.py"

    def test_remove_var_folders(self):
        gen = DisclosureGenerator()
        result = gen._sanitize_path("/var/folders/ab/cd123/T/src/api.py")
        assert result == "src/api.py"


# ---------------------------------------------------------------------------
# Finding Categorization
# ---------------------------------------------------------------------------


class TestFindingCategorization:
    """Test _categorize_findings"""

    def test_code_findings(self):
        gen = DisclosureGenerator()
        findings = [
            {"source_tool": "semgrep", "file_path": "src/api.py"},
            {"source_tool": "semgrep", "file_path": "src/auth.py"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(code) == 2
        assert len(deps) == 0

    def test_dependency_findings_trivy(self):
        gen = DisclosureGenerator()
        findings = [
            {"source_tool": "trivy", "file_path": "package-lock.json"},
            {"source_tool": "trivy", "file_path": "requirements.txt"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(code) == 0
        assert len(deps) == 2

    def test_mixed_findings(self):
        gen = DisclosureGenerator()
        findings = [
            {"source_tool": "semgrep", "file_path": "src/api.py"},
            {"source_tool": "trivy", "file_path": "package-lock.json"},
            {"source_tool": "semgrep", "file_path": "src/auth.py"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(code) == 2
        assert len(deps) == 1

    def test_lockfile_detected_as_dependency(self):
        gen = DisclosureGenerator()
        findings = [
            {"source_tool": "semgrep", "file_path": "package.json"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(deps) == 1

    def test_empty_findings(self):
        gen = DisclosureGenerator()
        code, deps = gen._categorize_findings([])
        assert code == []
        assert deps == []

    def test_fallback_source_field(self):
        gen = DisclosureGenerator()
        findings = [
            {"source": "trivy", "file": "go.mod"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(deps) == 1

    def test_non_dependency_non_trivy(self):
        gen = DisclosureGenerator()
        findings = [
            {"source_tool": "checkov", "file_path": "terraform/main.tf"},
        ]
        code, deps = gen._categorize_findings(findings)
        assert len(code) == 1
        assert len(deps) == 0


# ---------------------------------------------------------------------------
# High Severity Filtering
# ---------------------------------------------------------------------------


class TestHighSeverityFiltering:
    """Test _get_high_severity_findings"""

    def test_filters_high_and_critical(self):
        gen = DisclosureGenerator()
        findings = [
            {"severity": "critical", "id": "f1"},
            {"severity": "high", "id": "f2"},
            {"severity": "medium", "id": "f3"},
            {"severity": "low", "id": "f4"},
        ]
        result = gen._get_high_severity_findings(findings)
        assert len(result) == 2
        assert all(f["severity"] in ["critical", "high"] for f in result)

    def test_empty_findings(self):
        gen = DisclosureGenerator()
        result = gen._get_high_severity_findings([])
        assert result == []

    def test_no_high_severity(self):
        gen = DisclosureGenerator()
        findings = [
            {"severity": "medium", "id": "f1"},
            {"severity": "low", "id": "f2"},
        ]
        result = gen._get_high_severity_findings(findings)
        assert result == []

    def test_case_insensitive(self):
        gen = DisclosureGenerator()
        findings = [
            {"severity": "High", "id": "f1"},
            {"severity": "CRITICAL", "id": "f2"},
        ]
        result = gen._get_high_severity_findings(findings)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Private Report Generation
# ---------------------------------------------------------------------------


class TestPrivateReport:
    """Test _generate_private_report"""

    def test_basic_report_structure(self):
        gen = DisclosureGenerator("owner/repo")
        code_findings = [
            {
                "title": "SQL Injection",
                "file_path": "src/api.py",
                "line_number": 42,
                "description": "User input in SQL query",
                "cwe_id": "CWE-89",
                "recommendation": "Use parameterized queries",
            }
        ]
        report = gen._generate_private_report(code_findings, [])
        assert "SQL Injection" in report
        assert "src/api.py" in report
        assert "CWE-89" in report
        assert "Disclosure Timeline" in report

    def test_with_dependency_findings(self):
        gen = DisclosureGenerator("owner/repo")
        deps = [
            {
                "title": "CVE-2024-0001 in express",
                "severity": "high",
                "cve_id": "CVE-2024-0001",
                "recommendation": "Upgrade to 4.18.3",
            }
        ]
        report = gen._generate_private_report([], deps)
        assert "Dependency CVEs" in report
        assert "CVE-2024-0001" in report

    def test_empty_findings(self):
        gen = DisclosureGenerator("owner/repo")
        report = gen._generate_private_report([], [])
        assert "No code vulnerabilities found" in report
        assert "No dependency CVEs found" in report

    def test_long_description_truncated(self):
        gen = DisclosureGenerator("owner/repo")
        code_findings = [
            {
                "title": "Issue",
                "file_path": "src/api.py",
                "description": "x" * 1000,
            }
        ]
        report = gen._generate_private_report(code_findings, [])
        assert "..." in report  # Truncation indicator

    def test_custom_reporter_name(self):
        gen = DisclosureGenerator("owner/repo")
        report = gen._generate_private_report([], [], reporter_name="Security Team")
        assert "Security Team" in report

    def test_path_sanitization_in_report(self):
        gen = DisclosureGenerator("owner/repo")
        code_findings = [
            {
                "title": "Issue",
                "file_path": "/private/tmp/abc/src/api.py",
                "description": "Test",
            }
        ]
        report = gen._generate_private_report(code_findings, [])
        assert "/private/tmp/" not in report
        assert "src/api.py" in report


# ---------------------------------------------------------------------------
# Public Safe Report
# ---------------------------------------------------------------------------


class TestPublicSafeReport:
    """Test _generate_public_safe_report"""

    def test_no_exploit_details(self):
        gen = DisclosureGenerator()
        code_findings = [
            {
                "title": "SQL Injection",
                "source_tool": "semgrep",
                "description": "User input in SQL query with detailed exploit path",
            }
        ]
        report = gen._generate_public_safe_report(code_findings, [])
        assert "exploit" not in report.lower()
        assert "Security" in report

    def test_package_listing(self):
        gen = DisclosureGenerator()
        deps = [
            {"title": "CVE-2024-0001 in express", "severity": "high"},
            {"title": "CVE-2024-0002 in lodash", "severity": "medium"},
        ]
        report = gen._generate_public_safe_report([], deps)
        assert "express" in report
        assert "lodash" in report

    def test_empty_findings(self):
        gen = DisclosureGenerator()
        report = gen._generate_public_safe_report([], [])
        assert "Security" in report
        assert "improvements" in report


# ---------------------------------------------------------------------------
# generate() orchestration
# ---------------------------------------------------------------------------


class TestGenerate:
    """Test generate() method"""

    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_generates_report(self, mock_check):
        mock_check.return_value = {
            "has_security_policy": False,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        gen = DisclosureGenerator("owner/repo")
        findings = [
            {"source_tool": "semgrep", "file_path": "src/api.py", "severity": "high", "title": "SQL Injection"},
            {"source_tool": "trivy", "file_path": "package-lock.json", "severity": "medium", "title": "CVE in pkg"},
        ]
        report = gen.generate(findings)

        assert isinstance(report, DisclosureReport)
        assert "SQL Injection" in report.private_report
        assert report.repo_owner == "owner"
        assert report.repo_name == "repo"
        assert len(report.high_findings) == 1
        assert len(report.dependency_findings) == 1
        assert "reported" in report.disclosure_timeline

    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_saves_to_output_dir(self, mock_check, tmp_path):
        mock_check.return_value = {
            "has_security_policy": False,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        gen = DisclosureGenerator("owner/repo")
        findings = [
            {"source_tool": "semgrep", "file_path": "src/api.py", "severity": "high", "title": "Issue"},
        ]
        output_dir = tmp_path / "reports"
        gen.generate(findings, output_dir=str(output_dir))

        assert (output_dir / "DISCLOSURE_PRIVATE.md").exists()
        assert (output_dir / "ISSUE_PUBLIC_SAFE.md").exists()

    @patch.object(DisclosureGenerator, "_check_repo_security_options")
    def test_empty_findings(self, mock_check):
        mock_check.return_value = {
            "has_security_policy": False,
            "has_discussions": False,
            "has_private_reporting": False,
            "security_email": None,
        }
        gen = DisclosureGenerator("owner/repo")
        report = gen.generate([])
        assert isinstance(report, DisclosureReport)
        assert report.high_findings == []
        assert report.dependency_findings == []


# ---------------------------------------------------------------------------
# GitHub Security Options
# ---------------------------------------------------------------------------


class TestCheckRepoSecurityOptions:
    """Test _check_repo_security_options"""

    def test_no_repo_set(self):
        gen = DisclosureGenerator()
        options = gen._check_repo_security_options()
        assert options["has_security_policy"] is False
        assert options["has_discussions"] is False

    @patch("disclosure_generator.subprocess.run")
    def test_security_policy_found(self, mock_run):
        gen = DisclosureGenerator("owner/repo")

        def side_effect(cmd, **kwargs):
            mock_result = MagicMock()
            if "SECURITY.md" in str(cmd):
                mock_result.returncode = 0
                mock_result.stdout = ""
            elif "has_discussions" in str(cmd):
                mock_result.returncode = 0
                mock_result.stdout = '{"has_discussions": true}'
            else:
                mock_result.returncode = 0
                mock_result.stdout = "disabled"
            return mock_result

        mock_run.side_effect = side_effect
        options = gen._check_repo_security_options()
        assert options["has_security_policy"] is True

    @patch("disclosure_generator.subprocess.run")
    def test_gh_command_fails(self, mock_run):
        gen = DisclosureGenerator("owner/repo")
        mock_run.side_effect = FileNotFoundError("gh not found")
        options = gen._check_repo_security_options()
        assert options["has_security_policy"] is False


# ---------------------------------------------------------------------------
# create_github_discussion
# ---------------------------------------------------------------------------


class TestCreateGithubDiscussion:
    """Test create_github_discussion"""

    def test_no_repo_set(self):
        gen = DisclosureGenerator()
        result = gen.create_github_discussion()
        assert result is None

    @patch("disclosure_generator.subprocess.run")
    def test_api_failure(self, mock_run):
        gen = DisclosureGenerator("owner/repo")
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "API error"
        mock_run.return_value = mock_result

        result = gen.create_github_discussion()
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
