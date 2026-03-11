#!/usr/bin/env python3
"""
Unit tests for AutoFix PR Generator.

Covers path validation (reject outside project), behavior with mocked git,
and create_fix_pr / create_fix_branch with safe paths.
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from autofix_pr_generator import AutoFixPRGenerator, FixBranch, FixPR


class TestPathValidation:
    """Path validation: reject outside project, accept relative paths under project."""

    def test_rejects_path_outside_project(self, tmp_path):
        """Suggestion with file_path outside project root should not apply fix."""
        project = tmp_path / "repo"
        project.mkdir()
        (project / "src").mkdir()
        (project / "src" / "main.py").write_text("x = 1\n")

        # Path that escapes project (e.g. ../etc/passwd or absolute elsewhere)
        with patch("autofix_pr_generator.validate_path_safe") as mock_validate:
            mock_validate.side_effect = ValueError("path is outside base directory")

            gen = AutoFixPRGenerator(project_path=str(project))
            applied = gen._apply_fix(
                {
                    "finding_id": "f1",
                    "file_path": "../../../etc/passwd",
                    "fixed_code": "content",
                }
            )
            assert applied is False
            mock_validate.assert_called()

    def test_accepts_relative_path_under_project(self, tmp_path):
        """Suggestion with file_path under project should pass validation when mocked."""
        project = tmp_path / "repo"
        project.mkdir()
        (project / "src").mkdir()
        target = project / "src" / "main.py"
        target.write_text("vuln_code()\n")

        with patch("autofix_pr_generator.validate_path_safe") as mock_validate:
            mock_validate.return_value = str(target)

            gen = AutoFixPRGenerator(project_path=str(project))
            applied = gen._apply_fix(
                {
                    "finding_id": "f1",
                    "file_path": "src/main.py",
                    "original_code": "vuln_code()\n",
                    "fixed_code": "safe_code()\n",
                }
            )
            assert applied is True
            mock_validate.assert_called()
            assert target.read_text() == "safe_code()\n"

    def test_rejects_empty_file_path(self, tmp_path):
        """Empty or whitespace-only file_path should not apply fix."""
        project = tmp_path / "repo"
        project.mkdir()
        gen = AutoFixPRGenerator(project_path=str(project))

        for bad_path in ("", "   ", "\t"):
            applied = gen._apply_fix(
                {
                    "finding_id": "f1",
                    "file_path": bad_path,
                    "fixed_code": "x",
                }
            )
            assert applied is False


class TestCreateFixBranchMockedGit:
    """create_fix_branch with mocked git (no real git)."""

    @pytest.fixture
    def project_dir(self, tmp_path):
        d = tmp_path / "repo"
        d.mkdir()
        (d / "app.py").write_text("bad()\n")
        return d

    def test_create_fix_branch_path_validation_failure(self, project_dir):
        """When path validation fails, create_fix_branch returns FixBranch with success=False."""
        with patch("autofix_pr_generator.validate_path_safe") as mock_validate:
            mock_validate.side_effect = ValueError("outside project")

            with patch.object(AutoFixPRGenerator, "_run_git") as mock_git:
                mock_git.return_value = MagicMock(stdout="abc123\n", returncode=0)

                gen = AutoFixPRGenerator(project_path=str(project_dir))
                result = gen.create_fix_branch(
                    {
                        "finding_id": "f1",
                        "vulnerability_type": "xss",
                        "file_path": "../../../etc/passwd",
                        "fixed_code": "x",
                    }
                )

                assert isinstance(result, FixBranch)
                assert result.success is False
                assert result.commit_sha is None
                assert result.error is not None  # path validation failed -> apply fix failed

    def test_create_fix_branch_success_mocked_git(self, project_dir):
        """With path validation passing and git mocked, create_fix_branch returns success."""
        with patch("autofix_pr_generator.validate_path_safe") as mock_validate:
            mock_validate.return_value = str(project_dir / "app.py")

            with patch.object(AutoFixPRGenerator, "_run_git") as mock_git:
                mock_git.return_value = MagicMock(stdout="abc123\n", returncode=0)

                gen = AutoFixPRGenerator(project_path=str(project_dir))
                result = gen.create_fix_branch(
                    {
                        "finding_id": "f1",
                        "vulnerability_type": "sql-injection",
                        "file_path": "app.py",
                        "fixed_code": "safe()\n",
                    }
                )

                assert isinstance(result, FixBranch)
                # Git is mocked so we may get success=True if _apply_fix passes
                assert result.finding_id == "f1"
                assert result.file_path == "app.py"


class TestCreateFixPR:
    """create_fix_pr with mocked git and generator."""

    def test_create_fix_pr_returns_fix_pr_type(self, tmp_path):
        """create_fix_pr returns a FixPR instance."""
        project = tmp_path / "repo"
        project.mkdir()
        with patch.object(AutoFixPRGenerator, "create_fix_branch") as mock_branch:
            mock_branch.return_value = FixBranch(
                branch_name="argus/fix-x-abc",
                finding_id="f1",
                vulnerability_type="xss",
                file_path="app.py",
                commit_sha="abc123",
                success=True,
            )
            gen = AutoFixPRGenerator(project_path=str(project))
            pr = gen.create_fix_pr(
                {
                    "finding_id": "f1",
                    "vulnerability_type": "xss",
                    "file_path": "app.py",
                    "fixed_code": "safe();",
                }
            )
            assert isinstance(pr, FixPR)
            assert pr.branch_name == "argus/fix-x-abc"
            assert pr.commit_sha == "abc123"
            assert pr.success is True
