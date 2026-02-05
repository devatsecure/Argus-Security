"""
Tests for Feature 4: Incremental/Diff-Only Scanning (diff_scanner.py).

Tests DiffDetector, ChangedFile, IncrementalScanFilter, DiffFindingFilter.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from diff_scanner import ChangedFile, DiffDetector, DiffFindingFilter, IncrementalScanFilter
from pipeline.protocol import PipelineContext


# ============================================================================
# ChangedFile
# ============================================================================


class TestChangedFile:
    def test_defaults(self):
        cf = ChangedFile(path="src/main.py", status="M")
        assert cf.path == "src/main.py"
        assert cf.status == "M"
        assert cf.old_path is None
        assert cf.changed_lines == []

    def test_rename(self):
        cf = ChangedFile(path="new.py", status="R", old_path="old.py")
        assert cf.old_path == "old.py"

    def test_with_changed_lines(self):
        cf = ChangedFile(path="a.py", status="M", changed_lines=[(10, 20), (50, 55)])
        assert len(cf.changed_lines) == 2
        assert cf.changed_lines[0] == (10, 20)


# ============================================================================
# DiffDetector
# ============================================================================


class TestDiffDetector:
    def _make_detector(self, base_ref: str = "origin/main") -> DiffDetector:
        return DiffDetector("/tmp/repo", base_ref=base_ref)

    def test_init_with_explicit_base_ref(self):
        d = self._make_detector("HEAD~3")
        assert d.base_ref == "HEAD~3"
        assert d.repo_path == "/tmp/repo"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_am(self, mock_git):
        """Parse Added and Modified files."""
        mock_git.return_value = "A\tsrc/new_file.py\nM\tsrc/existing.py\n"
        d = self._make_detector()
        files = d.get_changed_files()
        assert len(files) == 2
        assert files[0].path == "src/new_file.py"
        assert files[0].status == "A"
        assert files[1].path == "src/existing.py"
        assert files[1].status == "M"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_rename(self, mock_git):
        """Parse Rename entries (R100 with old and new path)."""
        mock_git.return_value = "R100\told.py\tnew.py\n"
        d = self._make_detector()
        files = d.get_changed_files()
        assert len(files) == 1
        assert files[0].path == "new.py"
        assert files[0].status == "R"
        assert files[0].old_path == "old.py"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_deletes_excluded(self, mock_git):
        """Deleted files should be excluded."""
        mock_git.return_value = "D\tremoved.py\nM\tkept.py\n"
        d = self._make_detector()
        files = d.get_changed_files()
        assert len(files) == 1
        assert files[0].path == "kept.py"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_copy(self, mock_git):
        """Parse Copy entries."""
        mock_git.return_value = "C100\toriginal.py\tcopy.py\n"
        d = self._make_detector()
        files = d.get_changed_files()
        assert len(files) == 1
        assert files[0].path == "copy.py"
        assert files[0].status == "C"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_empty(self, mock_git):
        """Empty diff output yields no files."""
        mock_git.return_value = ""
        d = self._make_detector()
        files = d.get_changed_files()
        assert files == []

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_fallback_on_three_dot_failure(self, mock_git):
        """Falls back to two-dot diff when three-dot fails."""
        mock_git.side_effect = [
            RuntimeError("bad ref"),
            "M\tfallback.py\n",
        ]
        d = self._make_detector()
        files = d.get_changed_files()
        assert len(files) == 1
        assert files[0].path == "fallback.py"

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_files_both_fail(self, mock_git):
        """Returns empty list when both diff methods fail."""
        mock_git.side_effect = RuntimeError("all fail")
        d = self._make_detector()
        files = d.get_changed_files()
        assert files == []

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_lines(self, mock_git):
        """Parse hunk headers from unified diff."""
        mock_git.return_value = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -10,3 +10,5 @@ def foo():\n"
            "@@ -30,0 +32,2 @@ def bar():\n"
        )
        d = self._make_detector()
        ranges = d.get_changed_lines("file.py")
        assert ranges == [(10, 14), (32, 33)]

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_lines_single_line(self, mock_git):
        """Single line change (no count in hunk header)."""
        mock_git.return_value = "@@ -5,1 +5 @@\n"
        d = self._make_detector()
        ranges = d.get_changed_lines("file.py")
        assert ranges == [(5, 5)]

    @patch.object(DiffDetector, "_run_git")
    def test_get_changed_lines_deletion_hunk_skipped(self, mock_git):
        """Deletion hunks (count=0 in new file) are skipped."""
        mock_git.return_value = "@@ -10,3 +10,0 @@\n"
        d = self._make_detector()
        ranges = d.get_changed_lines("file.py")
        assert ranges == []

    # -- Resolve base ref --

    @patch.dict("os.environ", {"GITHUB_BASE_REF": "develop"}, clear=False)
    def test_resolve_base_ref_github_actions(self):
        d = DiffDetector("/tmp/repo", base_ref=None)
        assert d.base_ref == "origin/develop"

    @patch.dict("os.environ", {}, clear=False)
    @patch.object(DiffDetector, "_ref_exists", return_value=True)
    def test_resolve_base_ref_origin_main(self, mock_ref):
        # Remove GITHUB_BASE_REF if set
        import os
        os.environ.pop("GITHUB_BASE_REF", None)
        d = DiffDetector("/tmp/repo", base_ref=None)
        assert d.base_ref == "origin/main"

    # -- filter_findings_to_diff --

    def test_filter_findings_dict_in_diff(self):
        d = self._make_detector()
        changed = [
            ChangedFile(path="src/api.py", status="M", changed_lines=[(10, 20)]),
        ]
        findings = [
            {"path": "src/api.py", "line": 15, "severity": "high"},
            {"path": "src/api.py", "line": 50, "severity": "low"},
            {"path": "src/utils.py", "line": 5, "severity": "medium"},
        ]
        filtered = d.filter_findings_to_diff(findings, changed)
        assert len(filtered) == 1
        assert filtered[0]["line"] == 15

    def test_filter_findings_no_line(self):
        """Finding without a line number is kept if file is changed."""
        d = self._make_detector()
        changed = [ChangedFile(path="requirements.txt", status="M")]
        findings = [{"path": "requirements.txt", "severity": "medium"}]
        filtered = d.filter_findings_to_diff(findings, changed)
        assert len(filtered) == 1

    def test_filter_findings_no_path_kept(self):
        """Finding with no extractable path is kept conservatively."""
        d = self._make_detector()
        changed = [ChangedFile(path="x.py", status="M")]
        findings = [{"severity": "low"}]  # no path
        filtered = d.filter_findings_to_diff(findings, changed)
        assert len(filtered) == 1

    def test_filter_findings_attr_based(self):
        """Works with attribute-based finding objects."""

        @dataclass
        class Finding:
            file_path: str = "src/main.py"
            line_number: int = 12
            severity: str = "high"

        d = self._make_detector()
        changed = [ChangedFile(path="src/main.py", status="M", changed_lines=[(10, 15)])]
        findings = [Finding()]
        filtered = d.filter_findings_to_diff(findings, changed)
        assert len(filtered) == 1

    def test_filter_findings_empty_changed_lines_kept(self):
        """If changed_lines not populated, keep finding conservatively."""
        d = self._make_detector()
        changed = [ChangedFile(path="src/api.py", status="M", changed_lines=[])]
        findings = [{"path": "src/api.py", "line": 100, "severity": "low"}]
        filtered = d.filter_findings_to_diff(findings, changed)
        assert len(filtered) == 1

    def test_extract_path_dict(self):
        assert DiffDetector._extract_path({"path": "a.py"}) == "a.py"
        assert DiffDetector._extract_path({"file_path": "b.py"}) == "b.py"

    def test_extract_path_attr(self):

        @dataclass
        class F:
            path: str = "c.py"

        assert DiffDetector._extract_path(F()) == "c.py"

    def test_extract_line_dict(self):
        assert DiffDetector._extract_line({"line": 42}) == 42
        assert DiffDetector._extract_line({"line_number": 7}) == 7

    def test_extract_line_none(self):
        assert DiffDetector._extract_line({"severity": "high"}) is None


# ============================================================================
# IncrementalScanFilter (Pipeline Stage)
# ============================================================================


class TestIncrementalScanFilter:
    def _make_ctx(self, only_changed: bool = True) -> PipelineContext:
        return PipelineContext(
            config={"only_changed": only_changed},
            target_path="/tmp/repo",
        )

    def test_should_run_true(self):
        stage = IncrementalScanFilter()
        ctx = self._make_ctx(only_changed=True)
        assert stage.should_run(ctx) is True

    def test_should_run_false(self):
        stage = IncrementalScanFilter()
        ctx = self._make_ctx(only_changed=False)
        assert stage.should_run(ctx) is False

    def test_name_and_phase(self):
        stage = IncrementalScanFilter()
        assert stage.name == "phase0_5_incremental_filter"
        assert stage.phase_number == 0.5

    @patch.object(DiffDetector, "get_changed_files")
    @patch.object(DiffDetector, "get_changed_lines")
    def test_execute_sets_changed_files(self, mock_lines, mock_files):
        mock_files.return_value = [ChangedFile(path="a.py", status="M")]
        mock_lines.return_value = [(1, 10)]
        stage = IncrementalScanFilter()
        ctx = self._make_ctx()
        result = stage.execute(ctx)
        assert result.success
        assert ctx.changed_files is not None
        assert len(ctx.changed_files) == 1

    @patch.object(DiffDetector, "get_changed_files")
    def test_execute_no_changed_files(self, mock_files):
        mock_files.return_value = []
        stage = IncrementalScanFilter()
        ctx = self._make_ctx()
        result = stage.execute(ctx)
        assert result.success
        assert ctx.changed_files == []


# ============================================================================
# DiffFindingFilter (Pipeline Stage)
# ============================================================================


class TestDiffFindingFilter:
    def _make_ctx(self, only_changed: bool = True) -> PipelineContext:
        ctx = PipelineContext(
            config={"only_changed": only_changed},
            target_path="/tmp/repo",
        )
        return ctx

    def test_should_run_requires_changed_files(self):
        stage = DiffFindingFilter()
        ctx = self._make_ctx()
        ctx.changed_files = None
        assert stage.should_run(ctx) is False

        ctx.changed_files = [ChangedFile(path="a.py", status="M")]
        assert stage.should_run(ctx) is True

    def test_should_run_false_when_not_incremental(self):
        stage = DiffFindingFilter()
        ctx = self._make_ctx(only_changed=False)
        ctx.changed_files = [ChangedFile(path="a.py", status="M")]
        assert stage.should_run(ctx) is False

    def test_name_and_dependencies(self):
        stage = DiffFindingFilter()
        assert stage.name == "phase1_5_diff_finding_filter"
        assert stage.phase_number == 1.5
        assert "phase1_scanner_orchestration" in stage.required_stages

    @patch.object(DiffDetector, "filter_findings_to_diff")
    def test_execute_filters_findings(self, mock_filter):
        mock_filter.return_value = [{"path": "a.py", "line": 5}]
        stage = DiffFindingFilter()
        ctx = self._make_ctx()
        ctx.findings = [
            {"path": "a.py", "line": 5},
            {"path": "b.py", "line": 10},
        ]
        ctx.changed_files = [ChangedFile(path="a.py", status="M")]
        result = stage.execute(ctx)
        assert result.success
        assert len(ctx.findings) == 1
        assert result.metadata.get("filtered") == 1
