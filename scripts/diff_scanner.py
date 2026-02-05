"""
Incremental/Diff-Only Scanning Module.

Only scan changed files in PRs to reduce cost and latency. The ``only_changed``
config flag enables this module, which provides:

- ``DiffDetector`` -- Detects which files changed via git diff
- ``ChangedFile`` -- Dataclass representing a changed file and its hunks
- ``IncrementalScanFilter`` -- Pipeline stage (Phase 0.5) that limits scope
- ``DiffFindingFilter`` -- Pipeline stage (Phase 1.5) that filters findings

Usage::

    detector = DiffDetector("/path/to/repo", base_ref="origin/main")
    changed = detector.get_changed_files()
    for cf in changed:
        cf.changed_lines = detector.get_changed_lines(cf.path)
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure scripts dir is importable (same pattern as pipeline/stages.py)
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from pipeline.base_stage import BaseStage
from pipeline.protocol import PipelineContext

logger = logging.getLogger(__name__)


# ============================================================================
# Data model
# ============================================================================


@dataclass
class ChangedFile:
    """A file that was changed between the base ref and HEAD.

    Attributes
    ----------
    path : str
        Relative file path within the repository.
    status : str
        Git change status: A=added, M=modified, R=renamed, D=deleted, C=copied.
    old_path : str | None
        Previous path for renames (status ``R``).  ``None`` otherwise.
    changed_lines : list[tuple[int, int]]
        List of ``(start_line, end_line)`` ranges that were changed.
        Populated lazily by ``DiffDetector.get_changed_lines``.
    """

    path: str
    status: str  # A, M, R, D, C
    old_path: Optional[str] = None
    changed_lines: List[Tuple[int, int]] = field(default_factory=list)


# ============================================================================
# Core diff detection
# ============================================================================


class DiffDetector:
    """Detect changed files for incremental scanning.

    Uses ``git diff`` to determine which files changed between a base
    reference and HEAD, then extracts the exact line ranges from unified
    diff hunk headers.

    Parameters
    ----------
    repo_path : str
        Path to the git repository root.
    base_ref : str | None
        Base reference to diff against (e.g. ``"origin/main"``, ``"HEAD~1"``).
        If ``None``, auto-detects from environment variables or common defaults.
    """

    def __init__(self, repo_path: str, base_ref: Optional[str] = None) -> None:
        self.repo_path = repo_path
        self.base_ref = base_ref or self._resolve_base_ref()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_changed_files(self) -> List[ChangedFile]:
        """Return list of files changed since base_ref.

        Uses ``git diff --name-status <base_ref>...HEAD`` to detect
        Added (A), Modified (M), Renamed (R), and Copied (C) files.
        Deleted (D) files are excluded since there is nothing to scan.

        Returns
        -------
        list[ChangedFile]
            Changed files with status information.  ``changed_lines``
            is not yet populated -- call ``get_changed_lines`` separately.

        Raises
        ------
        RuntimeError
            If the git command fails (e.g. invalid base_ref).
        """
        try:
            output = self._run_git(
                ["diff", "--name-status", f"{self.base_ref}...HEAD"]
            )
        except RuntimeError:
            # Fallback: try two-dot diff (works when merge-base cannot be found)
            logger.debug(
                "Three-dot diff failed for %s, trying two-dot diff",
                self.base_ref,
            )
            try:
                output = self._run_git(
                    ["diff", "--name-status", f"{self.base_ref}..HEAD"]
                )
            except RuntimeError:
                logger.warning(
                    "Could not diff against %s; falling back to full scan",
                    self.base_ref,
                )
                return []

        changed: List[ChangedFile] = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            raw_status = parts[0].strip()
            # Normalise: R100, R075, C100 etc. -> R, C
            status = raw_status[0]

            if status == "D":
                # Deleted files have nothing to scan
                continue

            if status == "R" and len(parts) >= 3:
                # Rename: status\told_path\tnew_path
                old_path = parts[1].strip()
                new_path = parts[2].strip()
                changed.append(
                    ChangedFile(path=new_path, status=status, old_path=old_path)
                )
            elif status == "C" and len(parts) >= 3:
                # Copy: status\tsource_path\tnew_path
                new_path = parts[2].strip()
                changed.append(ChangedFile(path=new_path, status=status))
            else:
                # Added or Modified: status\tpath
                file_path = parts[1].strip()
                changed.append(ChangedFile(path=file_path, status=status))

        logger.info(
            "DiffDetector: %d changed file(s) detected against %s",
            len(changed),
            self.base_ref,
        )
        return changed

    def get_changed_lines(self, file_path: str) -> List[Tuple[int, int]]:
        """Return list of (start_line, end_line) ranges that changed.

        Uses ``git diff -U0 <base_ref>...HEAD -- <file_path>`` and parses
        the unified diff hunk headers (``@@ -a,b +c,d @@``) to extract
        the ranges of added/modified lines in the new version of the file.

        Parameters
        ----------
        file_path : str
            Relative path within the repository.

        Returns
        -------
        list[tuple[int, int]]
            Each tuple is an inclusive ``(start_line, end_line)`` range.
            Returns an empty list if parsing fails or the file was deleted.
        """
        try:
            output = self._run_git(
                ["diff", "-U0", f"{self.base_ref}...HEAD", "--", file_path]
            )
        except RuntimeError:
            try:
                output = self._run_git(
                    ["diff", "-U0", f"{self.base_ref}..HEAD", "--", file_path]
                )
            except RuntimeError:
                logger.debug(
                    "Could not get diff hunks for %s; treating entire file as changed",
                    file_path,
                )
                return []

        ranges: List[Tuple[int, int]] = []
        # Pattern: @@ -old_start[,old_count] +new_start[,new_count] @@
        hunk_pattern = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")

        for line in output.splitlines():
            match = hunk_pattern.match(line)
            if match:
                start = int(match.group(1))
                count_str = match.group(2)
                count = int(count_str) if count_str is not None else 1

                if count == 0:
                    # Pure deletion hunk in the new file -- no new lines
                    continue

                end = start + count - 1
                ranges.append((start, end))

        return ranges

    def filter_findings_to_diff(
        self,
        findings: List[Any],
        changed_files: List[ChangedFile],
    ) -> List[Any]:
        """Filter findings to only include those in changed files/lines.

        For each finding:
        - If the finding's file is not in ``changed_files`` -> remove
        - If the finding has a line number and that line is not in a
          changed range -> remove
        - If the finding has no line number (e.g., dependency vulnerability)
          -> keep if its file is changed

        Parameters
        ----------
        findings : list
            Heterogeneous findings (dataclass objects, Pydantic models, or dicts).
        changed_files : list[ChangedFile]
            Files with populated ``changed_lines``.

        Returns
        -------
        list
            Filtered findings that intersect with the diff.
        """
        # Build lookup: relative_path -> ChangedFile
        changed_map: Dict[str, ChangedFile] = {}
        for cf in changed_files:
            changed_map[cf.path] = cf
            # Also index by normalised path (strip leading ./)
            normalised = cf.path.lstrip("./")
            if normalised != cf.path:
                changed_map[normalised] = cf

        filtered: List[Any] = []
        for finding in findings:
            finding_path = self._extract_path(finding)
            if finding_path is None:
                # Cannot determine file -- keep conservatively
                filtered.append(finding)
                continue

            # Normalise the finding path for lookup
            finding_path_str = str(finding_path).lstrip("./")

            cf = changed_map.get(finding_path_str)
            if cf is None:
                # Also try the raw path
                cf = changed_map.get(str(finding_path))

            if cf is None:
                # File not in diff -> remove
                logger.debug(
                    "Filtering out finding in unchanged file: %s", finding_path_str
                )
                continue

            # File is in the diff -- now check line ranges
            finding_line = self._extract_line(finding)

            if finding_line is None:
                # No line info (e.g. dependency CVE) -- keep if file changed
                filtered.append(finding)
                continue

            if not cf.changed_lines:
                # No line-level data available -- keep conservatively
                filtered.append(finding)
                continue

            # Check if the finding line falls within any changed range
            in_diff = any(
                start <= finding_line <= end for start, end in cf.changed_lines
            )
            if in_diff:
                filtered.append(finding)
            else:
                logger.debug(
                    "Filtering out finding at %s:%d (not in changed ranges)",
                    finding_path_str,
                    finding_line,
                )

        logger.info(
            "DiffFindingFilter: %d -> %d findings after diff filtering",
            len(findings),
            len(filtered),
        )
        return filtered

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_base_ref(self) -> str:
        """Auto-detect the base reference.

        Resolution order:
        1. ``GITHUB_BASE_REF`` env var (GitHub Actions PR context)
        2. ``origin/main`` if it exists
        3. ``origin/master`` if it exists
        4. ``HEAD~1`` as last resort

        Returns
        -------
        str
            A git ref suitable for ``git diff <ref>...HEAD``.
        """
        # 1. GitHub Actions PR context
        github_base = os.environ.get("GITHUB_BASE_REF", "").strip()
        if github_base:
            ref = f"origin/{github_base}"
            logger.info("Using GITHUB_BASE_REF: %s", ref)
            return ref

        # 2. Try origin/main
        if self._ref_exists("origin/main"):
            logger.info("Using default base ref: origin/main")
            return "origin/main"

        # 3. Try origin/master
        if self._ref_exists("origin/master"):
            logger.info("Using default base ref: origin/master")
            return "origin/master"

        # 4. Fallback
        logger.info("No remote branch found; using HEAD~1 as base ref")
        return "HEAD~1"

    def _ref_exists(self, ref: str) -> bool:
        """Check whether a git ref exists in the repository."""
        try:
            self._run_git(["rev-parse", "--verify", ref])
            return True
        except RuntimeError:
            return False

    def _run_git(self, args: List[str]) -> str:
        """Run a git command and return stdout.

        Parameters
        ----------
        args : list[str]
            Arguments to ``git`` (not including ``git`` itself).

        Returns
        -------
        str
            Standard output of the command.

        Raises
        ------
        RuntimeError
            If git is not installed or the command exits with non-zero status.
        """
        cmd = ["git"] + args
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "git is not installed or not found in PATH"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"git command timed out: {' '.join(cmd)}"
            )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(
                f"git command failed (exit {result.returncode}): "
                f"{' '.join(cmd)}\n{stderr}"
            )

        return result.stdout

    @staticmethod
    def _extract_path(finding: Any) -> Optional[str]:
        """Extract the file path from a heterogeneous finding.

        Supports ``UnifiedFinding.path`` (Path object), ``HybridFinding.file_path``,
        and dict findings.

        Returns
        -------
        str | None
            The file path as a string, or ``None`` if not determinable.
        """
        # Attribute access (dataclass / Pydantic)
        for attr in ("path", "file_path"):
            val = getattr(finding, attr, None)
            if val is not None:
                return str(val)

        # Dict access
        if isinstance(finding, dict):
            for key in ("path", "file_path"):
                val = finding.get(key)
                if val is not None:
                    return str(val)

        return None

    @staticmethod
    def _extract_line(finding: Any) -> Optional[int]:
        """Extract the line number from a heterogeneous finding.

        Supports ``UnifiedFinding.line``, ``HybridFinding.line_number``,
        and dict findings.

        Returns
        -------
        int | None
            The line number, or ``None`` if not available.
        """
        # Attribute access
        for attr in ("line", "line_number"):
            val = getattr(finding, attr, None)
            if val is not None:
                try:
                    return int(val)
                except (TypeError, ValueError):
                    continue

        # Dict access
        if isinstance(finding, dict):
            for key in ("line", "line_number"):
                val = finding.get(key)
                if val is not None:
                    try:
                        return int(val)
                    except (TypeError, ValueError):
                        continue

        return None


# ============================================================================
# Pipeline Stages
# ============================================================================


class IncrementalScanFilter(BaseStage):
    """Phase 0.5: Filter target files to only changed files when only_changed=True.

    Runs BEFORE Phase 1 scanners.  Sets ``ctx.changed_files`` on the context
    so scanners can limit their scope.

    This stage is a no-op (skipped) when ``only_changed`` is not enabled,
    allowing the pipeline to fall through to a full scan.
    """

    name = "phase0_5_incremental_filter"
    display_name = "Phase 0.5: Incremental Scan Filter"
    phase_number = 0.5

    def should_run(self, ctx: PipelineContext) -> bool:
        """Only run when incremental scanning is enabled."""
        return ctx.config.get("only_changed", False)

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        """Detect changed files and attach them to the pipeline context.

        Sets ``ctx.changed_files`` for downstream stages.  Also populates
        ``changed_lines`` on each ``ChangedFile`` so that Phase 1.5 can
        do line-level filtering.
        """
        detector = DiffDetector(ctx.target_path)
        changed = detector.get_changed_files()

        if not changed:
            logger.warning(
                "IncrementalScanFilter: no changed files detected; "
                "downstream scanners will run on full codebase"
            )

        # Populate changed_lines for each file
        for cf in changed:
            cf.changed_lines = detector.get_changed_lines(cf.path)

        # Store on context for downstream stages
        ctx.changed_files = changed  # type: ignore[attr-defined]

        file_list = [cf.path for cf in changed]
        logger.info(
            "IncrementalScanFilter: %d changed file(s): %s",
            len(changed),
            ", ".join(file_list[:10]) + ("..." if len(file_list) > 10 else ""),
        )

        return {
            "changed_files": len(changed),
            "files": file_list,
        }


class DiffFindingFilter(BaseStage):
    """Phase 1.5: Filter findings to only those in changed files/lines.

    Runs AFTER Phase 1 scanners.  Removes findings that are not in the diff,
    reducing noise and cost for subsequent AI enrichment stages.
    """

    name = "phase1_5_diff_finding_filter"
    display_name = "Phase 1.5: Diff Finding Filter"
    phase_number = 1.5
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        """Only run when incremental scanning is enabled and changed files are available."""
        return (
            ctx.config.get("only_changed", False)
            and hasattr(ctx, "changed_files")
            and ctx.changed_files is not None
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        """Filter ctx.findings to the intersection with the diff."""
        detector = DiffDetector(ctx.target_path)
        before = len(ctx.findings)
        ctx.findings = detector.filter_findings_to_diff(
            ctx.findings, ctx.changed_files  # type: ignore[attr-defined]
        )
        after = len(ctx.findings)
        filtered = before - after

        if filtered:
            logger.info(
                "DiffFindingFilter: removed %d finding(s) outside the diff "
                "(%d -> %d)",
                filtered,
                before,
                after,
            )

        return {
            "before": before,
            "after": after,
            "filtered": filtered,
        }
